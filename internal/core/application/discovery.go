package application

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	log "github.com/sirupsen/logrus"
)

// coin is a bound vtxo or onchain utxo, tagged with its slot and source transaction.
type coin struct {
	Slot      int
	Outpoint  wire.OutPoint
	Amount    uint64
	Script    []byte
	Assets    []clientlib.Asset
	CreatedAt time.Time
	Expiry    time.Time // zero for onchain
	Swept     bool      // offchain only: arkd prices a swept vtxo as recoverable
	Confirms  int       // onchain only
	Source    *wire.MsgTx
}

// vtxoCoin leaves a malformed txid or script zero: the daemon checks every coin against its source.
func vtxoCoin(slot int, v clientlib.Vtxo) coin {
	c := coin{
		Slot: slot, Amount: v.Amount, Assets: v.Assets,
		CreatedAt: v.CreatedAt, Expiry: v.ExpiresAt, Swept: v.Swept,
	}
	c.Outpoint.Index = v.VOut
	if h, err := chainhash.NewHashFromStr(v.Txid); err == nil {
		c.Outpoint.Hash = *h
	}
	c.Script, _ = hex.DecodeString(v.Script)
	return c
}

// utxoCoin's CreatedAt is the block time, zero while unconfirmed.
func utxoCoin(slot int, u clientlib.ExplorerUtxo, confirms int) coin {
	c := coin{Slot: slot, Amount: u.Amount, Confirms: confirms}
	c.Outpoint.Index = u.Vout
	if h, err := chainhash.NewHashFromStr(u.Txid); err == nil {
		c.Outpoint.Hash = *h
	}
	c.Script, _ = hex.DecodeString(u.Script)
	if u.Status.Confirmed && u.Status.BlockTime > 0 {
		c.CreatedAt = time.Unix(u.Status.BlockTime, 0)
	}
	return c
}

type onchainSnapshot struct {
	at    time.Time
	coins []coin
}

// an untrusted template must not name the delegate key
func (s *service) checkDelegatePolicy(ctx context.Context, id string, inst *template.Instance, slots int, c *cosigner) error {
	t, err := s.repo.GetTemplate(ctx, id)
	if err != nil {
		return err
	}
	if t.Trusted {
		return nil
	}
	for slot := range slots {
		for _, leaf := range inst.Tapscripts(slot) {
			script, err := hex.DecodeString(leaf)
			if err != nil {
				return err
			}
			holds, err := scriptPushes(script, schnorr.SerializePubKey(c.key.PubKey()))
			if err != nil {
				return err
			}
			if holds {
				return ErrDelegateKeyLeaf
			}
		}
	}
	return nil
}

// sourceTx is a virtual tx, else an onchain one.
func (s *service) sourceTx(ctx context.Context, id string) (*wire.MsgTx, error) {
	tx, err := s.virtualTx(ctx, id)
	if err != nil && ctx.Err() == nil {
		if onchain, onchainErr := s.onchainTx(id); onchainErr == nil {
			return onchain, nil
		}
	}
	return tx, err
}

func (s *service) onchainTx(id string) (*wire.MsgTx, error) {
	raw, err := s.explorer.GetTxHex(id)
	if err != nil {
		return nil, err
	}
	tx := wire.NewMsgTx(2)
	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(raw))); err != nil {
		return nil, err
	}
	if tx.TxHash().String() != id {
		return nil, errors.New("explorer returned a different transaction")
	}
	return tx, nil
}

func (s *service) onchainUtxos(sl domain.SlotBinding) ([]clientlib.ExplorerUtxo, error) {
	_, key, err := pkScriptOf(sl.Tapscripts)
	if err != nil {
		return nil, err
	}
	addr, err := onchainAddress(key, s.network)
	if err != nil {
		return nil, err
	}
	return s.explorer.GetUtxos([]string{addr})
}

// a coin not listed yet is not spent; arkTxid is the ark tx that spent one of them, if any
func (s *service) spent(ctx context.Context, slots []domain.SlotBinding) (gone bool, arkTxid string, err error) {
	var vtxos []clientlib.Outpoint
	for _, sl := range slots {
		op, err := wire.NewOutPointFromString(sl.Outpoint)
		if err != nil {
			return false, "", err
		}
		if !sl.Onchain {
			vtxos = append(vtxos, clientlib.Outpoint{Txid: op.Hash.String(), VOut: op.Index})
			continue
		}
		outs, err := s.explorer.GetTxOutspends(op.Hash.String())
		if err != nil {
			return false, "", err
		}
		if int(op.Index) >= len(outs) || !outs[op.Index].Spent {
			return false, "", nil
		}
	}
	if len(vtxos) == 0 {
		return true, "", nil
	}
	resp, err := s.indexer.GetVtxos(ctx, clientlib.WithOutpoints(vtxos))
	if err != nil {
		return false, "", err
	}
	n := 0
	for _, v := range resp.Vtxos {
		if v.Spent || v.Swept || v.Unrolled {
			n++
		}
		if v.ArkTxid != "" {
			arkTxid = v.ArkTxid
		}
	}
	return n == len(vtxos), arkTxid, nil
}

// settleSpent follows the ark tx that spent d's coins, unless d's own settlement is still to finish.
func (s *service) settleSpent(ctx context.Context, d domain.Delegation, arkTxid string) error {
	rows, err := s.repo.ListSettlements(ctx)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(rows, func(row domain.Settlement) bool { return row.DelegationID == d.ID }) {
		return nil
	}
	if arkTxid == "" {
		return s.repo.SetStatus(ctx, d.ID, domain.DelegationStatusDone)
	}
	tx, err := s.virtualTx(ctx, arkTxid)
	if err != nil {
		return err
	}
	s.settle(ctx, spentBy(d, tx))
	return nil
}

func (s *service) onchainCoins(sl domain.SlotBinding, slot int, now time.Time) ([]coin, error) {
	cached, drops, ok := s.cachedOnchain(sl.Script)
	if !ok || now.Sub(cached.at) >= s.onchainPollInterval {
		utxos, err := s.onchainUtxos(sl)
		if err != nil {
			return nil, err
		}
		cached = onchainSnapshot{at: now}
		for _, u := range utxos {
			if u.Script != sl.Script {
				return nil, errors.New("explorer returned a coin with another script")
			}
			confirms, err := s.explorer.Confirmations(u.Txid)
			if err != nil {
				return nil, err
			}
			cached.coins = append(cached.coins, utxoCoin(0, u, confirms))
		}
		s.cacheOnchain(sl.Script, cached, drops)
	}
	var coins []coin
	for _, c := range cached.coins {
		if sl.Outpoint == "" || c.Outpoint.String() == sl.Outpoint {
			c.Slot = slot
			coins = append(coins, c)
		}
	}
	return coins, nil
}

func (s *service) slotCoins(sl domain.SlotBinding, slot int, byScript map[string][]clientlib.Vtxo, now time.Time) ([]coin, error) {
	if sl.Onchain {
		return s.onchainCoins(sl, slot, now)
	}
	var coins []coin
	for _, v := range byScript[sl.Script] {
		if !v.Spent && (sl.Outpoint == "" || sl.Outpoint == v.Outpoint.String()) {
			coins = append(coins, vtxoCoin(slot, v))
		}
	}
	return coins, nil
}

// discover also settles a bound delegation whose coins are all gone.
func (s *service) discover(ctx context.Context, delegations []domain.Delegation, active map[string]struct{}, now time.Time) (map[int64]Holdings, map[int64]string, []renewalInput, error) {
	tip := sync.OnceValues(func() (ports.ChainTip, error) {
		t, err := s.explorer.ChainTip()
		if err != nil {
			log.WithError(err).Warn("chain tip unknown: locktimes wait")
		}
		return t, err
	})
	slices.SortFunc(delegations, func(a, b domain.Delegation) int { return cmp.Compare(a.ID, b.ID) })
	s.pruneConsumed(now)
	holdings := map[int64]Holdings{}
	unwatched := map[int64]string{}
	scripts := s.watchAll(ctx, delegations, active, unwatched)
	byScript, err := s.spendableVtxos(ctx, scripts)
	if err != nil {
		return nil, nil, nil, err
	}
	// a bound coin is not the watch's, except a spend's
	boundOwners := map[string]int64{}
	for _, d := range delegations {
		if s.watched[d.ID] == nil || d.IsSpend() {
			continue
		}
		for _, sl := range d.Slots {
			if sl.Outpoint != "" {
				boundOwners[sl.Outpoint] = d.ID
			}
		}
	}
	used := map[string]int64{}
	watchScripts := map[string]int64{}
	var inputs []renewalInput
	s.entries = s.entries[:0]
next:
	for _, d := range delegations {
		w := s.watched[d.ID]
		if w == nil {
			continue
		}
		h := Holdings{}
		var group []renewalInput
		complete := true
		missing := 0
		var planned []plannedCoin
		plannable := true
		for slot, sl := range d.Slots {
			if sl.Outpoint == "" {
				if owner, exists := watchScripts[sl.Script]; exists {
					unwatched[d.ID] = fmt.Sprintf("shares a script with delegation %d", owner)
					continue next
				}
				watchScripts[sl.Script] = d.ID
			}
			coins, err := s.slotCoins(sl, slot, byScript, now)
			if err != nil {
				unwatched[d.ID] = err.Error()
				continue next
			}
			if len(coins) == 0 {
				complete = false
				missing++
			}
			for _, c := range coins {
				op := c.Outpoint.String()
				if s.isConsumed(op) || s.held[op] {
					continue
				}
				if owner, ok := boundOwners[op]; ok && owner != d.ID {
					continue
				}
				if owner, ok := used[op]; ok && owner != d.ID {
					complete = false
					continue
				}
				due := dueTime(w.instance, c, tip)
				deadline := s.deadline(c, due)
				switch {
				case sl.Onchain:
					deadline = time.Time{} // the plan decides
				case d.IsSpend():
					deadline = due // a wallet waits for it
				}
				h.add(c, due, deadline)
				unconfirmed := sl.Onchain && (c.Confirms < w.tmpl.Inputs()[slot].Schedule.MinConfirmations || c.CreatedAt.IsZero())
				eligible := !now.Before(due) && !unconfirmed && locktimeReached(w.instance, slot, tip)
				// a vtxo's due is read off its expiry: the plan can count on it. A deposit, locktime or confirmation count cannot be foreseen.
				if eligible || (!sl.Onchain && !c.Expiry.IsZero() && locktimeReached(w.instance, slot, tip)) {
					planned = append(planned, plannedCoin{coin: c, slot: slot, due: due, deadline: deadline, onchain: sl.Onchain})
				}
				if !eligible {
					complete = false
					continue
				}
				group = append(group, renewalInput{watched: w, coin: c, due: due, onchain: sl.Onchain})
			}
			if n := slices.IndexFunc(planned, func(p plannedCoin) bool { return p.slot == slot }); n < 0 || (len(d.Slots) > 1 && len(planned) != slot+1) {
				plannable = false
			}
		}
		holdings[d.ID] = h
		if w.tmpl.Type() == template.Intent && plannable && !s.sampled[d.ID] {
			s.entries = append(s.entries, entriesOf(d.ID, len(d.Slots), planned)...)
		}
		// a delegation in flight is settled by its lane
		if !d.IsWatch() && missing == len(d.Slots) && !s.sampled[d.ID] {
			spent, arkTxid, err := s.spent(ctx, d.Slots)
			if err == nil && spent {
				err = s.settleSpent(ctx, d, arkTxid)
			}
			if err != nil {
				unwatched[d.ID] = err.Error()
			}
			continue
		}
		if len(d.Slots) > 1 && (!complete || len(group) != len(d.Slots)) {
			continue
		}
		for _, in := range group {
			used[in.coin.Outpoint.String()] = d.ID
		}
		inputs = append(inputs, group...)
	}
	s.pruneCaches()
	return holdings, unwatched, inputs, nil
}

func (s *service) watchAll(ctx context.Context, delegations []domain.Delegation, active map[string]struct{}, unwatched map[int64]string) []string {
	cache := map[int64]*watched{}
	var scripts []string
	listed := map[string]bool{}
	for i := range delegations {
		d := &delegations[i]
		if _, ok := active[d.TemplateID]; !ok {
			unwatched[d.ID] = "template disabled"
			continue
		}
		w, known := s.watched[d.ID]
		if !known {
			var err error
			if w, err = s.watch(ctx, d); err != nil {
				unwatched[d.ID] = err.Error()
				continue
			}
		}
		cache[d.ID] = w
		if w == nil {
			unwatched[d.ID] = errOtherKey.Error()
			continue
		}
		for _, sl := range d.Slots {
			if !sl.Onchain && !listed[sl.Script] {
				listed[sl.Script] = true
				scripts = append(scripts, sl.Script)
			}
		}
	}
	s.watched = cache
	return scripts
}

func (s *service) pruneCaches() {
	live := map[string]bool{}
	for _, w := range s.watched {
		if w == nil {
			continue
		}
		for _, sl := range w.delegation.Slots {
			if sl.Onchain {
				live[sl.Script] = true
			}
		}
	}
	s.shared.Lock()
	defer s.shared.Unlock()
	maps.DeleteFunc(s.onchainCache, func(script string, _ onchainSnapshot) bool { return !live[script] })
}

func (h *Holdings) add(c coin, due, deadline time.Time) {
	h.Vtxos++
	h.Amount += c.Amount
	if !c.Expiry.IsZero() && (h.NextExpiry.IsZero() || c.Expiry.Before(h.NextExpiry)) {
		h.NextExpiry = c.Expiry
	}
	if h.NextDue.IsZero() || due.Before(h.NextDue) {
		h.NextDue = due
	}
	if !deadline.IsZero() && (h.NextDeadline.IsZero() || deadline.Before(h.NextDeadline)) {
		h.NextDeadline = deadline
	}
}

type plannedCoin struct {
	coin          coin
	slot          int
	due, deadline time.Time
	onchain       bool
}

// entriesOf: a watch's coins are an intent each; a multi-slot delegation spends all its slots in one.
func entriesOf(id int64, slots int, coins []plannedCoin) []planEntry {
	if slots == 1 {
		entries := make([]planEntry, 0, len(coins))
		for _, c := range coins {
			entries = append(entries, planEntry{
				outpoints: []string{c.coin.Outpoint.String()}, delegation: id, amount: c.coin.Amount,
				due: c.due, deadline: c.deadline, deposit: c.onchain, confirmed: c.coin.CreatedAt,
			})
		}
		return entries
	}
	e := planEntry{delegation: id, deposit: true}
	var deadline time.Time
	for _, c := range coins {
		e.outpoints = append(e.outpoints, c.coin.Outpoint.String())
		e.amount += c.coin.Amount
		e.due = maxTime(e.due, c.due)
		e.deposit = e.deposit && c.onchain
		if !c.deadline.IsZero() && (deadline.IsZero() || c.deadline.Before(deadline)) {
			deadline = c.deadline
		}
		if c.onchain && (e.confirmed.IsZero() || c.coin.CreatedAt.Before(e.confirmed)) {
			e.confirmed = c.coin.CreatedAt
		}
	}
	e.deadline = maxTime(e.due, deadline)
	return []planEntry{e}
}

// own exempts the successors from the delegation cap: the daemon built tx
func (s *service) successors(ctx context.Context, d *domain.Delegation, tx *wire.MsgTx, outpoints map[int]wire.OutPoint, sources map[string]*wire.MsgTx, own bool) error {
	body, ok := packets.Find(tx, packets.TypeAdvertisement)
	if !ok {
		return nil
	}
	records, err := packets.DecodeAdvertisement(body)
	if err != nil {
		return fmt.Errorf("%w: %v", errUnusableAdvertisement, err)
	}
	var errs []error
	for _, record := range records {
		id := hex.EncodeToString(record.Template[:])
		if err := s.successor(ctx, d, id, record.Outputs, outpoints, sources, own); err != nil {
			errs = append(errs, fmt.Errorf("template %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

func (s *service) successor(ctx context.Context, d *domain.Delegation, id string, indexes []uint16, outpoints map[int]wire.OutPoint, sources map[string]*wire.MsgTx, own bool) error {
	t, err := s.parseTemplate(ctx, id)
	if err != nil {
		return err
	}
	if len(t.Variables()) != 0 || len(t.Inputs()) != len(indexes) {
		return fmt.Errorf("%w: target requires variables or has wrong slot count", errUnusableAdvertisement)
	}
	c := s.cosignerFor(d.DelegatePubKey)
	if c == nil {
		return errOtherKey
	}
	var bound []*wire.OutPoint
	raw := make([]string, len(indexes))
	seen := map[wire.OutPoint]bool{}
	for i, index := range indexes {
		op, ok := outpoints[int(index)]
		if !ok || seen[op] {
			return fmt.Errorf("%w: it names an unavailable or duplicate output", errUnusableAdvertisement)
		}
		seen[op] = true
		bound = append(bound, &op)
		raw[i] = op.String()
	}
	inst, err := s.instanceFor(ctx, t, c, nil, bound, sources)
	if err != nil {
		return err
	}
	slots, _, err := bindSlots(t, inst, raw)
	if err != nil {
		return err
	}
	for i, op := range bound {
		source := sources[op.Hash.String()]
		if source == nil || int(op.Index) >= len(source.TxOut) {
			return fmt.Errorf("%w: missing settlement output", errUnusableAdvertisement)
		}
		if slots[i].Script != hex.EncodeToString(source.TxOut[op.Index].PkScript) {
			return fmt.Errorf("%w: advertised script differs from target template", errUnusableAdvertisement)
		}
	}
	_, err = s.create(ctx, domain.Delegation{
		TemplateID: id, ParentID: d.ID, Variables: map[string]string{},
		Fingerprint: domain.Fingerprint(id, nil, raw), DelegatePubKey: d.DelegatePubKey, Slots: slots,
	}, own)
	return err
}

// arkd refuses a locktime above its tip's height, or its median time past for a timestamp
func locktimeReached(inst *template.Instance, slot int, tip func() (ports.ChainTip, error)) bool {
	lt, ok := inst.Locktime(slot)
	if !ok {
		return true
	}
	t, err := tip()
	if err != nil {
		return false
	}
	if lt.IsSeconds() {
		return t.MedianTime >= int64(lt)
	}
	return t.Height >= int64(lt)
}
