package application

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mapSettlements finds the outpoint the batch gives each template output.
func (h *batchHandler) mapSettlements(raw string, t *tree.TxTree) error {
	commitment, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
	if err != nil {
		return err
	}
	var leaves []*wire.MsgTx
	if t != nil {
		for _, leaf := range t.Leaves() {
			leaves = append(leaves, leaf.UnsignedTx)
		}
	}
	used := map[wire.OutPoint]bool{}
	claim := func(p *pendingIntent, index int, want *wire.TxOut, txs []*wire.MsgTx, match func(*wire.MsgTx) bool) bool {
		for _, tx := range txs {
			for i, out := range tx.TxOut {
				op := wire.OutPoint{Hash: tx.TxHash(), Index: uint32(i)}
				if used[op] || extension.IsExtension(out.PkScript) || out.Value != want.Value ||
					!bytes.Equal(out.PkScript, want.PkScript) || !match(tx) {
					continue
				}
				used[op] = true
				p.settled[index] = op
				p.sources[op.Hash.String()] = tx
				return true
			}
		}
		return false
	}
	for _, p := range h.inBatch {
		p.commitment = commitment.UnsignedTx.TxHash().String()
		p.settled = map[int]wire.OutPoint{}
		p.sources = map[string]*wire.MsgTx{}
		for i, out := range p.outputs {
			if !claim(p, i, out, leaves, p.carriesPackets) {
				return fmt.Errorf("settlement output %d missing its value, script or packets", i)
			}
		}
		for i, out := range p.onchainOutputs {
			if !claim(p, len(p.outputs)+1+i, out, []*wire.MsgTx{commitment.UnsignedTx}, func(*wire.MsgTx) bool { return true }) {
				return errors.New("commitment does not pay expected onchain output")
			}
		}
	}
	return nil
}

// carriesPackets reports whether leaf kept the state and advertisement packets of the template tx.
func (p *pendingIntent) carriesPackets(leaf *wire.MsgTx) bool {
	for _, typ := range []uint8{packets.TypeState, packets.TypeAdvertisement} {
		if want, ok := packets.Find(p.logical, typ); ok {
			if got, _ := packets.Find(leaf, typ); !bytes.Equal(got, want) {
				return false
			}
		}
	}
	return true
}

// signCommitment returns "" when the intent has no onchain input.
func (h *batchHandler) signCommitment(ctx context.Context, p *pendingIntent, c *cosigner, raw, original string) (string, error) {
	if raw == "" { // the emulator signed none of its inputs
		raw = original
	}
	tx, err := mergeRemoteSignatures(original, raw, c)
	if err != nil {
		return "", err
	}
	boarding, err := p.withBoardingLeaves(tx)
	if err != nil || !boarding {
		return "", err
	}
	if err = h.svc.signForTemplate(ctx, p.inputs[0].watched.delegation.TemplateID, c, tx); err != nil {
		return "", err
	}
	return tx.B64Encode()
}

// only boarding inputs get a leaf and prevout, so only they get signed; reports whether the intent boards
func (p *pendingIntent) withBoardingLeaves(tx *psbt.Packet) (bool, error) {
	for i := range tx.Inputs {
		tx.Inputs[i].TaprootLeafScript = nil
	}
	boarding := false
	for _, in := range p.inputs {
		if !in.onchain {
			continue
		}
		i := slices.IndexFunc(tx.UnsignedTx.TxIn, func(txin *wire.TxIn) bool { return txin.PreviousOutPoint == in.coin.Outpoint })
		if i < 0 {
			return false, errors.New("commitment omits boarding input")
		}
		tx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{in.leaf}
		tx.Inputs[i].WitnessUtxo = in.prevOut
		boarding = true
	}
	return boarding, nil
}

// owned is the daemon's settlement of inputs by tx; spender is what the indexer or the chain will report spending them.
func owned(inputs []renewalInput, tx *wire.MsgTx, spender string) settlement {
	st := spentBy(inputs[0].watched.delegation, tx)
	st.own, st.spentBy = true, spender
	for _, in := range inputs {
		st.coins = append(st.coins, in.coin.Outpoint.String())
	}
	return st
}

// keep records st before its coins can move: a restart then still finds its successors.
func (s *service) keep(ctx context.Context, st settlement) error {
	var tx bytes.Buffer
	if err := st.tx.Serialize(&tx); err != nil {
		return err
	}
	row := domain.Settlement{
		Txid: st.tx.TxHash().String(), SpentBy: st.spentBy, DelegationID: st.delegation.ID, Tx: tx.Bytes(),
		Outpoints: map[int]string{}, Coins: st.coins, Checkpoints: st.checkpoints, Finals: st.finals, Landed: st.landed,
	}
	for i, op := range st.outpoints {
		row.Outpoints[i] = op.String()
	}
	for _, source := range st.sources {
		var raw bytes.Buffer
		if err := source.Serialize(&raw); err != nil {
			return err
		}
		row.Sources = append(row.Sources, raw.Bytes())
	}
	if err := s.repo.SaveSettlement(ctx, row); err != nil {
		return fmt.Errorf("record settlement: %w", err)
	}
	return nil
}

func (s *service) forget(ctx context.Context, st settlement) {
	if err := s.repo.DeleteSettlement(ctx, st.tx.TxHash().String(), st.spentBy); err != nil {
		log.WithError(err).WithField("txid", st.tx.TxHash().String()).Error("delete settlement")
	}
}

func (s *service) restore(ctx context.Context, row domain.Settlement) (settlement, error) {
	d, err := s.repo.GetByID(ctx, row.DelegationID)
	if err != nil {
		return settlement{}, err
	}
	st := settlement{
		delegation: *d, tx: wire.NewMsgTx(2), spentBy: row.SpentBy, outpoints: map[int]wire.OutPoint{},
		sources: map[string]*wire.MsgTx{}, coins: row.Coins, checkpoints: row.Checkpoints, finals: row.Finals,
		landed: row.Landed, own: true, created: row.CreatedAt,
	}
	if err := st.tx.Deserialize(bytes.NewReader(row.Tx)); err != nil {
		return settlement{}, err
	}
	for i, raw := range row.Outpoints {
		op, err := wire.NewOutPointFromString(raw)
		if err != nil {
			return settlement{}, err
		}
		st.outpoints[i] = *op
	}
	for _, raw := range row.Sources {
		source := wire.NewMsgTx(2)
		if err := source.Deserialize(bytes.NewReader(raw)); err != nil {
			return settlement{}, err
		}
		st.sources[source.TxHash().String()] = source
	}
	return st, nil
}

// arkd broadcasts a commitment seconds after it collects the forfeits
const landingWindow = 5 * time.Minute

// fate is what the indexer and the chain say became of a settlement's coins.
type fate int

const (
	unspent  fate = iota
	landed        // every coin was spent by the settlement's tx, and an ark tx was finalized
	accepted      // arkd holds the ark tx that spent the coins and did not finalize it
	lost          // another tx spent a coin
)

// finishSettlements finalizes the daemon's pending offchain txs, then settles what landed and drops what cannot.
// The coins of a batch not seen landing are held for a landing window.
func (s *service) finishSettlements(ctx context.Context) error {
	s.held = map[string]bool{}
	for _, st := range s.listUnsaved() {
		// retried once its lane is idle
		if s.sampled[st.delegation.ID] {
			continue
		}
		if err := s.keep(ctx, st); err == nil {
			s.dropUnsaved(st.tx.TxHash().String())
		}
	}
	rows, err := s.repo.ListSettlements(ctx)
	if err != nil {
		return fmt.Errorf("list settlements: %w", err)
	}
	for _, row := range rows {
		if s.sampled[row.DelegationID] {
			// its lane settles it
			for _, op := range row.Coins {
				s.held[op] = true
			}
			continue
		}
		st, err := s.restore(ctx, row)
		if err != nil {
			log.WithError(err).WithField("txid", row.Txid).Error("read settlement")
			for _, op := range row.Coins {
				s.held[op] = true
			}
			continue
		}
		if len(st.finals) > 0 {
			s.finalize(ctx, st)
			continue
		}
		if st.landed {
			s.settle(ctx, st)
			continue
		}
		f, err := s.fateOf(ctx, st)
		if err != nil {
			log.WithError(err).WithField("txid", row.Txid).Warn("check settlement")
		}
		switch {
		case err == nil && f == landed:
			s.settle(ctx, st)
			continue
		case err == nil && f == lost:
			s.forget(ctx, st)
			continue
		case err == nil && f == accepted:
			s.recoverPending(ctx, st)
			continue
		case err == nil && (st.delegation.Status != domain.DelegationStatusActive || time.Since(st.created) > landingWindow):
			s.forget(ctx, st)
			continue
		}
		if st.spentBy != st.tx.TxHash().String() { // a batch
			for _, op := range st.coins {
				s.held[op] = true
			}
		}
	}
	return nil
}

// finalize never finalizes an ark tx twice: arkd created the outputs of one it finalized.
func (s *service) finalize(ctx context.Context, st settlement) {
	txid := st.tx.TxHash().String()
	done, err := s.finalized(ctx, st.tx)
	refused := false
	if err == nil && !done {
		err = s.ark.FinalizeTx(ctx, txid, st.finals)
		// arkd answers Internal for good once it failed the tx
		refused = status.Code(err) == codes.Internal
	}
	if err != nil && isRejection(ctx, err) { // arkd no longer holds it
		log.WithError(err).WithField("txid", txid).Warn("offchain tx dropped")
		s.forget(ctx, st)
		s.release(st.coins...)
		return
	}
	if s.refusedFor(txid, refused) > s.renewalTimeout {
		s.abandon(ctx, st, err)
		return
	}
	s.consume(st.coins...)
	if err != nil {
		log.WithError(err).WithField("txid", txid).Warn("finalize offchain tx")
		return
	}
	st.finals = nil
	s.dropUnsaved(txid)
	s.renewed.Add(uint64(len(st.coins)))
	log.WithFields(log.Fields{"delegation": st.delegation.ID, "txid": txid}).Info("offchain tx finalized")
	ren := domain.Renewal{DelegationID: st.delegation.ID, Outpoints: st.coins, CommitmentTxid: txid, Success: true}
	if err := s.repo.RecordRenewal(ctx, ren); err != nil {
		log.WithError(err).WithField("delegation", st.delegation.ID).Error("record attempt")
	}
	s.settle(ctx, st)
}

// recoverPending reads back from arkd the checkpoints of a tx it accepted while the daemon was not listening.
func (s *service) recoverPending(ctx context.Context, st settlement) {
	finals, err := s.pendingFinals(ctx, st)
	if err == nil && finals != nil {
		st.finals = finals
		if err = s.keep(ctx, st); err != nil {
			s.keepUnsaved(st)
		}
		s.finalize(ctx, st)
		return
	}
	if err != nil {
		log.WithError(err).WithField("txid", st.tx.TxHash().String()).Warn("read pending offchain tx")
	}
	// arkd lists no such tx, or the emulator submitted it
	if s.refusedFor(st.tx.TxHash().String(), err == nil) > s.renewalTimeout {
		s.abandon(ctx, st, errors.New("arkd holds the tx without its checkpoints"))
	}
}

// pendingFinals is nil when arkd holds no such tx.
func (s *service) pendingFinals(ctx context.Context, st settlement) ([]string, error) {
	if len(st.checkpoints) == 0 {
		return nil, nil // the emulator submitted it
	}
	c := s.cosignerFor(st.delegation.DelegatePubKey)
	if c == nil {
		return nil, errOtherKey
	}
	spend := &offchainTx{originalCheckpoints: st.checkpoints}
	for _, raw := range st.checkpoints {
		cp, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
		if err != nil {
			return nil, err
		}
		spend.checkpoints = append(spend.checkpoints, cp)
	}
	proof, message, err := s.pendingTxProof(ctx, c, st.delegation.TemplateID, spend.checkpoints)
	if err != nil {
		return nil, err
	}
	txs, err := s.ark.GetPendingTx(ctx, proof, message)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(txs, func(tx clientlib.AcceptedOffchainTx) bool { return tx.Txid == st.tx.TxHash().String() })
	if i < 0 {
		return nil, nil
	}
	return s.signCheckpoints(ctx, c, st.delegation.TemplateID, spend, txs[i].SignedCheckpointTxs)
}

// pendingTxProof proves ownership of the checkpoints' coins with the leaves that spent them; arkd needs no server signature.
func (s *service) pendingTxProof(ctx context.Context, c *cosigner, templateID string, checkpoints []*psbt.Packet) (string, string, error) {
	message, err := intent.GetPendingTxMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeGetPendingTx},
		ExpireAt:    time.Now().Add(10 * time.Minute).Unix(),
	}.Encode()
	if err != nil {
		return "", "", err
	}
	inputs := make([]intent.Input, len(checkpoints))
	for i, cp := range checkpoints {
		in := cp.UnsignedTx.TxIn[0]
		inputs[i] = intent.Input{OutPoint: &in.PreviousOutPoint, Sequence: in.Sequence, WitnessUtxo: cp.Inputs[0].WitnessUtxo}
	}
	proof, err := intent.New(message, inputs, nil)
	if err != nil {
		return "", "", err
	}
	for i := range proof.Inputs {
		src := checkpoints[max(i-1, 0)].Inputs[0] // the message shares input 1's script
		proof.Inputs[i].TaprootLeafScript = src.TaprootLeafScript
		proof.Inputs[i].Unknowns = append(proof.Inputs[i].Unknowns, src.Unknowns...)
	}
	if err := s.signForTemplate(ctx, templateID, c, &proof.Packet); err != nil {
		return "", "", err
	}
	signed, err := proof.B64Encode()
	return signed, message, err
}

// abandon ends a settlement whose tx arkd holds and will never finalize: its coins are locked.
func (s *service) abandon(ctx context.Context, st settlement, err error) {
	log.WithError(err).WithFields(log.Fields{"delegation": st.delegation.ID, "txid": st.tx.TxHash().String()}).Error("offchain tx abandoned: its coins stay locked in arkd")
	s.forget(ctx, st)
	if !st.delegation.IsWatch() {
		if err := s.repo.SetStatus(ctx, st.delegation.ID, domain.DelegationStatusDone); err != nil {
			log.WithError(err).WithField("delegation", st.delegation.ID).Error("complete delegation")
		}
	}
}

func (s *service) fateOf(ctx context.Context, st settlement) (fate, error) {
	var vtxos []clientlib.Outpoint
	spent := 0
	for _, raw := range st.coins {
		op, err := wire.NewOutPointFromString(raw)
		if err != nil {
			return unspent, err
		}
		if !onchainCoin(st.delegation, raw) {
			vtxos = append(vtxos, clientlib.Outpoint{Txid: op.Hash.String(), VOut: op.Index})
			continue
		}
		outs, err := s.explorer.GetTxOutspends(op.Hash.String())
		if err != nil {
			return unspent, err
		}
		if int(op.Index) >= len(outs) || !outs[op.Index].Spent {
			continue
		}
		if outs[op.Index].SpentBy != st.spentBy {
			return lost, nil
		}
		spent++
	}
	arkTx := false
	if len(vtxos) > 0 {
		resp, err := s.indexer.GetVtxos(ctx, clientlib.WithOutpoints(vtxos))
		if err != nil {
			return unspent, err
		}
		for _, v := range resp.Vtxos {
			if !v.Spent && !v.Swept && !v.Unrolled {
				continue
			}
			if cmp.Or(v.SettledBy, v.ArkTxid) != st.spentBy {
				return lost, nil
			}
			arkTx = arkTx || v.SettledBy == ""
			spent++
		}
	}
	switch {
	case spent < len(st.coins):
		return unspent, nil
	case !arkTx:
		return landed, nil
	}
	done, err := s.finalized(ctx, st.tx)
	if err != nil || !done {
		return accepted, err
	}
	return landed, nil
}

// arkd creates the outputs of an ark tx when it is finalized
func (s *service) finalized(ctx context.Context, tx *wire.MsgTx) (bool, error) {
	outs := make([]clientlib.Outpoint, len(tx.TxOut))
	for i := range outs {
		outs[i] = clientlib.Outpoint{Txid: tx.TxHash().String(), VOut: uint32(i)}
	}
	resp, err := s.indexer.GetVtxos(ctx, clientlib.WithOutpoints(outs))
	if err != nil {
		return false, err
	}
	return len(resp.Vtxos) > 0, nil
}

// a watch has one slot; a bound delegation names its outpoints
func onchainCoin(d domain.Delegation, outpoint string) bool {
	i := slices.IndexFunc(d.Slots, func(sl domain.SlotBinding) bool { return sl.Outpoint == outpoint || sl.Outpoint == "" })
	return i >= 0 && d.Slots[i].Onchain
}

// refusedFor is how long arkd has refused txid; any other answer resets it.
func (s *service) refusedFor(txid string, refused bool) time.Duration {
	if !refused {
		delete(s.refusedSince, txid)
		return 0
	}
	if _, ok := s.refusedSince[txid]; !ok {
		s.refusedSince[txid] = time.Now()
	}
	return time.Since(s.refusedSince[txid])
}
