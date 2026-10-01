package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

func (s *service) logicalTx(ctx context.Context, inputs []renewalInput, fees arkfee.Config) (*psbt.Packet, []coin, error) {
	tx, coins, err := s.templateTx(ctx, inputs, fees)
	if err != nil {
		return nil, nil, err
	}
	if err := checkTemplateTx(tx, coins, inputs[0].watched.delegation); err != nil {
		return nil, nil, err
	}
	return tx, coins, nil
}

func (s *service) templateTx(ctx context.Context, inputs []renewalInput, fees arkfee.Config) (*psbt.Packet, []coin, error) {
	if len(inputs) == 0 {
		return nil, nil, errors.New("no inputs")
	}
	coins, err := s.sourcedCoins(ctx, inputs)
	if err != nil {
		return nil, nil, err
	}
	tx, err := s.build(ctx, inputs[0].watched, coins, fees)
	if err != nil {
		return nil, nil, fmt.Errorf("template tx: %w", err)
	}
	return tx, coins, nil
}

// build spends coins, one per slot in order.
func (s *service) build(ctx context.Context, w *watched, coins []coin, fees arkfee.Config) (*psbt.Packet, error) {
	sources := make([]*template.Source, len(coins))
	for n, c := range coins {
		if c.Slot != n {
			return nil, fmt.Errorf("%w: coin %d fills slot %d", ErrIneligible, n, c.Slot)
		}
		src, err := sourceOf(c)
		if err != nil {
			return nil, err
		}
		sources[n] = src
	}
	fee, err := s.fee(w.tmpl, fees)
	if err != nil {
		return nil, err
	}
	act, err := w.instance.Build(ctx, sources, fee)
	if err != nil {
		return nil, moduleError(err, ErrIneligible)
	}
	return act.Tx, nil
}

func (s *service) fee(t *template.Template, intent arkfee.Config) (template.Fee, error) {
	fee := template.Fee{Intent: intent, Dust: s.dust}
	if t.Type() != template.Onchain {
		return fee, nil
	}
	rate, err := s.explorer.GetFeeRate()
	if err != nil {
		return fee, fmt.Errorf("%w: fee rate: %v", ErrIneligible, err)
	}
	if !(rate > 0) {
		return fee, fmt.Errorf("%w: fee rate %v", ErrIneligible, rate)
	}
	limit := s.maxOnchainFeeRate
	rate = max(1, min(rate, limit))
	fee.Onchain = func(vsize int) uint64 {
		// never above the cap the daemon checks the signed transaction against
		return uint64(min(math.Ceil(rate*float64(vsize)), math.Floor(limit*float64(vsize))))
	}
	return fee, nil
}

func sourceOf(c coin) (*template.Source, error) {
	s := &template.Source{
		Outpoint: c.Outpoint, Tx: c.Source, Amount: c.Amount, Expiry: c.Expiry,
		Confirms: c.Confirms, CreatedAt: c.CreatedAt, Swept: c.Swept,
	}
	for _, a := range c.Assets {
		id, err := hex.DecodeString(a.AssetId)
		if err != nil || len(id) != 34 {
			return nil, fmt.Errorf("%w: asset id %q", ErrIneligible, a.AssetId)
		}
		s.Assets = append(s.Assets, template.Asset{ID: id, Amount: a.Amount})
	}
	return s, nil
}

// dueTime of a coin with malformed assets is now: its build then fails.
func dueTime(inst *template.Instance, c coin) time.Time {
	src, err := sourceOf(c)
	if err != nil {
		return time.Now()
	}
	return inst.DueAt(c.Slot, src, time.Now())
}

// moduleError keeps err in the chain under the daemon's sentinel, else fallback.
func moduleError(err, fallback error) error {
	for _, m := range [][2]error{
		{template.ErrUnsupported, ErrUnsupported},
		{template.ErrIneligible, ErrIneligible},
		{template.ErrInvalidVariables, ErrInvalidArgs},
	} {
		if errors.Is(err, m[0]) {
			return fmt.Errorf("%w: %w", m[1], err)
		}
	}
	if fallback != nil {
		return fmt.Errorf("%w: %w", fallback, err)
	}
	return err
}

// checkTemplateTx checks the template tx against the coins, slots and trees.
func checkTemplateTx(tx *psbt.Packet, coins []coin, d domain.Delegation) error {
	if tx == nil || tx.UnsignedTx == nil {
		return errors.New("template tx is empty")
	}
	if len(tx.Inputs) != len(coins) || len(tx.UnsignedTx.TxIn) != len(coins) {
		return fmt.Errorf("template tx has %d inputs for %d vtxos", len(tx.Inputs), len(coins))
	}
	for i, c := range coins {
		in := tx.Inputs[i]
		if in.WitnessUtxo == nil || len(in.TaprootLeafScript) != 1 {
			return fmt.Errorf("template tx input %d lacks its witness utxo or tap leaf", i)
		}
		if tx.UnsignedTx.TxIn[i].PreviousOutPoint != c.Outpoint {
			return fmt.Errorf("template tx input %d spends another coin", i)
		}
		if in.WitnessUtxo.Value != int64(c.Amount) || !bytes.Equal(in.WitnessUtxo.PkScript, c.Script) {
			return fmt.Errorf("template tx input %d witness utxo does not match", i)
		}
		leaf := in.TaprootLeafScript[0]
		if c.Slot >= len(d.Slots) {
			return errors.New("invalid slot")
		}
		if hex.EncodeToString(c.Script) != d.Slots[c.Slot].Script {
			return fmt.Errorf("coin %d is not at the script of its slot", i)
		}
		if !slices.Contains(d.Slots[c.Slot].Tapscripts, hex.EncodeToString(leaf.Script)) {
			return errors.New("selected leaf is not in registered tree")
		}
		control, err := txscript.ParseControlBlock(leaf.ControlBlock)
		if err != nil {
			return err
		}
		if !txscript.IsPayToTaproot(c.Script) {
			return errors.New("input is not taproot")
		}
		if err := txscript.VerifyTaprootLeafCommitment(control, c.Script[2:], leaf.Script); err != nil {
			return err
		}
	}
	for _, out := range tx.UnsignedTx.TxOut {
		if out == nil || out.Value < 0 {
			return errors.New("invalid template output")
		}
	}
	return nil
}

// each coin's source transaction must pay it exactly
func (s *service) sourcedCoins(ctx context.Context, inputs []renewalInput) ([]coin, error) {
	var virtualIDs []string
	for _, in := range inputs {
		if txid := in.coin.Outpoint.Hash.String(); !in.onchain && !slices.Contains(virtualIDs, txid) {
			virtualIDs = append(virtualIDs, txid)
		}
	}
	sources := map[string]*wire.MsgTx{}
	if len(virtualIDs) > 0 {
		var err error
		if sources, err = s.virtualTxs(ctx, virtualIDs); err != nil {
			return nil, err
		}
	}
	coins := make([]coin, len(inputs))
	for i, in := range inputs {
		if in.watched.delegation.ID != inputs[0].watched.delegation.ID {
			return nil, errors.New("mixed delegations")
		}
		coin := in.coin
		coin.Source = sources[coin.Outpoint.Hash.String()]
		if in.onchain {
			var err error
			if coin.Source, err = s.onchainTx(coin.Outpoint.Hash.String()); err != nil {
				return nil, err
			}
		}
		if coin.Source == nil || int(coin.Outpoint.Index) >= len(coin.Source.TxOut) {
			return nil, errors.New("missing source output")
		}
		prev := coin.Source.TxOut[coin.Outpoint.Index]
		if coin.Amount > math.MaxInt64 || prev.Value != int64(coin.Amount) || !bytes.Equal(prev.PkScript, coin.Script) {
			return nil, errors.New("coin differs from source output")
		}
		coins[i] = coin
	}
	return coins, nil
}

// only an active trusted template may sign with the delegate key
func (s *service) signForTemplate(ctx context.Context, id string, c *cosigner, tx *psbt.Packet) error {
	row, err := s.repo.GetTemplate(ctx, id)
	if err != nil {
		return err
	}
	if row.Status != domain.TemplateStatusActive {
		return domain.ErrTemplateDisabled
	}
	holds := false
	for _, in := range tx.Inputs {
		for _, leaf := range in.TaprootLeafScript {
			yes, err := scriptPushes(leaf.Script, schnorr.SerializePubKey(c.key.PubKey()))
			if err != nil {
				return err
			}
			holds = holds || yes
		}
	}
	if !holds {
		return nil
	}
	if !row.Trusted {
		return ErrDelegateKeyLeaf
	}
	_, err = signDelegateInputs(tx, c.key, witnessPrevouts(tx))
	return err
}
