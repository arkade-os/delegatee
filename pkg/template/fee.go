package template

import (
	"encoding/hex"
	"fmt"
	"math"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/delegatee/pkg/template/internal/asm"
	"github.com/btcsuite/btcd/wire/v2"
)

type fee struct {
	from        int
	max         uint64
	maxVariable string // an int variable holding max
}

func (c *compiler) fees() error {
	s := c.doc.Fees
	if s == nil {
		return nil
	}
	if c.t.typ == Offchain {
		return bad("an offchain template has no fees")
	}
	f := &fee{}
	var err error
	if f.from, err = c.inputIndex(s.From, "fees"); err != nil {
		return err
	}
	max, name, err := c.intVariable(s.Max)
	if err != nil {
		return err
	}
	f.max, f.maxVariable = uint64(max), name
	c.t.fee = f
	return nil
}

// FeeCap is the most the instance lets one of its transactions pay in fees; false when it pays none.
func (i *Instance) FeeCap() (uint64, bool) {
	f := i.tmpl.fee
	if f == nil {
		return 0, false
	}
	if f.maxVariable == "" {
		return f.max, true
	}
	n, _ := asm.ParseScriptNum(i.vars[f.maxVariable])
	return uint64(n), true
}

// maxFeeRounds bounds the search for an intent fee that prices its own outputs.
const maxFeeRounds = 32

// the Ark server charges inputs plus outputs at the amounts they receive once it is paid
func (i *Instance) intentFee(d *draft, sources []*Source, scripts [][]byte, fee Fee) (uint64, error) {
	est, err := arkfee.New(fee.Intent)
	if err != nil {
		return 0, fmt.Errorf("intent fee programs: %w", err)
	}
	inputs := uint64(0)
	for slot, s := range sources {
		var f arkfee.FeeAmount
		if i.tmpl.inputs[slot].onchain {
			f, err = est.EvalOnchainInput(arkfee.OnchainInput{Amount: s.Amount})
		} else {
			typ := arkfee.VtxoTypeVtxo
			if s.Swept {
				typ = arkfee.VtxoTypeRecoverable
			}
			f, err = est.EvalOffchainInput(arkfee.OffchainInput{Amount: s.Amount, Expiry: s.Expiry, Birth: s.CreatedAt, Type: typ})
		}
		if inputs, err = addFee(inputs, f, err); err != nil {
			return 0, fmt.Errorf("input %q: %w", i.tmpl.inputs[slot].name, err)
		}
	}
	charged := inputs
	for range maxFeeRounds {
		a, err := i.allocate(d, sources, charged, fee.Dust)
		if err != nil {
			return 0, err
		}
		next := inputs
		for k, o := range i.tmpl.outputs {
			out := arkfee.Output{Amount: a.sats[k], Script: hex.EncodeToString(scripts[k])}
			var f arkfee.FeeAmount
			if o.onchain {
				f, err = est.EvalOnchainOutput(out)
			} else {
				f, err = est.EvalOffchainOutput(out)
			}
			if next, err = addFee(next, f, err); err != nil {
				return 0, fmt.Errorf("output %q: %w", o.name, err)
			}
		}
		if next == charged {
			return charged, nil
		}
		charged = next
	}
	return 0, fmt.Errorf("%w: the intent fee does not converge", ErrIneligible)
}

// addFee rounds f up to whole satoshis.
func addFee(sum uint64, f arkfee.FeeAmount, err error) (uint64, error) {
	if err != nil {
		return 0, fmt.Errorf("%w: fee program: %v", ErrIneligible, err)
	}
	v := float64(f)
	if math.IsNaN(v) || v < 0 || v > maxAmount {
		return 0, fmt.Errorf("%w: fee %v out of range", ErrIneligible, v)
	}
	return sum + uint64(f.ToSatoshis()), nil
}

// vsize assumes ark-lib finalization: 64-byte signatures, bound items, leaf script and control block.
func vsize(tx *wire.MsgTx, spends []spending) int {
	signed := tx.Copy()
	for slot, in := range signed.TxIn {
		s := spends[slot]
		for _, w := range s.leaf.Witness {
			if w.Type == "signature" {
				in.Witness = append(in.Witness, make([]byte, 64))
			}
		}
		in.Witness = append(in.Witness, s.witness...)
		in.Witness = append(in.Witness, s.proof.Script, s.proof.ControlBlock)
	}
	weight := signed.SerializeSizeStripped()*3 + signed.SerializeSize()
	return (weight + 3) / 4
}
