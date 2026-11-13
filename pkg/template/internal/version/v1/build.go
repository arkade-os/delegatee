package v1

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/arkade-os/executor/pkg/template/internal/model"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/executor/pkg/template/internal/asm"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

type Fee = model.Fee
type Action = model.Action

type spending struct {
	entry   *arkade.EmulatorEntry
	witness wire.TxWitness
	leaf    *Leaf
	proof   *psbt.TaprootTapLeafScript
}

// Build builds the unsigned transaction spending sources, one per input in slot order.
func (i *Instance) Build(sources []*Source, fee Fee) (*Action, error) {
	t := i.tmpl
	if err := checkSources(sources, len(t.inputs)); err != nil {
		return nil, err
	}
	for slot, in := range t.inputs {
		if err := checkSourceScript(in, sources[slot], i.contracts[slot]); err != nil {
			return nil, err
		}
	}
	d := newDraft(t.typ, sources)
	i.lock(d.tx, d.index(0))

	spends, err := i.spends(d)
	if err != nil {
		return nil, err
	}
	scripts, err := i.outputScripts(d, sources)
	if err != nil {
		return nil, err
	}

	charged := uint64(0)
	if t.typ == Proof {
		if charged, err = i.intentFee(d, sources, scripts, fee); err != nil {
			return nil, err
		}
	}
	a, err := i.allocate(d, sources, charged, fee.Dust)
	if err != nil {
		return nil, err
	}

	tx := wire.NewMsgTx(d.tx.Version)
	for _, s := range sources {
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: s.Outpoint, Sequence: wire.MaxTxInSequenceNum})
	}
	i.lock(tx, 0)
	n := len(t.outputs)
	if t.packets != nil {
		n++
	}
	tx.TxOut = make([]*wire.TxOut, n)
	for k, o := range t.outputs {
		tx.TxOut[o.index] = &wire.TxOut{Value: int64(a.sats[k]), PkScript: scripts[k]}
	}

	act := &Action{Extension: -1, Fee: charged}
	ext, err := i.extension(d, sources, a, spends)
	if err != nil {
		return nil, err
	}
	if len(ext) > 0 {
		out, err := ext.TxOut()
		if err != nil {
			return nil, fmt.Errorf("%w: extension: %v", ErrIneligible, err)
		}
		act.Extension = int(t.packets.index)
		tx.TxOut[act.Extension] = out
	} else if t.packets != nil {
		return nil, fmt.Errorf("%w: nothing to write in the extension", ErrIneligible)
	}

	if t.typ == Onchain {
		if fee.Onchain == nil {
			return nil, fmt.Errorf("%w: no on-chain fee estimate", ErrIneligible)
		}
		act.Fee = fee.Onchain(vsize(tx, spends))
		if a, err = i.allocate(d, sources, act.Fee, fee.Dust); err != nil {
			return nil, err
		}
		for k, o := range t.outputs {
			tx.TxOut[o.index].Value = int64(a.sats[k])
		}
	}
	if act.Tx, err = i.packet(tx, sources, spends); err != nil {
		return nil, err
	}
	return act, nil
}

// lock matches offchain.BuildTxs: the highest locktime, and a non-final sequence on its inputs,
// which start at first in tx
func (i *Instance) lock(tx *wire.MsgTx, first int) {
	for slot, lt := range i.locktimes {
		if lt != nil {
			tx.LockTime = max(tx.LockTime, uint32(*lt))
			tx.TxIn[first+slot].Sequence = wire.MaxTxInSequenceNum - 1
		}
	}
}

func (i *Instance) spends(d *draft) ([]spending, error) {
	out := make([]spending, len(i.tmpl.inputs))
	for slot, in := range i.tmpl.inputs {
		fn := in.selected
		out[slot].leaf = in.selectedLeaf
		out[slot].proof = i.contracts[slot].Proofs[[2]string{in.function, in.leaf}]
		for _, w := range out[slot].leaf.Witness {
			if w.Type == "signature" {
				continue
			}
			raw, err := i.decoded(in.witness[w.Name], w.Type, d, slot)
			if err != nil {
				return nil, fmt.Errorf("input %q witness %q: %w", in.name, w.Name, err)
			}
			out[slot].witness = append(out[slot].witness, raw)
		}
		// metadata lists stack items top first; a witness lists them bottom first
		slices.Reverse(out[slot].witness)
		cov, ok := i.contracts[slot].Covenants[in.function]
		if !ok {
			continue
		}
		e := &arkade.EmulatorEntry{Vin: uint16(slot), Script: bytes.Clone(cov)}
		for k, f := range fn.Arkade.Inputs {
			raw, err := i.decoded(in.arguments[k], f.Type, d, slot)
			if err != nil {
				return nil, fmt.Errorf("input %q argument %q: %w", in.name, f.Name, err)
			}
			e.Witness = append(e.Witness, raw)
		}
		// the first declared input ends on top of the stack
		slices.Reverse(e.Witness)
		out[slot].entry = e
	}
	return out, nil
}

// decoded evaluates b with slot as context input and requires the canonical bytes of typ.
func (i *Instance) decoded(b byteTemplate, typ string, d *draft, slot int) ([]byte, error) {
	raw, err := i.resolve(b, d, d.index(slot))
	if err != nil {
		return nil, err
	}
	if err := asm.CanonicalBytes(typ, raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIneligible, err)
	}
	return raw, nil
}

func (i *Instance) packet(
	tx *wire.MsgTx, sources []*Source, spends []spending,
) (*psbt.Packet, error) {
	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIneligible, err)
	}
	for slot, s := range sources {
		c := i.contracts[slot]
		proof := *spends[slot].proof
		proof.ControlBlock, proof.Script = bytes.Clone(
			proof.ControlBlock,
		), bytes.Clone(
			proof.Script,
		)
		ptx.Inputs[slot].WitnessUtxo = &wire.TxOut{
			Value: int64(s.Amount), PkScript: bytes.Clone(pkScript(s)),
		}
		ptx.Inputs[slot].TaprootLeafScript = []*psbt.TaprootTapLeafScript{&proof}
		if err := txutils.SetArkPsbtField(
			ptx, slot, txutils.VtxoTaprootTreeField, txutils.TapTree(slices.Clone(c.Tapscripts)),
		); err != nil {
			return nil, err
		}
		if len(spends[slot].witness) > 0 {
			if err := txutils.SetArkPsbtField(
				ptx, slot, txutils.ConditionWitnessField, spends[slot].witness,
			); err != nil {
				return nil, err
			}
		}
	}
	return ptx, nil
}
