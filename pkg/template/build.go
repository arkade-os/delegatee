package template

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// maxFeeRounds bounds the search for an intent fee that prices its own outputs.
const maxFeeRounds = 32

// Fee is what the backend charges and accepts.
type Fee struct {
	Intent  arkfee.Config          // the Ark server's fee programs, for intents
	Onchain func(vsize int) uint64 // the fee of an onchain transaction of vsize virtual bytes
	Dust    uint64                 // minimum output amount
}

// Action is the transaction of an instance, unsigned.
type Action struct {
	Tx        *psbt.Packet
	Extension int    // output index of the extension, -1 without
	Fee       uint64 // what the transaction pays in fees
}

type spending struct {
	entry   *arkade.EmulatorEntry
	witness wire.TxWitness
	leaf    *Leaf
	proof   *psbt.TaprootTapLeafScript
}

// Build builds the unsigned transaction spending sources, one per input in slot order.
func (i *Instance) Build(_ context.Context, sources []*Source, fee Fee) (*Action, error) {
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

	spends, err := i.spends(d)
	if err != nil {
		return nil, err
	}
	scripts, err := i.outputScripts(d, sources)
	if err != nil {
		return nil, err
	}

	charged := uint64(0)
	if t.typ == Intent {
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

func (i *Instance) spends(d *draft) ([]spending, error) {
	out := make([]spending, len(i.tmpl.inputs))
	for slot, in := range i.tmpl.inputs {
		fn, err := in.contract.def.function(in.function)
		if err != nil {
			return nil, err
		}
		if out[slot].leaf, err = fn.leaf(in.leaf); err != nil {
			return nil, err
		}
		out[slot].proof = i.contracts[slot].proofs[[2]string{in.function, in.leaf}]
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
		cov, ok := i.contracts[slot].covenants[in.function]
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
	if err := canonicalBytes(typ, raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIneligible, err)
	}
	return raw, nil
}

func (i *Instance) outputScripts(d *draft, sources []*Source) ([][]byte, error) {
	out := make([][]byte, len(i.tmpl.outputs))
	for k, o := range i.tmpl.outputs {
		var err error
		switch l := o.locking; {
		case l.from >= 0:
			out[k] = bytes.Clone(pkScript(sources[l.from]))
		case l.contract != nil:
			var ct *contract
			if ct, err = i.contractOf(l.contract, d, o.from, false); err == nil {
				out[k] = ct.pkScript
			}
		default:
			out[k], err = i.resolve(l.script, d, d.index(o.from))
			if err == nil {
				err = checkScript(out[k], o.onchain)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("output %q: %w", o.name, err)
		}
	}
	return out, nil
}

// checkScript requires P2TR off chain and a script that parses on chain.
func checkScript(s []byte, onchain bool) error {
	if !onchain {
		if !txscript.IsPayToTaproot(s) {
			return fmt.Errorf("%w: an offchain output needs a P2TR script, got %d bytes", ErrIneligible, len(s))
		}
		if _, err := schnorr.ParsePubKey(s[2:]); err != nil {
			return fmt.Errorf("%w: an offchain output needs a valid taproot key", ErrIneligible)
		}
		return nil
	}
	tok := txscript.MakeScriptTokenizer(0, s)
	for tok.Next() {
	}
	if len(s) == 0 || tok.Err() != nil {
		return fmt.Errorf("%w: malformed script of %d bytes", ErrIneligible, len(s))
	}
	return nil
}

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

// packets are in ascending type
func (i *Instance) extension(d *draft, sources []*Source, a *allocation, spends []spending) (extension.Extension, error) {
	t := i.tmpl
	var ext extension.Extension
	assets, err := assetPacket(t, sources, a)
	if err != nil {
		return nil, err
	}
	if assets != nil {
		ext = append(ext, assets)
	}
	var entries []arkade.EmulatorEntry
	for _, s := range spends {
		if s.entry != nil {
			entries = append(entries, *s.entry)
		}
	}
	if len(entries) > 0 {
		emu, err := arkade.NewPacket(entries...)
		if err != nil {
			return nil, fmt.Errorf("%w: emulator packet: %v", ErrIneligible, err)
		}
		ext = append(ext, emu)
	}
	if t.packets == nil {
		if len(ext) > 0 {
			return nil, fmt.Errorf("%w: assets or a covenant need packets", ErrInvalidTemplate)
		}
		return nil, unmatched(sources, nil, false)
	}

	emitted := map[uint8]extension.Packet{}
	handled := map[handledKey]bool{}
	for _, r := range t.packets.rules {
		src := sources[r.from]
		handled[handledKey{src.Outpoint.Hash, r.typ}] = true
		switch r.action {
		case "copy":
			body, ok := packets.Find(src.Tx, r.typ)
			if !ok {
				return nil, fmt.Errorf("%w: input %q has no packet %d to copy", ErrIneligible, t.inputs[r.from].name, r.typ)
			}
			emitted[r.typ] = packets.Raw(r.typ, body)
		case "emit":
			body, err := i.resolve(r.data, d, d.index(r.from))
			if err != nil {
				return nil, fmt.Errorf("packet %d: %w", r.typ, err)
			}
			if len(body) == 0 {
				return nil, fmt.Errorf("%w: packet %d is empty", ErrIneligible, r.typ)
			}
			emitted[r.typ] = packets.Raw(r.typ, body)
		}
	}
	if err := unmatched(sources, handled, t.packets.drop); err != nil {
		return nil, err
	}
	for _, typ := range slices.Sorted(maps.Keys(emitted)) {
		ext = append(ext, emitted[typ])
	}

	if len(t.packets.adverts) > 0 {
		var id [32]byte
		_, _ = hex.Decode(id[:], []byte(t.id))
		body, err := packets.EncodeAdvertisement(t.packets.records(t, id))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidTemplate, err)
		}
		ext = append(ext, packets.Raw(packets.TypeAdvertisement, body))
	}
	return ext, nil
}

type handledKey struct {
	tx  [32]byte
	typ uint8
}

// unmatched fails on a source application packet no rule handles, unless drop.
func unmatched(sources []*Source, handled map[handledKey]bool, drop bool) error {
	for _, s := range sources {
		ext, err := extension.NewExtensionFromTx(s.Tx)
		if errors.Is(err, extension.ErrExtensionNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%w: source %s: malformed extension: %v", ErrIneligible, s.Outpoint, err)
		}
		for _, p := range ext {
			typ := p.Type()
			generated := typ == asset.PacketType || typ == arkade.PacketType || typ == packets.TypeAdvertisement
			if !generated && !drop && !handled[handledKey{s.Outpoint.Hash, typ}] {
				return fmt.Errorf("%w: source %s carries packet %d that no rule handles", ErrIneligible, s.Outpoint, typ)
			}
		}
	}
	return nil
}

// assetPacket is nil when no asset moves.
func assetPacket(t *Template, sources []*Source, a *allocation) (extension.Packet, error) {
	ids := map[string]bool{}
	for _, m := range a.assets {
		for id := range m {
			ids[id] = true
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	var groups []asset.AssetGroup
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		g, err := assetGroup(t, sources, a, id)
		if err != nil {
			return nil, fmt.Errorf("%w: asset %s: %v", ErrIneligible, id, err)
		}
		groups = append(groups, *g)
	}
	p, err := asset.NewPacket(groups)
	if err != nil {
		return nil, fmt.Errorf("%w: assets packet: %v", ErrIneligible, err)
	}
	return p, nil
}

func assetGroup(t *Template, sources []*Source, a *allocation, id string) (*asset.AssetGroup, error) {
	var ins []asset.AssetInput
	for slot, s := range sources {
		held := uint64(0)
		for _, as := range s.Assets {
			if hex.EncodeToString(as.ID) == id {
				held += as.Amount
			}
		}
		if held == 0 {
			continue
		}
		in, err := asset.NewAssetInput(uint16(slot), held)
		if err != nil {
			return nil, err
		}
		ins = append(ins, *in)
	}
	var outs []asset.AssetOutput
	for k, o := range t.outputs {
		if n := a.assets[k][id]; n > 0 {
			out, err := asset.NewAssetOutput(o.index, n)
			if err != nil {
				return nil, err
			}
			outs = append(outs, *out)
		}
	}
	aid, err := asset.NewAssetIdFromString(id)
	if err != nil {
		return nil, err
	}
	return asset.NewAssetGroup(aid, nil, ins, outs, nil)
}

func (i *Instance) packet(tx *wire.MsgTx, sources []*Source, spends []spending) (*psbt.Packet, error) {
	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIneligible, err)
	}
	for slot, s := range sources {
		c := i.contracts[slot]
		proof := *spends[slot].proof
		proof.ControlBlock, proof.Script = bytes.Clone(proof.ControlBlock), bytes.Clone(proof.Script)
		ptx.Inputs[slot].WitnessUtxo = &wire.TxOut{Value: int64(s.Amount), PkScript: bytes.Clone(pkScript(s))}
		ptx.Inputs[slot].TaprootLeafScript = []*psbt.TaprootTapLeafScript{&proof}
		if err := txutils.SetArkPsbtField(ptx, slot, txutils.VtxoTaprootTreeField, txutils.TapTree(slices.Clone(c.tapscripts))); err != nil {
			return nil, err
		}
		if len(spends[slot].witness) > 0 {
			if err := txutils.SetArkPsbtField(ptx, slot, txutils.ConditionWitnessField, spends[slot].witness); err != nil {
				return nil, err
			}
		}
	}
	return ptx, nil
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
