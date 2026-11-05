// Package execution turns a delegation's coins into the transactions arkd takes, and schedules them.
package execution

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// ErrBadTx marks a template transaction that does not spend what it was given.
var ErrBadTx = errors.New("bad template transaction")

var (
	errEmptyTemplateTx       = errors.New("template tx is empty")
	errLeafNotInTree         = errors.New("selected leaf is not in the registered tree")
	errNotTaproot            = errors.New("input is not taproot")
	errInvalidTemplateOutput = errors.New("invalid template output")
)

// Intent is a template transaction turned into what arkd registers: its proof and message, and
// what the batch must pay for it.
type Intent struct {
	Tx              *psbt.Packet // the logical transaction, its inputs holding their leaves
	Proof           string
	Message         string
	Outputs         []*wire.TxOut // the offchain outputs
	Onchain         []*wire.TxOut
	Boarding        []bool // per input of Tx: a boarding input, which has no forfeit
	HasArkadePacket bool   // the transaction carries an arkade packet, which the emulator cosigns
}

// Vtxos is how many inputs are vtxos, each forfeited to a connector.
func (in *Intent) Vtxos() int {
	n := len(in.Tx.UnsignedTx.TxIn)
	for _, boarding := range in.Boarding {
		if boarding {
			n--
		}
	}
	return n
}

func (in *Intent) boarding(i int) bool { return i < len(in.Boarding) && in.Boarding[i] }

func BuildOffchain(
	inst *template.Instance, inputs []delegation.Input, coins []delegation.Coin, txs map[string]*wire.MsgTx,
	fee template.Fee, unroll []byte,
) ([]delegation.Tx, error) {
	sources, err := sourcesOf(coins, txs)
	if err != nil {
		return nil, err
	}
	act, err := inst.Build(sources, fee)
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	if err := checkTx(act.Tx, coins, inputs); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadTx, err)
	}
	ins := make([]offchain.VtxoInput, len(coins))
	for i, c := range coins {
		leaf := act.Tx.Inputs[i].TaprootLeafScript[0]
		ctrl, err := txscript.ParseControlBlock(leaf.ControlBlock)
		if err != nil {
			return nil, err
		}
		ins[i] = offchain.VtxoInput{
			Outpoint: &sources[i].Outpoint, Amount: int64(c.Amount),
			Tapscript:          &waddrmgr.Tapscript{ControlBlock: ctrl, RevealedScript: leaf.Script},
			RevealedTapscripts: inputs[c.Input].Tapscripts,
		}
	}
	ark, checkpoints, err := offchain.BuildTxs(ins, act.Tx.UnsignedTx.TxOut, unroll)
	if err != nil {
		return nil, err
	}
	for i := range coins {
		witness, err := txutils.GetArkPsbtConditionWitness(act.Tx, i)
		if err != nil {
			return nil, err
		}
		if witness == nil {
			continue
		}
		if err = txutils.SetArkPsbtField(ark, i, txutils.ConditionWitnessField, witness); err != nil {
			return nil, err
		}
		if err = txutils.SetArkPsbtField(checkpoints[i], 0, txutils.ConditionWitnessField, witness); err != nil {
			return nil, err
		}
	}
	out := make([]delegation.Tx, 0, 1+len(checkpoints))
	for i, p := range append([]*psbt.Packet{ark}, checkpoints...) {
		var raw bytes.Buffer
		if err := p.Serialize(&raw); err != nil {
			return nil, err
		}
		out = append(out, delegation.Tx{Raw: raw.Bytes(), Txid: p.UnsignedTx.TxHash().String(), Spends: i == 0})
	}
	return out, nil
}

// sourcesOf pairs each coin with the transaction that created it, which must pay it exactly.
func sourcesOf(coins []delegation.Coin, txs map[string]*wire.MsgTx) ([]*template.Source, error) {
	sources := make([]*template.Source, len(coins))
	for i, c := range coins {
		op, err := wire.NewOutPointFromString(c.Outpoint)
		if err != nil {
			return nil, err
		}
		script, err := hex.DecodeString(c.Script)
		if err != nil {
			return nil, err
		}
		tx := txs[op.Hash.String()]
		if tx == nil || int(op.Index) >= len(tx.TxOut) {
			return nil, fmt.Errorf("coin %s: missing source output", c.Outpoint)
		}
		if prev := tx.TxOut[op.Index]; prev.Value != int64(c.Amount) || !bytes.Equal(prev.PkScript, script) {
			return nil, fmt.Errorf("coin %s differs from its source output", c.Outpoint)
		}
		held, err := heldAt(tx, op.Index)
		if err != nil {
			return nil, fmt.Errorf("coin %s: %w", c.Outpoint, err)
		}
		sources[i] = &template.Source{Outpoint: *op, Tx: tx, Amount: c.Amount, Assets: held, Expiry: c.ExpiresAt, CreatedAt: c.CreatedAt}
	}
	return sources, nil
}

// heldAt lists the assets the asset packet of tx puts on its output at index.
func heldAt(tx *wire.MsgTx, index uint32) ([]template.Asset, error) {
	ext, err := extension.NewExtensionFromTx(tx)
	if errors.Is(err, extension.ErrExtensionNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var held []template.Asset
	for i, g := range ext.GetAssetPacket() {
		id := g.AssetId
		if id == nil {
			if id, err = asset.NewAssetId(tx.TxHash().String(), uint16(i)); err != nil {
				return nil, err
			}
		}
		raw, err := id.Serialize()
		if err != nil {
			return nil, err
		}
		for _, o := range g.Outputs {
			if uint32(o.Vout) == index {
				held = append(held, template.Asset{ID: raw, Amount: o.Amount})
			}
		}
	}
	return held, nil
}

// checkTx checks that the template transaction spends exactly the coins, at the inputs' scripts,
// through leaves of their trees.
func checkTx(tx *psbt.Packet, coins []delegation.Coin, inputs []delegation.Input) error {
	if tx == nil || tx.UnsignedTx == nil {
		return errEmptyTemplateTx
	}
	if len(tx.Inputs) != len(coins) || len(tx.UnsignedTx.TxIn) != len(coins) {
		return fmt.Errorf("template tx has %d inputs for %d coins", len(tx.Inputs), len(coins))
	}
	for i, c := range coins {
		in := tx.Inputs[i]
		if in.WitnessUtxo == nil || len(in.TaprootLeafScript) != 1 {
			return fmt.Errorf("template tx input %d lacks its witness utxo or tap leaf", i)
		}
		if tx.UnsignedTx.TxIn[i].PreviousOutPoint.String() != c.Outpoint {
			return fmt.Errorf("template tx input %d spends another coin", i)
		}
		script, err := hex.DecodeString(c.Script)
		if err != nil {
			return err
		}
		if in.WitnessUtxo.Value != int64(c.Amount) || !bytes.Equal(in.WitnessUtxo.PkScript, script) {
			return fmt.Errorf("template tx input %d witness utxo does not match", i)
		}
		if c.Input >= len(inputs) || inputs[c.Input].Script != c.Script {
			return fmt.Errorf("coin %d is not at the script of its input", i)
		}
		leaf := in.TaprootLeafScript[0]
		if !slices.Contains(inputs[c.Input].Tapscripts, hex.EncodeToString(leaf.Script)) {
			return errLeafNotInTree
		}
		control, err := txscript.ParseControlBlock(leaf.ControlBlock)
		if err != nil {
			return err
		}
		if !txscript.IsPayToTaproot(script) {
			return errNotTaproot
		}
		if err := txscript.VerifyTaprootLeafCommitment(control, script[2:], leaf.Script); err != nil {
			return err
		}
	}
	for _, out := range tx.UnsignedTx.TxOut {
		if out == nil || out.Value < 0 {
			return errInvalidTemplateOutput
		}
	}
	return nil
}

// BuildIntent builds the transaction of inst spending coins, one per input in order, and the intent
// registering it under the cosigner key; txs hold the transactions that created the coins.
func BuildIntent(
	inst *template.Instance, inputs []delegation.Input, coins []delegation.Coin, txs map[string]*wire.MsgTx,
	fee template.Fee, cosigner *btcec.PublicKey,
) (*Intent, error) {
	sources, err := sourcesOf(coins, txs)
	if err != nil {
		return nil, err
	}
	act, err := inst.Build(sources, fee)
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	if err := checkTx(act.Tx, coins, inputs); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadTx, err)
	}
	tx := act.Tx.UnsignedTx
	offchain := len(tx.TxOut)
	onchain := []int{}
	if act.Extension >= 0 {
		offchain = act.Extension
		for i := offchain + 1; i < len(tx.TxOut); i++ {
			onchain = append(onchain, i)
		}
	}
	in := &Intent{Tx: act.Tx, Outputs: tx.TxOut[:offchain], Boarding: boardingOf(coins)}
	if act.Extension >= 0 {
		in.Onchain = tx.TxOut[offchain+1:]
	}
	ext, err := extension.NewExtensionFromTx(tx)
	if err != nil && !errors.Is(err, extension.ErrExtensionNotFound) {
		return nil, err
	}
	in.HasArkadePacket = hasArkadePacket(ext)
	if in.HasArkadePacket {
		emu, err := arkade.FindEmulatorPacket(tx)
		if err != nil {
			return nil, err
		}
		ext = withEmulatorPacket(ext, emu)
	}
	in.Message, err = intent.RegisterMessage{
		BaseMessage:          intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		OnchainOutputIndexes: onchain,
		CosignersPublicKeys:  []string{hex.EncodeToString(cosigner.SerializeCompressed())},
	}.Encode()
	if err != nil {
		return nil, err
	}
	proof, err := in.proof(sources, ext, act.Extension)
	if err != nil {
		return nil, err
	}
	if in.Proof, err = proof.B64Encode(); err != nil {
		return nil, err
	}
	return in, nil
}

// proof shifts every reference to a transaction input by one: the message is input 0.
func (in *Intent) proof(sources []*template.Source, ext extension.Extension, extIndex int) (*intent.Proof, error) {
	tx := in.Tx.UnsignedTx
	proof, err := intent.New(in.Message, in.proofInputs(), slices.Clone(tx.TxOut))
	if err != nil {
		return nil, fmt.Errorf("build intent proof: %w", err)
	}
	for i := range proof.Inputs {
		src := in.Tx.Inputs[max(i-1, 0)] // the message shares input 1's script
		proof.Inputs[i].TaprootLeafScript = src.TaprootLeafScript
		proof.Inputs[i].Unknowns = append(proof.Inputs[i].Unknowns, src.Unknowns...)
		if i == 0 || !in.HasArkadePacket {
			continue
		}
		// the emulator reads the transaction funding each input
		if err := txutils.SetArkPsbtField(&proof.Packet, i, arkade.PrevArkTxField, *sources[i-1].Tx); err != nil {
			return nil, err
		}
	}
	if extIndex >= 0 {
		shifted, err := shiftInputs(ext, 1)
		if err != nil {
			return nil, err
		}
		out, err := shifted.TxOut()
		if err != nil {
			return nil, err
		}
		proof.UnsignedTx.TxOut[extIndex] = out
	}
	return proof, nil
}

func (in *Intent) proofInputs() []intent.Input {
	inputs := make([]intent.Input, len(in.Tx.UnsignedTx.TxIn))
	for i, txin := range in.Tx.UnsignedTx.TxIn {
		inputs[i] = intent.Input{OutPoint: &txin.PreviousOutPoint, Sequence: txin.Sequence, WitnessUtxo: in.Tx.Inputs[i].WitnessUtxo}
	}
	return inputs
}

// Forfeits builds one forfeit per vtxo input, each spending its coin and a connector.
func (in *Intent) Forfeits(connectors []*psbt.Packet, forfeitScript []byte) ([]string, error) {
	tx := in.Tx.UnsignedTx
	if len(connectors) < in.Vtxos() {
		return nil, fmt.Errorf("got %d connectors for %d vtxos", len(connectors), in.Vtxos())
	}
	var forfeits []string
	for i, txin := range tx.TxIn {
		if in.boarding(i) {
			continue
		}
		next := len(forfeits)
		if connectors[next] == nil || connectors[next].UnsignedTx == nil {
			return nil, fmt.Errorf("connector %d is missing", next)
		}
		connector := connectors[next].UnsignedTx
		vout := slices.IndexFunc(connector.TxOut, func(out *wire.TxOut) bool {
			return !bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT)
		})
		if vout < 0 {
			return nil, fmt.Errorf("connector not found for vtxo %s", txin.PreviousOutPoint)
		}
		forfeit, err := tree.BuildForfeitTx(
			[]*wire.OutPoint{&txin.PreviousOutPoint, {Hash: connector.TxHash(), Index: uint32(vout)}},
			[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
			[]*wire.TxOut{in.Tx.Inputs[i].WitnessUtxo, connector.TxOut[vout]},
			forfeitScript,
			0,
		)
		if err != nil {
			return nil, err
		}
		forfeit.Inputs[0].TaprootLeafScript = in.Tx.Inputs[i].TaprootLeafScript
		raw, err := forfeit.B64Encode()
		if err != nil {
			return nil, err
		}
		forfeits = append(forfeits, raw)
	}
	return forfeits, nil
}

func boardingOf(coins []delegation.Coin) []bool {
	out := make([]bool, len(coins))
	for i, c := range coins {
		out[i] = c.Onchain
	}
	return out
}

// the extension package parses the emulator packet as opaque bytes
func withEmulatorPacket(ext extension.Extension, emu arkade.EmulatorPacket) extension.Extension {
	out := make(extension.Extension, 0, len(ext))
	for _, p := range ext {
		if p.Type() != arkade.PacketType {
			out = append(out, p)
		}
	}
	return append(out, emu)
}

func shiftInputs(ext extension.Extension, by uint16) (extension.Extension, error) {
	out := make(extension.Extension, 0, len(ext))
	for _, p := range ext {
		switch p := p.(type) {
		case arkade.EmulatorPacket:
			entries := make([]arkade.EmulatorEntry, len(p))
			for i, e := range p {
				e.Vin += by
				entries[i] = e
			}
			shifted, err := arkade.NewPacket(entries...)
			if err != nil {
				return nil, err
			}
			out = append(out, shifted)
		case asset.Packet:
			groups := make([]asset.AssetGroup, 0, len(p))
			for _, g := range p {
				ins := slices.Clone(g.Inputs)
				for i := range ins {
					if ins[i].Type == asset.AssetInputTypeLocal {
						ins[i].Vin += by
					}
				}
				shifted, err := asset.NewAssetGroup(g.AssetId, g.ControlAsset, ins, g.Outputs, g.Metadata)
				if err != nil {
					return nil, err
				}
				groups = append(groups, *shifted)
			}
			shifted, err := asset.NewPacket(groups)
			if err != nil {
				return nil, err
			}
			out = append(out, shifted)
		default:
			// the other packets reference outputs, which do not move
			out = append(out, p)
		}
	}
	return out, nil
}

func hasArkadePacket(ext extension.Extension) bool {
	return ext.GetPacketByType(arkade.PacketType) != nil
}
