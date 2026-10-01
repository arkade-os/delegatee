package template

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestBuildRenewal(t *testing.T) {
	tmpl := parseDoc(t, ownerFromPacket(t))
	owner := testKey(t, 2).SerializeCompressed()
	src := ownedSource(t, tmpl, testKey(t, 2), testKey(t, 2))
	src.Expiry = time.Now().Add(time.Hour)
	inst, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t), Sources: []*Source{src}})
	require.NoError(t, err)
	act, err := inst.Build(t.Context(), []*Source{src}, Fee{Dust: 330})
	require.NoError(t, err)

	tx := act.Tx.UnsignedTx
	require.EqualValues(t, 2, tx.Version)
	require.Len(t, tx.TxIn, 1)
	require.Equal(t, src.Outpoint, tx.TxIn[0].PreviousOutPoint)
	require.Len(t, tx.TxOut, 2)
	require.EqualValues(t, 100_000, tx.TxOut[0].Value)
	require.Equal(t, inst.PkScript(0), tx.TxOut[0].PkScript)
	require.Equal(t, 1, act.Extension)
	require.True(t, extension.IsExtension(tx.TxOut[1].PkScript))
	require.Zero(t, act.Fee)

	state, ok := packets.Find(tx, packets.TypeState)
	require.True(t, ok)
	require.Equal(t, owner, state)
	body, ok := packets.Find(tx, packets.TypeAdvertisement)
	require.True(t, ok)
	id, _ := hex.DecodeString(tmpl.ID())
	require.Equal(t, append(append([]byte{0x01, 0x22, 0x00}, id...), 0x00, 0x00), body)

	emu, err := arkade.FindEmulatorPacket(tx)
	require.NoError(t, err)
	require.Len(t, emu, 1)
	require.EqualValues(t, 0, emu[0].Vin)
	require.Equal(t, []byte{txscript.OP_1}, emu[0].Script)

	in := act.Tx.Inputs[0]
	require.Equal(t, inst.PkScript(0), in.WitnessUtxo.PkScript)
	require.EqualValues(t, 100_000, in.WitnessUtxo.Value)
	require.Len(t, in.TaprootLeafScript, 1)
	trees, err := txutils.GetArkPsbtFields(act.Tx, 0, txutils.VtxoTaprootTreeField)
	require.NoError(t, err)
	require.Equal(t, inst.Tapscripts(0), []string(trees[0]))
	w, err := txutils.GetArkPsbtFields(act.Tx, 0, txutils.ConditionWitnessField)
	require.NoError(t, err)
	require.Empty(t, w, "no bound witness item")
}

func TestBuildCopyNeedsThePacket(t *testing.T) {
	tmpl := parseDoc(t, keepScript(t))
	src := sourceWith(t, 100_000)
	inst, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t)})
	require.NoError(t, err)
	lockTo(src, inst.PkScript(0))
	_, err = inst.Build(t.Context(), []*Source{src}, Fee{Dust: 330})
	require.ErrorIs(t, err, ErrIneligible)

	src = sourceWith(t, 100_000, packets.Raw(packets.TypeState, []byte{9}))
	lockTo(src, inst.PkScript(0))
	act, err := inst.Build(t.Context(), []*Source{src}, Fee{Dust: 330})
	require.NoError(t, err)
	state, ok := packets.Find(act.Tx.UnsignedTx, packets.TypeState)
	require.True(t, ok)
	require.Equal(t, []byte{9}, state)
}

func TestBuildUnmatchedPackets(t *testing.T) {
	src := sourceWith(t, 100_000, packets.Raw(9, []byte{1}))
	for unmatched, wantErr := range map[string]bool{"reject": true, "drop": false} {
		tmpl := parseDoc(t, withUnmatched(t, unmatched))
		inst, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t)})
		require.NoError(t, err)
		lockTo(src, inst.PkScript(0))
		act, err := inst.Build(t.Context(), []*Source{src}, Fee{Dust: 330})
		if wantErr {
			require.ErrorIs(t, err, ErrIneligible)
			continue
		}
		require.NoError(t, err)
		_, found := packets.Find(act.Tx.UnsignedTx, 9)
		require.False(t, found)
	}

	inst, _, srcs := instanceOf(t, edited(t, mixedPaymentDoc(t, false), func(m map[string]any) {
		delete(m, "packets")
		m["outputs"].([]any)[1].(map[string]any)["index"] = 1
		fn := m["inputs"].([]any)[0].(map[string]any)["spend"].(map[string]any)
		fn["function"], fn["leaf"] = "spend", "spend"
	}), sourceWith(t, 100_000, packets.Raw(9, []byte{1})))
	_, err := inst.Build(t.Context(), srcs, Fee{Dust: 330})
	require.ErrorIs(t, err, ErrIneligible, "no packets object and a source packet")
}

func TestBuildMixedPayment(t *testing.T) {
	inst, _, src := mixedPayment(t, 100_000, nil)
	act, err := inst.Build(t.Context(), src, Fee{Dust: 330})
	require.NoError(t, err)
	tx := act.Tx.UnsignedTx
	require.Len(t, tx.TxOut, 3)
	require.EqualValues(t, 75_000, tx.TxOut[0].Value)
	require.True(t, extension.IsExtension(tx.TxOut[1].PkScript))
	require.EqualValues(t, 25_000, tx.TxOut[2].Value)
	_, found := packets.Find(tx, asset.PacketType)
	require.False(t, found, "no asset moves")
}

func TestBuildAssets(t *testing.T) {
	inst, _, src := instanceOf(t, twoFunds(t), coin(t, 50_000, Asset{assetID(1), 7}, Asset{assetID(2), 3}), coin(t, 60_000, Asset{assetID(1), 5}))
	act, err := inst.Build(t.Context(), src, Fee{Dust: 330})
	require.NoError(t, err)
	ext, err := extension.NewExtensionFromTx(act.Tx.UnsignedTx)
	require.NoError(t, err)
	require.Equal(t, []uint8{asset.PacketType, arkade.PacketType}, []uint8{ext[0].Type(), ext[1].Type()})
	pkt := ext.GetAssetPacket()
	require.Len(t, pkt, 2)

	id1, err := asset.NewAssetIdFromBytes(assetID(1))
	require.NoError(t, err)
	require.Equal(t, *id1, *pkt[0].AssetId)
	// extra_change draws $(OP_PUSHCURRENTINPUTINDEX) = 2 (proof input of extra) of asset 1 from funds, plus extra's 5
	require.Equal(t, []asset.AssetInput{assetIn(t, 0, 7), assetIn(t, 1, 5)}, pkt[0].Inputs)
	require.Equal(t, []asset.AssetOutput{assetOut(t, 0, 5), assetOut(t, 1, 7)}, pkt[0].Outputs)
	require.Equal(t, []asset.AssetInput{assetIn(t, 0, 3)}, pkt[1].Inputs)
	require.Equal(t, []asset.AssetOutput{assetOut(t, 0, 3)}, pkt[1].Outputs)

	emu, err := arkade.FindEmulatorPacket(act.Tx.UnsignedTx)
	require.NoError(t, err)
	require.Len(t, emu, 2)
	require.EqualValues(t, []uint16{0, 1}, []uint16{emu[0].Vin, emu[1].Vin})
}

func TestBuildWitnessAndArguments(t *testing.T) {
	tmpl := parseDoc(t, hashLockWithCovenant(t))
	preimage := bytes.Repeat([]byte{7}, 32)
	c := Context{Keys: testKeys(t), Variables: map[string][]byte{"ciphertext": {1}}, Decrypt: func([]byte) ([]byte, error) { return preimage, nil }}
	inst, err := tmpl.Instantiate(t.Context(), c)
	require.NoError(t, err)
	src := sourceWith(t, 100_000)
	lockTo(src, inst.PkScript(0))
	act, err := inst.Build(t.Context(), []*Source{src}, Fee{Dust: 330})
	require.NoError(t, err)
	require.EqualValues(t, 3, act.Tx.UnsignedTx.Version)
	require.Equal(t, 1, act.Extension)

	w, err := txutils.GetArkPsbtFields(act.Tx, 0, txutils.ConditionWitnessField)
	require.NoError(t, err)
	require.Equal(t, wire.TxWitness{preimage}, w[0])
	emu, err := arkade.FindEmulatorPacket(act.Tx.UnsignedTx)
	require.NoError(t, err)
	require.Equal(t, wire.TxWitness{preimage, scriptNum(7)}, emu[0].Witness, "covenant inputs reversed: the first on top")
}

func TestBuildConditionWitnessOrder(t *testing.T) {
	inst, err := parseDoc(t, twoItemCondition(t)).Instantiate(t.Context(), Context{Keys: testKeys(t)})
	require.NoError(t, err)
	src := sourceWith(t, 100_000)
	lockTo(src, inst.PkScript(0))
	act, err := inst.Build(t.Context(), []*Source{src}, Fee{Dust: 330})
	require.NoError(t, err)

	w, err := txutils.GetArkPsbtFields(act.Tx, 0, txutils.ConditionWitnessField)
	require.NoError(t, err)
	closure, err := script.DecodeClosure(act.Tx.Inputs[0].TaprootLeafScript[0].Script)
	require.NoError(t, err)
	cond, ok := closure.(*script.ConditionMultisigClosure)
	require.True(t, ok)
	holds, err := script.EvaluateScriptToBool(cond.Condition, w[0])
	require.NoError(t, err)
	require.True(t, holds, "the first declared item on top of the stack")
}

func TestBuildOnchain(t *testing.T) {
	tmpl := parseFixture(t, "minimal.json")
	inst, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t)})
	require.NoError(t, err)
	src := sourceWith(t, 100_000)
	lockTo(src, inst.PkScript(0))
	src.Confirms = 1
	var measured int
	act, err := inst.Build(t.Context(), []*Source{src}, Fee{Dust: 330, Onchain: func(vsize int) uint64 { measured = vsize; return 600 }})
	require.NoError(t, err)
	require.EqualValues(t, 600, act.Fee)
	require.EqualValues(t, 2, act.Tx.UnsignedTx.Version)
	require.EqualValues(t, 99_400, act.Tx.UnsignedTx.TxOut[0].Value)
	require.Equal(t, -1, act.Extension)
	// 94 bytes stripped, witness: marker and flag, signature, script of 34 bytes, control block of 33
	require.Equal(t, (94*4+2+1+65+35+34+3)/4, measured)

	_, err = inst.Build(t.Context(), []*Source{src}, Fee{Dust: 330, Onchain: func(int) uint64 { return 1001 }})
	require.ErrorIs(t, err, ErrIneligible)
	_, err = inst.Build(t.Context(), []*Source{src}, Fee{Dust: 330})
	require.ErrorIs(t, err, ErrIneligible, "no on-chain fee estimate")
}

func TestBuildIntentFee(t *testing.T) {
	inst, _, src := mixedPayment(t, 100_000, nil) // fees max 1000
	charge := arkfee.Config{IntentOffchainInputProgram: "200.0"}
	act, err := inst.Build(t.Context(), src, Fee{Dust: 330, Intent: charge})
	require.NoError(t, err)
	require.EqualValues(t, 200, act.Fee)
	require.EqualValues(t, 74_800, act.Tx.UnsignedTx.TxOut[0].Value)

	// the output fee depends on the amount it prices: 0.1% of the change, rounded up, and 1 per on-chain output
	perOutput := arkfee.Config{IntentOffchainOutputProgram: "amount * 0.001", IntentOnchainOutputProgram: "1.0"}
	act, err = inst.Build(t.Context(), src, Fee{Dust: 330, Intent: perOutput})
	require.NoError(t, err)
	require.EqualValues(t, 76, act.Fee)
	require.EqualValues(t, 74_924, act.Tx.UnsignedTx.TxOut[0].Value)

	src[0].Swept = true
	act, err = inst.Build(t.Context(), src, Fee{Dust: 330, Intent: arkfee.Config{IntentOffchainInputProgram: "inputType == 'recoverable' ? 300.0 : 200.0"}})
	require.NoError(t, err)
	require.EqualValues(t, 300, act.Fee, "a swept input is priced as recoverable")
	src[0].Swept = false

	oscillates := arkfee.Config{IntentOffchainOutputProgram: "amount >= 74950.0 ? 100.0 : 0.0"}
	_, err = inst.Build(t.Context(), src, Fee{Dust: 330, Intent: oscillates})
	require.ErrorIs(t, err, ErrIneligible, "no fixed point")

	free, _, src := mixedPaymentNoFees(t, 100_000)
	_, err = free.Build(t.Context(), src, Fee{Dust: 330, Intent: charge})
	require.ErrorIs(t, err, ErrIneligible, "arkd charges and the template pays nothing")
}

func TestBuildOutputScripts(t *testing.T) {
	other := testKey(t, 4).SerializeCompressed()
	doc := edited(t, mixedPaymentDoc(t, false), func(m map[string]any) {
		in := m["inputs"].([]any)[0].(map[string]any)
		m["outputs"].([]any)[0].(map[string]any)["locking"] = map[string]any{"contract": map[string]any{
			"definition": in["contract"].(map[string]any)["definition"],
			"arguments":  map[string]any{"owner": hex.EncodeToString(other)},
		}}
	})
	inst, _, src := instanceOf(t, doc, coin(t, 100_000))
	act, err := inst.Build(t.Context(), src, Fee{Dust: 330})
	require.NoError(t, err)
	want, err := build(inst.tmpl.inputs[0].contract.def, map[string]value{"owner": {"pubkey", other}}, testKeys(t))
	require.NoError(t, err)
	require.Equal(t, want.pkScript, act.Tx.UnsignedTx.TxOut[0].PkScript)

	for script, wantErr := range map[string]bool{
		"0014" + hex.EncodeToString(bytes.Repeat([]byte{1}, 20)):            true,
		"5120" + hex.EncodeToString(bytes.Repeat([]byte{1}, 31)):            true,
		"5120" + hex.EncodeToString(bytes.Repeat([]byte{0xff}, 32)):         true,
		"5120" + hex.EncodeToString(schnorr.SerializePubKey(testKey(t, 5))): false,
	} {
		doc := edited(t, mixedPaymentDoc(t, false), func(m map[string]any) {
			m["outputs"].([]any)[0].(map[string]any)["locking"] = script
		})
		inst, _, src := instanceOf(t, doc, coin(t, 100_000))
		_, err := inst.Build(t.Context(), src, Fee{Dust: 330})
		if wantErr {
			require.ErrorIs(t, err, ErrIneligible, script)
		} else {
			require.NoError(t, err, script)
		}
	}

	doc = edited(t, mixedPaymentDoc(t, false), func(m map[string]any) {
		m["outputs"].([]any)[1].(map[string]any)["locking"] = "4c"
	})
	inst, _, src = instanceOf(t, doc, coin(t, 100_000))
	_, err = inst.Build(t.Context(), src, Fee{Dust: 330})
	require.ErrorIs(t, err, ErrIneligible, "a truncated push is no script")
}

func TestBuildEmit(t *testing.T) {
	for data, wantErr := range map[string]bool{"abcd": false, "$(2 OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTPACKET OP_VERIFY)": false, "": true} {
		doc := edited(t, withUnmatched(t, "reject"), func(m map[string]any) {
			m["packets"].(map[string]any)["rules"] = []any{map[string]any{"type": 2, "action": "emit", "from": "funds", "data": data}}
		})
		inst, _, src := instanceOf(t, doc, sourceWith(t, 100_000, packets.Raw(packets.TypeState, []byte{0xab, 0xcd})))
		act, err := inst.Build(t.Context(), src, Fee{Dust: 330})
		if wantErr {
			require.ErrorIs(t, err, ErrIneligible, "an empty packet")
			continue
		}
		require.NoError(t, err, data)
		state, _ := packets.Find(act.Tx.UnsignedTx, packets.TypeState)
		require.Equal(t, []byte{0xab, 0xcd}, state, data)
	}
}

func TestBuildAdvertisements(t *testing.T) {
	a, b := bytes.Repeat([]byte{0xaa}, 32), bytes.Repeat([]byte{0xbb}, 32)
	doc := edited(t, twoFunds(t), func(m map[string]any) {
		outs := m["outputs"].([]any)
		// change 0, extra_change 1: advertise extra_change first
		m["packets"].(map[string]any)["advertise"] = []any{
			map[string]any{"template": hex.EncodeToString(b), "outputs": []any{outs[1].(map[string]any)["name"]}},
			map[string]any{"template": hex.EncodeToString(a), "outputs": []any{outs[0].(map[string]any)["name"]}},
		}
	})
	inst, _, src := instanceOf(t, doc, coin(t, 50_000, Asset{assetID(1), 2}), coin(t, 60_000))
	act, err := inst.Build(t.Context(), src, Fee{Dust: 330})
	require.NoError(t, err)
	body, ok := packets.Find(act.Tx.UnsignedTx, packets.TypeAdvertisement)
	require.True(t, ok)
	got, err := packets.DecodeAdvertisement(body)
	require.NoError(t, err)
	require.Equal(t, []packets.Record{{Template: [32]byte(a), Outputs: []uint16{0}}, {Template: [32]byte(b), Outputs: []uint16{1}}}, got)
}

func TestBuildRefusesSources(t *testing.T) {
	inst, _, src := mixedPayment(t, 100_000, nil)
	_, err := inst.Build(t.Context(), nil, Fee{Dust: 330})
	require.ErrorIs(t, err, ErrIneligible, "no source")
	_, err = inst.Build(t.Context(), []*Source{{Outpoint: src[0].Outpoint, Amount: 100_000}}, Fee{Dust: 330})
	require.ErrorIs(t, err, ErrIneligible, "no transaction")
	_, err = inst.Build(t.Context(), []*Source{coin(t, 100_000)}, Fee{Dust: 330})
	require.ErrorIs(t, err, ErrIneligible, "another script")
	moved := *src[0]
	moved.Amount++
	_, err = inst.Build(t.Context(), []*Source{&moved}, Fee{Dust: 330})
	require.ErrorIs(t, err, ErrIneligible, "an amount the output does not hold")
}

func TestBuildNeedsPackets(t *testing.T) {
	doc := edited(t, mixedPaymentDoc(t, false), func(m map[string]any) {
		delete(m, "packets")
		m["outputs"].([]any)[1].(map[string]any)["index"] = 1
	})
	doc = edited(t, doc, func(m map[string]any) {
		sp := m["inputs"].([]any)[0].(map[string]any)["spend"].(map[string]any)
		sp["function"], sp["leaf"] = "spend", "spend"
	})
	inst, _, src := instanceOf(t, doc, coin(t, 100_000, Asset{assetID(1), 1}))
	_, err := inst.Build(t.Context(), src, Fee{Dust: 330})
	require.ErrorIs(t, err, ErrInvalidTemplate, "assets and no extension")

	inst, _, src = instanceOf(t, doc, coin(t, 100_000))
	act, err := inst.Build(t.Context(), src, Fee{Dust: 330})
	require.NoError(t, err)
	require.Equal(t, -1, act.Extension)
	require.Len(t, act.Tx.UnsignedTx.TxOut, 2)
}

func TestBuildErrorsHidePlaintext(t *testing.T) {
	for name, c := range map[string]struct {
		typ   string
		plain []byte
		edit  func(outs []any)
	}{
		"amount": {"int", scriptNum(-123456789), func(outs []any) {
			outs[1].(map[string]any)["value"].(map[string]any)["amount"] = "<s>"
		}},
		"offchain script": {"bytes", bytes.Repeat([]byte{0xab}, 31), func(outs []any) {
			outs[0].(map[string]any)["locking"] = "5120<s>"
		}},
		"offchain key": {"bytes", bytes.Repeat([]byte{0xff}, 32), func(outs []any) {
			outs[0].(map[string]any)["locking"] = "5120<s>"
		}},
		"onchain script": {"bytes", []byte{txscript.OP_PUSHDATA1, 0xcd}, func(outs []any) {
			outs[1].(map[string]any)["locking"] = "<s>"
		}},
	} {
		t.Run(name, func(t *testing.T) {
			doc := edited(t, mixedPaymentDoc(t, false), func(m map[string]any) {
				m["secrets"] = map[string]any{"s": map[string]any{"type": c.typ, "from": "funds", "ciphertext": "00"}}
				c.edit(m["outputs"].([]any))
			})
			tmpl := parseDoc(t, doc)
			src := coin(t, 100_000)
			ct, err := build(tmpl.inputs[0].contract.def, map[string]value{"owner": {"pubkey", testKey(t, 2).SerializeCompressed()}}, testKeys(t))
			require.NoError(t, err)
			lockTo(src, ct.pkScript)
			inst, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t), Sources: []*Source{src},
				Decrypt: func([]byte) ([]byte, error) { return c.plain, nil }})
			require.NoError(t, err)
			_, err = inst.Build(t.Context(), []*Source{src}, Fee{Dust: 330})
			require.ErrorIs(t, err, ErrIneligible)
			require.NotContains(t, err.Error(), hex.EncodeToString(c.plain))
		})
	}
}

func assetIn(t *testing.T, vin uint16, n uint64) asset.AssetInput {
	t.Helper()
	x, err := asset.NewAssetInput(vin, n)
	require.NoError(t, err)
	return *x
}

func assetOut(t *testing.T, vout uint16, n uint64) asset.AssetOutput {
	t.Helper()
	x, err := asset.NewAssetOutput(vout, n)
	require.NoError(t, err)
	return *x
}

// keepScript is a watchable intent keeping value, script and assets, copying packet 2.
func keepScript(t *testing.T) []byte {
	t.Helper()
	return edited(t, mixedPaymentDoc(t, false), func(m map[string]any) {
		m["outputs"] = m["outputs"].([]any)[:1]
		m["packets"] = map[string]any{"output_index": 1, "rules": []any{packetRule(2, "copy", "funds")}}
	})
}

// withUnmatched is keepScript without rules, handling unmatched source packets as unmatched says.
func withUnmatched(t *testing.T, unmatched string) []byte {
	t.Helper()
	return edited(t, keepScript(t), func(m map[string]any) {
		m["packets"] = map[string]any{"output_index": 1, "unmatched": unmatched}
	})
}

// twoItemCondition is an offchain claim whose condition reads a = 2 from the top of the stack, then b = 3.
func twoItemCondition(t *testing.T) []byte {
	t.Helper()
	return []byte(`{
  "format": "delegateed-template/v1",
  "type": "offchain",
  "inputs": [{
    "name": "coin",
    "contract": {
      "definition": {
        "contractName": "TwoItems",
        "constructorInputs": [],
        "structs": [],
        "functions": [{"name": "claim", "arkade": {"inputs": [], "asm": ["OP_1"]},
          "leaves": [{"name": "claim",
          "asm": ["OP_2", "OP_EQUALVERIFY", "OP_3", "OP_EQUAL", "OP_VERIFY", "<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:claim>", "OP_CHECKSIG"],
          "witness": [{"name": "a", "type": "int", "encoding": "raw"}, {"name": "b", "type": "int", "encoding": "raw"},
                      {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true},
                      {"name": "emulatorSig", "type": "signature", "encoding": "schnorr-64", "injected": true}]}]}]
      }
    },
    "spend": {"function": "claim", "leaf": "claim", "witness": {"a": 2, "b": 3}}
  }],
  "outputs": [{"name": "payout", "index": 0, "value": {"from": "coin"},
    "locking": "5120f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"}],
  "packets": {"output_index": 1}
}`)
}

// hashLockWithCovenant is hashLock whose claim is a covenant taking (a int, b bytes32) bound to 7 and the preimage.
func hashLockWithCovenant(t *testing.T) []byte {
	t.Helper()
	return fmt.Append(nil, `{
  "format": "delegateed-template/v1",
  "type": "offchain",
  "variables": {"ciphertext": "bytes"},
  "secrets": {"preimage": {"type": "bytes32", "from": "htlc", "ciphertext": "<ciphertext>"}},
  "inputs": [{
    "name": "htlc",
    "contract": {
      "definition": {
        "contractName": "HashLock",
        "constructorInputs": [{"name": "h", "type": "bytes20"}],
        "structs": [],
        "functions": [{"name": "claim",
          "arkade": {"inputs": [{"name": "a", "type": "int"}, {"name": "b", "type": "bytes32"}], "asm": ["OP_2DROP", "OP_1"]},
          "leaves": [{"name": "claim",
          "asm": ["OP_SIZE", "32", "OP_EQUALVERIFY", "OP_HASH160", "<h>", "OP_EQUAL", "OP_VERIFY",
                  "<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:claim>", "OP_CHECKSIG"],
          "witness": [{"name": "preimage", "type": "bytes32", "encoding": "raw"},
                      {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true},
                      {"name": "emulatorSig", "type": "signature", "encoding": "schnorr-64", "injected": true}]}]}]
      },
      "arguments": {"h": "$(<preimage> OP_HASH160)"}
    },
    "spend": {"function": "claim", "leaf": "claim", "arguments": [7, "<preimage>"], "witness": {"preimage": "<preimage>"}}
  }],
  "outputs": [{"name": "payout", "index": 0, "value": {"from": "htlc"},
    "locking": "5120f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"}],
  "packets": {"output_index": 1}
}`)
}
