package template

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestFixtures(t *testing.T) {
	var ids map[string]string
	require.NoError(t, json.Unmarshal(fixture(t, "ids.json"), &ids))
	resolve := artifacts(t)
	for _, name := range []string{"renewal.json", "boarding.json", "counter.json", "vhtlc_claim.json", "onchain_release.json", "counter_seed.json", "minimal.json"} {
		t.Run(name, func(t *testing.T) {
			tmpl, err := Parse(t.Context(), fixture(t, name), resolve)
			require.NoError(t, err)
			require.Equal(t, ids[name], tmpl.ID(), "a fixture changed: update ids.json")
		})
	}
}

func TestDefaults(t *testing.T) {
	renewal := parseFixture(t, "renewal.json")
	require.Equal(t, Intent, renewal.Type())
	require.Equal(t, []Slot{{Name: "funds"}}, renewal.Inputs())
	require.Equal(t, []Field{{"exit_delay", "int"}, {"max_fee", "int"}, {"owner", "pubkey"}, {"renewal_window", "int"}}, renewal.Variables())
	require.True(t, renewal.ContextFree())

	boarding := parseFixture(t, "boarding.json")
	require.Equal(t, []Slot{{Name: "deposit", Onchain: true, Schedule: Schedule{MinConfirmations: 1}}}, boarding.Inputs())
	require.Equal(t, []Field{
		{"boarding_exit_delay", "int"}, {"exit_delay", "int"}, {"max_fee", "int"}, {"owner", "pubkey"}, {"renewal_window", "int"},
	}, boarding.Variables())
	require.True(t, boarding.ContextFree())
	require.Equal(t, renewal.Artifacts(), boarding.Artifacts(), "one DelegatedVtxo definition")
}

func TestProgramBinding(t *testing.T) {
	doc := fixture(t, "boarding.json")
	args := func(m map[string]any) map[string]any {
		return m["inputs"].([]any)[0].(map[string]any)["contract"].(map[string]any)["arguments"].(map[string]any)
	}
	for name, edit := range map[string]func(map[string]any){
		"unknown output": func(m map[string]any) { args(m)["renewalProgram"] = map[string]any{"program": "nope"} },
		"extra field":    func(m map[string]any) { args(m)["renewalProgram"] = map[string]any{"program": "funds", "x": 1} },
		"not bytes32":    func(m map[string]any) { args(m)["owner"] = map[string]any{"program": "funds"} },
		"script output": func(m map[string]any) {
			m["outputs"].([]any)[0].(map[string]any)["locking"] = "5120" + strings.Repeat("00", 32)
		},
		"program in output": func(m map[string]any) {
			c := m["outputs"].([]any)[0].(map[string]any)["locking"].(map[string]any)["contract"].(map[string]any)
			c["arguments"].(map[string]any)["owner"] = map[string]any{"program": "funds"}
		},
	} {
		_, err := Parse(t.Context(), edited(t, doc, edit), artifacts(t))
		require.ErrorIs(t, err, ErrInvalidTemplate, name)
	}
}

func TestFixtureShapes(t *testing.T) {
	claim := parseFixture(t, "vhtlc_claim.json")
	require.Equal(t, Offchain, claim.Type())
	require.True(t, claim.Secrets())
	require.Len(t, claim.Variables(), 9)

	_, err := parseFixture(t, "counter.json").Instantiate(t.Context(), Context{Keys: testKeys(t)})
	require.ErrorIs(t, err, ErrUnsupported, "a watch on two slots")
}

func TestRenewalAddress(t *testing.T) {
	for _, p := range []renewalParams{
		defaultParams(t),
		{owner: testKey(t, 5), exit: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}, window: 86_400, maxFee: 0},
		{owner: testKey(t, 6), exit: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1024}, window: 1, maxFee: 1_000_000},
	} {
		inst, err := parseFixture(t, "renewal.json").Instantiate(t.Context(), Context{Keys: testKeys(t), Variables: p.vars(t)})
		require.NoError(t, err)
		require.Equal(t, masterPkScript(t, testKeys(t), p), inst.PkScript(0))
	}
}

func TestRenewalDueAt(t *testing.T) {
	p := defaultParams(t)
	inst, err := parseFixture(t, "renewal.json").Instantiate(t.Context(), Context{Keys: testKeys(t), Variables: p.vars(t)})
	require.NoError(t, err)
	now := time.Now()
	expiry := now.Add(time.Hour)
	require.Equal(t, expiry.Add(-1024*time.Second), inst.DueAt(0, &Source{Expiry: expiry, CreatedAt: now.Add(-time.Hour)}, now))
	// a window over half the life would pay a fee every round
	require.Equal(t, expiry.Add(-5*time.Minute), inst.DueAt(0, &Source{Expiry: expiry, CreatedAt: expiry.Add(-10 * time.Minute)}, now))

	p.maxFee = 0
	free, err := parseFixture(t, "renewal.json").Instantiate(t.Context(), Context{Keys: testKeys(t), Variables: p.vars(t)})
	require.NoError(t, err)
	require.Equal(t, expiry.Add(-1024*time.Second), free.DueAt(0, &Source{Expiry: expiry, CreatedAt: expiry.Add(-10 * time.Minute)}, now))
}

func TestRenewalVariableRanges(t *testing.T) {
	renewal := parseFixture(t, "renewal.json")
	for name, edit := range map[string]func(map[string][]byte){
		"zero window":     func(v map[string][]byte) { v["renewal_window"] = scriptNum(0) },
		"negative window": func(v map[string][]byte) { v["renewal_window"] = scriptNum(-1) },
		"huge window":     func(v map[string][]byte) { v["renewal_window"] = scriptNum(1 << 32) },
		"negative fee":    func(v map[string][]byte) { v["max_fee"] = scriptNum(-1) },
	} {
		vars := defaultParams(t).vars(t)
		edit(vars)
		_, err := renewal.Instantiate(t.Context(), Context{Keys: testKeys(t), Variables: vars})
		require.ErrorIs(t, err, ErrInvalidVariables, name)
	}
}

func TestRenewalCovenant(t *testing.T) {
	p := defaultParams(t)
	renewal := parseFixture(t, "renewal.json")
	watch, err := renewal.Instantiate(t.Context(), Context{Keys: testKeys(t), Variables: p.vars(t)})
	require.NoError(t, err)
	vtxo := sourceWith(t, 100_000)
	lockTo(vtxo, watch.PkScript(0))
	vtxo.Expiry = time.Now().Add(time.Minute)
	vtxo.Assets = []Asset{{assetID(9), 21}}
	sources := []*Source{vtxo}
	inst, err := renewal.Instantiate(t.Context(), Context{Keys: testKeys(t), Variables: p.vars(t), Sources: sources})
	require.NoError(t, err)
	act, err := inst.Build(t.Context(), sources, Fee{Dust: 330})
	require.NoError(t, err)
	require.Equal(t, watch.PkScript(0), act.Tx.UnsignedTx.TxOut[0].PkScript, "the renewed coin stays at the watched address")

	require.NoError(t, runIntent(t, act, sources, 0, nil))
	cut := func(sats int64) func(*intentCheck) { return func(c *intentCheck) { c.tx.TxOut[0].Value -= sats } }
	require.NoError(t, runIntent(t, act, sources, 0, cut(1000)), "a fee up to max_fee")
	require.ErrorContains(t, runIntent(t, act, sources, 0, cut(1001)), "OP_VERIFY failed", "below input - max_fee")
	assetsElsewhere := tamper{"assets missing", func(c *intentCheck) { moveAssets(t, c.tx, 1) }, "source assets"}
	for _, tp := range append(intentTampers(t, 0), assetsElsewhere) {
		require.ErrorContains(t, runIntent(t, act, sources, 0, tp.edit), tp.reason, tp.name)
	}

	charged := func(fee string) (*Action, error) {
		return inst.Build(t.Context(), sources, Fee{Dust: 330, Intent: arkfee.Config{IntentOffchainInputProgram: fee}})
	}
	paid, err := charged("1000.0")
	require.NoError(t, err)
	require.EqualValues(t, 99_000, paid.Tx.UnsignedTx.TxOut[0].Value)
	require.NoError(t, runIntent(t, paid, sources, 0, nil))
	_, err = charged("1001.0")
	require.ErrorIs(t, err, ErrIneligible, "the template refuses a fee over max_fee")
}

func TestBoardingCovenant(t *testing.T) {
	board := boarded(t)
	p := defaultParams(t)
	out := board.act.Tx.UnsignedTx.TxOut[0]
	require.Equal(t, masterPkScript(t, testKeys(t), p), out.PkScript, "boards into the renewal address of the same variables")
	require.NoError(t, runIntent(t, board.act, board.sources, 0, nil))
	cut := func(sats int64) func(*intentCheck) { return func(c *intentCheck) { c.tx.TxOut[0].Value -= sats } }
	require.NoError(t, runIntent(t, board.act, board.sources, 0, cut(1000)), "a fee up to max_fee")
	require.ErrorContains(t, runIntent(t, board.act, board.sources, 0, cut(1001)), "false stack entry", "below input - max_fee")
	for _, tp := range intentTampers(t, 0) {
		switch tp.name {
		case "too early":
			continue // an on-chain coin has no expiry
		case "script":
			tp.reason = "OP_EQUALVERIFY failed"
		}
		require.ErrorContains(t, runIntent(t, board.act, board.sources, 0, tp.edit), tp.reason, tp.name)
	}
}

func TestBoardingThenRenewal(t *testing.T) {
	p := defaultParams(t)
	board := boarded(t)
	tx := board.act.Tx.UnsignedTx
	// the settlement leaf keeps output 0: the renewal watch finds it, renewal after renewal
	for generation := range 2 {
		vtxo := &Source{Outpoint: wire.OutPoint{Hash: tx.TxHash()}, Tx: tx, Amount: uint64(tx.TxOut[0].Value), Expiry: time.Now().Add(time.Minute)}
		inst, err := parseFixture(t, "renewal.json").Instantiate(t.Context(), Context{Keys: testKeys(t), Variables: p.vars(t), Sources: []*Source{vtxo}})
		require.NoError(t, err, "generation %d", generation)
		act, err := inst.Build(t.Context(), []*Source{vtxo}, Fee{Dust: 330})
		require.NoError(t, err)
		require.NoError(t, runIntent(t, act, []*Source{vtxo}, 0, nil), "generation %d", generation)
		require.Equal(t, tx.TxOut[0].PkScript, act.Tx.UnsignedTx.TxOut[0].PkScript)
		tx = act.Tx.UnsignedTx
	}
}

func TestCounterIncrements(t *testing.T) {
	counter := parseFixture(t, "counter.json")
	require.Len(t, counter.Inputs(), 2)
	watch := instantiateBound(t, counter, 5) // both coins from one transaction with packet 2 = 05 00 .. 00
	act, err := watch.inst.Build(t.Context(), watch.sources, Fee{Dust: 330})
	require.NoError(t, err)
	state, ok := packets.Find(act.Tx.UnsignedTx, packets.TypeState)
	require.True(t, ok)
	require.Equal(t, []byte{6, 0, 0, 0, 0, 0, 0, 0}, state)
	id, _ := hex.DecodeString(counter.ID())
	body, _ := packets.Find(act.Tx.UnsignedTx, packets.TypeAdvertisement)
	require.Equal(t, append(append([]byte{0x01, 0x24, 0x00}, id...), 0, 0, 1, 0), body)
}

func TestVHTLCAddress(t *testing.T) {
	var v struct {
		Server, PkScript string
		Tapscripts       []string
		Vars             map[string]string
	}
	require.NoError(t, json.Unmarshal(fixture(t, "vhtlc_vector.json"), &v))
	// the address the ts-sdk derives for the same keys, delays and preimage hash
	inst := instantiateVHTLC(t, v.Server, v.Vars)
	require.Equal(t, v.Tapscripts, inst.Tapscripts(0))
	require.Equal(t, v.PkScript, hex.EncodeToString(inst.PkScript(0)))
	require.Len(t, inst.Tapscripts(0), 9)
}

func TestCounterCovenant(t *testing.T) {
	counter := instantiateBound(t, parseFixture(t, "counter.json"), 5)
	act, err := counter.inst.Build(t.Context(), counter.sources, Fee{Dust: 330})
	require.NoError(t, err)
	for slot, name := range []string{"counter", "reserve"} {
		require.NoError(t, runIntent(t, act, counter.sources, slot, nil), name)
		// the reserve's covenant starts with 1 OP_DROP: its script, hence its output, differs from the counter's
		swap := tamper{"outputs swapped", func(c *intentCheck) { c.tx.TxOut[0], c.tx.TxOut[1] = c.tx.TxOut[1], c.tx.TxOut[0] }, "source script"}
		for _, tp := range append(tampers(t, slot, true), swap) {
			err := runIntent(t, act, counter.sources, slot, tp.edit)
			if name == "reserve" && (tp.name == "packet 2" || tp.name == "packet 2 absent") {
				require.NoError(t, err, "only the counter reads packet 2")
				continue
			}
			require.ErrorContains(t, err, tp.reason, "%s: %s", name, tp.name)
		}
	}
}

func TestVHTLCClaimCovenant(t *testing.T) {
	var v struct {
		Server string
		Vars   map[string]string
	}
	require.NoError(t, json.Unmarshal(fixture(t, "vhtlc_vector.json"), &v))
	htlc := sourceWith(t, 100_000)
	lockTo(htlc, instantiateVHTLC(t, v.Server, v.Vars).PkScript(0))
	inst := instantiateVHTLC(t, v.Server, v.Vars, htlc)
	act, err := inst.Build(t.Context(), []*Source{htlc}, Fee{Dust: 330})
	require.NoError(t, err)

	claim := func(edit func(*wire.TxOut)) error {
		tx := act.Tx.UnsignedTx.Copy()
		if edit != nil {
			edit(tx.TxOut[0])
		}
		ptx := *act.Tx
		ptx.UnsignedTx = tx
		f := prevouts{
			outs: map[wire.OutPoint]*wire.TxOut{htlc.Outpoint: act.Tx.Inputs[0].WitnessUtxo},
			txs:  map[wire.OutPoint]*wire.MsgTx{htlc.Outpoint: htlc.Tx},
		}
		return execute(t, &ptx, f, 0)
	}
	require.NoError(t, claim(nil))
	require.Error(t, claim(func(o *wire.TxOut) { o.PkScript = otherScript }), "another program")
	require.Error(t, claim(func(o *wire.TxOut) { o.Value-- }), "one satoshi less")
}

func TestCounterSeedCovenant(t *testing.T) {
	keys := testKeys(t)
	counter := parseFixture(t, "counter.json")
	var programs [][]byte
	for i := range counter.inputs {
		c, err := build(counter.inputs[i].contract.def, nil, keys)
		require.NoError(t, err)
		programs = append(programs, c.pkScript[2:])
	}
	vars := map[string][]byte{"counter_program": programs[0], "reserve_program": programs[1]}
	seed := parseFixture(t, "counter_seed.json")
	watch, err := seed.Instantiate(t.Context(), Context{Keys: keys, Variables: vars})
	require.NoError(t, err)
	deposit := sourceWith(t, 20_000)
	lockTo(deposit, watch.PkScript(0))
	deposit.Confirms = 1
	inst, err := seed.Instantiate(t.Context(), Context{Keys: keys, Variables: vars, Sources: []*Source{deposit}})
	require.NoError(t, err)
	act, err := inst.Build(t.Context(), []*Source{deposit}, Fee{Dust: 330})
	require.NoError(t, err)

	out := act.Tx.UnsignedTx.TxOut
	require.Equal(t, append([]byte{0x51, 0x20}, programs[0]...), out[0].PkScript)
	require.Equal(t, append([]byte{0x51, 0x20}, programs[1]...), out[1].PkScript)
	require.Equal(t, []int64{10_000, 10_000}, []int64{out[0].Value, out[1].Value})
	state, _ := packets.Find(act.Tx.UnsignedTx, packets.TypeState)
	require.Equal(t, []byte{5, 0, 0, 0, 0, 0, 0, 0}, state)
	id, _ := hex.DecodeString(counter.ID())
	ad, _ := packets.Find(act.Tx.UnsignedTx, packets.TypeAdvertisement)
	require.Equal(t, append(append([]byte{0x01, 0x24, 0x00}, id...), 0, 0, 1, 0), ad)

	sources := []*Source{deposit}
	require.NoError(t, runIntent(t, act, sources, 0, nil))
	swap := tamper{"outputs swapped", func(c *intentCheck) { c.tx.TxOut[0], c.tx.TxOut[1] = c.tx.TxOut[1], c.tx.TxOut[0] }, "OP_EQUALVERIFY failed"}
	reserve := tamper{"reserve script", func(c *intentCheck) { c.tx.TxOut[1].PkScript = otherScript }, "OP_EQUALVERIFY failed"}
	short := tamper{"reserve value -1", func(c *intentCheck) { c.tx.TxOut[1].Value-- }, "false stack entry"}
	for _, tp := range append(tampers(t, 0, false), swap, reserve, short) {
		if tp.name == "expiry" {
			continue // an on-chain coin has no expiry
		}
		require.ErrorContains(t, runIntent(t, act, sources, 0, tp.edit), tp.reason, tp.name)
	}
}

var otherScript = append([]byte{0x51, 0x20}, make([]byte, 32)...)

// cosignerHex is private scalar 1, the delegate key of testKeys, as intent messages spell it.
const cosignerHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

type renewalParams struct {
	owner          *btcec.PublicKey
	exit           arklib.RelativeLocktime
	window, maxFee int64
}

func defaultParams(t *testing.T) renewalParams {
	return renewalParams{owner: testKey(t, 2), exit: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512}, window: 1024, maxFee: 1000}
}

func (p renewalParams) vars(t *testing.T) map[string][]byte {
	t.Helper()
	seq, err := arklib.BIP68Sequence(p.exit)
	require.NoError(t, err)
	return map[string][]byte{
		"owner": p.owner.SerializeCompressed(), "exit_delay": scriptNum(int64(seq)),
		"renewal_window": scriptNum(p.window), "max_fee": scriptNum(p.maxFee),
	}
}

// masterCovenant is master's buildArkadeScript in its fee-check form, the only one renewal.json keeps.
func masterCovenant(t *testing.T, delegateHex string, window, maxFee int64) []byte {
	t.Helper()
	s, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHEXPIRY).AddInt64(window).AddOp(arkade.OP_SUB).AddOp(arkade.OP_CHECKTIME).AddOp(txscript.OP_VERIFY).
		AddData([]byte("type")).AddOp(arkade.OP_INSPECTINTENTMESSAGE).AddOp(txscript.OP_VERIFY).
		AddData([]byte(intent.IntentMessageTypeRegister)).AddOp(arkade.OP_EQUALVERIFY).
		AddData([]byte("onchain_output_indexes")).AddOp(arkade.OP_INSPECTINTENTMESSAGE).AddOp(txscript.OP_VERIFY).
		AddData([]byte("[]")).AddOp(arkade.OP_EQUALVERIFY).
		AddData([]byte("cosigners_public_keys.0")).AddOp(arkade.OP_INSPECTINTENTMESSAGE).AddOp(txscript.OP_VERIFY).
		AddData([]byte(delegateHex)).AddOp(arkade.OP_EQUALVERIFY).
		AddData([]byte("cosigners_public_keys.1")).AddOp(arkade.OP_INSPECTINTENTMESSAGE).AddOp(txscript.OP_NOT).AddOp(txscript.OP_VERIFY).AddOp(txscript.OP_DROP).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddOp(arkade.OP_1SUB).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddInt64(maxFee).AddOp(arkade.OP_ADD).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddOp(arkade.OP_INSPECTINPUTVALUE).AddOp(arkade.OP_GREATERTHANOREQUAL).AddOp(txscript.OP_VERIFY).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddOp(arkade.OP_1SUB).AddInt64(arkade.TunnelScriptPubKey | arkade.TunnelAssets).AddInt64(0).AddOp(arkade.OP_TUNNEL).
		Script()
	require.NoError(t, err)
	return s
}

// masterPkScript is master's tree around the delegate leaf, with the forfeit leaf of ark's default vtxo script first.
func masterPkScript(t *testing.T, keys Keys, p renewalParams) []byte {
	t.Helper()
	cov := masterCovenant(t, hex.EncodeToString(keys.Delegate.SerializeCompressed()), p.window, p.maxFee)
	tweaked := arkade.ComputeArkadeScriptPublicKey(keys.Emulator, arkade.ArkadeScriptHash(cov))
	vtxo := script.TapscriptsVtxoScript{Closures: []script.Closure{
		&script.MultisigClosure{PubKeys: []*btcec.PublicKey{p.owner, keys.Server}},
		&script.CSVMultisigClosure{MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{p.owner}}, Locktime: p.exit},
		&script.MultisigClosure{PubKeys: []*btcec.PublicKey{keys.Server, tweaked}},
	}}
	tapKey, _, err := vtxo.TapTree()
	require.NoError(t, err)
	pk, err := script.P2TRScript(tapKey)
	require.NoError(t, err)
	return pk
}

func artifacts(t testing.TB) Resolver {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "artifacts", "*.json"))
	require.NoError(t, err)
	paths = append(paths, filepath.Join("..", "..", "templates", "artifacts", "delegated_vtxo.json"))
	docs := map[string][]byte{}
	for _, p := range paths {
		doc, err := os.ReadFile(p)
		require.NoError(t, err)
		// some documents are invalid on purpose
		if a, err := ParseArtifact(doc); err == nil {
			docs[a.ID] = doc
		}
	}
	return func(_ context.Context, id string) ([]byte, error) {
		doc, ok := docs[id]
		if !ok {
			return nil, fmt.Errorf("unknown artifact %s", id)
		}
		return doc, nil
	}
}

type boundInstance struct {
	inst    *Instance
	sources []*Source
	act     *Action
}

// instantiateBound's source holds counter in packet 2 and advertises tmpl for outputs 0 and 1.
func instantiateBound(t *testing.T, tmpl *Template, counter uint64) boundInstance {
	t.Helper()
	keys := testKeys(t)
	r := packets.Record{Outputs: []uint16{0, 1}}
	_, err := hex.Decode(r.Template[:], []byte(tmpl.ID()))
	require.NoError(t, err)
	ad, err := packets.EncodeAdvertisement([]packets.Record{r})
	require.NoError(t, err)

	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})
	for _, in := range tmpl.inputs {
		c, err := build(in.contract.def, nil, keys)
		require.NoError(t, err)
		tx.AddTxOut(wire.NewTxOut(100_000, c.pkScript))
	}
	ext, err := extension.Extension{
		packets.Raw(packets.TypeState, binary.LittleEndian.AppendUint64(nil, counter)),
		packets.Raw(packets.TypeAdvertisement, ad),
	}.TxOut()
	require.NoError(t, err)
	tx.AddTxOut(ext)

	var sources []*Source
	for i := range tmpl.inputs {
		sources = append(sources, &Source{
			Outpoint: wire.OutPoint{Hash: tx.TxHash(), Index: uint32(i)}, Tx: tx, Amount: 100_000, Expiry: time.Now().Add(time.Minute),
		})
	}
	inst, err := tmpl.Instantiate(t.Context(), Context{Keys: keys, Sources: sources})
	require.NoError(t, err)
	return boundInstance{inst: inst, sources: sources}
}

// the ciphertext variable is the preimage itself, opened by an identity decryption
func instantiateVHTLC(t *testing.T, server string, vars map[string]string, sources ...*Source) *Instance {
	t.Helper()
	raw, err := hex.DecodeString(server)
	require.NoError(t, err)
	key, err := btcec.ParsePubKey(raw)
	require.NoError(t, err)
	values := map[string][]byte{}
	for n, h := range vars {
		values[n], err = hex.DecodeString(h)
		require.NoError(t, err)
	}
	c := Context{
		Keys:      Keys{Server: key, Emulator: testKey(t, 3)},
		Variables: values,
		Decrypt:   func(ciphertext []byte) ([]byte, error) { return ciphertext, nil },
	}
	if len(sources) > 0 {
		c.Sources = sources
	}
	inst, err := parseFixture(t, "vhtlc_claim.json").Instantiate(t.Context(), c)
	require.NoError(t, err)
	return inst
}

// boarded is the boarding of a 100,000-satoshi deposit under defaultParams.
func boarded(t *testing.T) boundInstance {
	t.Helper()
	keys := testKeys(t)
	vars := defaultParams(t).vars(t)
	vars["boarding_exit_delay"] = scriptNum(1<<22 | 2) // 1024 seconds, in BIP 68
	boarding := parseFixture(t, "boarding.json")
	watch, err := boarding.Instantiate(t.Context(), Context{Keys: keys, Variables: vars})
	require.NoError(t, err)
	deposit := sourceWith(t, 100_000)
	lockTo(deposit, watch.PkScript(0))
	deposit.Confirms = 1
	inst, err := boarding.Instantiate(t.Context(), Context{Keys: keys, Variables: vars, Sources: []*Source{deposit}})
	require.NoError(t, err)
	act, err := inst.Build(t.Context(), []*Source{deposit}, Fee{Dust: 330})
	require.NoError(t, err)
	return boundInstance{inst: inst, sources: []*Source{deposit}, act: act}
}

// intentCheck is what the emulator executes an intent covenant against.
type intentCheck struct {
	tx     *wire.MsgTx
	msg    intent.RegisterMessage
	expiry time.Time
}

// tamper is a dishonest variant of an intent and the failure the covenant must report.
type tamper struct {
	name   string
	edit   func(*intentCheck)
	reason string
}

// intentTampers break the checks of the default covenants on output out.
func intentTampers(t *testing.T, out int) []tamper {
	return []tamper{
		{"script", func(c *intentCheck) { c.tx.TxOut[out].PkScript = otherScript }, "source script"},
		{"second cosigner", func(c *intentCheck) { c.msg.CosignersPublicKeys = append(c.msg.CosignersPublicKeys, cosignerHex) }, "OP_VERIFY failed"},
		{"other cosigner", func(c *intentCheck) {
			c.msg.CosignersPublicKeys = []string{hex.EncodeToString(testKey(t, 7).SerializeCompressed())}
		}, "OP_EQUALVERIFY failed"},
		{"no cosigner", func(c *intentCheck) { c.msg.CosignersPublicKeys = []string{} }, "OP_VERIFY failed"},
		{"delete intent", func(c *intentCheck) { c.msg.Type = intent.IntentMessageTypeDelete }, "OP_EQUALVERIFY failed"},
		{"onchain output", func(c *intentCheck) { c.msg.OnchainOutputIndexes = []int{out} }, "OP_EQUALVERIFY failed"},
		{"too early", func(c *intentCheck) { c.expiry = time.Now().Add(2 * time.Hour) }, "OP_VERIFY failed"},
	}
}

// tunnel is when the covenant keeps output out with OP_TUNNEL rather than comparing it.
func tampers(t *testing.T, out int, tunnel bool) []tamper {
	other := append([]byte{0x01, 0x22, 0x00}, make([]byte, 34)...)
	value, script := "false stack entry", "OP_EQUALVERIFY failed"
	if tunnel {
		value, script = "source value", "source script"
	}
	return []tamper{
		{"value -1", func(c *intentCheck) { c.tx.TxOut[out].Value-- }, value},
		{"value +1", func(c *intentCheck) { c.tx.TxOut[out].Value++ }, value},
		{"script", func(c *intentCheck) { c.tx.TxOut[out].PkScript = otherScript }, script},
		{"packet 2", func(c *intentCheck) { setPacket(t, c.tx, packets.TypeState, []byte{7, 0, 0, 0, 0, 0, 0, 0}) }, "OP_EQUALVERIFY failed"},
		{"packet 2 absent", func(c *intentCheck) { setPacket(t, c.tx, packets.TypeState, nil) }, "OP_VERIFY failed"},
		{"advertisement", func(c *intentCheck) { setPacket(t, c.tx, packets.TypeAdvertisement, other) }, "OP_EQUALVERIFY failed"},
		{"advertisement absent", func(c *intentCheck) { setPacket(t, c.tx, packets.TypeAdvertisement, nil) }, "OP_VERIFY failed"},
		{"second cosigner", func(c *intentCheck) { c.msg.CosignersPublicKeys = append(c.msg.CosignersPublicKeys, cosignerHex) }, "OP_VERIFY failed"},
		{"other cosigner", func(c *intentCheck) {
			c.msg.CosignersPublicKeys = []string{hex.EncodeToString(testKey(t, 7).SerializeCompressed())}
		}, "OP_EQUALVERIFY failed"},
		{"no cosigner", func(c *intentCheck) { c.msg.CosignersPublicKeys = []string{} }, "OP_VERIFY failed"},
		{"delete intent", func(c *intentCheck) { c.msg.Type = intent.IntentMessageTypeDelete }, "OP_EQUALVERIFY failed"},
		{"onchain output", func(c *intentCheck) { c.msg.OnchainOutputIndexes = []int{out} }, "OP_EQUALVERIFY failed"},
		{"expiry", func(c *intentCheck) { c.expiry = time.Now().Add(2 * time.Hour) }, "OP_VERIFY failed"},
	}
}

// runIntent shifts template inputs and extension input references by one, as the emulator sees the proof.
func runIntent(t *testing.T, act *Action, sources []*Source, slot int, edit func(*intentCheck)) error {
	t.Helper()
	c := &intentCheck{
		tx: act.Tx.UnsignedTx.Copy(),
		msg: intent.RegisterMessage{
			BaseMessage:          intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
			OnchainOutputIndexes: []int{},
			CosignersPublicKeys:  []string{cosignerHex},
		},
		expiry: time.Now().Add(time.Minute),
	}
	if edit != nil {
		edit(c)
	}
	msg, err := c.msg.Encode()
	require.NoError(t, err)

	ins := make([]intent.Input, len(c.tx.TxIn))
	for i, in := range c.tx.TxIn {
		ins[i] = intent.Input{OutPoint: &in.PreviousOutPoint, Sequence: in.Sequence, WitnessUtxo: act.Tx.Inputs[i].WitnessUtxo}
	}
	outs := slices.Clone(c.tx.TxOut)
	outs[act.Extension] = shiftedExtension(t, c.tx)
	proof, err := intent.New(msg, ins, outs)
	require.NoError(t, err)

	ptx := &proof.Packet
	f := prevouts{outs: map[wire.OutPoint]*wire.TxOut{}, txs: map[wire.OutPoint]*wire.MsgTx{}}
	for i, in := range ptx.UnsignedTx.TxIn {
		ptx.Inputs[i].TaprootLeafScript = act.Tx.Inputs[max(i-1, 0)].TaprootLeafScript
		f.outs[in.PreviousOutPoint] = ptx.Inputs[i].WitnessUtxo
		if i == 0 {
			f.txs[in.PreviousOutPoint] = &wire.MsgTx{TxOut: []*wire.TxOut{ptx.Inputs[0].WitnessUtxo}}
			continue
		}
		f.txs[in.PreviousOutPoint] = sources[i-1].Tx
	}
	return execute(t, ptx, f, slot+1, arkade.WithIntentMessage(msg), arkade.WithExpiry(c.expiry.Unix()))
}

func execute(t *testing.T, ptx *psbt.Packet, f prevouts, vin int, opts ...arkade.ExecuteOption) error {
	t.Helper()
	emu, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	require.NoError(t, err)
	i := slices.IndexFunc(emu, func(e arkade.EmulatorEntry) bool { return int(e.Vin) == vin })
	require.GreaterOrEqual(t, i, 0, "no emulator entry for input %d", vin)
	s, err := arkade.ReadArkadeScript(ptx, testKey(t, 3), emu[i])
	require.NoError(t, err)
	return s.Execute(ptx.UnsignedTx, f, vin, opts...)
}

// shiftedExtension is tx's extension with emulator entries and asset inputs moved one input up.
func shiftedExtension(t *testing.T, tx *wire.MsgTx) *wire.TxOut {
	t.Helper()
	ext, err := extension.NewExtensionFromTx(tx)
	require.NoError(t, err)
	emu, err := arkade.FindEmulatorPacket(tx)
	require.NoError(t, err)
	for i := range emu {
		emu[i].Vin++
	}
	shifted, err := arkade.NewPacket(emu...)
	require.NoError(t, err)
	for k, p := range ext {
		switch p.Type() {
		case arkade.PacketType:
			ext[k] = shifted
		case asset.PacketType:
			assets := ext.GetAssetPacket()
			for g := range assets {
				for i := range assets[g].Inputs {
					assets[g].Inputs[i].Vin++
				}
			}
			ext[k] = assets
		}
	}
	out, err := ext.TxOut()
	require.NoError(t, err)
	return out
}

// moveAssets sends every asset output of tx to vout.
func moveAssets(t *testing.T, tx *wire.MsgTx, vout uint16) {
	t.Helper()
	ext, err := extension.NewExtensionFromTx(tx)
	require.NoError(t, err)
	k := slices.IndexFunc(ext, func(p extension.Packet) bool { return p.Type() == asset.PacketType })
	require.GreaterOrEqual(t, k, 0)
	assets := ext.GetAssetPacket()
	for g := range assets {
		for i := range assets[g].Outputs {
			assets[g].Outputs[i].Vout = vout
		}
	}
	ext[k] = assets
	out, err := ext.TxOut()
	require.NoError(t, err)
	i := slices.IndexFunc(tx.TxOut, func(o *wire.TxOut) bool { return extension.IsExtension(o.PkScript) })
	tx.TxOut[i] = out
}

// setPacket removes the packet when body is nil.
func setPacket(t *testing.T, tx *wire.MsgTx, typ uint8, body []byte) {
	t.Helper()
	ext, err := extension.NewExtensionFromTx(tx)
	require.NoError(t, err)
	k := slices.IndexFunc(ext, func(p extension.Packet) bool { return p.Type() == typ })
	require.GreaterOrEqual(t, k, 0)
	if body == nil {
		ext = slices.Delete(ext, k, k+1)
	} else {
		ext[k] = packets.Raw(typ, body)
	}
	out, err := ext.TxOut()
	require.NoError(t, err)
	i := slices.IndexFunc(tx.TxOut, func(o *wire.TxOut) bool { return extension.IsExtension(o.PkScript) })
	tx.TxOut[i] = out
}

// prevouts serves spent outputs and the transactions that created them, as the emulator's fetcher.
type prevouts struct {
	outs map[wire.OutPoint]*wire.TxOut
	txs  map[wire.OutPoint]*wire.MsgTx
}

func (p prevouts) FetchPrevOutput(op wire.OutPoint) *wire.TxOut { return p.outs[op] }

func (p prevouts) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx { return p.txs[op] }

func (p prevouts) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	if tx := p.txs[op]; tx != nil && int(op.Index) < len(tx.TxOut) {
		return tx.TxOut[op.Index].PkScript
	}
	return nil
}
