package template

import (
	"maps"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestLocktimeOnlyOffchain(t *testing.T) {
	parseDoc(t, []byte(releaseDoc))
	_, err := Parse(t.Context(), edited(t, []byte(releaseDoc), func(m map[string]any) { m["type"] = "intent" }), nil)
	require.ErrorIs(t, err, ErrUnsupported)
	require.ErrorContains(t, err, "absolute locktime")
}

func TestLocktimeFromLeaf(t *testing.T) {
	tmpl := parseDoc(t, []byte(releaseDoc))
	inst := releaseWatch(t, tmpl, 200)
	lt, ok := inst.Locktime(0)
	require.True(t, ok)
	require.Equal(t, arklib.AbsoluteLocktime(200), lt)
	require.False(t, lt.IsSeconds())

	lt, ok = releaseWatch(t, tmpl, 1_800_000_000).Locktime(0)
	require.True(t, ok)
	require.True(t, lt.IsSeconds())

	minimal, err := parseFixture(t, "minimal.json").Instantiate(t.Context(), Context{Keys: testKeys(t)})
	require.NoError(t, err)
	_, ok = minimal.Locktime(0)
	require.False(t, ok, "no CLTV leaf, no locktime")
}

func TestLocktimeNeedsCLTVClosure(t *testing.T) {
	doc := edited(t, []byte(releaseDoc), func(m map[string]any) {
		releaseLeaf(m)["asm"] = []any{"<lock>", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP", "<SERVER_KEY>", "OP_CHECKSIGVERIFY", "1"}
	})
	_, err := parseDoc(t, doc).Instantiate(t.Context(), releaseContext(t, 200))
	require.ErrorIs(t, err, ErrUnsupported)
	require.ErrorContains(t, err, "CLTV multisig closure")
}

func TestInstantiateRefusesMixedLocktimes(t *testing.T) {
	doc := edited(t, []byte(releaseDoc), func(m map[string]any) {
		in := m["inputs"].([]any)[0].(map[string]any)
		second := maps.Clone(in)
		second["name"] = "coin2"
		second["contract"] = map[string]any{
			"definition": in["contract"].(map[string]any)["definition"],
			"arguments":  map[string]any{"owner": "<owner>", "lock": "<lock2>"},
		}
		m["inputs"] = append(m["inputs"].([]any), second)
		m["variables"].(map[string]any)["lock2"] = "int"
		m["outputs"] = append(m["outputs"].([]any), map[string]any{
			"name": "paid2", "index": 1, "value": map[string]any{"from": "coin2"}, "locking": "5120<dest>",
		})
		m["packets"] = map[string]any{"output_index": 2}
	})
	tmpl := parseDoc(t, doc)
	sources := func(lock, lock2 int64) []*Source {
		a, b := sourceWith(t, 100_000), sourceWith(t, 100_000)
		lockTo(a, releaseWatch(t, parseDoc(t, []byte(releaseDoc)), lock).PkScript(0))
		lockTo(b, releaseWatch(t, parseDoc(t, []byte(releaseDoc)), lock2).PkScript(0))
		return []*Source{a, b}
	}
	c := releaseContext(t, 200)
	c.Variables["lock2"], c.Sources = scriptNum(300), sources(200, 300)
	_, err := tmpl.Instantiate(t.Context(), c)
	require.NoError(t, err, "two heights")

	c.Variables["lock2"], c.Sources = scriptNum(1_800_000_000), sources(200, 1_800_000_000)
	_, err = tmpl.Instantiate(t.Context(), c)
	require.ErrorIs(t, err, ErrUnsupported)
	require.ErrorContains(t, err, "mix block heights and timestamps")
}

func TestDueAtWaitsForTimestampLocktime(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	tmpl := parseDoc(t, []byte(releaseDoc))
	coin := sourceWith(t, 100_000)

	require.Equal(t, time.Unix(1_800_000_000, 0), releaseWatch(t, tmpl, 1_800_000_000).DueAt(0, coin, now))
	require.Equal(t, now, releaseWatch(t, tmpl, 1_700_000_000).DueAt(0, coin, now), "a past locktime changes nothing")
	require.Equal(t, now, releaseWatch(t, tmpl, 200).DueAt(0, coin, now), "a height is the caller's to check")
}

func TestBuildSetsLocktime(t *testing.T) {
	tmpl := parseDoc(t, []byte(releaseDoc))
	src := sourceWith(t, 100_000)
	lockTo(src, releaseWatch(t, tmpl, 200).PkScript(0))
	c := releaseContext(t, 200)
	c.Sources = []*Source{src}
	inst, err := tmpl.Instantiate(t.Context(), c)
	require.NoError(t, err)

	act, err := inst.Build(t.Context(), []*Source{src}, Fee{Dust: 330})
	require.NoError(t, err)
	require.EqualValues(t, 200, act.Tx.UnsignedTx.LockTime)
	require.Equal(t, uint32(wire.MaxTxInSequenceNum-1), act.Tx.UnsignedTx.TxIn[0].Sequence)
}

// releaseDoc pays its coin to dest once lock is reached, without any owner signature.
const releaseDoc = `{
  "format": "delegateed-template/v1",
  "type": "offchain",
  "variables": {"owner": "pubkey", "lock": "int", "dest": "bytes32"},
  "inputs": [{
    "name": "coin",
    "contract": {
      "definition": {
        "contractName": "Release",
        "constructorInputs": [{"name": "owner", "type": "pubkey"}, {"name": "lock", "type": "int"}],
        "structs": [],
        "functions": [
          {"name": "exit", "leaves": [{"name": "exit",
            "asm": ["4194306", "OP_CHECKSEQUENCEVERIFY", "OP_DROP", "<owner>", "OP_CHECKSIG"],
            "witness": [{"name": "ownerSig", "type": "signature", "encoding": "schnorr-64"}]}]},
          {"name": "release", "arkade": {"inputs": [], "asm": ["1"]}, "leaves": [{"name": "release",
            "asm": ["<lock>", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP", "<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:release>", "OP_CHECKSIG"],
            "witness": [
              {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true},
              {"name": "emulatorSig", "type": "signature", "encoding": "schnorr-64", "injected": true}]}]}
        ]
      },
      "arguments": {"owner": "<owner>", "lock": "<lock>"}
    },
    "spend": {"function": "release", "leaf": "release"}
  }],
  "outputs": [{"name": "paid", "index": 0, "value": {"from": "coin"}, "locking": "5120<dest>"}],
  "packets": {"output_index": 1}
}`

func releaseContext(t *testing.T, lock int64) Context {
	t.Helper()
	return Context{Keys: testKeys(t), Variables: map[string][]byte{
		"owner": testKey(t, 2).SerializeCompressed(), "lock": scriptNum(lock), "dest": schnorr.SerializePubKey(testKey(t, 4)),
	}}
}

func releaseWatch(t *testing.T, tmpl *Template, lock int64) *Instance {
	t.Helper()
	inst, err := tmpl.Instantiate(t.Context(), releaseContext(t, lock))
	require.NoError(t, err)
	return inst
}

func releaseLeaf(m map[string]any) map[string]any {
	def := m["inputs"].([]any)[0].(map[string]any)["contract"].(map[string]any)["definition"].(map[string]any)
	return def["functions"].([]any)[1].(map[string]any)["leaves"].([]any)[0].(map[string]any)
}
