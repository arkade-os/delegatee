package template

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
)

func TestBuildMatchesArkLib(t *testing.T) {
	server, owner, emulator := testKey(t, 1), testKey(t, 2), testKey(t, 3)
	def := parseDef(t, `{"contractName":"DelegatedVtxo","constructorInputs":[{"name":"owner","type":"pubkey"}],"functions":[
	 {"name":"spend","leaves":[{"name":"spend","asm":["<SERVER_KEY>","OP_CHECKSIGVERIFY","<owner>","OP_CHECKSIG"],"witness":[]}]},
	 {"name":"delayed","leaves":[{"name":"delayed","asm":["4194306","OP_CHECKSEQUENCEVERIFY","OP_DROP","<SERVER_KEY>","OP_CHECKSIG"],"witness":[]}]},
	 {"name":"renew","arkade":{"inputs":[],"asm":["OP_1"]},"leaves":[{"name":"renew","asm":["<SERVER_KEY>","OP_CHECKSIGVERIFY","<EMULATOR_KEY:renew>","OP_CHECKSIG"],"witness":[]}]}]}`)
	c, err := build(def, map[string]value{"owner": {"pubkey", owner.SerializeCompressed()}}, Keys{Server: server, Emulator: emulator})
	require.NoError(t, err)

	tweaked := arkade.ComputeArkadeScriptPublicKey(emulator, arkade.ArkadeScriptHash([]byte{txscript.OP_1}))
	want := &script.TapscriptsVtxoScript{Closures: []script.Closure{
		&script.MultisigClosure{PubKeys: []*btcec.PublicKey{server, owner}},
		&script.CSVMultisigClosure{
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{server}},
			Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1024},
		},
		&script.MultisigClosure{PubKeys: []*btcec.PublicKey{server, tweaked}},
	}}
	tapscripts, err := want.Encode()
	require.NoError(t, err)
	require.Equal(t, tapscripts, c.tapscripts)
	key, _, err := want.TapTree()
	require.NoError(t, err)
	pk, err := script.P2TRScript(key)
	require.NoError(t, err)
	require.Equal(t, pk, c.pkScript)
	require.Equal(t, []byte{txscript.OP_1}, c.covenants["renew"])

	leaf := c.proofs[[2]string{"renew", "renew"}]
	require.NotNil(t, leaf)
	control, err := txscript.ParseControlBlock(leaf.ControlBlock)
	require.NoError(t, err)
	require.NoError(t, txscript.VerifyTaprootLeafCommitment(control, c.pkScript[2:], leaf.Script))
}

func TestBuildTreeShapes(t *testing.T) {
	// one to nine leaves give the root ark-lib gives
	for n := 1; n <= 9; n++ {
		def, closures := nLeaves(t, n)
		c, err := build(def, nil, Keys{Server: testKey(t, 1), Emulator: testKey(t, 3)})
		require.NoError(t, err)
		key, _, err := (&script.TapscriptsVtxoScript{Closures: closures}).TapTree()
		require.NoError(t, err)
		require.Equal(t, schnorr.SerializePubKey(key), c.pkScript[2:], "%d leaves", n)
	}
}

// A covenant compares a key against a taproot witness program, so it needs the
// x-only bytes a leaf gets; arkadec's own e2e binds pubkeys the same way.
func TestBuildCovenantPushesXOnlyPubkey(t *testing.T) {
	owner := testKey(t, 2)
	def := parseDef(t, `{"contractName":"C","constructorInputs":[{"name":"owner","type":"pubkey"}],"functions":[
	 {"name":"pay","arkade":{"inputs":[],"asm":["<owner>","OP_DROP","OP_1"]},"leaves":[{"name":"pay","asm":["<SERVER_KEY>","OP_CHECKSIGVERIFY","<EMULATOR_KEY:pay>","OP_CHECKSIG"],"witness":[]}]}]}`)
	c, err := build(def, map[string]value{"owner": {"pubkey", owner.SerializeCompressed()}}, Keys{Server: testKey(t, 1), Emulator: testKey(t, 3)})
	require.NoError(t, err)

	want, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(owner)).AddOp(txscript.OP_DROP).AddOp(txscript.OP_1).Script()
	require.NoError(t, err)
	require.Equal(t, want, c.covenants["pay"])
}

func TestBuildRejects(t *testing.T) {
	keys := Keys{Server: testKey(t, 1), Emulator: testKey(t, 3)}
	def := parseDef(t, `{"contractName":"C","constructorInputs":[],"functions":[
	 {"name":"a","leaves":[{"name":"a","asm":["OP_1"],"witness":[]}]},
	 {"name":"b","leaves":[{"name":"b","asm":["OP_1"],"witness":[]}]}]}`)
	_, err := build(def, nil, keys)
	require.ErrorIs(t, err, ErrInvalidTemplate, "duplicate leaves")

	def = parseDef(t, `{"contractName":"C","constructorInputs":[{"name":"n","type":"int"}],"functions":[
	 {"name":"a","leaves":[{"name":"a","asm":["<n>","OP_DROP","OP_1"],"witness":[]}]}]}`)
	_, err = build(def, nil, keys)
	require.ErrorIs(t, err, ErrInvalidTemplate, "missing constructor value")
}

func TestBuildProofPerLeaf(t *testing.T) {
	def := parseDef(t, `{"contractName":"C","constructorInputs":[],"functions":[
	 {"name":"a/b","leaves":[{"name":"c","asm":["OP_1"],"witness":[]}]},
	 {"name":"a","leaves":[{"name":"b/c","asm":["OP_2"],"witness":[]}]}]}`)
	c, err := build(def, nil, Keys{Server: testKey(t, 1), Emulator: testKey(t, 3)})
	require.NoError(t, err)
	require.Len(t, c.proofs, 2)
}

func testKey(t testing.TB, n int) *btcec.PublicKey {
	t.Helper()
	var b [32]byte
	b[31] = byte(n)
	_, pub := btcec.PrivKeyFromBytes(b[:])
	return pub
}

func parseDef(t *testing.T, doc string) *Definition {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal([]byte(doc), &v))
	def, err := parseDefinition(v)
	require.NoError(t, err)
	return def
}

func nLeaves(t *testing.T, n int) (*Definition, []script.Closure) {
	t.Helper()
	server := testKey(t, 1)
	var fns []string
	var closures []script.Closure
	for i := range n {
		k := testKey(t, 10+i)
		name := fmt.Sprintf("f%d", i)
		fns = append(fns, fmt.Sprintf(
			`{"name":%q,"leaves":[{"name":%q,"asm":["<SERVER_KEY>","OP_CHECKSIGVERIFY","0x%s","OP_CHECKSIG"],"witness":[]}]}`,
			name, name, hex.EncodeToString(schnorr.SerializePubKey(k))))
		closures = append(closures, &script.MultisigClosure{PubKeys: []*btcec.PublicKey{server, k}})
	}
	def := parseDef(t, `{"contractName":"C","constructorInputs":[],"functions":[`+strings.Join(fns, ",")+`]}`)
	return def, closures
}
