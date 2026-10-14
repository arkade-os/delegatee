package template

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
)

func TestTaptreeContract(t *testing.T) {
	a, b := closureLeaf(t, testKey(t, 2)), closureLeaf(t, testKey(t, 4), testKey(t, 5))
	leaves := []string{a, serverLeaf(t), b}

	inst, err := instantiateTree(t, leaves)
	require.NoError(t, err)
	require.Equal(t, leaves, inst.Tapscripts(0), "the tree's leaves, in its order")
	require.Equal(t, arkdScript(t, leaves), inst.PkScript(0), "the key arkd derives for the same tree")
	require.Equal(t, serverLeaf(t), hex.EncodeToString(spendProof(t, inst).Script))

	_, err = instantiateTree(t, []string{a, b})
	require.ErrorIs(t, err, ErrIneligible, "the declared leaf is not in the tree")
	_, err = instantiateTree(t, []string{a, serverLeaf(t), "51"})
	require.ErrorIs(t, err, ErrIneligible, "a leaf that is no closure: arkd would refuse the spend")
	_, err = instantiateRaw(t, []byte{0x01})
	require.ErrorIs(t, err, ErrIneligible, "a tree that does not decode")
	_, err = instantiateRaw(t, []byte{})
	require.ErrorIs(t, err, ErrIneligible, "an empty tree holds no leaf")

	dup, err := instantiateTree(t, []string{serverLeaf(t), serverLeaf(t)})
	require.NoError(t, err, "a duplicated leaf is still in the tree")
	spendProof(t, dup)

	big := []string{serverLeaf(t)}
	for i := 10; i < 22; i++ {
		big = append(big, closureLeaf(t, testKey(t, i), testKey(t, i+100)))
	}
	raw, err := txutils.TapTree(big).Encode()
	require.NoError(t, err)
	require.Greater(t, len(raw), 520)
	_, err = instantiateRaw(t, raw)
	require.NoError(t, err, "a tree is decoded, never pushed: the push cap does not apply")
}

func TestTaptreeParse(t *testing.T) {
	for name, edit := range map[string]func(m map[string]any){
		"not a placeholder": func(m map[string]any) { firstContract(m)["taptree"] = "tree" },
		"undeclared":        func(m map[string]any) { firstContract(m)["taptree"] = "<nope>" },
		"not bytes":         func(m map[string]any) { firstContract(m)["taptree"] = "<to>" },
	} {
		_, err := Parse(t.Context(), edited(t, []byte(treeDoc), edit), nil)
		require.ErrorIs(t, err, ErrInvalidTemplate, name)
	}
	onOutput := edited(t, []byte(treeDoc), func(m map[string]any) {
		m["outputs"].([]any)[0].(map[string]any)["locking"] = map[string]any{"contract": firstContract(m)}
	})
	_, err := Parse(t.Context(), onOutput, nil)
	require.ErrorIs(t, err, ErrInvalidTemplate)
	require.ErrorContains(t, err, "taptree")

	for name, edit := range map[string]func(m map[string]any){
		"in the locking": func(m map[string]any) { m["outputs"].([]any)[0].(map[string]any)["locking"] = "5120<to><tree>" },
		"in an argument": func(m map[string]any) {
			c := firstContract(m)
			c["definition"].(map[string]any)["constructorInputs"] = []any{map[string]any{"name": "blob", "type": "bytes"}}
			c["arguments"] = map[string]any{"blob": "<tree>"}
		},
		"in a ciphertext": func(m map[string]any) {
			m["secrets"] = map[string]any{"s": map[string]any{"type": "bytes32", "from": "coin", "ciphertext": "<tree>"}}
		},
	} {
		_, err := Parse(t.Context(), edited(t, []byte(treeDoc), edit), nil)
		require.ErrorIs(t, err, ErrInvalidTemplate, name)
		require.ErrorContains(t, err, "outside the taptree field", name)
	}
}

// treeDoc watches a coin whose tree is given whole and holds the leaf "<SERVER_KEY> OP_CHECKSIG".
const treeDoc = `{
  "format": "delegateed-template/v1",
  "type": "offchain",
  "variables": {"tree": "bytes", "to": "bytes32"},
  "inputs": [{
    "name": "coin",
    "contract": {
      "definition": {"contractName": "T", "constructorInputs": [], "structs": [], "functions": [
        {"name": "spend", "leaves": [{"name": "spend", "asm": ["<SERVER_KEY>", "OP_CHECKSIG"],
          "witness": [{"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true}]}]}
      ]},
      "arguments": {},
      "taptree": "<tree>"
    },
    "spend": {"function": "spend", "leaf": "spend"}
  }],
  "outputs": [{"name": "out", "index": 0, "value": {"from": "coin"}, "locking": "5120<to>"}]
}`

func closureLeaf(t *testing.T, keys ...*btcec.PublicKey) string {
	t.Helper()
	s, err := (&script.MultisigClosure{PubKeys: keys}).Script()
	require.NoError(t, err)
	return hex.EncodeToString(s)
}

func serverLeaf(t *testing.T) string {
	t.Helper()
	return closureLeaf(t, testKeys(t).Server)
}

func instantiateTree(t *testing.T, leaves []string) (*Instance, error) {
	t.Helper()
	raw, err := txutils.TapTree(leaves).Encode()
	require.NoError(t, err)
	return instantiateRaw(t, raw)
}

func instantiateRaw(t *testing.T, raw []byte) (*Instance, error) {
	t.Helper()
	return parseDoc(t, []byte(treeDoc)).Instantiate(t.Context(), Context{
		Keys:      testKeys(t),
		Variables: map[string][]byte{"tree": raw, "to": make([]byte, 32)},
	})
}

func arkdScript(t *testing.T, leaves []string) []byte {
	t.Helper()
	vs := &script.TapscriptsVtxoScript{}
	require.NoError(t, vs.Decode(leaves))
	key, _, err := vs.TapTree()
	require.NoError(t, err)
	s, err := script.P2TRScript(key)
	require.NoError(t, err)
	return s
}

// spendProof checks the spend leaf's control block opens the instance's key.
func spendProof(t *testing.T, inst *Instance) *psbt.TaprootTapLeafScript {
	t.Helper()
	proof := inst.contracts[0].proofs[[2]string{"spend", "spend"}]
	require.NotNil(t, proof)
	cb, err := txscript.ParseControlBlock(proof.ControlBlock)
	require.NoError(t, err)
	require.NoError(t, txscript.VerifyTaprootLeafCommitment(cb, inst.PkScript(0)[2:], proof.Script), "the control block opens the tree's key")
	return proof
}

func firstContract(m map[string]any) map[string]any {
	return m["inputs"].([]any)[0].(map[string]any)["contract"].(map[string]any)
}
