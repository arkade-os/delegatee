package template

import (
	"bytes"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestInstantiateWatch(t *testing.T) {
	tmpl := parseFixture(t, "minimal.json")
	require.True(t, tmpl.ContextFree())
	inst, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t)})
	require.NoError(t, err)
	require.Len(t, inst.Tapscripts(0), 1)
	require.Len(t, inst.PkScript(0), 34)
}

func TestInstantiateDelegateKey(t *testing.T) {
	keys := testKeys(t)
	inst, err := parseFixture(t, "minimal.json").Instantiate(t.Context(), Context{Keys: keys})
	require.NoError(t, err)
	want, err := build(parseDef(t, `{"contractName":"R","constructorInputs":[],"functions":[
	 {"name":"release","leaves":[{"name":"release","asm":["<SERVER_KEY>","OP_CHECKSIG"],"witness":[]}]}]}`), nil, keys)
	require.NoError(t, err)
	require.Equal(t, want.tapscripts, inst.Tapscripts(0), "x-only in a leaf, like the server key it equals here")

	keys.Delegate = nil
	_, err = parseFixture(t, "minimal.json").Instantiate(t.Context(), Context{Keys: keys})
	require.Error(t, err)
}

func TestInstantiateVariables(t *testing.T) {
	tmpl := parseDoc(t, edited(t, delegateArgument(t), func(m map[string]any) {
		m["variables"] = map[string]any{"delegate": "pubkey"}
		m["inputs"].([]any)[0].(map[string]any)["contract"].(map[string]any)["arguments"] = map[string]any{"delegate": "<delegate>"}
	}))
	key := testKey(t, 2).SerializeCompressed()
	a, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t), Variables: map[string][]byte{"delegate": key}})
	require.NoError(t, err)
	b, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t), Variables: map[string][]byte{"delegate": testKey(t, 4).SerializeCompressed()}})
	require.NoError(t, err)
	require.NotEqual(t, a.PkScript(0), b.PkScript(0))

	for name, vars := range map[string]map[string][]byte{
		"missing": {}, "extra": {"delegate": key, "x": {1}}, "x-only": {"delegate": key[1:]},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t), Variables: vars})
			require.ErrorIs(t, err, ErrInvalidVariables)
		})
	}
}

func TestInstantiateFromSource(t *testing.T) {
	// the owner comes from packet 2 of the source: not watchable, and the script follows the packet
	tmpl := parseDoc(t, ownerFromPacket(t))
	require.False(t, tmpl.ContextFree())
	_, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t)})
	require.ErrorIs(t, err, ErrUnsupported, "a watch needs context-free bindings")

	alice := ownedSource(t, tmpl, testKey(t, 2), testKey(t, 2))
	bob := ownedSource(t, tmpl, testKey(t, 4), testKey(t, 4))
	a, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t), Sources: []*Source{alice}})
	require.NoError(t, err)
	b, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t), Sources: []*Source{bob}})
	require.NoError(t, err)
	require.NotEqual(t, a.PkScript(0), b.PkScript(0))
	require.Equal(t, pkScript(alice), a.PkScript(0))

	_, err = tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t), Sources: []*Source{sourceWith(t, 100_000)}})
	require.ErrorIs(t, err, ErrIneligible, "no packet 2")
	_, err = parseFixture(t, "minimal.json").Instantiate(t.Context(), Context{Keys: testKeys(t), Sources: []*Source{{Outpoint: wire.OutPoint{Index: 7}, Amount: 5}}})
	require.ErrorIs(t, err, ErrIneligible, "a source without its transaction")

	for name, sources := range map[string][]*Source{
		"script of another owner": {ownedSource(t, tmpl, testKey(t, 2), testKey(t, 4))},
		"missing source":          {nil},
		"too many sources":        {alice, bob},
		"none":                    {},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t), Sources: sources})
			require.ErrorIs(t, err, ErrIneligible)
		})
	}
}

func TestSecrets(t *testing.T) {
	tmpl := parseDoc(t, hashLock(t)) // variable ciphertext, secret preimage, argument $(<preimage> OP_HASH160)
	require.True(t, tmpl.Secrets())
	require.True(t, tmpl.ContextFree())
	preimage := bytes.Repeat([]byte{7}, 32)
	opened := 0
	c := Context{Keys: testKeys(t), Variables: map[string][]byte{"ciphertext": []byte("sealed")},
		Decrypt: func(ct []byte) ([]byte, error) {
			require.Equal(t, []byte("sealed"), ct)
			opened++
			return preimage, nil
		}}
	inst, err := tmpl.Instantiate(t.Context(), c)
	require.NoError(t, err)
	require.Equal(t, 1, opened)
	_, kept := reflect.TypeFor[Instance]().FieldByName("secrets")
	require.False(t, kept, "an instance holds no plaintext")

	d := newDraft(Offchain, []*Source{{}})
	twice := byteTemplate{{name: "preimage"}, {expr: []string{"<preimage>", "OP_SIZE", "OP_NIP"}}}
	got, err := inst.resolve(twice, d, 0)
	require.NoError(t, err)
	require.Equal(t, append(bytes.Clone(preimage), 32), got)
	_, err = inst.resolve(twice, d, 0)
	require.NoError(t, err)
	require.Equal(t, 2, opened, "a secret opens once per draft")

	_, err = inst.resolve(twice, newDraft(Offchain, []*Source{{}}), 0)
	require.NoError(t, err)
	require.Equal(t, 3, opened, "a fresh draft decrypts again")

	c.Decrypt = func([]byte) ([]byte, error) { return preimage[:31], nil }
	_, err = tmpl.Instantiate(t.Context(), c)
	require.ErrorIs(t, err, ErrIneligible, "the plaintext is not a bytes32")
	c.Decrypt = nil
	_, err = tmpl.Instantiate(t.Context(), c)
	require.ErrorIs(t, err, ErrUnsupported)
}

func TestResolveConcurrent(t *testing.T) {
	preimage := bytes.Repeat([]byte{7}, 32)
	var opened atomic.Int64
	inst, err := parseDoc(t, hashLock(t)).Instantiate(t.Context(), Context{Keys: testKeys(t),
		Variables: map[string][]byte{"ciphertext": []byte("sealed")},
		Decrypt: func([]byte) ([]byte, error) {
			opened.Add(1)
			return bytes.Clone(preimage), nil
		}})
	require.NoError(t, err)
	witness := inst.tmpl.inputs[0].witness["preimage"]
	var wg sync.WaitGroup
	results := make([][][]byte, 8)
	for g := range results {
		wg.Go(func() {
			for range 50 {
				d := newDraft(Offchain, []*Source{{}})
				got, err := inst.resolve(witness, d, 0)
				if err != nil {
					got = []byte(err.Error())
				}
				results[g] = append(results[g], got)
			}
		})
	}
	wg.Wait()
	for _, rs := range results {
		require.Len(t, rs, 50)
		for _, got := range rs {
			require.Equal(t, preimage, got)
		}
	}
	require.EqualValues(t, 1+8*50, opened.Load())
}

func TestDueAt(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	offchain := parseDoc(t, ownerFromPacket(t)) // schedule before_expiry_seconds 1024
	src := ownedSource(t, offchain, testKey(t, 2), testKey(t, 2))
	src.Expiry = now.Add(2 * time.Hour)
	inst, err := offchain.Instantiate(t.Context(), Context{Keys: testKeys(t), Sources: []*Source{src}})
	require.NoError(t, err)
	require.Equal(t, src.Expiry.Add(-1024*time.Second), inst.DueAt(0, src, now))
	src.CreatedAt = now.Add(-time.Minute)
	require.Equal(t, src.Expiry.Add(-1024*time.Second), inst.DueAt(0, src, now), "the lead, whatever the creation")
	src.Expiry = time.Time{}
	require.Equal(t, now.Add(time.Hour), inst.DueAt(0, src, now), "no expiry is not due")

	onchain := parseDoc(t, edited(t, fixture(t, "minimal.json"), func(m map[string]any) {
		m["inputs"].([]any)[0].(map[string]any)["schedule"] = map[string]any{"min_confirmations": 2}
	}))
	inst, err = onchain.Instantiate(t.Context(), Context{Keys: testKeys(t)})
	require.NoError(t, err)
	coin := sourceWith(t, 100_000)
	coin.Confirms = 1
	require.True(t, inst.DueAt(0, coin, now).After(now))
	coin.CreatedAt = now.Add(-time.Minute)
	require.True(t, inst.DueAt(0, coin, now).After(now), "created is not confirmed enough")
	coin.Confirms = 2
	require.Equal(t, coin.CreatedAt, inst.DueAt(0, coin, now), "due since its block")
	coin.CreatedAt = time.Time{}
	require.Equal(t, now, inst.DueAt(0, coin, now))

	inst, err = parseFixture(t, "minimal.json").Instantiate(t.Context(), Context{Keys: testKeys(t)})
	require.NoError(t, err)
	require.Equal(t, now, inst.DueAt(0, coin, now), "immediate")
	coin.CreatedAt = now.Add(-time.Minute)
	require.Equal(t, coin.CreatedAt, inst.DueAt(0, coin, now), "immediate, due since created")
}

func TestInstantiateRefusesNonClosureEmulatorLeaf(t *testing.T) {
	doc := edited(t, mixedPaymentDoc(t, false), func(m map[string]any) {
		def := m["inputs"].([]any)[0].(map[string]any)["contract"].(map[string]any)["definition"].(map[string]any)
		leafOf(def, 1)["asm"] = []any{"<EMULATOR_KEY:pay>", "OP_CHECKSIGVERIFY", "<SERVER_KEY>", "OP_CHECKSIGVERIFY", "OP_1"}
	})
	tmpl := parseDoc(t, doc)
	_, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t)})
	require.ErrorIs(t, err, ErrUnsupported)
}

func testKeys(t testing.TB) Keys {
	t.Helper()
	return Keys{Server: testKey(t, 1), Emulator: testKey(t, 3), Delegate: testKey(t, 1)}
}

func parseDoc(t *testing.T, doc []byte) *Template {
	t.Helper()
	tmpl, err := Parse(t.Context(), doc, nil)
	require.NoError(t, err)
	return tmpl
}

func parseFixture(t *testing.T, name string) *Template {
	t.Helper()
	tmpl, err := Parse(t.Context(), fixture(t, name), artifacts(t))
	require.NoError(t, err)
	return tmpl
}

// ownedSource's packet 2 holds packet and its script is tmpl's contract for owner.
func ownedSource(t *testing.T, tmpl *Template, packet, owner *btcec.PublicKey) *Source {
	t.Helper()
	src := sourceWith(t, 100_000, packets.Raw(packets.TypeState, packet.SerializeCompressed()))
	c, err := build(tmpl.inputs[0].contract.def, map[string]value{"owner": {"pubkey", owner.SerializeCompressed()}}, testKeys(t))
	require.NoError(t, err)
	lockTo(src, c.pkScript)
	return src
}

// ownerFromPacket is a renewal intent whose owner key is packet 2 of the source.
func ownerFromPacket(t *testing.T) []byte {
	t.Helper()
	return []byte(`{
  "format": "delegateed-template/v1",
  "type": "intent",
  "inputs": [{
    "name": "funds",
    "schedule": {"before_expiry_seconds": 1024},
    "contract": {
      "definition": {
        "contractName": "DelegatedVtxo",
        "constructorInputs": [{"name": "owner", "type": "pubkey"}],
        "structs": [],
        "functions": [
          {"name": "spend", "leaves": [{"name": "spend", "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<owner>", "OP_CHECKSIG"],
            "witness": [{"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true},
                        {"name": "ownerSig", "type": "signature", "encoding": "schnorr-64"}]}]},
          {"name": "delayed_server_spend", "leaves": [{"name": "delayed_server_spend",
            "asm": ["4194306", "OP_CHECKSEQUENCEVERIFY", "OP_DROP", "<SERVER_KEY>", "OP_CHECKSIG"],
            "witness": [{"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true}]}]},
          {"name": "renew", "arkade": {"inputs": [], "asm": ["OP_1"]},
            "leaves": [{"name": "renew", "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:renew>", "OP_CHECKSIG"],
            "witness": [{"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true},
                        {"name": "emulatorSig", "type": "signature", "encoding": "schnorr-64", "injected": true}]}]}
        ]
      },
      "arguments": {"owner": "$(2 OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTPACKET OP_VERIFY)"}
    },
    "spend": {"function": "renew", "leaf": "renew"}
  }],
  "outputs": [{"name": "renewed", "index": 0, "value": {"from": "funds"}, "locking": {"from": "funds"}, "assets": [{"from": "funds"}]}],
  "packets": {
    "output_index": 1,
    "rules": [{"type": 2, "action": "copy", "from": "funds"}],
    "advertise": [{"template": "self", "outputs": ["renewed"]}]
  }
}`)
}

// hashLock is an offchain claim of a hash lock whose preimage is a sealed secret.
func hashLock(t *testing.T) []byte {
	t.Helper()
	return []byte(`{
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
        "functions": [{"name": "claim", "leaves": [{"name": "claim",
          "asm": ["OP_HASH160", "<h>", "OP_EQUALVERIFY", "<SERVER_KEY>", "OP_CHECKSIG"],
          "witness": [{"name": "preimage", "type": "bytes32", "encoding": "raw"},
                      {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true}]}]}]
      },
      "arguments": {"h": "$(<preimage> OP_HASH160)"}
    },
    "spend": {"function": "claim", "leaf": "claim", "witness": {"preimage": "<preimage>"}}
  }],
  "outputs": [{"name": "payout", "index": 0, "value": {"from": "htlc"},
    "locking": "5120f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"}]
}`)
}
