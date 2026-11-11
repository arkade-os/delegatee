package template

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/executor/pkg/template/ecies"
	"github.com/arkade-os/executor/pkg/template/internal/asm"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
)

func predicateBuild(t *testing.T, typ string, programs ...string) (*Instance, []*Source) {
	t.Helper()
	base := parseFixture(t, "minimal.json")
	seed, err := base.Instantiate(Context{Keys: testKeys(t)})
	require.NoError(t, err)
	doc := edited(t, fixture(t, "minimal.json"), func(m map[string]any) {
		m["type"] = typ
		delete(m, "fees")
		in := m["inputs"].([]any)[0].(map[string]any)
		out := m["outputs"].([]any)[0].(map[string]any)
		inputs, outputs := []any{}, []any{}
		for slot, program := range programs {
			name := fmt.Sprintf("funds%d", slot)
			inputs = append(inputs, map[string]any{"name": name, "contract": in["contract"], "spend": in["spend"], "predicate": program})
			outputs = append(outputs, map[string]any{"name": fmt.Sprintf("payment%d", slot), "index": slot, "value": map[string]any{"from": name}, "locking": out["locking"]})
		}
		m["inputs"], m["outputs"] = inputs, outputs
	})
	tmpl, err := Parse(doc, nil)
	require.NoError(t, err)
	require.True(t, tmpl.ContextFree())
	sources := make([]*Source, len(programs))
	for slot := range sources {
		sources[slot] = sourceWith(t, int64(10000+slot))
		lockTo(sources[slot], seed.PkScript(0))
	}
	inst, err := tmpl.Instantiate(Context{Keys: testKeys(t), Sources: sources})
	require.NoError(t, err)
	return inst, sources
}

func TestOfflineReceivePredicateSDKVectors(t *testing.T) {
	v := vhtlcVector(t)
	tree, err := txutils.TapTree(v.Tapscripts).Encode()
	require.NoError(t, err)
	unhex := func(s string) []byte { b, err := hex.DecodeString(s); require.NoError(t, err); return b }
	cov, err := asm.Assemble(nonInteractiveClaimCovenant, func(string) (asm.Value, error) { return asm.Value{Type: "bytes32", Raw: unhex(v.ReceiverProgram)}, nil })
	require.NoError(t, err)
	tmpl := parseFixture(t, "offline_receive_predicate.json")
	for _, name := range []string{"offline_receive_predicate_vector.json", "offline_receive_amount_predicate_vector.json"} {
		t.Run(name, func(t *testing.T) {
			var vector struct{ TemplateID, Packet, Predicate, RecipientSecretKey string }
			require.NoError(t, json.Unmarshal(fixture(t, name), &vector))
			require.Equal(t, tmpl.ID(), vector.TemplateID)
			key, _ := btcec.PrivKeyFromBytes(unhex(vector.RecipientSecretKey))
			body, err := base64.StdEncoding.DecodeString(vector.Packet)
			require.NoError(t, err)
			for _, amount := range []int64{9999, 10000, 12000} {
				ptx, _ := streamed(t, append(bytes.Clone(body), tlv(2, cov)...))
				ptx.UnsignedTx.TxOut[0].PkScript = unhex(v.PkScript)
				ptx.UnsignedTx.TxOut[0].Value = amount
				ptx.Outputs[0].TaprootTapTree = tree
				got, err := tmpl.Trigger().Match(ptx, TriggerKeys{Encryption: key.PubKey()})
				require.NoError(t, err)
				vars := map[string][]byte{}
				for n, value := range got[0].Variables {
					vars[n] = unhex(value)
				}
				inst, err := tmpl.Instantiate(Context{Keys: testKeys(t), Variables: vars, Decrypt: func(ct []byte) ([]byte, error) { return ecies.Decrypt(key, ct, tmpl.ID()) }})
				require.NoError(t, err)
				src := &Source{Tx: ptx.UnsignedTx, Amount: uint64(amount)}
				src.Outpoint.Hash = src.Tx.TxHash()
				act, err := inst.Build([]*Source{src}, Fee{Dust: 330})
				if amount >= 12000 || amount == 10000 && vector.Predicate == "51" {
					require.NoError(t, err)
					require.EqualValues(t, amount, act.Tx.UnsignedTx.TxOut[0].Value)
					require.Equal(t, "5120"+v.ReceiverProgram, hex.EncodeToString(act.Tx.UnsignedTx.TxOut[0].PkScript))
				} else {
					require.ErrorIs(t, err, ErrIneligible)
					require.Nil(t, act)
				}
			}
		})
	}
}

func TestInputPredicate(t *testing.T) {
	for _, tc := range []struct {
		name, program string
		accepted      bool
	}{
		{"true", "51", true},
		{"empty initial stack", "740087", true},
		{"resolved expression", "$(0x51)", true},
		{"false", "00", false},
		{"noncanonical true", "52", false},
		{"nonminimal numeric true", "020100", false},
		{"extra stack", "5151", false},
		{"empty", "", false},
		{"malformed", "4c02ff", false},
		{"unbalanced branch", "006351", false},
		{"forbidden inactive", "0063cf6851", false},
		{"nonminimal inactive", "00634c01116851", false},
		{"reserved inactive", "0063506851", false},
		{"unknown inactive", "0063ff6851", false},
		{"201 nonpush", strings.Repeat("61", 201) + "51", true},
		{"202 nonpush", strings.Repeat("61", 202) + "51", false},
		{"520 bytes", "4d0002" + strings.Repeat("11", 512) + "7561616151", true},
		{"521 resolved bytes", strings.Repeat("00", 520) + "$(0x11)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst, sources := predicateBuild(t, "onchain", tc.program)
			act, err := inst.Build(sources, Fee{Dust: 330, Onchain: func(int) uint64 { return 0 }})
			if tc.accepted {
				require.NoError(t, err)
				require.NotNil(t, act)
			} else {
				require.ErrorIs(t, err, ErrIneligible)
				require.Nil(t, act)
			}
		})
	}
}

func TestInputPredicateSecretBinding(t *testing.T) {
	doc := edited(t, fixture(t, "minimal.json"), func(m map[string]any) {
		m["variables"] = map[string]any{"ciphertext": "bytes"}
		m["secrets"] = map[string]any{"program": map[string]any{"type": "bytes", "from": "funds", "ciphertext": "<ciphertext>"}}
		m["inputs"].([]any)[0].(map[string]any)["predicate"] = "<program>"
	})
	tmpl := parseDoc(t, doc)
	opened := 0
	inst, err := tmpl.Instantiate(Context{Keys: testKeys(t), Variables: map[string][]byte{"ciphertext": {1}}, Decrypt: func([]byte) ([]byte, error) {
		opened++
		return []byte{0x51}, nil
	}})
	require.NoError(t, err)
	require.Zero(t, opened)
	src := sourceWith(t, 10000)
	lockTo(src, inst.PkScript(0))
	_, err = inst.Build([]*Source{src}, Fee{Dust: 330, Onchain: func(int) uint64 { return 0 }})
	require.NoError(t, err)
	require.Equal(t, 1, opened)
}

func TestInputPredicateBindingValidation(t *testing.T) {
	for name, binding := range map[string]any{
		"null": nil, "boolean": true, "number": 1, "output program": map[string]any{"program": "payment"},
		"unknown name": "<unknown>", "literal oversize": strings.Repeat("00", 521),
	} {
		t.Run(name, func(t *testing.T) {
			doc := edited(t, fixture(t, "minimal.json"), func(m map[string]any) {
				m["inputs"].([]any)[0].(map[string]any)["predicate"] = binding
			})
			_, err := Parse(doc, nil)
			require.ErrorIs(t, err, ErrInvalidTemplate)
		})
	}
}

func TestOfflineReceivePredicate(t *testing.T) {
	v := vhtlcVector(t)
	unhex := func(s string) []byte { b, err := hex.DecodeString(s); require.NoError(t, err); return b }
	tmpl := parseFixture(t, "offline_receive_predicate.json")
	require.Equal(t, "9175f4917d1c2e90c4a70d8036e49679a94cef048860ea2f4f337c12ab68609a", tmpl.ID())
	key, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))
	tree, err := txutils.TapTree(v.Tapscripts).Encode()
	require.NoError(t, err)
	for _, tc := range []struct {
		name, sealed, supplied string
		amount                 int64
		minimum                []byte
		receiver               bool
		ok                     bool
	}{
		{"explicit true", "51", "51", 10000, asm.ScriptNum(10000), true, true},
		{"condition met", "cdc902e02ea2", "cdc902e02ea2", 12000, asm.ScriptNum(10000), true, true},
		{"condition unmet", "cdc902e02ea2", "cdc902e02ea2", 10000, asm.ScriptNum(10000), true, false},
		{"substituted program", "cdc902e02ea2", "51", 12000, asm.ScriptNum(10000), true, false},
		{"stripped program", "51", "", 12000, asm.ScriptNum(10000), true, false},
		{"false sealed", "00", "00", 12000, asm.ScriptNum(10000), true, false},
		{"wrong receiver", "51", "51", 12000, asm.ScriptNum(10000), false, false},
		{"underfunded", "51", "51", 9999, asm.ScriptNum(10000), true, false},
		{"missing minimum", "51", "51", 12000, nil, true, false},
		{"nonminimal minimum", "51", "51", 12000, []byte{1, 0}, true, false},
		{"zero minimum", "51", "51", 12000, []byte{}, true, false},
		{"negative minimum", "51", "51", 12000, asm.ScriptNum(-1), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receiver := unhex(v.ReceiverProgram)
			if !tc.receiver {
				receiver = bytes.Repeat([]byte{2}, 32)
			}
			hash := sha256.Sum256(unhex(tc.sealed))
			terms := append(append(append(unhex(v.Preimage), receiver...), hash[:]...), tc.minimum...)
			ciphertext, err := ecies.Encrypt(key.PubKey(), terms, tmpl.ID())
			require.NoError(t, err)
			vars := map[string][]byte{"taptree": tree, "receiver_program": unhex(v.ReceiverProgram), "ciphertext": ciphertext, "predicate": unhex(tc.supplied)}
			inst, err := tmpl.Instantiate(Context{Keys: testKeys(t), Variables: vars, Decrypt: func(ct []byte) ([]byte, error) { return ecies.Decrypt(key, ct, tmpl.ID()) }})
			require.NoError(t, err)
			src := sourceWith(t, tc.amount)
			lockTo(src, inst.PkScript(0))
			act, err := inst.Build([]*Source{src}, Fee{Dust: 330})
			if tc.ok {
				require.NoError(t, err)
				require.EqualValues(t, tc.amount, act.Tx.UnsignedTx.TxOut[0].Value)
				require.Equal(t, "5120"+v.ReceiverProgram, hex.EncodeToString(act.Tx.UnsignedTx.TxOut[0].PkScript))
				w, err := txutils.GetArkPsbtFields(act.Tx, 0, txutils.ConditionWitnessField)
				require.NoError(t, err)
				require.Equal(t, unhex(v.Preimage), w[0][0])
			} else {
				require.ErrorIs(t, err, ErrIneligible)
				require.Nil(t, act)
				require.NotContains(t, err.Error(), hex.EncodeToString(terms))
			}
		})
	}
	program := unhex(v.ReceiverProgram)
	cov, err := asm.Assemble(nonInteractiveClaimCovenant, func(string) (asm.Value, error) { return asm.Value{Type: "bytes32", Raw: program}, nil })
	require.NoError(t, err)
	for _, present := range []bool{true, false} {
		body := tlv(1, []byte{1}, 2, cov, 3, key.PubKey().SerializeCompressed())
		if present {
			body = append(body, tlv(4, []byte{0x51})...)
		}
		ptx, _ := streamed(t, body)
		ptx.UnsignedTx.TxOut[0].PkScript = unhex(v.PkScript)
		ptx.Outputs[0].TaprootTapTree = tree
		got, err := tmpl.Trigger().Match(ptx, TriggerKeys{Encryption: key.PubKey()})
		if present {
			require.NoError(t, err)
			require.Equal(t, "51", got[0].Variables["predicate"])
		} else {
			require.ErrorIs(t, err, ErrNoMatch)
		}
	}
}

func TestInputPredicateFrozenPolicy(t *testing.T) {
	for op, cap := range arkade.DefaultComputeLimits() {
		if predicateOpcode(op) {
			require.Equal(t, cap, predicateComputeLimit(op))
			require.Equal(t, arkade.DefaultAggregateComputeLimits()[op], 4*predicateComputeLimit(op))
		}
	}
	for _, op := range []byte{arkade.OP_CHECKSIG, arkade.OP_CHECKSIGVERIFY, arkade.OP_CHECKSIGADD,
		arkade.OP_SIGHASH, arkade.OP_TXID, arkade.OP_TXWEIGHT, arkade.OP_TUNNEL, arkade.OP_INSPECTPACKET,
		arkade.OP_INSPECTOUTPUTVALUE, arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY, arkade.OP_INSPECTNUMOUTPUTS,
		arkade.OP_INSPECTINPUTARKADESCRIPTHASH, arkade.OP_INSPECTINPUTARKADEWITNESSHASH, arkade.OP_INSPECTINTENTMESSAGE,
		arkade.OP_CHECKMULTISIG, arkade.OP_CHECKMULTISIGVERIFY, arkade.OP_CODESEPARATOR} {
		require.Error(t, checkPredicate([]byte{0, arkade.OP_IF, op, arkade.OP_ENDIF, arkade.OP_1}, &predicateBudget{}))
	}
	for op := byte(arkade.OP_INSPECTNUMASSETGROUPS); op <= arkade.OP_INSPECTINASSETLOOKUP; op++ {
		require.False(t, predicateOpcode(op))
	}
	for _, badPush := range [][]byte{{0x4c, 0}, {1, 1}, {1, 0x81}, {0x4d, 1, 0, 0x11}, {0x4e, 1, 0, 0, 0, 0x11}} {
		program := append(append([]byte{0, arkade.OP_IF}, badPush...), arkade.OP_ENDIF, arkade.OP_1)
		require.Error(t, checkPredicate(program, &predicateBudget{}))
	}
	for _, op := range []byte{arkade.OP_CHECKSIGFROMSTACK, arkade.OP_ECMUL, arkade.OP_ECMULSCALARVERIFY, arkade.OP_TWEAKVERIFY, arkade.OP_ECPAIRING, arkade.OP_MODEXP} {
		program := append(append([]byte{0, arkade.OP_IF}, bytes.Repeat([]byte{op}, predicateComputeLimit(op)+1)...), arkade.OP_ENDIF, arkade.OP_1)
		require.ErrorContains(t, checkPredicate(program, &predicateBudget{}), "predicate compute limit")
	}
}

func TestInputPredicateSignature(t *testing.T) {
	key, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{4}, 32))
	message := sha256.Sum256([]byte("predicate statement"))
	signature, err := schnorr.Sign(key, message[:])
	require.NoError(t, err)
	for _, valid := range []bool{true, false} {
		msg := bytes.Clone(message[:])
		if !valid {
			msg[0] ^= 1
		}
		program, err := txscript.NewScriptBuilder().AddData(signature.Serialize()).AddData(msg).AddData(schnorr.SerializePubKey(key.PubKey())).AddOp(arkade.OP_CHECKSIGFROMSTACK).Script()
		require.NoError(t, err)
		inst, sources := predicateBuild(t, "onchain", hex.EncodeToString(program))
		_, err = inst.Build(sources, Fee{Dust: 330, Onchain: func(int) uint64 { return 0 }})
		if valid {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, ErrIneligible)
			require.NotContains(t, err.Error(), hex.EncodeToString(program))
		}
	}
}

func TestInputPredicateConcurrentBuildBudgets(t *testing.T) {
	program := predicateWork(16) + hex.EncodeToString(append(bytes.Repeat([]byte{0x51, 0x51, 0x51, 0xda, 0x75}, 48), 0x51))
	inst, sources := predicateBuild(t, "onchain", program, program, program, program)
	errors := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_, err := inst.Build(sources, Fee{Dust: 330, Onchain: func(int) uint64 { return 0 }})
			errors <- err
		})
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}

func TestInputPredicateContext(t *testing.T) {
	for _, typ := range []string{"onchain", "offchain", "intent"} {
		t.Run(typ, func(t *testing.T) {
			var programs []string
			for slot := range 2 {
				index := slot
				if typ == "intent" {
					index++
				}
				program, err := asm.Assemble(strings.Fields(fmt.Sprintf("OP_PUSHCURRENTINPUTINDEX %d OP_EQUALVERIFY OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTVALUE %d OP_EQUAL", index, 10000+slot)), nil)
				require.NoError(t, err)
				programs = append(programs, hex.EncodeToString(program))
			}
			inst, sources := predicateBuild(t, typ, programs...)
			_, err := inst.Build(sources, Fee{Dust: 330, Onchain: func(int) uint64 { return 0 }})
			require.NoError(t, err)
		})
	}
}

func TestInputPredicateBudget(t *testing.T) {
	program := hex.EncodeToString(append(bytes.Repeat([]byte{0x51, 0x51, 0x51, 0xda, 0x75}, 50), 0x51))
	for _, count := range []int{4, 6} {
		inst, sources := predicateBuild(t, "onchain", strings.Split(strings.TrimSuffix(strings.Repeat(program+",", count), ","), ",")...)
		_, err := inst.Build(sources, Fee{Dust: 330, Onchain: func(int) uint64 { return 0 }})
		if count == 4 {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, ErrIneligible)
		}
	}
}

func predicateWork(n int) string {
	return "$(" + strings.Repeat("1 1 1 OP_MODEXP OP_DROP ", n) + "0)"
}

func TestPredicateResolutionBudget(t *testing.T) {
	raw := func(n int) string {
		return hex.EncodeToString(append(bytes.Repeat([]byte{0x51, 0x51, 0x51, 0xda, 0x75}, n), 0x51))
	}
	for _, tc := range []struct {
		name, binding string
		inputs        int
		accepted      bool
	}{
		{"empty expressions at limit", strings.Repeat(predicateWork(32), 2) + "51", 1, true},
		{"empty expressions over limit", strings.Repeat(predicateWork(32), 3) + "51", 1, false},
		{"combined at limit", predicateWork(32) + raw(32), 1, true},
		{"combined over limit", predicateWork(33) + raw(32), 1, false},
		{"aggregate at limit", predicateWork(64) + "51", 4, true},
		{"aggregate over limit", predicateWork(52) + "51", 5, false},
		{"opcode bytes are data", predicateWork(64) + "$(0xda OP_DROP 0)51", 1, true},
		{"inactive resolution over limit", predicateWork(64) + "$(0 OP_IF 1 1 1 OP_MODEXP OP_DROP OP_ENDIF 0)51", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			programs := make([]string, tc.inputs)
			for k := range programs {
				programs[k] = tc.binding
			}
			inst, sources := predicateBuild(t, "onchain", programs...)
			act, err := inst.Build(sources, Fee{Dust: 330, Onchain: func(int) uint64 { return 0 }})
			if tc.accepted {
				require.NoError(t, err)
				require.NotNil(t, act)
			} else {
				require.ErrorIs(t, err, ErrIneligible, "action returned: %v", act != nil)
				require.Nil(t, act)
			}
		})
	}
}

func TestPredicateResolutionNestedBudget(t *testing.T) {
	for _, tc := range []struct {
		name, predicate, ciphertext string
		accepted                    bool
	}{
		{"nested ciphertext at limit", "<program>", predicateWork(64) + "51", true},
		{"nested ciphertext over limit", "<program>", predicateWork(32) + predicateWork(33) + "51", false},
		{"nested combined over limit", predicateWork(32) + "<program>", predicateWork(33) + "51", false},
		{"reject before assembly lookup", predicateWork(64) + "$(<program> OP_DROP 1 1 1 OP_MODEXP OP_DROP 0)51", "51", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := edited(t, fixture(t, "minimal.json"), func(m map[string]any) {
				m["secrets"] = map[string]any{"program": map[string]any{"type": "bytes", "from": "funds", "ciphertext": tc.ciphertext}}
				in := m["inputs"].([]any)[0].(map[string]any)
				in["predicate"] = predicateWork(64) + "51"
				m["inputs"] = append(m["inputs"].([]any), map[string]any{"name": "other", "contract": in["contract"], "spend": in["spend"], "predicate": tc.predicate})
				out := m["outputs"].([]any)[0].(map[string]any)
				m["outputs"] = append(m["outputs"].([]any), map[string]any{"name": "other", "index": 1, "value": map[string]any{"from": "other"}, "locking": out["locking"]})
			})
			_, sources := predicateBuild(t, "onchain", "51", "51")
			opened := 0
			inst, err := parseDoc(t, doc).Instantiate(Context{Keys: testKeys(t), Sources: sources, Decrypt: func(ct []byte) ([]byte, error) { opened++; return ct, nil }})
			require.NoError(t, err)
			act, err := inst.Build(sources, Fee{Dust: 330, Onchain: func(int) uint64 { return 0 }})
			if tc.accepted {
				require.NoError(t, err)
				require.NotNil(t, act)
				require.Equal(t, 1, opened)
			} else {
				require.ErrorIs(t, err, ErrIneligible, "action returned: %v", act != nil)
				require.Nil(t, act)
				require.Zero(t, opened)
			}
		})
	}
}

func TestPredicateResolutionPhaseEnds(t *testing.T) {
	for _, result := range []string{"51", "00"} {
		inst, sources := predicateBuild(t, "onchain", predicateWork(64)+result)
		d := newDraft(Onchain, sources)
		err := inst.predicates(d)
		if result == "51" {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, ErrIneligible)
		}
		ordinary, err := parseByteTemplate(predicateWork(64) + predicateWork(64))
		require.NoError(t, err)
		value, err := inst.resolve(ordinary, d, 0)
		require.NoError(t, err)
		require.Empty(t, value)
	}
}
