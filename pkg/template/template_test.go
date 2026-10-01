package template

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/stretchr/testify/require"
)

func TestParseMinimal(t *testing.T) {
	doc := fixture(t, "minimal.json")
	tmpl, err := Parse(t.Context(), doc, nil)
	require.NoError(t, err)
	require.Equal(t, Onchain, tmpl.Type())
	require.Equal(t, []Slot{{Name: "funds", Onchain: true}}, tmpl.Inputs())
	require.Empty(t, tmpl.Variables())
	inst, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t)})
	require.NoError(t, err)
	max, ok := inst.FeeCap()
	require.True(t, ok)
	require.EqualValues(t, 1000, max)
	require.Len(t, tmpl.ID(), 64)
}

func TestIDIgnoresDefaultsAndSpelling(t *testing.T) {
	doc := fixture(t, "minimal.json")
	base, err := Parse(t.Context(), doc, nil)
	require.NoError(t, err)
	for name, edit := range map[string]func(map[string]any){
		"explicit empty variables": func(m map[string]any) { m["variables"] = map[string]any{} },
		"explicit null packets":    func(m map[string]any) { m["packets"] = nil },
		"explicit input type":      func(m map[string]any) { m["inputs"].([]any)[0].(map[string]any)["type"] = "onchain" },
		"explicit schedule": func(m map[string]any) {
			m["inputs"].([]any)[0].(map[string]any)["schedule"] = map[string]any{"immediate": true}
		},
		"explicit assets": func(m map[string]any) { m["outputs"].([]any)[0].(map[string]any)["assets"] = []any{} },
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Parse(t.Context(), edited(t, doc, edit), nil)
			require.NoError(t, err)
			require.Equal(t, base.ID(), got.ID())
		})
	}
	changed, err := Parse(t.Context(), edited(t, doc, func(m map[string]any) {
		m["fees"].(map[string]any)["max"] = 1001
	}), nil)
	require.NoError(t, err)
	require.NotEqual(t, base.ID(), changed.ID())
}

func TestParseRejects(t *testing.T) {
	doc := delegateArgument(t)
	in := func(m map[string]any) map[string]any { return m["inputs"].([]any)[0].(map[string]any) }
	out := func(m map[string]any) map[string]any { return m["outputs"].([]any)[0].(map[string]any) }
	for name, edit := range map[string]func(map[string]any){
		"format":                  func(m map[string]any) { m["format"] = "delegateed-template/v2" },
		"type":                    func(m map[string]any) { m["type"] = "batch" },
		"unknown field":           func(m map[string]any) { m["extra"] = 1 },
		"field in another case":   func(m map[string]any) { m["Fees"] = m["fees"] },
		"no input":                func(m map[string]any) { m["inputs"] = []any{} },
		"bad name":                func(m map[string]any) { in(m)["name"] = "Funds" },
		"unknown function":        func(m map[string]any) { in(m)["spend"] = map[string]any{"function": "nope", "leaf": "release"} },
		"unknown leaf":            func(m map[string]any) { in(m)["spend"] = map[string]any{"function": "release", "leaf": "nope"} },
		"missing argument":        func(m map[string]any) { in(m)["contract"].(map[string]any)["arguments"] = map[string]any{} },
		"extra argument":          func(m map[string]any) { in(m)["contract"].(map[string]any)["arguments"].(map[string]any)["x"] = "00" },
		"offchain input onchain":  func(m map[string]any) { in(m)["type"] = "offchain" },
		"expiry schedule onchain": func(m map[string]any) { in(m)["schedule"] = map[string]any{"before_expiry_seconds": 10} },
		"index gap":               func(m map[string]any) { out(m)["index"] = 1 },
		"value from unknown":      func(m map[string]any) { out(m)["value"] = map[string]any{"from": "nope"} },
		"no remainder output":     func(m map[string]any) { out(m)["value"] = map[string]any{"from": "funds", "amount": 5} },
		"fee from unknown":        func(m map[string]any) { m["fees"] = map[string]any{"from": "nope", "max": 1} },
		"undeclared variable":     func(m map[string]any) { out(m)["locking"] = "5120<receiver>" },
		"rule on reserved type": func(m map[string]any) {
			m["packets"] = map[string]any{"output_index": 1, "rules": []any{map[string]any{"type": 5, "action": "drop", "from": "funds"}}}
		},
		"assets onchain":       func(m map[string]any) { out(m)["assets"] = []any{map[string]any{"from": "funds"}} },
		"expression bad token": func(m map[string]any) { out(m)["locking"] = "$(1 a>)" },
		"expression tab":       func(m map[string]any) { out(m)["locking"] = "$(1\tOP_1ADD)" },
		"expression opcode":    func(m map[string]any) { out(m)["locking"] = "$(OP_NOPE)" },
		"fees offchain":        func(m map[string]any) { m["type"] = "offchain" },
		"extra witness": func(m map[string]any) {
			in(m)["spend"].(map[string]any)["witness"] = map[string]any{"delegateSig": "00"}
		},
		"spend argument": func(m map[string]any) { in(m)["spend"].(map[string]any)["arguments"] = []any{"00"} },
		"sequence":       func(m map[string]any) { in(m)["sequence"] = 4294967295 },
		"integer for pubkey": func(m map[string]any) {
			in(m)["contract"].(map[string]any)["arguments"].(map[string]any)["delegate"] = 5
		},
		"invalid pubkey literal": func(m map[string]any) {
			in(m)["contract"].(map[string]any)["arguments"].(map[string]any)["delegate"] = "02" + strings.Repeat("ff", 32)
		},
		"forbidden expression opcode": func(m map[string]any) {
			in(m)["contract"].(map[string]any)["arguments"].(map[string]any)["delegate"] = "$(0 OP_INSPECTOUTPUTVALUE)"
		},
		"variable secret clash": func(m map[string]any) {
			m["variables"] = map[string]any{"x": "bytes"}
			m["secrets"] = map[string]any{"x": map[string]any{"type": "bytes32", "from": "funds", "ciphertext": "<x>"}}
		},
		"ciphertext names a secret": func(m map[string]any) {
			m["secrets"] = map[string]any{"s": map[string]any{"type": "bytes32", "from": "funds", "ciphertext": "<s>"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(t.Context(), edited(t, doc, edit), nil)
			require.Error(t, err)
			require.True(t, errors.Is(err, ErrInvalidTemplate) || errors.Is(err, ErrInvalidArtifact), err)
		})
	}
	_, err := Parse(t.Context(), []byte(strings.Replace(string(fixture(t, "minimal.json")), `"type": "onchain",`, `"type": "onchain", "type": "onchain",`, 1)), nil)
	require.ErrorIs(t, err, ErrInvalidTemplate, "duplicate key")
}

func TestParseIntent(t *testing.T) {
	doc := edited(t, fixture(t, "minimal.json"), func(m map[string]any) {
		m["type"] = "intent"
		m["outputs"].([]any)[0].(map[string]any)["assets"] = []any{map[string]any{"from": "funds"}}
		m["packets"] = map[string]any{
			"output_index": 1,
			"rules":        []any{map[string]any{"type": 2, "action": "copy", "from": "funds"}},
			"advertise":    []any{map[string]any{"template": "self", "outputs": []any{"payment"}}},
		}
	})
	tmpl, err := Parse(t.Context(), doc, nil)
	require.NoError(t, err)
	require.Equal(t, Intent, tmpl.Type())
	require.Equal(t, []Slot{{Name: "funds"}}, tmpl.Inputs())

	pk := func(m map[string]any) map[string]any { return m["packets"].(map[string]any) }
	rule := func(typ int, action string) map[string]any {
		return map[string]any{"type": typ, "action": action, "from": "funds"}
	}
	for name, edit := range map[string]func(map[string]any){
		"copy and drop": func(m map[string]any) { pk(m)["rules"] = append(pk(m)["rules"].([]any), rule(2, "drop")) },
		"two emits": func(m map[string]any) {
			a, b := rule(3, "emit"), rule(3, "emit")
			a["data"], b["data"] = "00", "01"
			pk(m)["rules"] = []any{a, b}
		},
		"emit without data": func(m map[string]any) { pk(m)["rules"] = []any{rule(3, "emit")} },
		"copy with data": func(m map[string]any) {
			r := rule(3, "copy")
			r["data"] = "00"
			pk(m)["rules"] = []any{r}
		},
		"unmatched": func(m map[string]any) { pk(m)["unmatched"] = "keep" },
		"extension before offchain": func(m map[string]any) {
			pk(m)["output_index"] = 0
			m["outputs"].([]any)[0].(map[string]any)["index"] = 1
		},
		"self with variables": func(m map[string]any) { m["variables"] = map[string]any{"x": "int"} },
		"output advertised twice": func(m map[string]any) {
			pk(m)["advertise"] = append(pk(m)["advertise"].([]any), map[string]any{"template": "self", "outputs": []any{"payment"}})
		},
		"self count": func(m map[string]any) {
			pk(m)["advertise"] = []any{map[string]any{"template": "self", "outputs": []any{}}}
		},
		"bad target": func(m map[string]any) {
			pk(m)["advertise"] = []any{map[string]any{"template": "SELF", "outputs": []any{"payment"}}}
		},
		"confirmations offchain": func(m map[string]any) {
			m["inputs"].([]any)[0].(map[string]any)["schedule"] = map[string]any{"min_confirmations": 1}
		},
		"asset id short": func(m map[string]any) {
			m["outputs"].([]any)[0].(map[string]any)["assets"] = []any{map[string]any{"from": "funds", "asset": "00"}}
		},
		"two catch-alls": func(m map[string]any) {
			m["outputs"].([]any)[0].(map[string]any)["assets"] = []any{map[string]any{"from": "funds"}, map[string]any{"from": "funds"}}
		},
		"copy and emit from two inputs": func(m map[string]any) {
			twoInputs(t, m)
			pk(m)["rules"] = []any{rule(2, "copy"), packetRule(2, "emit", "more")}
		},
		"two copies from two inputs": func(m map[string]any) {
			twoInputs(t, m)
			pk(m)["rules"] = []any{rule(2, "copy"), packetRule(2, "copy", "more")}
		},
		"self feeds an onchain slot from an offchain output": func(m map[string]any) {
			m["inputs"].([]any)[0].(map[string]any)["type"] = "onchain"
			delete(m["outputs"].([]any)[0].(map[string]any), "assets")
		},
		"too many rules": func(m map[string]any) {
			rules := []any{}
			for range 256 {
				rules = append(rules, rule(3, "drop"))
			}
			pk(m)["rules"] = rules
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(t.Context(), edited(t, doc, edit), nil)
			require.ErrorIs(t, err, ErrInvalidTemplate)
		})
	}

	_, err = Parse(t.Context(), edited(t, doc, func(m map[string]any) {
		twoInputs(t, m)
		pk(m)["rules"] = []any{rule(3, "drop"), packetRule(3, "drop", "more"), packetRule(3, "emit", "more"), rule(2, "copy")}
	}), nil)
	require.NoError(t, err, "drops combine across inputs and with an emit")
}

func TestBindingTypes(t *testing.T) {
	doc := fixture(t, "minimal.json")
	// covenant gives the release function one covenant input of type typ, bound to arg.
	covenant := func(typ string, arg any, vars map[string]any) func(map[string]any) {
		return func(m map[string]any) {
			in := m["inputs"].([]any)[0].(map[string]any)
			fn := in["contract"].(map[string]any)["definition"].(map[string]any)["functions"].([]any)[0].(map[string]any)
			fn["arkade"] = map[string]any{"inputs": []any{map[string]any{"name": "a", "type": typ}}, "asm": []any{"OP_TRUE"}}
			in["spend"].(map[string]any)["arguments"] = []any{arg}
			m["packets"] = map[string]any{"output_index": 1}
			if vars != nil {
				m["variables"] = vars
			}
		}
	}
	for name, tc := range map[string]struct {
		edit func(map[string]any)
		ok   bool
	}{
		"lone name of the field's type": {covenant("pubkey", "<k>", map[string]any{"k": "pubkey"}), true},
		"pubkey variable in bytes":      {covenant("bytes", "<k>", map[string]any{"k": "pubkey"}), true},
		"integer for int":               {covenant("int", 5, nil), true},
		"expression is not typed here":  {covenant("bytes32", "$(<k> OP_SHA256)", map[string]any{"k": "pubkey"}), true},
		"pubkey variable in bytes32":    {covenant("bytes32", "<k>", map[string]any{"k": "pubkey"}), false},
		"integer for pubkey":            {covenant("pubkey", 5, nil), false},
		"boolean for int":               {covenant("int", true, nil), false},
		"non-minimal int literal":       {covenant("int", "0100", nil), false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(t.Context(), edited(t, doc, tc.edit), nil)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrInvalidTemplate)
			}
		})
	}
}

func TestVHTLC(t *testing.T) {
	doc := []byte(vhtlc)
	_, err := Parse(t.Context(), doc, nil)
	require.NoError(t, err)

	args := func(m map[string]any) map[string]any {
		return m["inputs"].([]any)[0].(map[string]any)["contract"].(map[string]any)["arguments"].(map[string]any)
	}
	for name, edit := range map[string]func(map[string]any){
		"short bytes32":              func(m map[string]any) { args(m)["receiverProgram"] = strings.Repeat("00", 31) },
		"pubkey variable in bytes32": func(m map[string]any) { args(m)["receiverProgram"] = "<sender>" },
		"witness of the wrong type": func(m map[string]any) {
			m["inputs"].([]any)[0].(map[string]any)["spend"].(map[string]any)["witness"] = map[string]any{"preimage": "<sender>"}
		},
		"asset amount not positive": func(m map[string]any) {
			out := m["outputs"].([]any)[0].(map[string]any)
			out["assets"] = append(out["assets"].([]any), map[string]any{"from": "htlc", "asset": strings.Repeat("ab", 34), "amount": "00"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(t.Context(), edited(t, doc, edit), nil)
			require.ErrorIs(t, err, ErrInvalidTemplate)
		})
	}

	_, err = Parse(t.Context(), edited(t, doc, func(m map[string]any) {
		m["inputs"].([]any)[0].(map[string]any)["spend"] = map[string]any{"function": "refundWithoutReceiver", "leaf": "refundWithoutReceiver"}
	}), nil)
	require.ErrorIs(t, err, ErrUnsupported, "an absolute locktime path")
}

func TestSecretsOnlyHashedInScripts(t *testing.T) {
	doc := fixture(t, "vhtlc_claim.json")
	in := func(m map[string]any) map[string]any { return m["inputs"].([]any)[0].(map[string]any) }
	arg := func(name string, v any) func(map[string]any) {
		return func(m map[string]any) { in(m)["contract"].(map[string]any)["arguments"].(map[string]any)[name] = v }
	}
	// fnArg gives nonInteractiveClaim one covenant input of type bytes32, bound to v.
	fnArg := func(v any) func(map[string]any) {
		return func(m map[string]any) {
			fns := in(m)["contract"].(map[string]any)["definition"].(map[string]any)["functions"].([]any)
			for _, f := range fns {
				if f := f.(map[string]any); f["name"] == "nonInteractiveClaim" {
					f["arkade"].(map[string]any)["inputs"] = []any{map[string]any{"name": "a", "type": "bytes32"}}
				}
			}
			in(m)["spend"].(map[string]any)["arguments"] = []any{v}
		}
	}
	locking := func(v any) func(map[string]any) {
		return func(m map[string]any) { m["outputs"].([]any)[0].(map[string]any)["locking"] = v }
	}
	for name, tc := range map[string]struct {
		edit func(map[string]any)
		ok   bool
	}{
		"bare secret in a constructor argument":   {arg("receiverProgram", "<preimage>"), false},
		"secret among literals":                   {arg("preimageHash", "<preimage>00"), false},
		"unhashed expression":                     {arg("receiverProgram", "$(<preimage> OP_SIZE OP_DROP)"), false},
		"hash before the end":                     {arg("receiverProgram", "$(<preimage> OP_SHA256 OP_DROP <preimage>)"), false},
		"sha256 constructor argument":             {arg("receiverProgram", "$(<preimage> OP_SHA256)"), true},
		"hash256 constructor argument":            {arg("receiverProgram", "$(<preimage> OP_HASH256)"), true},
		"ripemd160 constructor argument":          {arg("preimageHash", "$(<preimage> OP_SHA256 OP_RIPEMD160)"), true},
		"function argument, a witness item":       {fnArg("<preimage>"), true},
		"locking script, only in the transaction": {locking("5120<preimage>"), true},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(t.Context(), edited(t, doc, tc.edit), nil)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrInvalidTemplate)
				require.ErrorContains(t, err, "must be hashed")
			}
		})
	}
}

func TestArtifactReference(t *testing.T) {
	doc := fixture(t, "minimal.json")
	var m map[string]any
	require.NoError(t, json.Unmarshal(doc, &m))
	def := m["inputs"].([]any)[0].(map[string]any)["contract"].(map[string]any)["definition"]
	raw, err := json.Marshal(def)
	require.NoError(t, err)
	artifact, err := ParseArtifact(raw)
	require.NoError(t, err)

	referenced := edited(t, doc, func(m map[string]any) {
		m["inputs"].([]any)[0].(map[string]any)["contract"].(map[string]any)["definition"] = map[string]any{"artifact": artifact.ID}
	})
	resolve := func(_ context.Context, id string) ([]byte, error) {
		require.Equal(t, artifact.ID, id)
		return raw, nil
	}
	tmpl, err := Parse(t.Context(), referenced, resolve)
	require.NoError(t, err)
	require.Equal(t, []string{artifact.ID}, tmpl.Artifacts())
	inline, err := Parse(t.Context(), doc, nil)
	require.NoError(t, err)
	require.NotEqual(t, inline.ID(), tmpl.ID(), "the id hashes the template as written")

	_, err = Parse(t.Context(), referenced, nil)
	require.ErrorIs(t, err, ErrInvalidTemplate, "no resolver")
	_, err = Parse(t.Context(), referenced, func(context.Context, string) ([]byte, error) {
		return []byte(strings.Replace(string(raw), "Release", "Other", 1)), nil
	})
	require.ErrorIs(t, err, ErrInvalidTemplate, "the stored document does not hash to the id")
	down := errors.New("database down")
	_, err = Parse(t.Context(), referenced, func(context.Context, string) ([]byte, error) { return nil, down })
	require.ErrorIs(t, err, down)
	require.NotErrorIs(t, err, ErrInvalidTemplate, "an outage is not a bad document")
}

func TestPushOpcodesRefused(t *testing.T) {
	hidden := func(op byte) string { return fmt.Sprintf("0x01%02x", op) }
	require.ErrorIs(t, checkExpression([]string{"OP_DATA_2", hidden(arkade.OP_INSPECTNUMOUTPUTS), "OP_NIP"}), ErrInvalidTemplate)
	many := []string{}
	for range 100 {
		many = append(many, "OP_DATA_2", hidden(arkade.OP_INSPECTINTENTMESSAGE), "OP_NIP")
	}
	require.ErrorIs(t, checkExpression(many), ErrInvalidTemplate)
	for _, op := range []string{"OP_DATA_1", "OP_DATA_75", "OP_PUSHDATA1", "OP_PUSHDATA2", "OP_PUSHDATA4"} {
		_, err := assemble([]string{op, "0x01"}, nil)
		require.Error(t, err, op)
	}

	doc := fixture(t, "minimal.json")
	out := func(m map[string]any) map[string]any { return m["outputs"].([]any)[0].(map[string]any) }
	_, err := Parse(t.Context(), edited(t, doc, func(m map[string]any) {
		out(m)["locking"] = fmt.Sprintf("5120$(OP_DATA_2 0x01%02x OP_NIP)", arkade.OP_TXID)
	}), nil)
	require.ErrorIs(t, err, ErrInvalidTemplate, "locking expression")
	_, err = Parse(t.Context(), edited(t, doc, func(m map[string]any) {
		def := m["inputs"].([]any)[0].(map[string]any)["contract"].(map[string]any)["definition"].(map[string]any)
		leafOf(def, 0)["asm"] = []any{"OP_DATA_1", "<delegate>", "OP_CHECKSIG"}
	}), nil)
	require.ErrorIs(t, err, ErrInvalidArtifact, "leaf")
}

func TestParseRefusesUnbuildable(t *testing.T) {
	_, err := Parse(t.Context(), edited(t, fixture(t, "renewal.json"), func(m map[string]any) { delete(m, "packets") }), nil)
	require.ErrorIs(t, err, ErrInvalidTemplate, "a covenant without packets")

	_, err = Parse(t.Context(), edited(t, mixedPaymentDoc(t, false), func(m map[string]any) {
		in := m["inputs"].([]any)[0].(map[string]any)
		sp := in["spend"].(map[string]any)
		sp["function"], sp["leaf"] = "spend", "spend"
		def := in["contract"].(map[string]any)["definition"].(map[string]any)
		delete(leafOf(def, 0)["witness"].([]any)[1].(map[string]any), "injected")
	}), nil)
	require.ErrorIs(t, err, ErrInvalidTemplate, "a signature nobody injects")

	adverts := func(n int) []byte {
		return edited(t, mixedPaymentDoc(t, false), func(m map[string]any) {
			outs := m["outputs"].([]any)
			outs[1].(map[string]any)["index"] = n + 2
			var ads []any
			for k := range n {
				name := fmt.Sprintf("o%d", k)
				outs = append(outs, map[string]any{"name": name, "index": 1 + k, "value": map[string]any{"from": "funds", "amount": 1000},
					"locking": "5120f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"})
				ads = append(ads, map[string]any{"template": strings.Repeat("ab", 32), "outputs": []any{name}})
			}
			m["outputs"] = outs
			m["packets"] = map[string]any{"output_index": n + 1, "advertise": ads}
		})
	}
	_, err = Parse(t.Context(), adverts(14), nil)
	require.NoError(t, err, "14 records fit")
	_, err = Parse(t.Context(), adverts(15), nil)
	require.ErrorIs(t, err, ErrInvalidTemplate, "15 records do not fit")
}

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join("testdata", name))
	if errors.Is(err, fs.ErrNotExist) {
		doc, err = os.ReadFile(filepath.Join("..", "..", "templates", name))
	}
	require.NoError(t, err)
	return doc
}

// delegateArgument is minimal.json with the key bound as a constructor argument.
func delegateArgument(t *testing.T) []byte {
	t.Helper()
	return edited(t, fixture(t, "minimal.json"), func(m map[string]any) {
		c := m["inputs"].([]any)[0].(map[string]any)["contract"].(map[string]any)
		def := c["definition"].(map[string]any)
		def["constructorInputs"] = []any{map[string]any{"name": "delegate", "type": "pubkey"}}
		leafOf(def, 0)["asm"] = []any{"<delegate>", "OP_CHECKSIG"}
		c["arguments"] = map[string]any{"delegate": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}
	})
}

func edited(t *testing.T, doc []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(doc, &m))
	edit(m)
	out, err := json.Marshal(m)
	require.NoError(t, err)
	return out
}

// twoInputs adds an input "more", its remainder output and a second advertised slot.
func twoInputs(t *testing.T, m map[string]any) {
	t.Helper()
	raw, err := json.Marshal(m["inputs"].([]any)[0])
	require.NoError(t, err)
	var more map[string]any
	require.NoError(t, json.Unmarshal(raw, &more))
	more["name"] = "more"
	m["inputs"] = append(m["inputs"].([]any), more)
	m["outputs"] = append(m["outputs"].([]any), map[string]any{
		"name": "more_out", "index": 1, "value": map[string]any{"from": "more"}, "locking": map[string]any{"from": "more"},
	})
	p := m["packets"].(map[string]any)
	p["output_index"] = 2
	p["advertise"] = []any{map[string]any{"template": "self", "outputs": []any{"payment", "more_out"}}}
}

func packetRule(typ int, action, from string) map[string]any {
	r := map[string]any{"type": typ, "action": action, "from": from}
	if action == "emit" {
		r["data"] = "00"
	}
	return r
}

// vhtlc is the protocol's non-interactive VHTLC claim example.
const vhtlc = `
{
  "format": "delegateed-template/v1",
  "type": "offchain",
  "variables": {
    "sender": "pubkey",
    "receiver": "pubkey",
    "refund_locktime": "int",
    "unilateral_claim_delay": "int",
    "unilateral_refund_delay": "int",
    "unilateral_refund_without_receiver_delay": "int",
    "receiver_program": "bytes32",
    "sender_program": "bytes32",
    "ciphertext": "bytes"
  },
  "secrets": {"preimage": {"type": "bytes32", "from": "htlc", "ciphertext": "<ciphertext>"}},
  "inputs": [
    {
      "name": "htlc",
      "contract": {
        "definition": {
          "contractName": "VHTLC",
          "constructorInputs": [
            {"name": "sender", "type": "pubkey"},
            {"name": "receiver", "type": "pubkey"},
            {"name": "preimageHash", "type": "bytes20"},
            {"name": "refundLocktime", "type": "int"},
            {"name": "unilateralClaimDelay", "type": "int"},
            {"name": "unilateralRefundDelay", "type": "int"},
            {"name": "unilateralRefundWithoutReceiverDelay", "type": "int"},
            {"name": "receiverProgram", "type": "bytes32"},
            {"name": "senderProgram", "type": "bytes32"}
          ],
          "structs": [],
          "functions": [
            {
              "name": "claim",
              "leaves": [
                {
                  "name": "claim",
                  "asm": [
                    "OP_SIZE", "32", "OP_EQUALVERIFY", "OP_HASH160", "<preimageHash>", "OP_EQUAL", "OP_VERIFY",
                    "<receiver>", "OP_CHECKSIGVERIFY", "<SERVER_KEY>", "OP_CHECKSIG"
                  ],
                  "witness": [
                    {"name": "preimage", "type": "bytes32", "encoding": "raw"},
                    {"name": "receiverSig", "type": "signature", "encoding": "schnorr-64"},
                    {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true}
                  ]
                }
              ]
            },
            {
              "name": "refund",
              "leaves": [
                {
                  "name": "refund",
                  "asm": [
                    "<sender>", "OP_CHECKSIGVERIFY", "<receiver>", "OP_CHECKSIGVERIFY", "<SERVER_KEY>",
                    "OP_CHECKSIG"
                  ],
                  "witness": [
                    {"name": "senderSig", "type": "signature", "encoding": "schnorr-64"},
                    {"name": "receiverSig", "type": "signature", "encoding": "schnorr-64"},
                    {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true}
                  ]
                }
              ]
            },
            {
              "name": "refundWithoutReceiver",
              "leaves": [
                {
                  "name": "refundWithoutReceiver",
                  "asm": [
                    "<refundLocktime>", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP", "<sender>", "OP_CHECKSIGVERIFY",
                    "<SERVER_KEY>", "OP_CHECKSIG"
                  ],
                  "witness": [
                    {"name": "senderSig", "type": "signature", "encoding": "schnorr-64"},
                    {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true}
                  ]
                }
              ]
            },
            {
              "name": "unilateralClaim",
              "leaves": [
                {
                  "name": "unilateralClaim",
                  "asm": [
                    "OP_SIZE", "32", "OP_EQUALVERIFY", "OP_HASH160", "<preimageHash>", "OP_EQUAL", "OP_VERIFY",
                    "<unilateralClaimDelay>", "OP_CHECKSEQUENCEVERIFY", "OP_DROP", "<receiver>", "OP_CHECKSIG"
                  ],
                  "witness": [
                    {"name": "preimage", "type": "bytes32", "encoding": "raw"},
                    {"name": "receiverSig", "type": "signature", "encoding": "schnorr-64"}
                  ]
                }
              ]
            },
            {
              "name": "unilateralRefund",
              "leaves": [
                {
                  "name": "unilateralRefund",
                  "asm": [
                    "<unilateralRefundDelay>", "OP_CHECKSEQUENCEVERIFY", "OP_DROP", "<sender>",
                    "OP_CHECKSIGVERIFY", "<receiver>", "OP_CHECKSIG"
                  ],
                  "witness": [
                    {"name": "senderSig", "type": "signature", "encoding": "schnorr-64"},
                    {"name": "receiverSig", "type": "signature", "encoding": "schnorr-64"}
                  ]
                }
              ]
            },
            {
              "name": "unilateralRefundWithoutReceiver",
              "leaves": [
                {
                  "name": "unilateralRefundWithoutReceiver",
                  "asm": [
                    "<unilateralRefundWithoutReceiverDelay>", "OP_CHECKSEQUENCEVERIFY", "OP_DROP", "<sender>",
                    "OP_CHECKSIG"
                  ],
                  "witness": [{"name": "senderSig", "type": "signature", "encoding": "schnorr-64"}]
                }
              ]
            },
            {
              "name": "nonInteractiveClaim",
              "arkade": {
                "inputs": [],
                "asm": [
                  "OP_PUSHCURRENTINPUTINDEX", "OP_DUP", "OP_INSPECTOUTPUTSCRIPTPUBKEY", "1", "OP_EQUALVERIFY",
                  "<receiverProgram>", "OP_EQUALVERIFY", "OP_INSPECTOUTPUTVALUE", "OP_PUSHCURRENTINPUTINDEX",
                  "OP_INSPECTINPUTVALUE", "OP_GREATERTHANOREQUAL"
                ]
              },
              "leaves": [
                {
                  "name": "nonInteractiveClaim",
                  "asm": [
                    "OP_SIZE", "32", "OP_EQUALVERIFY", "OP_HASH160", "<preimageHash>", "OP_EQUAL", "OP_VERIFY",
                    "<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:nonInteractiveClaim>", "OP_CHECKSIG"
                  ],
                  "witness": [
                    {"name": "preimage", "type": "bytes32", "encoding": "raw"},
                    {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true},
                    {"name": "emulatorSig", "type": "signature", "encoding": "schnorr-64", "injected": true}
                  ]
                }
              ]
            },
            {
              "name": "nonInteractiveRefund",
              "arkade": {
                "inputs": [],
                "asm": [
                  "OP_PUSHCURRENTINPUTINDEX", "OP_DUP", "OP_INSPECTOUTPUTSCRIPTPUBKEY", "1", "OP_EQUALVERIFY",
                  "<senderProgram>", "OP_EQUALVERIFY", "OP_INSPECTOUTPUTVALUE", "OP_PUSHCURRENTINPUTINDEX",
                  "OP_INSPECTINPUTVALUE", "OP_GREATERTHANOREQUAL"
                ]
              },
              "leaves": [
                {
                  "name": "nonInteractiveRefund",
                  "asm": [
                    "<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<receiver>", "OP_CHECKSIGVERIFY",
                    "<EMULATOR_KEY:nonInteractiveRefund>", "OP_CHECKSIG"
                  ],
                  "witness": [
                    {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true},
                    {"name": "receiverSig", "type": "signature", "encoding": "schnorr-64"},
                    {"name": "emulatorSig", "type": "signature", "encoding": "schnorr-64", "injected": true}
                  ]
                },
                {
                  "name": "nonInteractiveRefundWithoutReceiver",
                  "asm": [
                    "<refundLocktime>", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP", "<SERVER_KEY>",
                    "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:nonInteractiveRefund>", "OP_CHECKSIG"
                  ],
                  "witness": [
                    {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true},
                    {"name": "emulatorSig", "type": "signature", "encoding": "schnorr-64", "injected": true}
                  ]
                }
              ]
            }
          ]
        },
        "arguments": {
          "sender": "<sender>",
          "receiver": "<receiver>",
          "preimageHash": "$(<preimage> OP_HASH160)",
          "refundLocktime": "<refund_locktime>",
          "unilateralClaimDelay": "<unilateral_claim_delay>",
          "unilateralRefundDelay": "<unilateral_refund_delay>",
          "unilateralRefundWithoutReceiverDelay": "<unilateral_refund_without_receiver_delay>",
          "receiverProgram": "<receiver_program>",
          "senderProgram": "<sender_program>"
        }
      },
      "spend": {
        "function": "nonInteractiveClaim",
        "leaf": "nonInteractiveClaim",
        "witness": {"preimage": "<preimage>"}
      }
    }
  ],
  "outputs": [
    {
      "name": "payout",
      "index": 0,
      "value": {"from": "htlc"},
      "locking": "5120<receiver_program>",
      "assets": [{"from": "htlc"}]
    }
  ],
  "packets": {"output_index": 1, "unmatched": "drop"}
}
`
