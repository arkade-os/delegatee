package template

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseArtifact(t *testing.T) {
	doc, err := os.ReadFile("testdata/artifacts/single_sig.compiler.json")
	require.NoError(t, err)
	a, err := ParseArtifact(doc)
	require.ErrorIs(t, err, ErrInvalidArtifact, "a covenant input of type signature cannot be bound")
	require.Nil(t, a)

	bare := `{"contractName":"Exit","constructorInputs":[{"name":"user","type":"pubkey"},{"name":"exit","type":"int"}],
	  "functions":[{"name":"unilateral","leaves":[{"name":"unilateral",
	  "witness":[{"name":"userSig","type":"signature","encoding":"schnorr-64"}],
	  "asm":["<exit>","OP_CHECKSEQUENCEVERIFY","OP_DROP","<user>","OP_CHECKSIG"]}]}]}`
	a, err = ParseArtifact([]byte(bare))
	require.NoError(t, err)
	require.Equal(t, "Exit", a.Definition.ContractName)
	require.Empty(t, a.Definition.Structs)

	withMetadata := strings.Replace(bare, `{"contractName"`, `{"formatVersion":1,"compiler":{"name":"arkade-compiler","version":"0.1.0"},"updatedAt":"2026-07-08T00:00:00Z","structs":[],"contractName"`, 1)
	b, err := ParseArtifact([]byte(withMetadata))
	require.NoError(t, err)
	require.Equal(t, a.ID, b.ID, "metadata and an explicit empty structs do not change the id")
	require.Len(t, a.ID, 64)
}

func TestParseArtifactCovenant(t *testing.T) {
	doc := func(asm string) string {
		return `{"contractName":"C","constructorInputs":[{"name":"k","type":"pubkey"}],"functions":[{"name":"f",
		"arkade":{"inputs":[{"name":"amount","type":"int"}],"asm":[` + asm + `]},
		"leaves":[{"name":"l","witness":[{"name":"s","type":"signature","encoding":"schnorr-64","injected":true}],
		"asm":["<SERVER_KEY>","OP_CHECKSIGVERIFY","<EMULATOR_KEY:f>","OP_CHECKSIG"]}]}]}`
	}
	a, err := ParseArtifact([]byte(doc(`"<k>","OP_CHECKSIG"`)))
	require.NoError(t, err)
	require.NotNil(t, a.Definition.Functions[0].Arkade)
	require.Equal(t, "f", a.Definition.json()["functions"].([]any)[0].(map[string]any)["name"])

	_, err = ParseArtifact([]byte(doc(`"<amount>","OP_DROP"`)))
	require.ErrorIs(t, err, ErrInvalidArtifact, "covenant inputs are never placeholders")
}

func TestParseArtifactRejects(t *testing.T) {
	base := func(asm string) string {
		return `{"contractName":"C","constructorInputs":[{"name":"k","type":"pubkey"}],"functions":[{"name":"f","leaves":[{"name":"l","witness":[],"asm":[` + asm + `]}]}]}`
	}
	for name, doc := range map[string]string{
		"unknown field":                    `{"contractName":"C","constructorInputs":[],"functions":[],"extra":1}`,
		"no function":                      `{"contractName":"C","constructorInputs":[],"functions":[]}`,
		"unknown opcode":                   base(`"OP_NOPE"`),
		"decimal too large":                base(`"9007199254740992"`),
		"decimal too small":                base(`"-9007199254740992"`),
		"unknown placeholder":              base(`"<missing>","OP_CHECKSIG"`),
		"vtxo import":                      base(`"<VTXO:Other(k)>"`),
		"introspection fallback":           base(`"<tx.inputs[?].value>"`),
		"unknown type":                     `{"contractName":"C","constructorInputs":[{"name":"k","type":"float"}],"functions":[{"name":"f","leaves":[{"name":"l","witness":[],"asm":["OP_1"]}]}]}`,
		"duplicate function":               `{"contractName":"C","constructorInputs":[],"functions":[{"name":"f","leaves":[{"name":"l","witness":[],"asm":["OP_1"]}]},{"name":"f","leaves":[{"name":"l","witness":[],"asm":["OP_1"]}]}]}`,
		"duplicate leaf":                   `{"contractName":"C","constructorInputs":[],"functions":[{"name":"f","leaves":[{"name":"l","witness":[],"asm":["OP_1"]},{"name":"l","witness":[],"asm":["OP_2"]}]}]}`,
		"emulator key of a plain function": base(`"<EMULATOR_KEY:f>","OP_CHECKSIG"`),
		"unknown encoding":                 `{"contractName":"C","constructorInputs":[],"functions":[{"name":"f","leaves":[{"name":"l","witness":[{"name":"w","type":"int","encoding":"hex"}],"asm":["OP_1"]}]}]}`,
		"malformed json":                   `{`,
		"negative zero":                    base(`"-0"`),
		"leading zero":                     base(`"007"`),
		"duplicate witness name":           `{"contractName":"C","constructorInputs":[],"functions":[{"name":"f","leaves":[{"name":"l","witness":[{"name":"w","type":"int","encoding":"raw"},{"name":"w","type":"int","encoding":"raw"}],"asm":["OP_1"]}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseArtifact([]byte(doc))
			require.ErrorIs(t, err, ErrInvalidArtifact)
		})
	}
}

func TestArtifactIDStable(t *testing.T) {
	want := mustID(t, []byte(idDoc))
	reordered := `{"functions":[{"leaves":[{"asm":["<n>","OP_DROP","OP_1"],"witness":[],"name":"m"}],"name":"g"}],"structs":[],"constructorInputs":[{"type":"int","name":"n"}],"contractName":"C"}`
	noStructs := `{"contractName":"C","constructorInputs":[{"name":"n","type":"int"}],"functions":[{"name":"g","leaves":[{"name":"m","witness":[],"asm":["<n>","OP_DROP","OP_1"]}]}]}`
	require.Equal(t, mustID(t, []byte(noStructs)), mustID(t, []byte(reordered)), "key order and empty structs")

	for name, fn := range map[string]func(m map[string]any){
		"injected false": func(m map[string]any) {
			w := leafOf(m, 0)["witness"].([]any)[0].(map[string]any)
			w["injected"] = false
		},
		"metadata": func(m map[string]any) {
			m["formatVersion"] = 1
			m["compiler"] = map[string]any{"name": "x"}
			m["source"] = map[string]any{}
			m["updatedAt"] = "now"
			m["fingerprint"] = "abc"
		},
	} {
		t.Run(name, func(t *testing.T) {
			doc, base := edited(t, []byte(idDoc), fn), []byte(idDoc)
			if name == "injected false" {
				base = edited(t, []byte(idDoc), func(m map[string]any) {
					delete(leafOf(m, 0)["witness"].([]any)[0].(map[string]any), "injected")
				})
			}
			require.Equal(t, mustID(t, base), mustID(t, doc))
		})
	}
	require.Len(t, want, 64)
}

func TestArtifactIDChanges(t *testing.T) {
	want := mustID(t, []byte(idDoc))
	for name, fn := range map[string]func(m map[string]any){
		"asm token":        func(m map[string]any) { leafOf(m, 1)["asm"].([]any)[2] = "OP_2" },
		"function name":    func(m map[string]any) { fnOf(m, 1)["name"] = "h" },
		"leaf name":        func(m map[string]any) { leafOf(m, 1)["name"] = "z" },
		"constructor type": func(m map[string]any) { m["constructorInputs"].([]any)[1].(map[string]any)["type"] = "bytes" },
		"witness encoding": func(m map[string]any) {
			leafOf(m, 0)["witness"].([]any)[0].(map[string]any)["encoding"] = "raw"
		},
		"swap functions": func(m map[string]any) {
			fs := m["functions"].([]any)
			fs[0], fs[1] = fs[1], fs[0]
		},
		"swap leaves": func(m map[string]any) {
			ls := fnOf(m, 0)["leaves"].([]any)
			ls[0], ls[1] = ls[1], ls[0]
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, want, mustID(t, edited(t, []byte(idDoc), fn)))
		})
	}
}

func TestArtifactUnknownFieldAtEachLevel(t *testing.T) {
	for name, get := range map[string]func(m map[string]any) map[string]any{
		"function":          func(m map[string]any) map[string]any { return fnOf(m, 0) },
		"arkade":            func(m map[string]any) map[string]any { return fnOf(m, 0)["arkade"].(map[string]any) },
		"leaf":              func(m map[string]any) map[string]any { return leafOf(m, 0) },
		"witness item":      func(m map[string]any) map[string]any { return leafOf(m, 0)["witness"].([]any)[0].(map[string]any) },
		"constructor input": func(m map[string]any) map[string]any { return m["constructorInputs"].([]any)[0].(map[string]any) },
		"struct":            func(m map[string]any) map[string]any { return m["structs"].([]any)[0].(map[string]any) },
		"struct field": func(m map[string]any) map[string]any {
			return m["structs"].([]any)[0].(map[string]any)["fields"].([]any)[0].(map[string]any)
		},
	} {
		t.Run(name, func(t *testing.T) {
			doc := edited(t, []byte(idDoc), func(m map[string]any) { get(m)["extra"] = 1 })
			_, err := ParseArtifact(doc)
			require.ErrorIs(t, err, ErrInvalidArtifact)
		})
	}
}

func TestArtifactPlaceholders(t *testing.T) {
	for tok, ok := range map[string]bool{
		"<EMULATOR_KEY:>":  false,
		"<EMULATOR_KEY:g>": false, // g has no arkade
		"<TWEAK:k>":        false,
		"<TWEAK:n:f>":      false, // n is an int
		"<TWEAK:k:f>":      true,
		"<TWEAK:k:g>":      false,
		"<EMULATOR_KEY:f>": true,
	} {
		t.Run(tok, func(t *testing.T) {
			doc := edited(t, []byte(idDoc), func(m map[string]any) { leafOf(m, 1)["asm"] = []any{tok, "OP_CHECKSIG"} })
			_, err := ParseArtifact(doc)
			if ok {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrInvalidArtifact)
			}
		})
	}
	doc := edited(t, []byte(idDoc), func(m map[string]any) {
		leafOf(m, 1)["asm"] = []any{"9007199254740991", "-9007199254740991", "OP_DROP"}
	})
	_, err := ParseArtifact(doc)
	require.NoError(t, err)
	doc = edited(t, []byte(idDoc), func(m map[string]any) { leafOf(m, 1)["asm"] = []any{"0", "OP_DROP"} })
	_, err = ParseArtifact(doc)
	require.NoError(t, err, "zero is a valid decimal")
}

func TestArtifactTypes(t *testing.T) {
	for name, inputs := range map[string][]any{
		"array of struct":   {map[string]any{"name": "a", "type": "S[2]"}},
		"array over cap":    {map[string]any{"name": "a", "type": "pubkey[1025]"}},
		"zero-length array": {map[string]any{"name": "a", "type": "pubkey[0]"}},
		"flat name clash": {
			map[string]any{"name": "a", "type": "S"},
			map[string]any{"name": "a.x", "type": "int"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			doc := edited(t, []byte(idDoc), func(m map[string]any) {
				m["constructorInputs"] = inputs
				fnOf(m, 1)["leaves"].([]any)[0].(map[string]any)["asm"] = []any{"OP_1"}
				fnOf(m, 0)["arkade"].(map[string]any)["asm"] = []any{"OP_1"}
			})
			_, err := ParseArtifact(doc)
			require.ErrorIs(t, err, ErrInvalidArtifact)
		})
	}
}

func TestFlatConstructor(t *testing.T) {
	d := Definition{
		Structs:           []Struct{{Name: "Policy", Fields: []Field{{"owner", "pubkey"}, {"limit", "int"}}}},
		ConstructorInputs: []Field{{"owners", "pubkey[2]"}, {"policy", "Policy"}, {"h", "bytes32"}},
	}
	got, err := d.flatConstructor()
	require.NoError(t, err)
	require.Equal(t, []Field{{"owners.0", "pubkey"}, {"owners.1", "pubkey"}, {"policy.owner", "pubkey"}, {"policy.limit", "int"}, {"h", "bytes32"}}, got)
}

func TestFlatConstructorCap(t *testing.T) {
	nested := func(k int, leaf string) []byte {
		structs := []string{`{"name":"S0","fields":[` + leaf + `]}`}
		for i := 1; i <= k; i++ {
			prev := "S" + strconv.Itoa(i-1)
			structs = append(structs, `{"name":"S`+strconv.Itoa(i)+`","fields":[{"name":"a","type":"`+prev+`"},{"name":"b","type":"`+prev+`"}]}`)
		}
		return []byte(`{"contractName":"C","constructorInputs":[{"name":"x","type":"S` + strconv.Itoa(k) + `"}],"structs":[` +
			strings.Join(structs, ",") + `],"functions":[{"name":"f","leaves":[{"name":"l","witness":[],"asm":["OP_1"]}]}]}`)
	}
	for name, doc := range map[string][]byte{
		"arrays multiplied by structs": nested(10, `{"name":"a","type":"bytes[1024]"},{"name":"b","type":"bytes[1024]"}`),
		"empty structs multiplied":     nested(40, ``),
	} {
		t.Run(name, func(t *testing.T) {
			require.Less(t, len(doc), 4096)
			start := time.Now()
			_, err := ParseArtifact(doc)
			require.ErrorIs(t, err, ErrInvalidArtifact)
			require.Less(t, time.Since(start), time.Second)
		})
	}

	_, err := ParseArtifact(nested(0, `{"name":"a","type":"bytes[1024]"}`))
	require.NoError(t, err, "one full array fits")
}

const idDoc = `{"contractName":"C","constructorInputs":[{"name":"k","type":"pubkey"},{"name":"n","type":"int"}],
"structs":[{"name":"S","fields":[{"name":"x","type":"int"}]}],
"functions":[
{"name":"f","arkade":{"inputs":[{"name":"a","type":"int"}],"asm":["<k>","OP_CHECKSIG"]},"leaves":[
 {"name":"l1","witness":[{"name":"s","type":"signature","encoding":"schnorr-64","injected":true}],"asm":["<SERVER_KEY>","OP_CHECKSIGVERIFY","<EMULATOR_KEY:f>","OP_CHECKSIG"]},
 {"name":"l2","witness":[],"asm":["OP_1"]}]},
{"name":"g","leaves":[{"name":"m","witness":[],"asm":["<n>","OP_DROP","OP_1"]}]}]}`

func mustID(t *testing.T, doc []byte) string {
	t.Helper()
	a, err := ParseArtifact(doc)
	require.NoError(t, err)
	return a.ID
}

func fnOf(m map[string]any, i int) map[string]any {
	return m["functions"].([]any)[i].(map[string]any)
}

func leafOf(m map[string]any, f int) map[string]any {
	return fnOf(m, f)["leaves"].([]any)[0].(map[string]any)
}
