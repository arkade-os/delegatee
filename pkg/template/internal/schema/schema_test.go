package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/arkade-os/executor/pkg/template/internal/abi"
	"github.com/stretchr/testify/require"
)

func TestFixtureIDs(t *testing.T) {
	var ids map[string]string
	require.NoError(t, json.Unmarshal(fixture(t, "ids.json"), &ids))
	for name, id := range ids {
		t.Run(name, func(t *testing.T) {
			doc, err := Decode(fixture(t, name))
			require.NoError(t, err)
			doc.Normalize()
			b, err := doc.Canonical()
			require.NoError(t, err)
			sum := sha256.Sum256(b)
			require.Equal(t, id, hex.EncodeToString(sum[:]), "a fixture changed: update ids.json")
		})
	}
}

func TestDecodeAcceptsNullFeesAndPackets(t *testing.T) {
	doc := fixture(t, "minimal.json")
	without := canonicalOf(t, edited(t, doc, func(m map[string]any) { delete(m, "fees") }))
	nulled := edited(t, doc, func(m map[string]any) { m["fees"] = nil; m["packets"] = nil })
	got, err := Decode(nulled)
	require.NoError(t, err)
	require.Nil(t, got.Fees)
	require.Nil(t, got.Packets)
	require.Equal(t, without, canonicalOf(t, nulled))
}

func TestDecodeRejects(t *testing.T) {
	doc := fixture(t, "minimal.json")
	in := func(m map[string]any) map[string]any { return m["inputs"].([]any)[0].(map[string]any) }
	out := func(m map[string]any) map[string]any { return m["outputs"].([]any)[0].(map[string]any) }
	for name, edit := range map[string]func(map[string]any){
		"unknown field":         func(m map[string]any) { m["extra"] = 1 },
		"field in another case": func(m map[string]any) { m["Fees"] = m["fees"] },
		"null schedule":         func(m map[string]any) { in(m)["schedule"] = nil },
		"null variables":        func(m map[string]any) { m["variables"] = nil },
		"immediate false":       func(m map[string]any) { in(m)["schedule"] = map[string]any{"immediate": false} },
		"schedule two keys":     func(m map[string]any) { in(m)["schedule"] = map[string]any{"immediate": true, "min_confirmations": 1} },
		"format":                func(m map[string]any) { m["format"] = "template/v2" },
		"type":                  func(m map[string]any) { m["type"] = "batch" },
		"no input":              func(m map[string]any) { m["inputs"] = []any{} },
		"bad name":              func(m map[string]any) { in(m)["name"] = "Funds" },
		"sequence":              func(m map[string]any) { in(m)["sequence"] = 4294967295 },
		"rule on reserved type": func(m map[string]any) {
			m["packets"] = map[string]any{"output_index": 1, "rules": []any{map[string]any{"type": 5, "action": "drop", "from": "funds"}}}
		},
		"index too big":              func(m map[string]any) { out(m)["index"] = 65536 },
		"asset amount without asset": func(m map[string]any) { out(m)["assets"] = []any{map[string]any{"from": "funds", "amount": 5}} },
		"unmatched typo":             func(m map[string]any) { m["packets"] = map[string]any{"output_index": 1, "unmatched": "ignore"} },
		"program in a locking":       func(m map[string]any) { out(m)["locking"] = map[string]any{"program": "x"} },
		"binding of two keys": func(m map[string]any) {
			out(m)["value"].(map[string]any)["amount"] = map[string]any{"program": "x", "y": 1}
		},
		"empty pool":                func(m map[string]any) { out(m)["value"].(map[string]any)["from"] = []any{} },
		"taptree not a placeholder": func(m map[string]any) { in(m)["contract"].(map[string]any)["taptree"] = "tree" },
		"artifact ref extra key": func(m map[string]any) {
			in(m)["contract"].(map[string]any)["definition"] = map[string]any{"artifact": "00", "x": 1}
		},
		"empty input type":  func(m map[string]any) { in(m)["type"] = "" },
		"empty output type": func(m map[string]any) { out(m)["type"] = "" },
		"empty taptree":     func(m map[string]any) { in(m)["contract"].(map[string]any)["taptree"] = "" },
		"empty asset id":    func(m map[string]any) { out(m)["assets"] = []any{map[string]any{"from": "funds", "asset": ""}} },
		"empty unmatched":   func(m map[string]any) { m["packets"] = map[string]any{"output_index": 1, "unmatched": ""} },
		"null amount":       func(m map[string]any) { out(m)["value"].(map[string]any)["amount"] = nil },
		"array amount":      func(m map[string]any) { out(m)["value"].(map[string]any)["amount"] = []any{} },
		"object amount":     func(m map[string]any) { out(m)["value"].(map[string]any)["amount"] = map[string]any{"x": 1} },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(edited(t, doc, edit))
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
}

func TestPooledOutputValueIsRefused(t *testing.T) {
	for name, from := range map[string]any{"several inputs": []any{"funds", "extra"}, "one in a list": []any{"funds"}, "empty": []any{}} {
		doc := edited(t, fixture(t, "minimal.json"), func(m map[string]any) {
			m["outputs"].([]any)[0].(map[string]any)["value"] = map[string]any{"from": from}
		})
		_, err := Decode(doc)
		require.ErrorIs(t, err, ErrInvalid, name)
	}
}

func TestInlineDefinitionErrorIsArtifactOnly(t *testing.T) {
	doc := edited(t, fixture(t, "minimal.json"), func(m map[string]any) {
		m["inputs"].([]any)[0].(map[string]any)["contract"].(map[string]any)["definition"].(map[string]any)["functions"] = []any{}
	})
	_, err := Decode(doc)
	require.ErrorIs(t, err, abi.ErrInvalid)
	require.NotErrorIs(t, err, ErrInvalid)
}

func TestCanonicalKeepsForms(t *testing.T) {
	doc := fixture(t, "minimal.json")
	c := canonicalOf(t, edited(t, doc, func(m map[string]any) {
		m["fees"] = map[string]any{"from": "funds", "max": "<x>"}
		m["inputs"].([]any)[0].(map[string]any)["schedule"] = map[string]any{"before_expiry_seconds": 10}
		m["packets"] = map[string]any{"output_index": 1, "unmatched": "reject"}
	}))
	require.Contains(t, c, `"max":"<x>"`)
	require.Contains(t, c, `"before_expiry_seconds":10`)
	require.NotContains(t, c, "unmatched")

	claim := fixture(t, "claim.json")
	zero := edited(t, claim, func(m map[string]any) { m["trigger"].(map[string]any)["min_value"] = 0 })
	none := edited(t, claim, func(m map[string]any) { delete(m["trigger"].(map[string]any), "min_value") })
	require.Equal(t, canonicalOf(t, none), canonicalOf(t, zero))
	require.NotEqual(t, canonicalOf(t, claim), canonicalOf(t, zero))
}

func canonicalOf(t *testing.T, doc []byte) string {
	t.Helper()
	d, err := Decode(doc)
	require.NoError(t, err)
	d.Normalize()
	b, err := d.Canonical()
	require.NoError(t, err)
	return string(b)
}

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if errors.Is(err, fs.ErrNotExist) {
		doc, err = os.ReadFile(filepath.Join("..", "..", "..", "..", "templates", name))
	}
	require.NoError(t, err)
	return doc
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
