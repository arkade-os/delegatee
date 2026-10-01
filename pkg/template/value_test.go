package template

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalBytes(t *testing.T) {
	key, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	for _, tc := range []struct {
		name, typ string
		raw       []byte
		ok        bool
	}{
		{"pubkey", "pubkey", key, true},
		{"x-only is not a pubkey", "pubkey", key[1:], false},
		{"above the field", "pubkey", append([]byte{2}, bytes.Repeat([]byte{0xff}, 32)...), false},
		{"not on curve", "pubkey", append([]byte{2}, bytes.Repeat([]byte{0x05}, 32)...), false},
		{"bytes32", "bytes32", make([]byte, 32), true},
		{"bytes32 short", "bytes32", make([]byte, 31), false},
		{"bytes20", "bytes20", make([]byte, 20), true},
		{"bytes any", "bytes", []byte{1, 2, 3}, true},
		{"bytes of a push", "bytes", make([]byte, 520), true},
		{"bytes over a push", "bytes", make([]byte, 521), false},
		{"asset", "asset", make([]byte, 32), true},
		{"int zero is empty", "int", nil, true},
		{"int 1024", "int", []byte{0x00, 0x04}, true},
		{"int with a padding byte", "int", []byte{0x01, 0x00}, false},
		{"int negative zero", "int", []byte{0x80}, false},
		{"bool true", "bool", []byte{1}, true},
		{"bool false", "bool", nil, true},
		{"bool two", "bool", []byte{2}, false},
		{"signature", "signature", make([]byte, 64), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := canonicalBytes(tc.typ, tc.raw)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrInvalidVariables)
				if len(tc.raw) > 2 {
					require.NotContains(t, err.Error(), hex.EncodeToString(tc.raw[1:4]), "no plaintext")
				}
			}
		})
	}
}

func TestParseByteTemplate(t *testing.T) {
	b, err := parseByteTemplate("5120<receiver_program>")
	require.NoError(t, err)
	require.Equal(t, byteTemplate{{hex: []byte{0x51, 0x20}}, {name: "receiver_program"}}, b)

	b, err = parseByteTemplate("$(2 OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTPACKET OP_VERIFY)")
	require.NoError(t, err)
	require.Equal(t, []string{"2", "OP_PUSHCURRENTINPUTINDEX", "OP_INSPECTINPUTPACKET", "OP_VERIFY"}, b[0].expr)

	b, err = parseByteTemplate("$(<preimage> OP_HASH160)")
	require.NoError(t, err)
	require.Equal(t, []string{"<preimage>", "OP_HASH160"}, b[0].expr)
	require.Equal(t, []string{"preimage"}, b.names())

	b, err = parseByteTemplate("01$(1 OP_1ADD)ff")
	require.NoError(t, err)
	require.Len(t, b, 3)
	_, ok := b.literal()
	require.False(t, ok)

	b, err = parseByteTemplate("<a>$(<b> <a>)<b>")
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, b.names())

	b, err = parseByteTemplate("")
	require.NoError(t, err)
	lit, ok := b.literal()
	require.True(t, ok)
	require.Empty(t, lit)

	for name, in := range map[string]string{
		"uppercase hex": "AB", "odd hex": "abc", "double space": "$(1  2)", "leading space": "$( 1)",
		"trailing space": "$(1 )", "empty expression": "$()",
		"unclosed": "$(1", "bad name": "<Owner>", "empty name": "<>", "nested": "$($(1))",
		"unclosed name": "<a", "bad name in expression": "$(<A>)", "stray char": "zz",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseByteTemplate(in)
			require.ErrorIs(t, err, ErrInvalidTemplate)
		})
	}
}

func TestParseBinding(t *testing.T) {
	for name, tc := range map[string]struct {
		in   any
		want string
	}{
		"int":      {json.Number("1024"), "0004"},
		"zero":     {json.Number("0"), ""},
		"negative": {json.Number("-1"), "81"},
		"true":     {true, "01"},
		"false":    {false, ""},
		"string":   {"ab01", "ab01"},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := parseBinding(tc.in)
			require.NoError(t, err)
			lit, ok := b.literal()
			require.True(t, ok)
			require.Equal(t, tc.want, hex.EncodeToString(lit))
		})
	}

	for name, in := range map[string]any{
		"null": nil, "array": []any{}, "object": map[string]any{}, "fraction": json.Number("1.5"),
		"too large": json.Number("9007199254740992"), "bad string": "AB",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseBinding(in)
			require.ErrorIs(t, err, ErrInvalidTemplate)
		})
	}
}

func TestScriptNum(t *testing.T) {
	const max = 1<<53 - 1
	for n, want := range map[int64]string{
		0: "", 1: "01", -1: "81", 127: "7f", 128: "8000", 1024: "0004", 1791000000: "c07dc06a",
		max: "ffffffffffff1f", -max: "ffffffffffff9f",
	} {
		require.Equal(t, want, hex.EncodeToString(scriptNum(n)))
		got, err := parseScriptNum(scriptNum(n))
		require.NoError(t, err)
		require.Equal(t, n, got)
	}

	for name, raw := range map[string][]byte{
		"padded":        {0x01, 0x00},
		"negative zero": {0x80},
		"zero byte":     {0x00},
		"padded sign":   {0x01, 0x80},
		"too large":     {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20},
		"too long":      {1, 2, 3, 4, 5, 6, 7, 8, 9},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseScriptNum(raw)
			require.ErrorIs(t, err, ErrInvalidVariables)
		})
	}
}
