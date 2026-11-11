package template

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/executor/pkg/template/internal/schema"

	"github.com/stretchr/testify/require"
)

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

func TestBind(t *testing.T) {
	c := &compiler{named: map[string]bool{}, t: &Template{variables: map[string]string{}, secrets: map[string]secret{}}}
	n := func(x int64) schema.Binding { return schema.Binding{Int: &x} }
	b := func(x bool) schema.Binding { return schema.Binding{Bool: &x} }
	s := func(x string) schema.Binding { return schema.Binding{Str: &x} }
	for name, tc := range map[string]struct {
		in   schema.Binding
		typ  string
		want string
	}{
		"int":      {n(1024), "int", "0004"},
		"zero":     {n(0), "int", ""},
		"negative": {n(-1), "int", "81"},
		"true":     {b(true), "bool", "01"},
		"false":    {b(false), "bool", ""},
		"string":   {s("ab01"), "bytes", "ab01"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := c.bind(tc.in, tc.typ, true)
			require.NoError(t, err)
			lit, ok := got.literal()
			require.True(t, ok)
			require.Equal(t, tc.want, hex.EncodeToString(lit))
		})
	}

	p := "x"
	for name, tc := range map[string]struct {
		in  schema.Binding
		typ string
	}{
		"too large": {n(9007199254740992), "int"}, "bad string": {s("AB"), "bytes"},
		"int for bytes": {n(1), "bytes"}, "bool for int": {b(true), "int"},
		"program": {schema.Binding{Program: &p}, "bytes32"}, "empty": {schema.Binding{}, "bytes"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.bind(tc.in, tc.typ, true)
			require.ErrorIs(t, err, ErrInvalidTemplate)
		})
	}
}
