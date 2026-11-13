package asm

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
)

func TestAssemble(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	lookup := func(name string) (Value, error) {
		switch name {
		case "SERVER_KEY":
			return Value{Type: "bytes32", Raw: key}, nil
		case "delay":
			return Value{Type: "int", Raw: ScriptNum(4194306)}, nil
		case "zero":
			return Value{Type: "int", Raw: nil}, nil
		case "empty":
			return Value{Type: "bytes", Raw: nil}, nil
		case "one":
			return Value{"bool", []byte{1}}, nil
		case "nul":
			return Value{"bytes", []byte{0}}, nil
		case "big":
			return Value{Type: "bytes", Raw: make([]byte, 521)}, nil
		case "badint":
			return Value{"int", []byte{0x80}}, nil
		}
		return Value{}, fmt.Errorf("unknown %s", name)
	}
	want, err := txscript.NewScriptBuilder().
		AddInt64(4194306).AddOp(txscript.OP_CHECKSEQUENCEVERIFY).AddOp(txscript.OP_DROP).
		AddData(key).AddOp(txscript.OP_CHECKSIG).Script()
	require.NoError(t, err)
	got, err := Assemble(
		[]string{"<delay>", "OP_CHECKSEQUENCEVERIFY", "OP_DROP", "<SERVER_KEY>", "OP_CHECKSIG"},
		lookup,
	)
	require.NoError(t, err)
	require.Equal(t, want, got)

	got, err = Assemble(
		[]string{"4194306", "0x74797065", "OP_INSPECTINTENTMESSAGE", "<zero>", "16", "17", "-1"},
		lookup,
	)
	require.NoError(t, err)
	want, _ = txscript.NewScriptBuilder().AddInt64(4194306).AddData([]byte("type")).
		AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddInt64(0).AddInt64(16).AddInt64(17).AddInt64(-1).Script()
	require.Equal(t, want, got)

	got, err = Assemble(
		[]string{"0x05", "0x81", "<empty>", "<one>", "9007199254740991", "-9007199254740991"},
		lookup,
	)
	require.NoError(t, err)
	want, _ = txscript.NewScriptBuilder().AddData([]byte{5}).AddData([]byte{0x81}).AddData(nil).
		AddData([]byte{1}).AddInt64(1<<53 - 1).AddInt64(1 - 1<<53).Script()
	require.Equal(t, want, got)
	require.Equal(t, byte(txscript.OP_5), got[0])
	require.Equal(t, byte(txscript.OP_1NEGATE), got[1])

	for _, tokens := range [][]string{{"0x00"}, {"<nul>"}} {
		got, err = Assemble(tokens, lookup)
		require.NoError(t, err)
		require.Equal(t, []byte{0x01, 0x00}, got)
	}
	got, err = Assemble([]string{"<empty>"}, lookup)
	require.NoError(t, err)
	require.Equal(t, []byte{0x00}, got)

	got, err = Assemble(nil, lookup)
	require.NoError(t, err)
	require.Empty(t, got)

	for name, tokens := range map[string][]string{
		"unknown opcode":    {"OP_NOPE"},
		"uppercase hex":     {"0xAB"},
		"odd hex":           {"0xabc"},
		"unknown name":      {"<nope>"},
		"leading zero":      {"007"},
		"empty":             {""},
		"negative zero":     {"-0"},
		"too large":         {"9007199254740992"},
		"too small":         {"-9007199254740992"},
		"overflow":          {"99999999999999999999"},
		"long hex":          {"0x" + string(bytes.Repeat([]byte("ab"), 521))},
		"long value":        {"<big>"},
		"bad int value":     {"<badint>"},
		"empty placeholder": {"<>"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Assemble(tokens, lookup)
			require.Error(t, err)
		})
	}
}
