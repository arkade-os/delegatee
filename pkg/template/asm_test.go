package template

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
	lookup := func(name string) (value, error) {
		switch name {
		case "SERVER_KEY":
			return value{"bytes32", key}, nil
		case "delay":
			return value{"int", scriptNum(4194306)}, nil
		case "zero":
			return value{"int", nil}, nil
		case "empty":
			return value{"bytes", nil}, nil
		case "one":
			return value{"bool", []byte{1}}, nil
		case "nul":
			return value{"bytes", []byte{0}}, nil
		case "big":
			return value{"bytes", make([]byte, 521)}, nil
		case "badint":
			return value{"int", []byte{0x80}}, nil
		}
		return value{}, fmt.Errorf("unknown %s", name)
	}
	want, err := txscript.NewScriptBuilder().
		AddInt64(4194306).AddOp(txscript.OP_CHECKSEQUENCEVERIFY).AddOp(txscript.OP_DROP).
		AddData(key).AddOp(txscript.OP_CHECKSIG).Script()
	require.NoError(t, err)
	got, err := assemble([]string{"<delay>", "OP_CHECKSEQUENCEVERIFY", "OP_DROP", "<SERVER_KEY>", "OP_CHECKSIG"}, lookup)
	require.NoError(t, err)
	require.Equal(t, want, got)

	got, err = assemble([]string{"4194306", "0x74797065", "OP_INSPECTINTENTMESSAGE", "<zero>", "16", "17", "-1"}, lookup)
	require.NoError(t, err)
	want, _ = txscript.NewScriptBuilder().AddInt64(4194306).AddData([]byte("type")).
		AddOp(arkade.OP_INSPECTINTENTMESSAGE).AddInt64(0).AddInt64(16).AddInt64(17).AddInt64(-1).Script()
	require.Equal(t, want, got)

	got, err = assemble([]string{"0x05", "0x81", "<empty>", "<one>", "9007199254740991", "-9007199254740991"}, lookup)
	require.NoError(t, err)
	want, _ = txscript.NewScriptBuilder().AddData([]byte{5}).AddData([]byte{0x81}).AddData(nil).
		AddData([]byte{1}).AddInt64(1<<53 - 1).AddInt64(1 - 1<<53).Script()
	require.Equal(t, want, got)
	require.Equal(t, byte(txscript.OP_5), got[0])
	require.Equal(t, byte(txscript.OP_1NEGATE), got[1])

	for _, tokens := range [][]string{{"0x00"}, {"<nul>"}} {
		got, err = assemble(tokens, lookup)
		require.NoError(t, err)
		require.Equal(t, []byte{0x01, 0x00}, got)
	}
	got, err = assemble([]string{"<empty>"}, lookup)
	require.NoError(t, err)
	require.Equal(t, []byte{0x00}, got)

	got, err = assemble(nil, lookup)
	require.NoError(t, err)
	require.Empty(t, got)

	for name, tokens := range map[string][]string{
		"unknown opcode": {"OP_NOPE"}, "uppercase hex": {"0xAB"}, "odd hex": {"0xabc"},
		"unknown name": {"<nope>"}, "leading zero": {"007"}, "empty": {""},
		"negative zero": {"-0"}, "too large": {"9007199254740992"}, "too small": {"-9007199254740992"},
		"overflow": {"99999999999999999999"}, "long hex": {"0x" + string(bytes.Repeat([]byte("ab"), 521))},
		"long value": {"<big>"}, "bad int value": {"<badint>"}, "empty placeholder": {"<>"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := assemble(tokens, lookup)
			require.Error(t, err)
		})
	}
}
