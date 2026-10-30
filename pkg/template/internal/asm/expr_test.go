package asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/stretchr/testify/require"
)

func TestCheckExpressionComputeLimits(t *testing.T) {
	modexp := func(n int) []string {
		return strings.Fields(strings.Repeat("2 3 5 OP_MODEXP OP_DROP ", n))
	}
	require.NoError(t, CheckExpression(modexp(64)))
	require.ErrorIs(t, CheckExpression(modexp(65)), ErrBadExpression)
}

func TestCheckExpression(t *testing.T) {
	for _, op := range []string{
		"OP_INSPECTOUTPUTVALUE", "OP_INSPECTOUTPUTSCRIPTPUBKEY", "OP_INSPECTNUMOUTPUTS", "OP_TUNNEL", "OP_INSPECTPACKET",
		"OP_INSPECTNUMASSETGROUPS", "OP_FINDASSETGROUPBYASSETID", "OP_INSPECTINPUTARKADESCRIPTHASH", "OP_INSPECTINTENTMESSAGE",
		"OP_TXID", "OP_TXWEIGHT", "OP_SIGHASH", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKSIGADD",
		"OP_INSPECTINASSETCOUNT", "OP_INSPECTOUTASSETCOUNT",
	} {
		require.ErrorIs(t, CheckExpression([]string{op}), ErrBadExpression, op)
	}
	require.NoError(t, CheckExpression(strings.Fields("2 OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTPACKET OP_VERIFY")))
	require.True(t, ContextFree([]string{"<preimage>", "OP_HASH160"}))
	for _, op := range []string{"OP_INSPECTINPUTPACKET", "OP_PUSHCURRENTINPUTINDEX", "OP_INSPECTINPUTVALUE", "OP_PUSHEXPIRY", "OP_CHECKTIME", "OP_INSPECTVERSION", "OP_INSPECTLOCKTIME",
		"OP_CHECKLOCKTIMEVERIFY", "OP_NOP2", "OP_CHECKSEQUENCEVERIFY", "OP_NOP3"} {
		require.False(t, ContextFree([]string{op}), op)
	}
}

func TestPushOpcodesRefused(t *testing.T) {
	hidden := func(op byte) string { return fmt.Sprintf("0x01%02x", op) }
	require.ErrorIs(t, CheckExpression([]string{"OP_DATA_2", hidden(arkade.OP_INSPECTNUMOUTPUTS), "OP_NIP"}), ErrBadExpression)
	many := []string{}
	for range 100 {
		many = append(many, "OP_DATA_2", hidden(arkade.OP_INSPECTINTENTMESSAGE), "OP_NIP")
	}
	require.ErrorIs(t, CheckExpression(many), ErrBadExpression)
	for _, op := range []string{"OP_DATA_1", "OP_DATA_75", "OP_PUSHDATA1", "OP_PUSHDATA2", "OP_PUSHDATA4"} {
		_, err := Assemble([]string{op, "0x01"}, nil)
		require.Error(t, err, op)
	}
}
