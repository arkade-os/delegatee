package template

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestEvalReadsSourcePacket(t *testing.T) {
	owner := testKey(t, 2).SerializeCompressed()
	src := sourceWith(t, 100_000, packets.Raw(packets.TypeState, owner))
	d := newDraft(Intent, []*Source{src})
	got, err := d.eval([]string{"2", "OP_PUSHCURRENTINPUTINDEX", "OP_INSPECTINPUTPACKET", "OP_VERIFY"}, d.index(0), nil)
	require.NoError(t, err)
	require.Equal(t, owner, got)
}

func TestEvalCounter(t *testing.T) {
	src := sourceWith(t, 100_000, packets.Raw(packets.TypeState, []byte{5, 0, 0, 0, 0, 0, 0, 0}))
	d := newDraft(Intent, []*Source{src})
	got, err := d.eval(strings.Fields("2 OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTPACKET OP_VERIFY OP_BIN2NUM OP_1ADD 8 OP_NUM2BIN"), d.index(0), nil)
	require.NoError(t, err)
	require.Equal(t, []byte{6, 0, 0, 0, 0, 0, 0, 0}, got)
}

func TestEvalIneligible(t *testing.T) {
	bare := sourceWith(t, 100_000) // no extension
	d := newDraft(Intent, []*Source{bare})
	for name, expr := range map[string]string{
		"missing packet":    "2 OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTPACKET OP_VERIFY",
		"two elements":      "1 2",
		"empty stack":       "1 OP_DROP",
		"script error":      "OP_ADD",
		"element too large": "0x" + strings.Repeat("00", 300) + " OP_DUP OP_CAT",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := d.eval(strings.Fields(expr), d.index(0), nil)
			require.ErrorIs(t, err, ErrIneligible)
		})
	}
	got, err := d.eval([]string{"OP_0"}, d.index(0), nil)
	require.NoError(t, err, "an empty element is a valid result")
	require.Empty(t, got)
}

func TestEvalPlaceholderAndIntrospection(t *testing.T) {
	src := sourceWith(t, 100_000)
	d := newDraft(Offchain, []*Source{src})
	preimage := bytes.Repeat([]byte{7}, 32)
	got, err := d.eval([]string{"<preimage>", "OP_HASH160"}, 0, func(string) (value, error) { return value{"bytes32", preimage}, nil })
	require.NoError(t, err)
	require.Equal(t, address.Hash160(preimage), got)

	got, err = d.eval([]string{"OP_PUSHCURRENTINPUTINDEX", "OP_INSPECTINPUTVALUE"}, 0, nil)
	require.NoError(t, err)
	require.Equal(t, scriptNum(100_000), got)
}

func TestEvalIntentMessageInput(t *testing.T) {
	d := newDraft(Intent, []*Source{sourceWith(t, 100_000)})
	got, err := d.eval(strings.Fields("0 OP_INSPECTINPUTSCRIPTPUBKEY OP_DROP"), d.index(0), nil)
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{1}, 32), got)

	got, err = d.eval(strings.Fields("0 OP_INSPECTINPUTVALUE"), d.index(0), nil)
	require.NoError(t, err)
	require.Empty(t, got)

	_, err = d.eval(strings.Fields("2 0 OP_INSPECTINPUTPACKET"), d.index(0), nil)
	require.ErrorIs(t, err, ErrIneligible)
}

func TestEvalRefusesUnboundSource(t *testing.T) {
	for name, mutate := range map[string]func(*Source){
		"hash mismatch":  func(s *Source) { s.Outpoint.Hash[0] ^= 1 },
		"index range":    func(s *Source) { s.Outpoint.Index = 5 },
		"amount differs": func(s *Source) { s.Amount++ },
	} {
		t.Run(name, func(t *testing.T) {
			src := sourceWith(t, 100_000, packets.Raw(packets.TypeState, []byte{1}))
			mutate(src)
			d := newDraft(Offchain, []*Source{src})
			for _, expr := range []string{"0 OP_INSPECTINPUTVALUE", "0 OP_INSPECTINPUTSCRIPTPUBKEY", "2 0 OP_INSPECTINPUTPACKET"} {
				_, err := d.eval(strings.Fields(expr), 0, nil)
				require.ErrorIs(t, err, ErrIneligible, expr)
			}
		})
	}
}

func TestEvalRebound(t *testing.T) {
	src := sourceWith(t, 100_000)
	lockTo(src, append([]byte{0x51, 0x20}, bytes.Repeat([]byte{2}, 32)...))
	d := newDraft(Offchain, []*Source{src})
	got, err := d.eval(strings.Fields("0 OP_INSPECTINPUTSCRIPTPUBKEY OP_DROP"), 0, nil)
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{2}, 32), got)
}

func TestEvalWithoutTx(t *testing.T) {
	src := sourceWith(t, 100_000)
	src.Tx = nil
	d := newDraft(Offchain, []*Source{src})
	got, err := d.eval(strings.Fields("0 OP_INSPECTINPUTVALUE"), 0, nil)
	require.NoError(t, err)
	require.Equal(t, scriptNum(100_000), got)
	_, err = d.eval(strings.Fields("2 0 OP_INSPECTINPUTPACKET"), 0, nil)
	require.ErrorIs(t, err, ErrIneligible)
}

func TestEvalErrorHidesValues(t *testing.T) {
	plain := []byte{0xc3, 0xc3, 0x43, 0x00}
	d := newDraft(Offchain, []*Source{sourceWith(t, 100_000)})
	_, err := d.eval([]string{"<s>", "OP_1ADD"}, 0, func(string) (value, error) { return value{"bytes", plain}, nil })
	require.ErrorIs(t, err, ErrIneligible)
	require.NotContains(t, err.Error(), hex.EncodeToString(plain))
	require.Contains(t, err.Error(), "ErrMinimalData")
}

func TestCheckExpressionComputeLimits(t *testing.T) {
	modexp := func(n int) []string {
		return strings.Fields(strings.Repeat("2 3 5 OP_MODEXP OP_DROP ", n))
	}
	require.NoError(t, checkExpression(modexp(64)))
	require.ErrorIs(t, checkExpression(modexp(65)), ErrInvalidTemplate)
}

func TestCheckExpression(t *testing.T) {
	for _, op := range []string{
		"OP_INSPECTOUTPUTVALUE", "OP_INSPECTOUTPUTSCRIPTPUBKEY", "OP_INSPECTNUMOUTPUTS", "OP_TUNNEL", "OP_INSPECTPACKET",
		"OP_INSPECTNUMASSETGROUPS", "OP_FINDASSETGROUPBYASSETID", "OP_INSPECTINPUTARKADESCRIPTHASH", "OP_INSPECTINTENTMESSAGE",
		"OP_TXID", "OP_TXWEIGHT", "OP_SIGHASH", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKSIGADD",
		"OP_INSPECTINASSETCOUNT", "OP_INSPECTOUTASSETCOUNT",
	} {
		require.ErrorIs(t, checkExpression([]string{op}), ErrInvalidTemplate, op)
	}
	require.NoError(t, checkExpression(strings.Fields("2 OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTPACKET OP_VERIFY")))
	require.True(t, contextFree([]string{"<preimage>", "OP_HASH160"}))
	for _, op := range []string{"OP_INSPECTINPUTPACKET", "OP_PUSHCURRENTINPUTINDEX", "OP_INSPECTINPUTVALUE", "OP_PUSHEXPIRY", "OP_CHECKTIME", "OP_INSPECTVERSION", "OP_INSPECTLOCKTIME",
		"OP_CHECKLOCKTIMEVERIFY", "OP_NOP2", "OP_CHECKSEQUENCEVERIFY", "OP_NOP3"} {
		require.False(t, contextFree([]string{op}), op)
	}
}

// sourceWith returns a source whose output 0 holds amount at a fixed P2TR script.
func sourceWith(t testing.TB, amount int64, pkts ...extension.Packet) *Source {
	t.Helper()
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})
	tx.AddTxOut(wire.NewTxOut(amount, append([]byte{0x51, 0x20}, bytes.Repeat([]byte{1}, 32)...)))
	if len(pkts) > 0 {
		out, err := extension.Extension(pkts).TxOut()
		require.NoError(t, err)
		tx.AddTxOut(out)
	}
	return &Source{Outpoint: wire.OutPoint{Hash: tx.TxHash()}, Tx: tx, Amount: uint64(amount)}
}

// lockTo moves output 0 of src's transaction to script.
func lockTo(src *Source, script []byte) {
	src.Tx.TxOut[0].PkScript = script
	src.Outpoint.Hash = src.Tx.TxHash()
}
