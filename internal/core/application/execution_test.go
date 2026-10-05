package application

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestBuild(t *testing.T) {
	env := newTestEnv(t)
	in := dueInput(t, env, 0, 1000)
	coins, err := env.svc.sourcedCoins(t.Context(), []renewalInput{in})
	require.NoError(t, err)
	c := coins[0]
	ptx, err := env.svc.build(t.Context(), in.watched, coins, arkfee.Config{})
	require.NoError(t, err)
	require.Equal(t, c.Script, ptx.UnsignedTx.TxOut[0].PkScript)
	require.Equal(t, c.Outpoint, ptx.UnsignedTx.TxIn[0].PreviousOutPoint)

	_, err = env.svc.build(t.Context(), in.watched, []coin{c, c}, arkfee.Config{})
	require.ErrorIs(t, err, ErrIneligible)
	second := c
	second.Slot = 1
	_, err = env.svc.build(t.Context(), in.watched, []coin{second}, arkfee.Config{})
	require.ErrorIs(t, err, ErrIneligible)
	asset := c
	asset.Assets = []clientlib.Asset{{AssetId: "x", Amount: 1}}
	_, err = env.svc.build(t.Context(), in.watched, []coin{asset}, arkfee.Config{})
	require.ErrorIs(t, err, ErrIneligible)
	require.ErrorContains(t, err, "asset id")
	moved := c
	moved.Script = []byte{0x51}
	moved.Source = wire.NewMsgTx(3)
	moved.Source.AddTxIn(&wire.TxIn{})
	moved.Source.AddTxOut(wire.NewTxOut(int64(c.Amount), moved.Script))
	moved.Outpoint = wire.OutPoint{Hash: moved.Source.TxHash()}
	_, err = env.svc.build(t.Context(), in.watched, []coin{moved}, arkfee.Config{})
	require.ErrorIs(t, err, ErrIneligible, "a module refusal")
	require.ErrorIs(t, err, template.ErrIneligible, "the original stays in the chain")
}

func TestOnchainFee(t *testing.T) {
	e, inputs := releaseEnv(t)
	w := inputs[0].watched
	feeCap, ok := w.instance.FeeCap()
	require.True(t, ok)
	require.Equal(t, uint64(1000), feeCap)
	coins, err := e.svc.sourcedCoins(t.Context(), inputs)
	require.NoError(t, err)
	fee := func(t *testing.T) (int64, int) {
		t.Helper()
		ptx, err := e.svc.build(t.Context(), w, coins, arkfee.Config{})
		require.NoError(t, err)
		return int64(coins[0].Amount) - ptx.UnsignedTx.TxOut[0].Value, signedVsize(ptx)
	}
	e.svc.maxOnchainFeeRate = 5
	low, vsize := fee(t)
	require.Equal(t, int64(2*vsize), low)
	e.explorer.feeRate = 1000
	high, vsize := fee(t)
	require.LessOrEqual(t, float64(high), 5*float64(vsize), "the cap the executor checks")
	require.Greater(t, high, low, "the rate is capped, not refused")
	require.LessOrEqual(t, high, int64(feeCap))
	e.explorer.feeRate = 0.2
	floor, vsize := fee(t)
	require.Equal(t, int64(vsize), floor, "never under 1 sat/vB")

	e.explorer.feeRate = 0
	_, err = e.svc.build(t.Context(), w, coins, arkfee.Config{})
	require.ErrorIs(t, err, ErrIneligible)
	require.ErrorContains(t, err, "fee rate 0")
	e.explorer.feeErr = errBoom
	_, err = e.svc.build(t.Context(), w, coins, arkfee.Config{})
	require.ErrorIs(t, err, ErrIneligible)
}

func TestDueTime(t *testing.T) {
	env := newTestEnv(t)
	tmpl, err := template.Parse(t.Context(), document(t, "minimal.json"), nil)
	require.NoError(t, err)
	inst, err := env.svc.newInstance(t.Context(), tmpl, env.svc.cosigners[0], nil, nil, nil)
	require.NoError(t, err)
	created := time.Now().Add(-time.Hour).Truncate(time.Second)
	require.Equal(t, created, dueTime(inst, coin{CreatedAt: created}, noTip))
	for name, c := range map[string]coin{
		"immediate":       {},
		"malformed asset": {CreatedAt: created, Assets: []clientlib.Asset{{AssetId: "x"}}},
	} {
		require.WithinDuration(t, time.Now(), dueTime(inst, c, noTip), time.Minute, name)
	}
}

// signedVsize is ptx's virtual size once each input carries a signature, its leaf and its control block.
func signedVsize(ptx *psbt.Packet) int {
	tx := ptx.UnsignedTx.Copy()
	for i, in := range tx.TxIn {
		leaf := ptx.Inputs[i].TaprootLeafScript[0]
		in.Witness = wire.TxWitness{make([]byte, 64), leaf.Script, leaf.ControlBlock}
	}
	return (tx.SerializeSizeStripped()*3 + tx.SerializeSize() + 3) / 4
}
