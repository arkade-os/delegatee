package application

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/delegatee/internal/core/domain"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestLeavesPay(t *testing.T) {
	leaf := func(outs ...*wire.TxOut) *psbt.Packet {
		return &psbt.Packet{UnsignedTx: &wire.MsgTx{TxOut: outs}}
	}
	alice, bob := []byte{0x51, 0x01}, []byte{0x51, 0x02}
	leaves := []*psbt.Packet{
		leaf(wire.NewTxOut(1000, alice), wire.NewTxOut(0, []byte{0x51})),
		leaf(wire.NewTxOut(1000, alice)),
		leaf(wire.NewTxOut(500, bob)),
	}

	require.NoError(t, leavesPay(leaves, []*wire.TxOut{
		wire.NewTxOut(1000, alice), wire.NewTxOut(500, bob), wire.NewTxOut(1000, alice),
	}))
	// the same leaf cannot pay two vtxos
	require.ErrorContains(t, leavesPay(leaves, []*wire.TxOut{
		wire.NewTxOut(1000, alice), wire.NewTxOut(1000, alice), wire.NewTxOut(1000, alice),
	}), "no leaf pays 1000")
	// right script, short amount
	require.ErrorContains(t, leavesPay(leaves, []*wire.TxOut{wire.NewTxOut(501, bob)}), "no leaf pays 501")
	require.ErrorContains(t, leavesPay(nil, []*wire.TxOut{wire.NewTxOut(500, bob)}), "no leaf pays")
}

func TestLeavesPayChecksAssets(t *testing.T) {
	const assetID = "abababababababababababababababababababababababababababababababab0000"
	script := []byte{0x51, 0x02}
	packet, err := assetPacketFor([]types.Vtxo{{Assets: []types.Asset{{AssetId: assetID, Amount: 5}}}})
	require.NoError(t, err)
	ext, err := (extension.Extension{packet}).TxOut()
	require.NoError(t, err)
	leaf := &psbt.Packet{UnsignedTx: &wire.MsgTx{TxOut: []*wire.TxOut{
		wire.NewTxOut(1_000, script), ext,
	}}}

	require.NoError(t, leavesPayWithAssets(
		[]*psbt.Packet{leaf},
		[]*wire.TxOut{wire.NewTxOut(1_000, script)},
		[][]types.Asset{{{AssetId: assetID, Amount: 5}}},
	))
	require.Error(t, leavesPayWithAssets(
		[]*psbt.Packet{leaf},
		[]*wire.TxOut{wire.NewTxOut(1_000, script)},
		[][]types.Asset{{{AssetId: assetID, Amount: 6}}},
	))
}

func TestRenewPaysTheFeeOrRefuses(t *testing.T) {
	env := newTestEnv(t)
	env.setFees("200.0")
	env.ark.streamErr = errBoom // stop right after the intents are built
	pays := dueInput(t, env, domain.Params{RenewalWindow: 600, MaxFee: 300}, 1, 10_000)
	refuses := dueInput(t, env, domain.Params{RenewalWindow: 600, MaxFee: 199}, 2, 10_000)
	free := dueInput(t, env, domain.Params{RenewalWindow: 600}, 3, 10_000)

	results := env.svc.renew(t.Context(), []renewalInput{pays, refuses, free})
	require.Len(t, results, 3)
	byOutpoint := map[string]error{}
	for _, r := range results {
		require.Len(t, r.inputs, 1)
		byOutpoint[r.inputs[0].vtxo.Outpoint.String()] = r.err
	}
	require.ErrorContains(t, byOutpoint[refuses.vtxo.Outpoint.String()], "intent fee 200 exceeds the delegation max fee 199")
	require.ErrorContains(t, byOutpoint[free.vtxo.Outpoint.String()], "exceeds the delegation max fee 0")
	require.ErrorContains(t, byOutpoint[pays.vtxo.Outpoint.String()], "event stream: boom")

	// only the payer reached the emulator, with its output short of exactly the fee
	require.Len(t, env.emulator.submitted, 1)
	proof, err := psbt.NewFromRawBytes(strings.NewReader(env.emulator.submitted[0].Proof), true)
	require.NoError(t, err)
	require.Equal(t, int64(9_800), proof.UnsignedTx.TxOut[0].Value)
	require.Equal(t, pays.pkScript, proof.UnsignedTx.TxOut[0].PkScript)
	require.Len(t, proof.UnsignedTx.TxIn, 2, "bip322 message input plus the vtxo")
	require.Contains(t, env.emulator.submitted[0].Message, env.svc.delegatePubKeyHex)
}

func TestRenewPricesOutputFeeAtTheActualOutputAmount(t *testing.T) {
	env := newTestEnv(t)
	env.ark.info.Fees = types.FeeInfo{IntentFees: arkfee.Config{
		IntentOffchainOutputProgram: "amount < 10000.0 ? 200.0 : 100.0",
	}}
	env.ark.streamErr = errBoom
	in := dueInput(t, env, domain.Params{RenewalWindow: 600, MaxFee: 300}, 1, 10_000)

	results := env.svc.renew(t.Context(), []renewalInput{in})
	require.Len(t, results, 1)
	require.ErrorContains(t, results[0].err, "event stream: boom")
	require.Len(t, env.emulator.submitted, 1)
	proof, err := psbt.NewFromRawBytes(strings.NewReader(env.emulator.submitted[0].Proof), true)
	require.NoError(t, err)
	require.Equal(t, int64(9_800), proof.UnsignedTx.TxOut[0].Value)
}

func TestRenewFeeErrors(t *testing.T) {
	env := newTestEnv(t)
	in := dueInput(t, env, domain.Params{RenewalWindow: 600}, 1, 1000)

	env.ark.infoErr = errBoom
	results := env.svc.renew(t.Context(), []renewalInput{in})
	require.Len(t, results, 1)
	require.ErrorIs(t, results[0].err, errBoom)

	env.ark.infoErr = nil
	env.setFees("not a program(")
	results = env.svc.renew(t.Context(), []renewalInput{in})
	require.ErrorContains(t, results[0].err, "arkd intent fees")
}

// One vtxo the emulator refuses must not drag down the others of its intent.
func TestRenewRetriesPerVtxo(t *testing.T) {
	env := newTestEnv(t)
	p := domain.Params{RenewalWindow: 600}
	d := env.register(t, p)
	c, err := env.svc.covenantFor(p)
	require.NoError(t, err)
	pkScript, leaf, err := env.svc.delegateLeaf(d, c)
	require.NoError(t, err)
	var inputs []renewalInput
	for n := 1; n <= 3; n++ {
		inputs = append(inputs, renewalInput{
			vtxo: env.vtxo(t, d, n, 1000, time.Minute), delegation: d,
			pkScript: pkScript, leaf: leaf, arkadeScript: c.arkadeScript,
		})
	}
	bad := inputs[1].vtxo.Txid
	env.emulator.reject = func(in emulatorclient.Intent) error {
		proof, err := psbt.NewFromRawBytes(strings.NewReader(in.Proof), true)
		require.NoError(t, err)
		for _, txin := range proof.UnsignedTx.TxIn {
			if txin.PreviousOutPoint.Hash.String() == bad {
				return errBoom
			}
		}
		return nil
	}

	results := env.svc.renew(t.Context(), inputs)
	require.Len(t, env.emulator.submitted, 4, "one intent of three, then one each")
	require.Len(t, env.ark.registered, 2)
	var rejected, stranded int
	for _, r := range results {
		switch {
		case strings.Contains(r.err.Error(), "emulator rejected intent"):
			rejected++
			require.Equal(t, bad, r.inputs[0].vtxo.Txid)
		case strings.Contains(r.err.Error(), "batch session"):
			stranded++ // the fake stream closes before any batch
		}
	}
	require.Equal(t, 1, rejected)
	require.Equal(t, 2, stranded)
}

func TestBuildIntentNeedsThePreviousTx(t *testing.T) {
	env := newTestEnv(t)
	in := dueInput(t, env, domain.Params{RenewalWindow: 600}, 1, 1000)
	env.indexer.prevMiss = true
	results := env.svc.renew(t.Context(), []renewalInput{in})
	require.ErrorContains(t, results[0].err, "virtual tx "+in.vtxo.Txid+" not found")

	env.indexer.prevMiss, env.indexer.txs[in.vtxo.Txid] = false, "garbage"
	results = env.svc.renew(t.Context(), []renewalInput{in})
	require.ErrorContains(t, results[0].err, "virtual tx")
}

func TestAssetPacket(t *testing.T) {
	packet, err := assetPacketFor([]types.Vtxo{{Amount: 1}, {Amount: 2}})
	require.NoError(t, err)
	require.Nil(t, packet, "no assets, no packet")

	gold := strings.Repeat("ab", 32) + "0000"
	silver := strings.Repeat("cd", 32) + "0100"
	packet, err = assetPacketFor([]types.Vtxo{
		{Assets: []types.Asset{{AssetId: gold, Amount: 5}}},
		{},
		{Assets: []types.Asset{{AssetId: silver, Amount: 7}, {AssetId: gold, Amount: 1}}},
	})
	require.NoError(t, err)
	require.Len(t, packet, 2, "one group per asset")
	// proof input i (vtxo i-1) pays output i-1
	require.Equal(t, uint16(1), packet[0].Inputs[0].Vin)
	require.Equal(t, uint16(0), packet[0].Outputs[0].Vout)
	require.Equal(t, uint16(3), packet[0].Inputs[1].Vin)
	require.Equal(t, uint16(2), packet[0].Outputs[1].Vout)
	require.Equal(t, uint64(7), packet[1].Outputs[0].Amount)

	_, err = assetPacketFor([]types.Vtxo{{Assets: []types.Asset{{AssetId: "zz", Amount: 1}}}})
	require.Error(t, err)
}

func TestBatchHandlerSelection(t *testing.T) {
	env := newTestEnv(t)
	hashed := func(id string) string {
		sum := sha256.Sum256([]byte(id))
		return hex.EncodeToString(sum[:])
	}
	mine, other := &pendingIntent{id: "mine"}, &pendingIntent{id: "later"}
	h := &batchHandler{svc: env.svc, pending: []*pendingIntent{mine, other}}

	skip, _, err := h.OnBatchStarted(t.Context(), client.BatchStartedEvent{Id: "b0", HashedIntentIds: []string{hashed("someone")}})
	require.NoError(t, err)
	require.True(t, skip, "not our batch")
	require.Empty(t, env.ark.confirmed)

	skip, timeout, err := h.OnBatchStarted(t.Context(), client.BatchStartedEvent{
		Id: "b1", HashedIntentIds: []string{hashed("mine")}, BatchExpiry: 1024,
	})
	require.NoError(t, err)
	require.False(t, skip)
	require.Equal(t, 1024*time.Second, timeout)
	require.Equal(t, []string{"mine"}, env.ark.confirmed)
	require.Equal(t, []*pendingIntent{mine}, h.inBatch)
	require.Equal(t, []*pendingIntent{other}, h.pending)
	require.Equal(t, arklib.LocktimeTypeSecond, h.batchExpiry.Type)

	_, _, err = h.OnBatchStarted(t.Context(), client.BatchStartedEvent{Id: "b2", HashedIntentIds: []string{hashed("later")}, BatchExpiry: 144})
	require.NoError(t, err)
	require.Equal(t, arklib.LocktimeTypeBlock, h.batchExpiry.Type)

	require.NoError(t, h.OnBatchFailed(t.Context(), client.BatchFailedEvent{Id: "another", Reason: "x"}))
	require.ErrorContains(t, h.OnBatchFailed(t.Context(), client.BatchFailedEvent{Id: "b2", Reason: "timeout"}), "batch b2 failed: timeout")

	// the no-op callbacks stay no-ops
	require.NoError(t, h.OnStreamStarted(t.Context(), client.StreamStartedEvent{}))
	require.NoError(t, h.OnBatchFinalized(t.Context(), client.BatchFinalizedEvent{}))
	require.NoError(t, h.OnTreeTxEvent(t.Context(), client.TreeTxEvent{}))
	require.NoError(t, h.OnTreeSignatureEvent(t.Context(), client.TreeSignatureEvent{}))
	done, err := h.OnTreeNonces(t.Context(), client.TreeNoncesEvent{})
	require.NoError(t, err)
	require.False(t, done)
}

func TestForfeits(t *testing.T) {
	env := newTestEnv(t)
	in := dueInput(t, env, domain.Params{RenewalWindow: 600}, 1, 1000)
	h := &batchHandler{svc: env.svc, inBatch: []*pendingIntent{{inputs: []renewalInput{in}}}}

	connectorTx := wire.NewMsgTx(3)
	connectorTx.AddTxOut(wire.NewTxOut(0, txutils.ANCHOR_PKSCRIPT))
	connectorTx.AddTxOut(wire.NewTxOut(330, []byte{0x51, 0x20}))
	connector := &psbt.Packet{UnsignedTx: connectorTx}

	forfeits, err := h.buildForfeits([]renewalInput{in}, []*psbt.Packet{connector})
	require.NoError(t, err)
	require.Len(t, forfeits, 1)
	forfeit, err := psbt.NewFromRawBytes(strings.NewReader(forfeits[0]), true)
	require.NoError(t, err)
	require.Len(t, forfeit.UnsignedTx.TxIn, 2)
	require.Equal(t, in.vtxo.Txid, forfeit.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String())
	require.Equal(t, wire.OutPoint{Hash: connectorTx.TxHash(), Index: 1}, forfeit.UnsignedTx.TxIn[1].PreviousOutPoint)
	require.Equal(t, env.svc.forfeitPkScript, forfeit.UnsignedTx.TxOut[0].PkScript)
	require.Equal(t, int64(1330), forfeit.UnsignedTx.TxOut[0].Value, "vtxo plus connector go to arkd")
	require.Equal(t, in.leaf.Script, forfeit.Inputs[0].TaprootLeafScript[0].Script)

	onlyAnchor := wire.NewMsgTx(3)
	onlyAnchor.AddTxOut(wire.NewTxOut(0, txutils.ANCHOR_PKSCRIPT))
	_, err = h.buildForfeits([]renewalInput{in}, []*psbt.Packet{{UnsignedTx: onlyAnchor}})
	require.ErrorContains(t, err, "connector not found")

	// nothing is forfeited for a batch that cannot be verified
	_, err = h.OnBatchFinalization(t.Context(), client.BatchFinalizationEvent{}, nil, nil)
	require.ErrorContains(t, err, "refusing to forfeit")
}

func dueInput(t *testing.T, env *testEnv, p domain.Params, n int, amount uint64) renewalInput {
	t.Helper()
	d := env.register(t, p)
	c, err := env.svc.covenantFor(d.Params)
	require.NoError(t, err)
	pkScript, leaf, err := env.svc.delegateLeaf(d, c)
	require.NoError(t, err)
	return renewalInput{
		vtxo: env.vtxo(t, d, n, amount, time.Minute), delegation: d,
		pkScript: pkScript, leaf: leaf, arkadeScript: c.arkadeScript,
	}
}
