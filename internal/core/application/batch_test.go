package application

import (
	"encoding/hex"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

var testExpiry = arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1024}

// testBatch is what an honest arkd proposes for the given outputs: a
// commitment tx whose output 0 funds the vtxo tree and output 1 the connectors.
type testBatch struct {
	commitment string
	vtxoTree   *tree.TxTree
	connectors *tree.TxTree
	amount     int64
}

func buildBatch(t *testing.T, env *testEnv, outputs []*wire.TxOut, connectors int) testBatch {
	t.Helper()
	sweepRoot, err := sweepTapTreeRoot(env.svc.forfeitPubKey, testExpiry)
	require.NoError(t, err)
	leaves := make([]tree.Leaf, len(outputs))
	for i, out := range outputs {
		leaves[i] = tree.Leaf{
			Outputs:             []tree.LeafOutput{{Amount: uint64(out.Value), Script: hex.EncodeToString(out.PkScript)}},
			CosignersPublicKeys: []string{env.svc.delegatePubKeyHex},
		}
	}
	forfeitKey := hex.EncodeToString(env.svc.forfeitPubKey.SerializeCompressed())
	connectorLeaves := make([]tree.Leaf, connectors)
	for i := range connectorLeaves {
		connectorLeaves[i] = tree.Leaf{
			Outputs:             []tree.LeafOutput{{Amount: 330, Script: hex.EncodeToString(env.svc.forfeitPkScript)}},
			CosignersPublicKeys: []string{forfeitKey},
		}
	}

	batchScript, batchAmount, err := tree.BuildBatchOutput(leaves, sweepRoot)
	require.NoError(t, err)
	connectorScript, connectorAmount, err := tree.BuildConnectorOutput(connectorLeaves)
	require.NoError(t, err)
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 7}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(batchAmount, batchScript))
	tx.AddTxOut(wire.NewTxOut(connectorAmount, connectorScript))
	commitment, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	b64, err := commitment.B64Encode()
	require.NoError(t, err)

	txid := tx.TxHash()
	vtxoTree, err := tree.BuildVtxoTree(&wire.OutPoint{Hash: txid, Index: 0}, leaves, sweepRoot, testExpiry)
	require.NoError(t, err)
	connectorTree, err := tree.BuildConnectorTree(&wire.OutPoint{Hash: txid, Index: 1}, connectorLeaves)
	require.NoError(t, err)
	return testBatch{b64, vtxoTree, connectorTree, batchAmount}
}

func TestValidateBatch(t *testing.T) {
	env := newTestEnv(t)
	alice, bob := append([]byte{0x51, 0x20}, make([]byte, 32)...), append([]byte{0x51, 0x20}, make([]byte, 32)...)
	bob[5] = 1
	ours := []*wire.TxOut{wire.NewTxOut(10_000, alice), wire.NewTxOut(10_000, alice), wire.NewTxOut(5_000, bob)}
	// the batch also serves someone else
	batch := buildBatch(t, env, append([]*wire.TxOut{wire.NewTxOut(777, bob)}, ours...), 3)
	validate := func(b testBatch, outputs []*wire.TxOut) error {
		return validateBatch(b.commitment, b.vtxoTree, b.connectors, env.svc.forfeitPubKey, testExpiry, outputs)
	}
	require.NoError(t, validate(batch, ours))

	t.Run("a coin is missing", func(t *testing.T) {
		short := buildBatch(t, env, ours[:2], 3)
		require.ErrorContains(t, validate(short, ours), "no leaf pays 5000")
	})
	t.Run("a coin is short-paid", func(t *testing.T) {
		cheap := buildBatch(t, env, []*wire.TxOut{ours[0], ours[1], wire.NewTxOut(4_999, bob)}, 3)
		require.ErrorContains(t, validate(cheap, ours), "no leaf pays 5000")
	})
	t.Run("one leaf for two identical coins", func(t *testing.T) {
		single := buildBatch(t, env, ours[1:], 3)
		require.ErrorContains(t, validate(single, ours), "no leaf pays 10000")
	})
	t.Run("trees of another commitment tx", func(t *testing.T) {
		other := buildBatch(t, env, append(ours, wire.NewTxOut(1, bob)), 3)
		mixed := batch
		mixed.vtxoTree = other.vtxoTree
		require.ErrorContains(t, validate(mixed, ours), "vtxo tree")
		// forfeits valid without this commitment tx ever confirming
		mixed = batch
		mixed.connectors = other.connectors
		require.ErrorContains(t, validate(mixed, ours), "connectors spend")
	})
	t.Run("sweepable by someone else, or sooner", func(t *testing.T) {
		stranger := newTestEnv(t)
		require.ErrorContains(t,
			validateBatch(batch.commitment, batch.vtxoTree, batch.connectors, stranger.svc.forfeitPubKey, testExpiry, ours),
			"vtxo tree")
		sooner := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512}
		require.ErrorContains(t,
			validateBatch(batch.commitment, batch.vtxoTree, batch.connectors, env.svc.forfeitPubKey, sooner, ours),
			"vtxo tree")
	})
	t.Run("garbage", func(t *testing.T) {
		require.ErrorContains(t, validate(testBatch{"nope", batch.vtxoTree, batch.connectors, 0}, ours), "commitment tx")
		require.ErrorContains(t, validate(testBatch{batch.commitment, batch.vtxoTree, nil, 0}, ours), "connector tree is missing")
		require.ErrorContains(t, validate(testBatch{batch.commitment, nil, batch.connectors, 0}, ours), "vtxo tree is missing")
	})
}

// The whole cosigner role against an honest coordinator: nonces, signatures,
// then forfeits, which only leave once the batch checks out.
func TestBatchHandlerSignsAndForfeits(t *testing.T) {
	env := newTestEnv(t)
	first := dueInput(t, env, domain.Params{RenewalWindow: 600}, 1, 10_000)
	second := dueInput(t, env, domain.Params{RenewalWindow: 700}, 2, 20_000)
	for _, in := range []*renewalInput{&first, &second} {
		in.output = wire.NewTxOut(int64(in.vtxo.Amount), in.pkScript)
	}
	batch := buildBatch(t, env, []*wire.TxOut{first.output, second.output}, 2)
	h := &batchHandler{
		svc: env.svc, signerSession: tree.NewTreeSignerSession(env.svc.key), batchExpiry: testExpiry,
		inBatch: []*pendingIntent{{inputs: []renewalInput{first}}, {inputs: []renewalInput{second}}},
	}
	ctx := t.Context()

	skip, err := h.OnTreeSigningStarted(ctx, client.TreeSigningStartedEvent{CosignersPubkeys: []string{"02aa"}}, batch.vtxoTree)
	require.NoError(t, err)
	require.True(t, skip, "a tree we do not cosign")

	started := client.TreeSigningStartedEvent{
		Id: "b1", UnsignedCommitmentTx: batch.commitment, CosignersPubkeys: []string{env.svc.delegatePubKeyHex},
	}
	skip, err = h.OnTreeSigningStarted(ctx, started, batch.vtxoTree)
	require.NoError(t, err)
	require.False(t, skip)
	require.NotEmpty(t, env.ark.nonces)

	sweepRoot, err := sweepTapTreeRoot(env.svc.forfeitPubKey, testExpiry)
	require.NoError(t, err)
	coordinator, err := tree.NewTreeCoordinatorSession(sweepRoot, batch.amount, batch.vtxoTree)
	require.NoError(t, err)
	coordinator.AddNonce(env.svc.key.PubKey(), env.ark.nonces)
	aggregated, err := coordinator.AggregateNonces()
	require.NoError(t, err)

	done, err := h.OnTreeNoncesAggregated(ctx, client.TreeNoncesAggregatedEvent{Id: "b1", Nonces: aggregated})
	require.NoError(t, err)
	require.True(t, done)
	ban, err := coordinator.AddSignatures(env.svc.key.PubKey(), env.ark.sigs)
	require.NoError(t, err)
	require.False(t, ban, "our partial signatures verify")
	_, err = coordinator.SignTree()
	require.NoError(t, err)

	started.UnsignedCommitmentTx = "garbage"
	_, err = h.OnTreeSigningStarted(ctx, started, batch.vtxoTree)
	require.Error(t, err)

	// finalization: a batch missing one of our coins gets no forfeit at all
	stingy := buildBatch(t, env, []*wire.TxOut{first.output}, 2)
	_, err = h.OnBatchFinalization(ctx, client.BatchFinalizationEvent{Tx: stingy.commitment}, stingy.vtxoTree, stingy.connectors)
	require.ErrorContains(t, err, "refusing to forfeit")
	require.Empty(t, env.ark.forfeits)

	few := buildBatch(t, env, []*wire.TxOut{first.output, second.output}, 1)
	_, err = h.OnBatchFinalization(ctx, client.BatchFinalizationEvent{Tx: few.commitment}, few.vtxoTree, few.connectors)
	require.ErrorContains(t, err, "got 0 connectors for 1 vtxos")

	env.ark.forfeits = nil
	signed, err := h.OnBatchFinalization(ctx, client.BatchFinalizationEvent{Tx: batch.commitment}, batch.vtxoTree, batch.connectors)
	require.NoError(t, err)
	require.Len(t, signed, 2)
	require.ElementsMatch(t, signed, env.ark.forfeits, "submitted per intent, in any order")
	connectorsUsed := map[wire.OutPoint]bool{}
	for _, b64 := range signed {
		forfeit, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
		require.NoError(t, err)
		connectorsUsed[forfeit.UnsignedTx.TxIn[1].PreviousOutPoint] = true
	}
	require.Len(t, connectorsUsed, 2, "each forfeit spends its own connector")

	env.emulator.infoErr = errBoom
	_, err = h.OnBatchFinalization(ctx, client.BatchFinalizationEvent{Tx: batch.commitment}, batch.vtxoTree, batch.connectors)
	require.ErrorContains(t, err, "emulator finalization")
}
