package application

import (
	"bytes"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestValidateBatch(t *testing.T) {
	env := newTestEnv(t)
	alice, bob := append([]byte{0x51, 0x20}, make([]byte, 32)...), append([]byte{0x51, 0x20}, make([]byte, 32)...)
	bob[5] = 1
	ours := []*wire.TxOut{wire.NewTxOut(10_000, alice), wire.NewTxOut(10_000, alice), wire.NewTxOut(5_000, bob)}
	// the batch also serves someone else
	batch := buildBatch(t, env, append([]*wire.TxOut{wire.NewTxOut(777, bob)}, ours...), 3)
	validate := func(b testBatch, outputs []*wire.TxOut) error {
		return validateBatch(b.commitment, b.vtxoTree, b.connectors, env.svc.forfeitPubKey, testExpiry, outputs, nil, true)
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
			validateBatch(batch.commitment, batch.vtxoTree, batch.connectors, stranger.svc.forfeitPubKey, testExpiry, ours, nil, true),
			"vtxo tree")
		sooner := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512}
		require.ErrorContains(t,
			validateBatch(batch.commitment, batch.vtxoTree, batch.connectors, env.svc.forfeitPubKey, sooner, ours, nil, true),
			"vtxo tree")
	})
	t.Run("garbage", func(t *testing.T) {
		require.ErrorContains(t, validate(testBatch{"nope", batch.vtxoTree, batch.connectors, 0}, ours), "commitment tx")
		require.ErrorContains(t, validate(testBatch{batch.commitment, batch.vtxoTree, nil, 0}, ours), "connector tree is missing")
		require.ErrorContains(t, validate(testBatch{batch.commitment, nil, batch.connectors, 0}, ours), "vtxo tree is missing")
	})
	t.Run("malformed tree is rejected without a panic", func(t *testing.T) {
		malformed := &tree.TxTree{Root: &psbt.Packet{UnsignedTx: &wire.MsgTx{}}}
		require.ErrorContains(t, validateBatch(batch.commitment, malformed, batch.connectors, env.svc.forfeitPubKey, testExpiry, ours, nil, true), "no input")
	})
	t.Run("connectors must spend commitment output one", func(t *testing.T) {
		wrong := buildBatch(t, env, ours, 3)
		wrong.connectors.Root.UnsignedTx.TxIn[0].PreviousOutPoint.Index = 0
		require.ErrorContains(t, validate(wrong, ours), "connector output 1")
	})
}

// forfeits leave only once the batch checks out
func TestBatchHandlerSignsAndForfeits(t *testing.T) {
	env := newTestEnv(t)
	first := builtIntent(t, env, dueInput(t, env, 0, 10_000))
	second := builtIntent(t, env, dueInput(t, env, 0, 20_000))
	firstOut, secondOut := first.outputs[0], second.outputs[0]
	require.Equal(t, int64(10_000), firstOut.Value, "no fee: the template pays the vtxo back in full")
	batch := buildBatch(t, env, []*wire.TxOut{firstOut, secondOut}, 2)
	carry(batch.vtxoTree, first, second)
	h := &batchHandler{
		svc: env.svc, signerSession: tree.NewTreeSignerSession(env.svc.cosigners[0].key), batchExpiry: testExpiry,
		inBatch: []*pendingIntent{first, second},
	}
	ctx := t.Context()

	skip, err := h.OnTreeSigningStarted(ctx, clientlib.TreeSigningStartedEvent{CosignersPubkeys: []string{"02aa"}}, batch.vtxoTree)
	require.NoError(t, err)
	require.True(t, skip, "a tree we do not cosign")

	started := clientlib.TreeSigningStartedEvent{
		Id: "b1", UnsignedCommitmentTx: batch.commitment, CosignersPubkeys: []string{env.svc.cosigners[0].pubKey},
	}
	skip, err = h.OnTreeSigningStarted(ctx, started, batch.vtxoTree)
	require.NoError(t, err)
	require.False(t, skip)
	require.NotEmpty(t, env.ark.nonces)

	sweepRoot, err := sweepTapTreeRoot(env.svc.forfeitPubKey, testExpiry)
	require.NoError(t, err)
	coordinator, err := tree.NewTreeCoordinatorSession(sweepRoot, batch.amount, batch.vtxoTree)
	require.NoError(t, err)
	coordinator.AddNonce(env.svc.cosigners[0].key.PubKey(), env.ark.nonces)
	aggregated, err := coordinator.AggregateNonces()
	require.NoError(t, err)

	done, err := h.OnTreeNoncesAggregated(ctx, clientlib.TreeNoncesAggregatedEvent{Id: "b1", Nonces: aggregated})
	require.NoError(t, err)
	require.True(t, done)
	ban, err := coordinator.AddSignatures(env.svc.cosigners[0].key.PubKey(), env.ark.sigs)
	require.NoError(t, err)
	require.False(t, ban, "our partial signatures verify")
	_, err = coordinator.SignTree()
	require.NoError(t, err)

	started.UnsignedCommitmentTx = "garbage"
	_, err = h.OnTreeSigningStarted(ctx, started, batch.vtxoTree)
	require.Error(t, err)

	// finalization: a batch missing one of our coins gets no forfeit at all
	stingy := buildBatch(t, env, []*wire.TxOut{firstOut}, 2)
	_, err = h.OnBatchFinalization(ctx, clientlib.BatchFinalizationEvent{Tx: stingy.commitment}, stingy.vtxoTree, stingy.connectors)
	require.ErrorContains(t, err, "refusing to forfeit")
	require.Empty(t, env.ark.forfeits)

	few := buildBatch(t, env, []*wire.TxOut{firstOut, secondOut}, 1)
	carry(few.vtxoTree, first, second)
	_, err = h.OnBatchFinalization(ctx, clientlib.BatchFinalizationEvent{Tx: few.commitment}, few.vtxoTree, few.connectors)
	require.ErrorContains(t, err, "got 0 connectors for 1 vtxos")

	env.ark.forfeits = nil
	signed, err := h.OnBatchFinalization(ctx, clientlib.BatchFinalizationEvent{Tx: batch.commitment}, batch.vtxoTree, batch.connectors)
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
	for _, p := range h.inBatch {
		require.Contains(t, p.sources, p.settled[0].Hash.String(), "the output is found in the leaf carrying its packets")
	}

	env.emulator.infoErr = errBoom
	_, err = h.OnBatchFinalization(ctx, clientlib.BatchFinalizationEvent{Tx: batch.commitment}, batch.vtxoTree, batch.connectors)
	require.ErrorContains(t, err, "emulator finalization")
}

func TestBatchWithoutVtxoOutputs(t *testing.T) {
	env := newTestEnv(t)
	batch := buildBatch(t, env, []*wire.TxOut{wire.NewTxOut(1000, append([]byte{0x51, 0x20}, make([]byte, 32)...))}, 1)
	err := validateBatch(batch.commitment, nil, batch.connectors, env.svc.forfeitPubKey, testExpiry, nil, nil, true)
	require.NoError(t, err, "vtxos leaving onchain need connectors, not a vtxo tree")
	err = validateBatch(batch.commitment, nil, nil, env.svc.forfeitPubKey, testExpiry, nil, nil, true)
	require.ErrorContains(t, err, "connector tree is missing")
}

func TestWithBoardingLeaves(t *testing.T) {
	board := wire.OutPoint{Index: 1}
	leaf := &psbt.TaprootTapLeafScript{Script: []byte{0x51}}
	prev := wire.NewTxOut(20_000, []byte{0x51, 0x20})
	other := &psbt.TaprootTapLeafScript{Script: []byte{0x52}}
	p := &pendingIntent{inputs: []renewalInput{
		{coin: coin{Outpoint: wire.OutPoint{Hash: board.Hash}}},
		{onchain: true, coin: coin{Outpoint: board}, leaf: leaf, prevOut: prev},
	}}
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 7}, nil, nil))
	tx.AddTxIn(wire.NewTxIn(&board, nil, nil))
	commitment, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	commitment.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{other}

	boarding, err := p.withBoardingLeaves(commitment)
	require.NoError(t, err)
	require.True(t, boarding)
	require.Empty(t, commitment.Inputs[0].TaprootLeafScript, "another input gets no leaf")
	require.Equal(t, []*psbt.TaprootTapLeafScript{leaf}, commitment.Inputs[1].TaprootLeafScript)
	require.Equal(t, prev, commitment.Inputs[1].WitnessUtxo)

	commitment.UnsignedTx.TxIn = commitment.UnsignedTx.TxIn[:1]
	_, err = p.withBoardingLeaves(commitment)
	require.ErrorContains(t, err, "omits boarding input")
}

var testExpiry = arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1024}

// testBatch's commitment output 0 funds the vtxo tree and output 1 the connectors.
type testBatch struct {
	commitment string
	vtxoTree   *tree.TxTree
	connectors *tree.TxTree
	amount     int64
}

// buildBatch also spends boarding in the commitment.
func buildBatch(t *testing.T, env *testEnv, outputs []*wire.TxOut, connectors int, boarding ...wire.OutPoint) testBatch {
	t.Helper()
	sweepRoot, err := sweepTapTreeRoot(env.svc.forfeitPubKey, testExpiry)
	require.NoError(t, err)
	leaves := make([]tree.Leaf, len(outputs))
	for i, out := range outputs {
		leaves[i] = tree.Leaf{
			Outputs:             []tree.LeafOutput{{Amount: uint64(out.Value), Script: hex.EncodeToString(out.PkScript)}},
			CosignersPublicKeys: []string{env.svc.cosigners[0].pubKey},
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
	for _, op := range boarding {
		tx.AddTxIn(wire.NewTxIn(&op, nil, nil))
	}
	tx.AddTxOut(wire.NewTxOut(batchAmount, batchScript))
	tx.AddTxOut(wire.NewTxOut(connectorAmount, connectorScript))
	commitment, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	commitment.Inputs[0].WitnessUtxo = wire.NewTxOut(batchAmount+connectorAmount, env.svc.forfeitPkScript)
	b64, err := commitment.B64Encode()
	require.NoError(t, err)

	txid := tx.TxHash()
	vtxoTree, err := tree.BuildVtxoTree(&wire.OutPoint{Hash: txid, Index: 0}, leaves, sweepRoot, testExpiry)
	require.NoError(t, err)
	connectorTree, err := tree.BuildConnectorTree(&wire.OutPoint{Hash: txid, Index: 1}, connectorLeaves)
	require.NoError(t, err)
	return testBatch{b64, vtxoTree, connectorTree, batchAmount}
}

// carry copies each intent's packets onto the leaf paying it, as arkd does.
func carry(vtxoTree *tree.TxTree, intents ...*pendingIntent) {
	for _, leaf := range vtxoTree.Leaves() {
		for _, p := range intents {
			out := leaf.UnsignedTx.TxOut[0]
			if out.Value != p.outputs[0].Value || !bytes.Equal(out.PkScript, p.outputs[0].PkScript) {
				continue
			}
			ext := slices.IndexFunc(p.logical.TxOut, func(o *wire.TxOut) bool { return extension.IsExtension(o.PkScript) })
			leaf.UnsignedTx.AddTxOut(p.logical.TxOut[ext])
			leaf.Outputs = append(leaf.Outputs, psbt.POutput{})
		}
	}
}
