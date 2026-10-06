package ports

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
)

// Ark is the server the daemon settles with.
type Ark interface {
	GetInfo(ctx context.Context) (*clientlib.Info, error)
	RegisterIntent(ctx context.Context, proof, message string) (string, error)
	ConfirmRegistration(ctx context.Context, intentID string) error
	GetEventStream(ctx context.Context, topics []string) (<-chan clientlib.BatchEventChannel, func(), error)
	SubmitTreeNonces(ctx context.Context, batchID, cosignerPubkey string, nonces tree.TreeNonces) error
	SubmitTreeSignatures(ctx context.Context, batchID, cosignerPubkey string, signatures tree.TreePartialSigs) error
	SubmitSignedForfeitTxs(ctx context.Context, signedForfeitTxs []string, signedCommitmentTx string) error
	SubmitTx(ctx context.Context, signedArkTx string, checkpointTxs []string) (arkTxid, finalArkTx string, signedCheckpointTxs []string, err error)
	FinalizeTx(ctx context.Context, arkTxid string, finalCheckpointTxs []string) error
	// GetPendingTx lists the offchain txs arkd accepted and did not finalize, spending the coins the proof owns.
	GetPendingTx(ctx context.Context, proof, message string) ([]clientlib.AcceptedOffchainTx, error)
}

// Indexer lists the coins and transactions the server knows.
type Indexer interface {
	GetVtxos(ctx context.Context, opts ...clientlib.GetVtxosOption) (*clientlib.VtxosResponse, error)
	GetVirtualTxs(ctx context.Context, txids []string, opts ...clientlib.PageOption) (*clientlib.VirtualTxsResponse, error)
	// NewSubscription streams what happens to scripts until ctx ends or its stop function runs: either closes the channel.
	NewSubscription(ctx context.Context, scripts []string) (string, <-chan clientlib.ScriptEvent, func(), error)
	UpdateSubscription(ctx context.Context, subscriptionID string, scriptsToAdd, scriptsToRemove []string) error
}
