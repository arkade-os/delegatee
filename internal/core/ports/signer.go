package ports

import (
	"context"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/executor/internal/core/domain/execution"
	"github.com/btcsuite/btcd/btcec/v2"
)

type ArkInfo struct {
	Network             arklib.Network
	SignerPubkey        *btcec.PublicKey
	ForfeitPubkey       *btcec.PublicKey
	ForfeitOutputScript []byte // where forfeits pay
	Dust                uint64
	IntentFees          arkfee.Config
	SessionDuration     time.Duration
	CheckpointTapscript []byte // the server's unroll leaf every checkpoint output carries
}

// Signer is arkd's batch and offchain protocols; psbts pass through base64-encoded.
type Signer interface {
	Info(ctx context.Context) (ArkInfo, error)
	// RegisterIntent queues the intent for a batch; the core names it by the txid of its proof.
	RegisterIntent(ctx context.Context, proof, message string) error
	// ConfirmRegistration confirms the intent of proofTxid, which a batch selected.
	ConfirmRegistration(ctx context.Context, proofTxid string) error
	// BatchEvents follows every batch, whoever's intents it takes, until ctx ends or stop is
	// called. The trees of a batch come only for the topics added: the cosigner keys and the coin
	// outpoints of its intents.
	BatchEvents(ctx context.Context) (events <-chan BatchEvent, stop func(), err error)
	UpdateTopics(ctx context.Context, add, remove []string) error
	SubmitTreeNonces(ctx context.Context, batchID, cosigner string, nonces tree.TreeNonces) error
	SubmitTreeSignatures(
		ctx context.Context, batchID, cosigner string, signatures tree.TreePartialSigs,
	) error
	SubmitSignedForfeitTxs(
		ctx context.Context, signedForfeits []string, signedCommitmentTx string,
	) error
	SubmitTx(
		ctx context.Context, signedArkTx string, checkpoints []string,
	) (arkTxid, finalArkTx string, signedCheckpoints []string, err error)
}

// BatchEvent is an event of a batch.
type BatchEvent interface{ batchEvent() }

// BatchStarted opens a batch; Selected are the proof txids of our intents it took.
type BatchStarted struct {
	ID          string
	Selected    []string
	BatchExpiry arklib.RelativeLocktime
}

// TreeSigningStarted asks the cosigners for their nonces over VtxoTree.
type TreeSigningStarted struct {
	ID                   string
	UnsignedCommitmentTx string
	CosignersPubkeys     []string
	VtxoTree             *tree.TxTree
}

type TreeNoncesAggregated struct {
	ID         string
	TreeNonces tree.TreeNonces
}

// BatchFinalization asks for the forfeits; ConnectorTree is nil when no vtxo is settled.
type BatchFinalization struct {
	ID            string
	CommitmentTx  string
	ConnectorTree *tree.TxTree
}

type BatchFinalized struct {
	ID             string
	CommitmentTxid string
}

// BatchFailed ends a batch; Blamed are the proof txids of our intents the reason holds against.
type BatchFailed struct {
	ID     string
	Reason string
	Blamed []string
}

// StreamReconnected says the batch events may have been missed.
type StreamReconnected struct{}

type Database interface {
	Ping(ctx context.Context) error
}

// TODO once the emulation is merged into arkd, merge this interface with Signer

type EmulatorInfo struct {
	SignerPubkey *btcec.PublicKey
}

// Emulator cosigns what a covenant allows.
type Emulator interface {
	Info(ctx context.Context) (EmulatorInfo, error)
	// SubmitTx cosigns an offchain transaction and its checkpoints, given base64 psbts.
	SubmitTx(
		ctx context.Context, tx string, checkpoints []string,
	) (signedTx string, signedCheckpoints []string, err error)
	// SubmitIntent cosigns the proof of an intent.
	SubmitIntent(ctx context.Context, in execution.Intent) (signedProof string, err error)
	// SubmitFinalization cosigns the forfeits of an intent once its batch is validated.
	SubmitFinalization(
		ctx context.Context, in execution.Intent, forfeits []string, connectorTree tree.FlatTxTree, commitmentTx string,
	) (signedForfeits []string, signedCommitmentTx string, err error)
}

func (BatchStarted) batchEvent()         {}
func (TreeSigningStarted) batchEvent()   {}
func (TreeNoncesAggregated) batchEvent() {}
func (BatchFinalization) batchEvent()    {}
func (BatchFinalized) batchEvent()       {}
func (BatchFailed) batchEvent()          {}
func (StreamReconnected) batchEvent()    {}
