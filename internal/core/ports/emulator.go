package ports

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
)

// Emulator cosigns what a covenant allows.
type Emulator interface {
	GetInfo(ctx context.Context) (*emulatorclient.Info, error)
	SubmitIntent(ctx context.Context, intent emulatorclient.Intent) (signedProof string, err error)
	SubmitFinalization(
		ctx context.Context, intent emulatorclient.Intent, forfeits []string,
		connectorTree tree.FlatTxTree, commitmentTx string,
	) (signedForfeits []string, signedCommitmentTx string, err error)
	SubmitTx(ctx context.Context, tx string, checkpoints []string) (signedTx string, signedCheckpoints []string, err error)
	SubmitOnchainTx(ctx context.Context, tx string) (signedTx string, err error)
}
