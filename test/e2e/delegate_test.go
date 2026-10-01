// Package e2e drives the delegatee against the regtest compose stack; run with `make test-e2e`.
package e2e

import (
	"testing"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/stretchr/testify/require"
)

func TestConcurrentDelegations(t *testing.T) {
	d := startDelegatee(t)
	boardings, renewals := boardingWatches(t, d, 10)
	fundMany(t, boardings, 20_000)

	for i, r := range renewals {
		landed(t, d, boardings[i], r, 1)
		landed(t, d, r, r, 1)
	}
}

func TestManyDelegations(t *testing.T) {
	d := startDelegatee(t)
	boardings, renewals := boardingWatches(t, d, 128)
	fundMany(t, boardings, 20_000)

	for i, r := range renewals {
		landed(t, d, boardings[i], r, 1)
	}
	// arkd may split the intents over a few batches when a session fails to start
	batches := map[string]bool{}
	for _, r := range renewals {
		batches[landed(t, d, r, r, 1)[0].CommitmentTxids[0]] = true
	}
	require.LessOrEqual(t, len(batches), 8, "the renewals share batches")
}

func TestAssetRenewal(t *testing.T) {
	d := startDelegatee(t)
	alice := fundedWallet(t)
	issued, err := alice.IssueAsset(t.Context(), assetAmount, nil, nil)
	require.NoError(t, err)
	asset := clientlib.Asset{AssetId: issued.IssuedAssets[0].String(), Amount: assetAmount}

	w := renewalWatch(t, d, newOwner(t, d), 0)
	pay(t, alice, w.Address, asset)
	renewed := landed(t, d, w, w, 1)
	require.Equal(t, []clientlib.Asset{asset}, renewed[0].Assets)
}
