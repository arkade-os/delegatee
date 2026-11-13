//go:build e2e

package e2e

import (
	"slices"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	executorv1 "github.com/arkade-os/executor/api-spec/protobuf/gen/executor/v1"
	"github.com/stretchr/testify/require"
)

func TestBoardingThenRenewal(t *testing.T) {
	d := start(t)
	owner := newOwner(t, d)
	w, renewal := boardingDelegations(t, d, owner)
	require.Equal(t, owner.boardingAddress(t), w.Address)
	faucet(t, w.Address, 20_000)

	boarded := landed(t, d, w, renewal, 1)
	require.EqualValues(t, 20_000, boarded[0].Amount)
	renewed := landed(t, d, renewal, renewal, 1)
	require.Equal(
		t, boarded[0].Script, renewed[0].Script, "the same delegation finds every renewed coin",
	)

	require.Eventually(t, func() bool {
		resp, err := d.admin.ListDelegations(t.Context(), &executorv1.ListDelegationsRequest{})
		if err != nil {
			return false
		}
		i := slices.IndexFunc(
			resp.Delegations,
			func(s *executorv1.DelegationSummary) bool { return s.Delegation.Id == renewal.Id },
		)
		return i >= 0 && resp.Delegations[i].Coins == 1 && resp.Delegations[i].Amount == 20_000 &&
			resp.Delegations[i].NextDue > 0
	}, time.Minute, 100*time.Millisecond, "the summary does not report the coin")
}

func TestSeveralCoinsAtOneAddress(t *testing.T) {
	d := start(t)
	w, renewal := boardingDelegations(t, d, newOwner(t, d))
	// cancelled, the renewal leaves the boarded coins alone until they are all counted
	_, err := d.admin.CancelDelegation(
		t.Context(), &executorv1.CancelDelegationRequest{Id: renewal.Id},
	)
	require.NoError(t, err)
	for _, sats := range []int64{10_000, 10_000, 30_000} {
		faucet(t, w.Address, sats)
	}

	boarded := landed(t, d, w, renewal, 3)
	var amounts []uint64
	for _, b := range boarded {
		amounts = append(amounts, b.Amount)
	}
	slices.Sort(amounts)
	require.Equal(t, []uint64{10_000, 10_000, 30_000}, amounts)

	_, err = d.admin.ResumeDelegation(
		t.Context(), &executorv1.ResumeDelegationRequest{Id: renewal.Id},
	)
	require.NoError(t, err)
	landed(t, d, renewal, renewal, 3)
}

func TestManyDelegations(t *testing.T) {
	d := start(t)
	var boardings, renewals []*executorv1.Delegation
	for range 128 {
		boarding, renewal := boardingDelegations(t, d, newOwner(t, d))
		boardings, renewals = append(boardings, boarding), append(renewals, renewal)
	}
	fundMany(t, boardings, 20_000)

	for i, r := range renewals {
		landed(t, d, boardings[i], r, 1)
	}
	batches := map[string]bool{}
	for _, r := range renewals {
		batches[landed(t, d, r, r, 1)[0].CommitmentTxids[0]] = true
	}
	require.LessOrEqual(t, len(batches), 8, "the renewals share batches")
}

func TestAssetRenewal(t *testing.T) {
	d := start(t)
	alice := fundedWallet(t)
	var assets []clientlib.Asset
	for _, amount := range []uint64{assetAmount, 2 * assetAmount} {
		var id string
		// the previous issuance's change is spendable once the indexer lists it
		require.Eventually(t, func() bool {
			issued, err := alice.IssueAsset(t.Context(), amount, nil, nil)
			if err == nil {
				id = issued.IssuedAssets[0].String()
			}
			return err == nil
		}, time.Minute, 2*time.Second)
		assets = append(assets, clientlib.Asset{AssetId: id, Amount: amount})
	}

	w := renewalDelegation(t, d, newOwner(t, d), 0)
	pay(t, alice, w.Address, assets...)
	renewed := landed(t, d, w, w, 1)
	require.ElementsMatch(t, assets, renewed[0].Assets)
}
