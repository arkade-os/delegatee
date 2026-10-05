package e2e

import (
	"encoding/hex"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestBoardingThenRenewal(t *testing.T) {
	d := startDelegatee(t)
	owner := newOwner(t, d)
	w, renewal := boardingWatch(t, d, owner)
	require.Equal(t, owner.boardingAddress(t), w.Address)
	faucet(t, w.Address, 20_000)

	boarded := landed(t, d, w, renewal, 1)
	require.EqualValues(t, 20_000, boarded[0].Amount)
	renewed := landed(t, d, renewal, renewal, 1)
	require.Equal(t, boarded[0].Script, renewed[0].Script, "the same watch finds every renewed coin")

	require.Eventually(t, func() bool {
		row, err := summaryOf(t, d, renewal.Id)
		return err == nil && row.Managed && row.VtxoCount == 1 && row.TotalAmount == 20_000 && row.NextRenewalAt > 0
	}, time.Minute, 100*time.Millisecond, "holdings not reported")
}

func TestCounter(t *testing.T) {
	d := startDelegatee(t)
	counter := registerTemplate(t, d, "counter.json")
	seed := registerTemplate(t, d, "counter_seed.json")

	faucet(t, watch(t, d, seed, counterPrograms(t, d)).Address, 20_000)

	pair := successor(t, d, counter, 0)
	require.Len(t, pair.Slots, 2)
	require.Equal(t, counterState(5), packet(t, d, pair.Slots[0].Outpoint, packets.TypeState))
	next := successor(t, d, counter, pair.Id)
	require.Equal(t, counterState(6), packet(t, d, next.Slots[0].Outpoint, packets.TypeState))
}

func TestVHTLCClaim(t *testing.T) {
	d := startDelegatee(t)
	claim := registerTemplate(t, d, "vhtlc_claim.json")
	trust(t, d, claim)
	swap := newSwap(t, d)

	w := watch(t, d, claim, swap.variables)
	alice := fundedWallet(t)
	funding, err := alice.SendOffChain(t.Context(), []clientlib.Receiver{{To: w.Address, Amount: 10_000}})
	require.NoError(t, err)

	paid := waitForVtxo(t, d, swap.receiverScript, funding)
	require.EqualValues(t, 10_000, paid.Amount)
}

func TestOnchainRelease(t *testing.T) {
	d := startDelegatee(t)
	release := registerTemplate(t, d, "onchain_release.json")
	trust(t, d, release)

	w := watch(t, d, release, nil)
	faucet(t, w.Address, 20_000)

	tx := waitForBroadcast(t, d, w.Id)
	require.Equal(t, releaseRecipient, hex.EncodeToString(tx.TxOut[0].PkScript))
	fee := feeOf(t, tx)
	require.Positive(t, fee)
	require.LessOrEqual(t, fee, int64(1000), "the fee stays under the cap")
}

func TestVHTLCRefundAfterLocktime(t *testing.T) {
	d := startDelegatee(t)
	refund := registerTemplate(t, d, "vhtlc_refund.json")
	trust(t, d, refund)
	swap := newSwap(t, d)
	// arkd compares a timestamp with the median time past, which an idle regtest leaves far behind the clock
	swap.variables["refund_locktime"] = scriptNum(medianTime(t))

	w := watch(t, d, refund, swap.variables)
	alice := fundedWallet(t)
	funding, err := alice.SendOffChain(t.Context(), []clientlib.Receiver{{To: w.Address, Amount: 10_000}})
	require.NoError(t, err)

	sender, err := hex.DecodeString(swap.variables["sender_program"])
	require.NoError(t, err)
	paid := waitForVtxo(t, d, append([]byte{0x51, 0x20}, sender...), funding)
	require.EqualValues(t, 10_000, paid.Amount)
}

func TestUntrustedTemplateCannotUseTheDelegateKey(t *testing.T) {
	d := startDelegatee(t)
	release := registerTemplate(t, d, "onchain_release.json")

	_, err := d.client.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{TemplateId: release})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)

	trust(t, d, release)
	watch(t, d, release, nil)
}
