package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	offchaintx "github.com/arkade-os/arkd/pkg/client-lib/offchain-tx"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/config"
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
	paid, _ := swapClaim(t, startDelegatee(t), "vhtlc_claim.json")
	require.EqualValues(t, 10_000, paid.Amount)
}

// the poll is an hour: only the subscription can wake the scan
func TestVHTLCClaimIsPrompt(t *testing.T) {
	d := startDelegatee(t, func(cfg *config.Config) { cfg.PollInterval = time.Hour })
	paid, took := swapClaim(t, d, "vhtlc_claim.json")
	require.EqualValues(t, 10_000, paid.Amount)
	require.Less(t, took, 30*time.Second)
}

// covclaimd's flow: the funding transaction carries the sealed preimage and nobody registers anything
func TestStreamClaim(t *testing.T) {
	d := startDelegatee(t)
	streamActive(t, d, fixtureID(t, "noninteractiveclaim.json"))

	swap := newSwap(t, d)
	addr, pkScript, tree := swapOutput(t, d, swap)
	info, err := d.client.GetInfo(t.Context(), &delegateev1.GetInfoRequest{})
	require.NoError(t, err)
	key, err := hex.DecodeString(info.EncryptionPubkey)
	require.NoError(t, err)
	program, err := hex.DecodeString(swap.variables["receiver_program"])
	require.NoError(t, err)
	ciphertext, err := hex.DecodeString(swap.variables["ciphertext"])
	require.NoError(t, err)

	alice := fundedWallet(t)
	funding, err := alice.SendOffChain(t.Context(), []clientlib.Receiver{{To: addr, Amount: 10_000}},
		offchaintx.WithExtraPacket(packets.Raw(4, claimPacket(ciphertext, enforcePayTo(t, program), key))),
		offchaintx.WithTxOutsTaprootTree(map[string][]byte{hex.EncodeToString(pkScript): tree}))
	require.NoError(t, err)
	paid := waitForVtxo(t, d, swap.receiverScript, funding)
	require.EqualValues(t, 10_000, paid.Amount)

	claim, err := d.indexer.GetVirtualTxs(t.Context(), []string{paid.Txid})
	require.NoError(t, err)
	require.Len(t, claim.Txs, 1)
	raw, err := base64.StdEncoding.DecodeString(claim.Txs[0])
	require.NoError(t, err)
	require.True(t, bytes.Contains(raw, swap.preimage), "the claim reveals the preimage")
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
