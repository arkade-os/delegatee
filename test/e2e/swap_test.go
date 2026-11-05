//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	offchaintx "github.com/arkade-os/arkd/pkg/client-lib/offchain-tx"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/pkg/template/ecies"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/arkade-os/delegatee/test/daemon"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

// nothing is due: only the subscription can wake the daemon
func TestVHTLCClaimIsPrompt(t *testing.T) {
	paid, took := swapClaim(t, start(t))
	require.EqualValues(t, 10_000, paid.Amount)
	require.Less(t, took, 30*time.Second)
}

// the funding transaction carries the sealed preimage and nobody registers anything
func TestStreamClaim(t *testing.T) {
	d := start(t)
	claim := registerTemplate(t, d, "noninteractiveclaim.json")
	streamActive(t, d, claim)

	swap, fund := streamFunding(t, d, claim)
	funding := fund(fundedWallet(t))
	paid := waitForVtxo(t, d, hex.EncodeToString(swap.receiverScript), funding)
	require.EqualValues(t, 10_000, paid.Amount)
	requirePreimage(t, d, paid, swap)
	oneSucceeded(t, d, streamChild(t, d).Id)
}

// a secret sealed to another template is not opened by the stream
func TestStreamClaimRefusesASecretSealedToAnotherTemplate(t *testing.T) {
	d := start(t)
	claim := registerTemplate(t, d, "noninteractiveclaim.json")
	streamActive(t, d, claim)
	alice := fundedWallet(t)

	wrong := registerTemplate(t, d, "vhtlc_claim.json")
	swap, fund := streamFunding(t, d, wrong)
	funding := fund(alice)
	neverSpent(t, d, funding+":0")
	require.Empty(t, vtxosAt(t, d, hex.EncodeToString(swap.receiverScript)), "nothing was paid")

	control, fundControl := streamFunding(t, d, claim)
	controlFunding := fundControl(alice)
	paid := waitForVtxo(t, d, hex.EncodeToString(control.receiverScript), controlFunding)
	require.EqualValues(t, 10_000, paid.Amount)
}

func TestVHTLCRefundAfterLocktime(t *testing.T) {
	d := start(t)
	refund := registerTemplate(t, d, "vhtlc_refund.json")
	swap := newSwap(t, d, refund)
	// arkd compares a timestamp with the median time past, which an idle regtest leaves far behind the clock
	swap.variables["refund_locktime"] = daemon.ScriptNum(medianTime(t))

	w := registerDelegation(t, d, refund, swap.variables)
	alice := fundedWallet(t)
	funding, err := alice.SendOffChain(t.Context(), []clientlib.Receiver{{To: w.Address, Amount: 10_000}})
	require.NoError(t, err)

	sender, err := hex.DecodeString(swap.variables["sender_program"])
	require.NoError(t, err)
	paid := waitForVtxo(t, d, hex.EncodeToString(append([]byte{0x51, 0x20}, sender...)), funding)
	require.EqualValues(t, 10_000, paid.Amount)
	oneSucceeded(t, d, w.Id)
}

// swap is a VHTLC whose preimage is sealed to the daemon.
type swap struct {
	variables      map[string]string
	receiverScript []byte
	preimage       []byte
}

// newSwap seals the preimage of a new swap for the template templateID.
func newSwap(t *testing.T, d delegatee, templateID string) swap {
	t.Helper()
	info, err := d.client.GetInfo(t.Context(), &delegateev1.GetInfoRequest{})
	require.NoError(t, err)
	preimage := make([]byte, 32)
	_, err = rand.Read(preimage)
	require.NoError(t, err)
	ciphertext, err := ecies.Encrypt(parseKey(t, info.EncryptionPubkey), preimage, templateID)
	require.NoError(t, err)
	sender, receiver := pubKey(t), pubKey(t)
	program := schnorr.SerializePubKey(receiver)
	return swap{
		variables: map[string]string{
			"sender":                  hex.EncodeToString(sender.SerializeCompressed()),
			"receiver":                hex.EncodeToString(receiver.SerializeCompressed()),
			"refund_locktime":         daemon.ScriptNum(time.Now().Add(24 * time.Hour).Unix()),
			"unilateral_claim_delay":  daemon.ScriptNum(1<<22 | 2),
			"unilateral_refund_delay": daemon.ScriptNum(1<<22 | 3),
			"unilateral_refund_without_receiver_delay": daemon.ScriptNum(1<<22 | 4),
			"receiver_program":                         hex.EncodeToString(program),
			"sender_program":                           hex.EncodeToString(schnorr.SerializePubKey(sender)),
			"ciphertext":                               hex.EncodeToString(ciphertext),
		},
		receiverScript: append([]byte{0x51, 0x20}, program...),
		preimage:       preimage,
	}
}

// swapClaim funds a VHTLC watched under the claim template and waits for its claim.
func swapClaim(t *testing.T, d delegatee) (clientlib.Vtxo, time.Duration) {
	t.Helper()
	claim := registerTemplate(t, d, "vhtlc_claim.json")
	swap := newSwap(t, d, claim)

	w := registerDelegation(t, d, claim, swap.variables)
	alice := fundedWallet(t)
	funding, err := alice.SendOffChain(t.Context(), []clientlib.Receiver{{To: w.Address, Amount: 10_000}})
	require.NoError(t, err)
	sent := time.Now()
	paid := waitForVtxo(t, d, hex.EncodeToString(swap.receiverScript), funding)
	took := time.Since(sent)
	oneSucceeded(t, d, w.Id)
	return paid, took
}

// streamFunding prepares the funding of a swap sealed to sealedTo, which the default stream matches; fund pays it.
func streamFunding(t *testing.T, d delegatee, sealedTo string) (swap, func(testWallet) string) {
	t.Helper()
	swap := newSwap(t, d, sealedTo)
	addr, pkScript, tree := swapOutput(t, d, swap)
	info, err := d.client.GetInfo(t.Context(), &delegateev1.GetInfoRequest{})
	require.NoError(t, err)
	key, err := hex.DecodeString(info.EncryptionPubkey)
	require.NoError(t, err)
	program, err := hex.DecodeString(swap.variables["receiver_program"])
	require.NoError(t, err)
	ciphertext, err := hex.DecodeString(swap.variables["ciphertext"])
	require.NoError(t, err)
	return swap, func(alice testWallet) string {
		funding, err := alice.SendOffChain(t.Context(), []clientlib.Receiver{{To: addr, Amount: 10_000}},
			offchaintx.WithExtraPacket(packets.Raw(4, daemon.TLV(ciphertext, daemon.EnforcePayTo(t, program), key))),
			offchaintx.WithTxOutsTaprootTree(map[string][]byte{hex.EncodeToString(pkScript): tree}))
		require.NoError(t, err)
		return funding
	}
}

func streamActive(t *testing.T, d delegatee, templateID string) {
	t.Helper()
	require.Eventually(t, func() bool {
		resp, err := d.admin.ListStreams(t.Context(), &delegateev1.ListStreamsRequest{})
		return err == nil && slices.ContainsFunc(resp.Streams, func(s *delegateev1.Stream) bool {
			return s.TemplateId == templateID && s.Status == "active"
		})
	}, 30*time.Second, time.Second, "the stream is not active")
}

// streamChild waits for the only delegation a stream spawned.
func streamChild(t *testing.T, d delegatee) *delegateev1.Delegation {
	t.Helper()
	var child *delegateev1.Delegation
	require.Eventually(t, func() bool {
		resp, err := d.admin.ListDelegations(t.Context(), &delegateev1.ListDelegationsRequest{Limit: 1000})
		if err != nil {
			return false
		}
		var spawned []*delegateev1.Delegation
		for _, s := range resp.Delegations {
			if s.Delegation.StreamId != 0 {
				spawned = append(spawned, s.Delegation)
			}
		}
		if len(spawned) != 1 {
			return false
		}
		child = spawned[0]
		return true
	}, time.Minute, time.Second, "no single delegation spawned")
	return child
}

// requirePreimage checks that the transaction making paid reveals the preimage of swap.
func requirePreimage(t *testing.T, d delegatee, paid clientlib.Vtxo, swap swap) {
	t.Helper()
	claimTx, err := d.indexer.GetVirtualTxs(t.Context(), []string{paid.Txid})
	require.NoError(t, err)
	require.Len(t, claimTx.Txs, 1)
	raw, err := base64.StdEncoding.DecodeString(claimTx.Txs[0])
	require.NoError(t, err)
	require.True(t, bytes.Contains(raw, swap.preimage), "the claim reveals the preimage")
}

// oneSucceeded waits for exactly one succeeded attempt of the delegation.
func oneSucceeded(t *testing.T, d delegatee, id int64) {
	t.Helper()
	require.Eventually(t, func() bool {
		return len(succeededOf(t, d, id)) == 1
	}, time.Minute, time.Second, "delegation %d has not one succeeded attempt", id)
}

func succeededOf(t *testing.T, d delegatee, id int64) []*delegateev1.Attempt {
	t.Helper()
	return slices.DeleteFunc(attemptsOf(t, d, id), func(a *delegateev1.Attempt) bool { return a.Status != "succeeded" })
}

// swapOutput is the Ark address of swap, its script and its BIP-371 tree, derived as a funder does.
func swapOutput(t *testing.T, d delegatee, swap swap) (string, []byte, []byte) {
	t.Helper()
	keys := keysOf(t, d)
	inst := instantiate(t, "vhtlc_claim.json", keys, swap.variables, func([]byte) ([]byte, error) { return swap.preimage, nil })
	tree, err := txutils.TapTree(inst.Tapscripts(0)).Encode()
	require.NoError(t, err)
	tapKey, err := schnorr.ParsePubKey(inst.PkScript(0)[2:])
	require.NoError(t, err)
	addr, err := (&arklib.Address{HRP: arklib.BitcoinRegTest.Addr, Signer: keys.Server, VtxoTapKey: tapKey}).EncodeV0()
	require.NoError(t, err)
	return addr, inst.PkScript(0), tree
}

func medianTime(t *testing.T) int64 {
	t.Helper()
	var blocks []struct {
		MedianTime int64 `json:"mediantime"`
	}
	getJSON(t, explorerURL+"/blocks", &blocks)
	require.NotEmpty(t, blocks)
	return blocks[0].MedianTime
}
