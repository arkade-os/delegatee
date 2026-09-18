package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"encoding/hex"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/config"
	"github.com/arkade-os/delegatee/internal/core/application"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

// TestRestartAndKeys: coins funded while the service is down are renewed
// after a restart with the same key. An instance with another key, on the
// same database, leaves them alone and says they are not its own.
func TestRestartAndKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the regtest stack")
	}
	ctx := t.Context()
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	withKey := func(c *config.Config) { c.SecretKey = key }

	alice, alicePubKey := setupAlice(t)
	fundAndSettle(t, alice, 100_000)

	first := startDelegatee(t, withKey)
	reg := registerDelegation(t, first, alicePubKey, renewalWindow, 0)
	first.stop()

	fundingTxid, err := alice.SendOffChain(ctx, []types.Receiver{{To: reg.address, Amount: delegateAmount}})
	require.NoError(t, err)

	stranger := startDelegatee(t)
	require.Eventually(t, func() bool {
		st, err := stranger.admin.GetStatus(ctx, &delegateev1.GetStatusRequest{})
		return err == nil && st.GetLastScanAt() > 0
	}, 30*time.Second, 500*time.Millisecond)
	list, err := stranger.admin.ListDelegations(ctx, &delegateev1.ListDelegationsRequest{})
	require.NoError(t, err)
	var seen bool
	for _, d := range list.GetDelegations() {
		if d.GetAddress() == reg.address {
			seen = true
			require.Equal(t, "active", d.GetStatus())
			require.False(t, d.GetManaged(), "registered under another key")
		}
	}
	require.True(t, seen, "both instances share the table")
	neverRenewed(t, stranger, reg.pkScript, fundingTxid)
	stranger.stop()

	second := startDelegatee(t, withKey)
	renewed := waitForRenewedVtxo(t, second.indexer, reg.pkScript, fundingTxid, func(types.Vtxo) bool { return true })
	t.Logf("renewed after restart: %s", renewed.Outpoint.String())
	// the address did not move with the restart
	again, err := second.client.GetInfo(ctx, &delegateev1.GetInfoRequest{RenewalWindow: renewalWindow})
	require.NoError(t, err)
	require.Contains(t, reg.tapscripts, again.GetDelegateTapscript())
}

// TestCancelStopsRenewals: a cancelled address is left alone, for real, until
// it is registered again.
func TestCancelStopsRenewals(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the regtest stack")
	}
	ctx := t.Context()
	d := startDelegatee(t)
	alice, alicePubKey := setupAlice(t)
	fundAndSettle(t, alice, 100_000)

	reg := registerDelegation(t, d, alicePubKey, renewalWindow, 0)
	_, err := d.admin.CancelDelegation(ctx, &delegateev1.CancelDelegationRequest{Address: reg.address})
	require.NoError(t, err)
	fundingTxid, err := alice.SendOffChain(ctx, []types.Receiver{{To: reg.address, Amount: delegateAmount}})
	require.NoError(t, err)
	neverRenewed(t, d, reg.pkScript, fundingTxid)
	detail, err := d.client.GetDelegation(ctx, &delegateev1.GetDelegationRequest{Address: reg.address})
	require.NoError(t, err)
	require.Empty(t, detail.GetRenewals(), "not even attempted")
	require.Len(t, detail.GetVtxos(), 1, "still visible to its owner")

	_, err = d.client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{
		Tapscripts: reg.tapscripts, RenewalWindow: renewalWindow,
	})
	require.NoError(t, err)
	waitForRenewedVtxo(t, d.indexer, reg.pkScript, fundingTxid, func(types.Vtxo) bool { return true })
}

// TestSeveralCoinsAtOneAddress: all the coins of an address go in one batch,
// each keeping its own amount, two identical ones included (each needs its
// own leaf for the pre-forfeit check to pass).
func TestSeveralCoinsAtOneAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the regtest stack")
	}
	ctx := t.Context()
	d := startDelegatee(t, func(c *config.Config) { c.PollInterval = 10 * time.Second })
	alice, alicePubKey := setupAlice(t)
	fundAndSettle(t, alice, 200_000)

	reg := registerDelegation(t, d, alicePubKey, renewalWindow, 0)
	amounts := []uint64{10_000, 10_000, 25_000, 1_000}
	receivers := make([]types.Receiver, len(amounts))
	for i, a := range amounts {
		receivers[i] = types.Receiver{To: reg.address, Amount: a}
	}
	fundingTxid, err := alice.SendOffChain(ctx, receivers)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		got := map[uint64]int{}
		commitments := map[string]bool{}
		for _, v := range spendable(t, d, reg.pkScript) {
			if v.Txid == fundingTxid || v.Preconfirmed {
				return false
			}
			got[v.Amount]++
			commitments[v.CommitmentTxids[0]] = true
		}
		return got[10_000] == 2 && got[25_000] == 1 && got[1_000] == 1 && len(commitments) == 1
	}, 2*time.Minute, time.Second, "the four coins were not renewed together")

	detail, err := d.client.GetDelegation(ctx, &delegateev1.GetDelegationRequest{Address: reg.address})
	require.NoError(t, err)
	var firstRenewal *delegateev1.Renewal
	for _, r := range detail.GetRenewals() {
		require.True(t, r.GetSuccess(), r.GetError())
		firstRenewal = r // newest first
	}
	require.Len(t, firstRenewal.GetOutpoints(), len(amounts), "one renewal row for the whole address")
}

// TestFeeDropUnblocksRenewal: a coin refused because arkd charges more than
// its owner allowed is retried every poll and goes through once the fee is gone.
func TestFeeDropUnblocksRenewal(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the regtest stack")
	}
	ctx := t.Context()
	d := startDelegatee(t)
	alice, alicePubKey := setupAlice(t)
	fundAndSettle(t, alice, 100_000)
	reg := registerDelegation(t, d, alicePubKey, renewalWindow, 0)

	clearFees := func() { postJSON(t, arkdAdminURL+"/v1/admin/intentFees/clear", `{}`) }
	t.Cleanup(clearFees)
	postJSON(t, arkdAdminURL+"/v1/admin/intentFees", `{"fees":{"offchainInputFee":"100.0"}}`)
	st, err := d.admin.GetStatus(ctx, &delegateev1.GetStatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "100.0", st.GetIntentFees().GetOffchainInput(), "the operator sees what arkd charges")

	// alice pays the fee for her own send; the delegation cannot
	fundingTxid, err := alice.SendOffChain(ctx, []types.Receiver{{To: reg.address, Amount: delegateAmount}})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		list, err := d.admin.ListDelegations(ctx, &delegateev1.ListDelegationsRequest{})
		if err != nil {
			return false
		}
		for _, l := range list.GetDelegations() {
			if l.GetAddress() == reg.address && l.GetLastRenewal() != nil {
				return !l.GetLastRenewal().GetSuccess() &&
					strings.Contains(l.GetLastRenewal().GetError(), "exceeds the delegation max fee 0")
			}
		}
		return false
	}, time.Minute, 500*time.Millisecond, "refusal not reported to the operator")
	neverRenewed(t, d, reg.pkScript, fundingTxid)
	detail, err := d.client.GetDelegation(ctx, &delegateev1.GetDelegationRequest{Address: reg.address})
	require.NoError(t, err)
	require.Len(t, detail.GetRenewals(), 1, "refused every poll, recorded once")

	clearFees()
	renewed := waitForRenewedVtxo(t, d.indexer, reg.pkScript, fundingTxid, func(types.Vtxo) bool { return true })
	require.Equal(t, delegateAmount, renewed.Amount, "nothing was deducted")
}

// TestWalletFlowOverREST follows the README with plain HTTP and JSON.
func TestWalletFlowOverREST(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the regtest stack")
	}
	d := startDelegatee(t)
	base := "http://" + d.addr
	userKey, userPubKey := hexKeyPair(t)

	var info struct {
		DelegatePubkey, ServerPubkey, EmulatorTweakedPubkey, DelegateTapscript, RenewalWindow, MaxFee string
	}
	getJSON(t, base+"/v1/info?renewalWindow=900&maxFee=120", &info)
	require.Equal(t, "900", info.RenewalWindow)
	require.Equal(t, "120", info.MaxFee)
	_, tapscripts, _ := delegateScript(t, &delegateev1.GetInfoResponse{
		ServerPubkey: info.ServerPubkey, EmulatorTweakedPubkey: info.EmulatorTweakedPubkey,
		DelegateTapscript: info.DelegateTapscript,
	}, userPubKey)

	post := func(body any) (int, map[string]any) {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		resp, err := http.Post(base+"/v1/delegate", "application/json", bytes.NewReader(raw))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		return resp.StatusCode, out
	}
	code, out := post(map[string]any{"tapscripts": tapscripts, "renewalWindow": 900, "maxFee": 121})
	require.Equal(t, http.StatusBadRequest, code, "params the script was not built for")
	require.Contains(t, out["message"], "missing delegate leaf")
	code, _ = post(map[string]any{"tapscripts": tapscripts, "renewalWindow": 900, "maxFee": -1})
	require.Equal(t, http.StatusBadRequest, code)

	code, out = post(map[string]any{"tapscripts": tapscripts, "renewalWindow": 900, "maxFee": 120})
	require.Equal(t, http.StatusOK, code)
	delegation := out["delegation"].(map[string]any)
	address := delegation["address"].(string)
	require.True(t, strings.HasPrefix(address, "tark1"))
	require.Equal(t, "120", delegation["maxFee"])
	code, _ = post(map[string]any{"tapscripts": tapscripts, "renewalWindow": 900, "maxFee": 120})
	require.Equal(t, http.StatusConflict, code, "already registered")

	var detail struct {
		Delegation struct{ Address, Status string }
		Vtxos      []any
		Renewals   []any
	}
	getJSON(t, base+"/v1/delegate/"+address, &detail)
	require.Equal(t, address, detail.Delegation.Address)
	require.Equal(t, "active", detail.Delegation.Status)
	require.Empty(t, detail.Vtxos)

	// the owner stops delegating with a signature from the exit key
	revoke := func(key *btcec.PrivateKey, ts int64) (int, map[string]any) {
		sig, err := schnorr.Sign(key, application.RevocationHash(address, ts))
		require.NoError(t, err)
		raw, err := json.Marshal(map[string]any{
			"pubkey": hex.EncodeToString(key.PubKey().SerializeCompressed()), "signature": hex.EncodeToString(sig.Serialize()), "timestamp": ts,
		})
		require.NoError(t, err)
		resp, err := http.Post(base+"/v1/delegate/"+address+"/revoke", "application/json", bytes.NewReader(raw))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		return resp.StatusCode, out
	}
	stranger, _ := hexKeyPair(t)
	code, out = revoke(stranger, time.Now().Unix())
	require.Equal(t, http.StatusForbidden, code)
	require.Contains(t, out["message"], "not a key of the exit leaf")
	code, _ = revoke(userKey, time.Now().Add(-time.Hour).Unix())
	require.Equal(t, http.StatusForbidden, code, "stale signature")
	code, _ = revoke(userKey, time.Now().Unix())
	require.Equal(t, http.StatusOK, code)
	getJSON(t, base+"/v1/delegate/"+address, &detail)
	require.Equal(t, "revoked", detail.Delegation.Status)

	resp, err := http.Get(base + "/v1/delegate/tark1nobody")
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	// the admin API is not reachable from the public port
	req, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, base+"/v1/admin/delegate/"+address, nil)
	require.NoError(t, err)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestStopWaitsForTheBatch: stopping mid-renewal finishes the batch first.
// An intent abandoned mid-round would stall arkd and strand the coin.
func TestStopWaitsForTheBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the regtest stack")
	}
	ctx := t.Context()
	d := startDelegatee(t)
	alice, alicePubKey := setupAlice(t)
	fundAndSettle(t, alice, 100_000)
	reg := registerDelegation(t, d, alicePubKey, renewalWindow, 0)
	fundingTxid, err := alice.SendOffChain(ctx, []types.Receiver{{To: reg.address, Amount: delegateAmount}})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		st, err := d.admin.GetStatus(ctx, &delegateev1.GetStatusRequest{})
		return err == nil && st.GetRenewingVtxos() == 1
	}, time.Minute, 20*time.Millisecond, "never saw the renewal in flight")
	d.stop() // returns once the batch is done

	// the service is gone: whatever shows up now, it did before returning
	var renewed bool
	require.Eventually(t, func() bool {
		for _, v := range spendable(t, d, reg.pkScript) {
			renewed = renewed || (v.Txid != fundingTxid && !v.Preconfirmed)
		}
		return renewed
	}, 15*time.Second, 500*time.Millisecond, "the in-flight renewal was abandoned")
}
