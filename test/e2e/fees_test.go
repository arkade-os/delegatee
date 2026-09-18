package e2e

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const arkdAdminURL = "http://localhost:7071"

// TestIntentFees makes arkd charge 100 sats per offchain input: a delegation
// with max_fee 150 is renewed minus the fee, one with max_fee 0 is left
// alone with the reason recorded. Slow: a delegation that may pay fees is
// only renewed in the second half of a vtxo's life, 256s on regtest.
func TestIntentFees(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the regtest stack")
	}
	ctx := t.Context()
	const fee = 100

	d := startDelegatee(t)
	client, indexerSvc := d.client, d.indexer

	alice, alicePubKey := setupAlice(t)
	fundAndSettle(t, alice, 100_000)

	type delegation struct {
		address  string
		pkScript []byte
	}
	register := func(maxFee int64) delegation {
		info, err := client.GetInfo(ctx, &delegateev1.GetInfoRequest{RenewalWindow: renewalWindow, MaxFee: maxFee})
		require.NoError(t, err)
		require.Equal(t, maxFee, info.GetMaxFee())
		_, tapscripts, pkScript := delegateScript(t, info, alicePubKey)
		// the params are part of the covenant: registering with others fails
		_, err = client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{
			Tapscripts: tapscripts, RenewalWindow: renewalWindow, MaxFee: maxFee + 1,
		})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
		reg, err := client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{
			Tapscripts: tapscripts, RenewalWindow: renewalWindow, MaxFee: maxFee,
		})
		require.NoError(t, err)
		require.Equal(t, maxFee, reg.GetDelegation().GetMaxFee())
		return delegation{reg.GetDelegation().GetAddress(), pkScript}
	}
	paying, free := register(150), register(0)
	require.NotEqual(t, paying.address, free.address)

	_, err := alice.SendOffChain(ctx, []types.Receiver{
		{To: paying.address, Amount: delegateAmount}, {To: free.address, Amount: delegateAmount},
	})
	require.NoError(t, err)
	// a second delegation that pays fees holds an asset: the fee covenant
	// tunnels script and assets but not the value, unlike the zero-fee one
	withAsset := register(200)
	_, assetIDs, err := alice.IssueAsset(ctx, assetAmount, nil, nil)
	require.NoError(t, err)
	assetID := assetIDs[0].String()
	_, err = alice.SendOffChain(ctx, []types.Receiver{{
		To: withAsset.address, Amount: delegateAmount, Assets: []types.Asset{{AssetId: assetID, Amount: assetAmount}},
	}})
	require.NoError(t, err)

	// fund first, charge after: the test is about renewals, not alice's sends
	postJSON(t, arkdAdminURL+"/v1/admin/intentFees", `{"fees":{"offchainInputFee":"`+strconv.Itoa(fee)+`.0"}}`)
	t.Cleanup(func() { postJSON(t, arkdAdminURL+"/v1/admin/intentFees/clear", `{}`) })

	require.Eventually(t, func() bool {
		resp, err := indexerSvc.GetVtxos(ctx,
			indexer.WithScripts([]string{hex.EncodeToString(paying.pkScript)}), indexer.WithSpendableOnly())
		if err != nil {
			return false
		}
		for _, v := range resp.Vtxos {
			if !v.Preconfirmed && v.Amount == delegateAmount-fee {
				return true
			}
		}
		return false
	}, 7*time.Minute, time.Second, "vtxo not renewed minus the fee")
	require.Eventually(t, func() bool {
		for _, v := range spendable(t, d, withAsset.pkScript) {
			if !v.Preconfirmed && v.Amount == delegateAmount-fee {
				return len(v.Assets) == 1 && v.Assets[0].AssetId == assetID && v.Assets[0].Amount == assetAmount
			}
		}
		return false
	}, 2*time.Minute, time.Second, "asset coin not renewed minus the fee with its asset intact")

	// renewed once, not in every round: the amount lost is exactly one fee
	time.Sleep(15 * time.Second)
	resp, err := indexerSvc.GetVtxos(ctx,
		indexer.WithScripts([]string{hex.EncodeToString(paying.pkScript)}), indexer.WithSpendableOnly())
	require.NoError(t, err)
	require.Len(t, resp.Vtxos, 1)
	require.Equal(t, uint64(delegateAmount-fee), resp.Vtxos[0].Amount)

	require.Eventually(t, func() bool {
		detail, err := client.GetDelegation(ctx, &delegateev1.GetDelegationRequest{Address: free.address})
		if err != nil || len(detail.GetRenewals()) == 0 {
			return false
		}
		ren := detail.GetRenewals()[0]
		return !ren.GetSuccess() && strings.Contains(ren.GetError(), "exceeds the delegation max fee")
	}, time.Minute, 500*time.Millisecond, "fee refusal not recorded")
	resp, err = indexerSvc.GetVtxos(ctx,
		indexer.WithScripts([]string{hex.EncodeToString(free.pkScript)}), indexer.WithSpendableOnly())
	require.NoError(t, err)
	require.Len(t, resp.Vtxos, 1)
	require.True(t, resp.Vtxos[0].Preconfirmed, "zero max fee vtxo must not be renewed")
}

func postJSON(t *testing.T, url, body string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
