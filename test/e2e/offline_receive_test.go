package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/core/application"
	"github.com/arkade-os/delegatee/pkg/template/ecies"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/stretchr/testify/require"
)

func TestOfflineReceiveFundingDuringDowntime(t *testing.T) {
	d := startDelegatee(t)
	swap := newSwap(t, d)
	addr, pkScript, tree := swapOutput(t, d, swap)
	templateID := registerTemplate(t, d, "offline_receive.json")
	_, err := d.admin.SetTemplateTrusted(t.Context(), &delegateev1.SetTemplateTrustedRequest{Id: templateID, Trusted: true})
	require.NoError(t, err)
	info, err := d.client.GetInfo(t.Context(), &delegateev1.GetInfoRequest{})
	require.NoError(t, err)
	key, err := application.PubKeyFromHex(info.EncryptionPubkey)
	require.NoError(t, err)
	number := func(n int64) string {
		raw, err := arkade.BigNumFromInt64(n).Bytes()
		require.NoError(t, err)
		return hex.EncodeToString(raw)
	}
	until := time.Now().Add(time.Hour).Unix()
	payload, err := json.Marshal(map[string]any{
		"format": "delegatee-secrets/v1", "template_id": templateID,
		"values": map[string]string{
			"preimage":      hex.EncodeToString(swap.preimage),
			"minimum_value": number(10_000), "claim_until": number(until),
			"lockup_program": hex.EncodeToString(pkScript[2:]),
		},
	})
	require.NoError(t, err)
	ciphertext, err := ecies.Encrypt(key, payload)
	require.NoError(t, err)
	code, response := postJSON(t, "http://"+d.addr+"/v1/delegate", map[string]any{
		"template_id": templateID, "expires_at": until,
		"variables": map[string]string{
			"taptree": hex.EncodeToString(tree), "receiver_program": swap.variables["receiver_program"],
			"ciphertext": hex.EncodeToString(ciphertext),
		},
	})
	require.Equal(t, 200, code)
	require.Equal(t, addr, response["delegation"].(map[string]any)["address"])
	alice := fundedWallet(t)
	d.stop()
	funding, err := alice.SendOffChain(t.Context(), []clientlib.Receiver{{To: addr, Amount: 10_000}})
	require.NoError(t, err)
	d = restart(t, d)
	paid := waitForVtxo(t, d, swap.receiverScript, funding)
	require.EqualValues(t, 10_000, paid.Amount)
	claim, err := d.indexer.GetVirtualTxs(t.Context(), []string{paid.Txid})
	require.NoError(t, err)
	require.Len(t, claim.Txs, 1)
	raw, err := base64.StdEncoding.DecodeString(claim.Txs[0])
	require.NoError(t, err)
	require.True(t, bytes.Contains(raw, swap.preimage))
}
