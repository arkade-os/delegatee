package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	singlekeywallet "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store/inmemory"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/store"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/core/application"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// restClient talks to the JSON gateway with the generated messages.
type restClient struct{ base string }

func (c restClient) GetInfo(ctx context.Context, req *delegateev1.GetInfoRequest) (*delegateev1.GetInfoResponse, error) {
	out := &delegateev1.GetInfoResponse{}
	url := fmt.Sprintf("%s/v1/info?renewalWindow=%d", c.base, req.GetRenewalWindow())
	return out, c.do(ctx, http.MethodGet, url, nil, out)
}

func (c restClient) RegisterDelegation(ctx context.Context, req *delegateev1.RegisterDelegationRequest) (*delegateev1.RegisterDelegationResponse, error) {
	out := &delegateev1.RegisterDelegationResponse{}
	return out, c.do(ctx, http.MethodPost, c.base+"/v1/delegate", req, out)
}

func (c restClient) do(ctx context.Context, method, url string, in, out proto.Message) error {
	var body io.Reader
	if in != nil {
		raw, err := protojson.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: %d %s", method, url, resp.StatusCode, raw)
	}
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(raw, out)
}

// TestLiveDelegatee drives a deployed delegatee on a live network. It needs
// a funded wallet, so it prints a boarding address and waits for you to send
// to it (e.g. from https://faucet.mutinynet.com). Run with:
//
//	DELEGATEE_URL=https://delegatee.mutinynet.arkade.sh \
//	ARK_URL=https://mutinynet.arkade.sh \
//	go test -v -count=1 -timeout 40m -run TestLiveDelegatee ./test/e2e/
//
// WALLET_KEY (hex) reuses a wallet you already funded. With a 3 day window
// the renewal only happens 3 days before the vtxo expires: the first run
// funds the delegate vtxo and tells you when to rerun.
func TestLiveDelegatee(t *testing.T) {
	delegateeURL := os.Getenv("DELEGATEE_URL")
	arkURL := os.Getenv("ARK_URL")
	if delegateeURL == "" || arkURL == "" {
		t.Skip("set DELEGATEE_URL and ARK_URL")
	}
	ctx := t.Context()

	// the public endpoint only exposes the JSON gateway
	client := restClient{base: strings.TrimSuffix(delegateeURL, "/")}

	indexerSvc, err := grpcindexer.NewClient(arkURL)
	require.NoError(t, err)
	t.Cleanup(indexerSvc.Close)

	// --- wallet
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	if k := os.Getenv("WALLET_KEY"); k != "" {
		raw, err := hex.DecodeString(k)
		require.NoError(t, err)
		privKey, _ = btcec.PrivKeyFromBytes(raw)
	}
	t.Logf("WALLET_KEY=%x", privKey.Serialize())
	idStore, err := inmemorystore.NewStore()
	require.NoError(t, err)
	identity, err := singlekeywallet.NewIdentity(idStore)
	require.NoError(t, err)
	configStore, err := store.NewStore(store.Config{ConfigStoreType: types.InMemoryStore})
	require.NoError(t, err)
	w, err := clientlib.NewWallet(configStore, clientlib.WithIdentity(identity))
	require.NoError(t, err)
	require.NoError(t, w.Init(ctx, clientlib.InitArgs{
		ServerUrl: arkURL, Seed: hex.EncodeToString(privKey.Serialize()), Password: password,
		ExplorerURL: "https://mempool.mutinynet.arkade.sh/api",
	}))
	require.NoError(t, w.Unlock(ctx, password))
	t.Cleanup(w.Stop) // Stop panics on a wallet that never initialised
	wallet := testWallet{w}

	balance, err := wallet.Balance(ctx)
	require.NoError(t, err)
	if balance.OffchainBalance.Total == 0 {
		if onchainTotal(balance) == 0 {
			_, offchain, boarding, err := wallet.Receive(ctx)
			require.NoError(t, err)
			fmt.Printf("\n>>> fund the wallet, checking every 10s:\n"+
				"    offchain: %s  (e.g. curl -X POST https://faucet.mutinynet.arkade.sh/faucet -d '{\"address\":\"%s\",\"amount\":50000}')\n"+
				"    onchain:  %s  (e.g. https://faucet.mutinynet.com)\n\n", offchain.Address, offchain.Address, boarding.Address)
			require.Eventually(t, func() bool {
				b, err := wallet.Balance(ctx)
				return err == nil && (onchainTotal(b) > 0 || b.OffchainBalance.Total > 0)
			}, 20*time.Minute, 10*time.Second, "funds never arrived")
			balance, err = wallet.Balance(ctx)
			require.NoError(t, err)
		}
		if balance.OffchainBalance.Total == 0 {
			t.Log("settling boarding funds (waits for a batch)...")
			_, err = wallet.Settle(ctx)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				b, err := wallet.Balance(ctx)
				return err == nil && b.OffchainBalance.Total > 0
			}, 5*time.Minute, 5*time.Second, "offchain balance never arrived")
		}
	}
	balance, err = wallet.Balance(ctx)
	require.NoError(t, err)
	t.Logf("offchain balance: %d sats", balance.OffchainBalance.Total)

	// --- delegate address with a 3 day renewal window
	const window = int64(3 * 24 * 3600)
	info, err := client.GetInfo(ctx, &delegateev1.GetInfoRequest{RenewalWindow: window})
	require.NoError(t, err)
	t.Logf("delegatee %s on %s", info.GetVersion(), info.GetNetwork())
	serverPubKey, err := application.PubKeyFromHex(info.GetServerPubkey())
	require.NoError(t, err)
	tweakedPubKey, err := application.PubKeyFromHex(info.GetEmulatorTweakedPubkey())
	require.NoError(t, err)
	vtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{PubKeys: []*btcec.PublicKey{serverPubKey, tweakedPubKey}},
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{privKey.PubKey()}},
				Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 2048},
			},
		},
	}
	tapscripts, err := vtxoScript.Encode()
	require.NoError(t, err)
	tapKey, _, err := vtxoScript.TapTree()
	require.NoError(t, err)
	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)

	address, err := (&arklib.Address{HRP: "tark", Signer: serverPubKey, VtxoTapKey: tapKey}).EncodeV0()
	require.NoError(t, err)
	_, err = client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{
		Tapscripts: tapscripts, RenewalWindow: window,
	})
	if err != nil && !strings.Contains(err.Error(), "already registered") { // reruns with the same WALLET_KEY
		require.NoError(t, err)
	}
	t.Logf("delegation at %s", address)

	// reuse a vtxo funded by an earlier run, else fund one now
	listVtxos := func() []types.Vtxo {
		resp, err := indexerSvc.GetVtxos(ctx,
			indexer.WithScripts([]string{hex.EncodeToString(pkScript)}), indexer.WithSpendableOnly())
		if err != nil {
			return nil
		}
		return resp.Vtxos
	}
	vtxos := listVtxos()
	if len(vtxos) == 0 {
		amount := min(balance.OffchainBalance.Total/2, 20_000)
		fundingTxid, err := wallet.SendOffChain(ctx, []types.Receiver{{To: address, Amount: amount}})
		require.NoError(t, err)
		t.Logf("funded %d sats in %s", amount, fundingTxid)
		require.Eventually(t, func() bool { vtxos = listVtxos(); return len(vtxos) > 0 }, time.Minute, 5*time.Second)
	}
	current := vtxos[0]
	opensAt := current.ExpiresAt.Add(-time.Duration(window) * time.Second)
	t.Logf("vtxo %s expires %s, renewal window opens %s", current.Outpoint.String(), current.ExpiresAt, opensAt)
	if wait := time.Until(opensAt); wait > 10*time.Minute {
		t.Logf("rerun after %s with WALLET_KEY=%x to see the renewal", opensAt.Format(time.RFC3339), privKey.Serialize())
		return
	}

	t.Log("waiting for the delegatee to renew it...")
	var renewed types.Vtxo
	require.Eventually(t, func() bool {
		for _, v := range listVtxos() {
			if v.Txid != current.Txid && !v.Preconfirmed && !v.Spent && v.Amount == current.Amount {
				renewed = v
				return true
			}
		}
		return false
	}, 30*time.Minute, 15*time.Second, "vtxo not renewed")
	t.Logf("renewed: %s in commitment %v, expires %s", renewed.Outpoint.String(), renewed.CommitmentTxids, renewed.ExpiresAt)
}
