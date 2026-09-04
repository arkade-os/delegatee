// Package e2e drives the delegatee against a live regtest stack (nigiri +
// arkd + emulator, see docker-compose.regtest.yml) and the postgres from the
// same compose file. Run with `make test-e2e`.
package e2e

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	singlekeywallet "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store/inmemory"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/config"
	"github.com/arkade-os/delegatee/internal/core/application"
	grpcservice "github.com/arkade-os/delegatee/internal/interface/grpc"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	arkURL         = "localhost:7070"
	emulatorURL    = "localhost:7073"
	explorerURL    = "http://localhost:3000"
	delegateAmount = uint64(10_000)
	assetAmount    = uint64(1_000)
	exitDelay      = uint32(512)
	renewalWindow  = 1024 // regtest batch expiry is 512s, so leaves are always renewable
	password       = "password"
)

func TestDelegateRenewal(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the regtest stack")
	}
	ctx := t.Context()

	// --- delegateed in-process on a free port, real dependencies
	dsn := os.Getenv("DELEGATEE_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres@localhost:5432/delegatee?sslmode=disable"
	}
	delegateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	port, adminPort := freePort(t), freePort(t)
	svc, err := grpcservice.NewService("e2e", &config.Config{
		ArkURL:            arkURL,
		EmulatorURL:       emulatorURL,
		DatabaseURL:       dsn,
		Port:              port,
		AdminPort:         adminPort,
		SecretKey:         delegateKey,
		PollInterval:      2 * time.Second,
		RenewalTimeout:    2 * time.Minute,
		MaxVtxosPerIntent: 16,
	})
	require.NoError(t, err)
	require.NoError(t, svc.Start())
	t.Cleanup(svc.Stop)

	addr := net.JoinHostPort("localhost", strconv.Itoa(int(port)))
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := delegateev1.NewDelegateeServiceClient(conn)
	adminConn, err := grpc.NewClient(
		net.JoinHostPort("localhost", strconv.Itoa(int(adminPort))),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = adminConn.Close() })
	admin := delegateev1.NewAdminServiceClient(adminConn)

	indexerSvc, err := grpcindexer.NewClient(arkURL)
	require.NoError(t, err)
	t.Cleanup(indexerSvc.Close)

	// --- alice: funded sdk wallet, the user who delegates
	alice, alicePubKey := setupAlice(t)
	fundAndSettle(t, alice, 100_000)

	// --- build the delegate script from GetInfo (grpc and REST agree)
	info, err := client.GetInfo(ctx, &delegateev1.GetInfoRequest{RenewalWindow: renewalWindow})
	require.NoError(t, err)
	require.Equal(t, int64(renewalWindow), info.GetRenewalWindow())
	var restInfo struct {
		DelegatePubkey string `json:"delegatePubkey"`
	}
	getJSON(t, "http://"+addr+"/v1/info?renewalWindow="+strconv.Itoa(renewalWindow), &restInfo)
	require.Equal(t, info.GetDelegatePubkey(), restInfo.DelegatePubkey)
	var health struct{ Status string }
	getJSON(t, "http://"+addr+"/healthz", &health)
	require.Equal(t, "SERVING", health.Status)

	serverPubKey, err := application.PubKeyFromHex(info.GetServerPubkey())
	require.NoError(t, err)
	tweakedPubKey, err := application.PubKeyFromHex(info.GetEmulatorTweakedPubkey())
	require.NoError(t, err)

	delegateScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{PubKeys: []*btcec.PublicKey{serverPubKey, tweakedPubKey}},
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{alicePubKey}},
				Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: exitDelay},
			},
		},
	}
	tapscripts, err := delegateScript.Encode()
	require.NoError(t, err)
	require.Contains(t, tapscripts, info.GetDelegateTapscript())
	tapKey, _, err := delegateScript.TapTree()
	require.NoError(t, err)
	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)

	// --- register
	reg, err := client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{Tapscripts: tapscripts, RenewalWindow: renewalWindow})
	require.NoError(t, err)
	address := reg.GetDelegation().GetAddress()
	require.Equal(t, "active", reg.GetDelegation().GetStatus())
	require.Equal(t, int64(renewalWindow), reg.GetDelegation().GetRenewalWindow())
	expectedAddr, err := (&arklib.Address{HRP: "tark", Signer: serverPubKey, VtxoTapKey: tapKey}).EncodeV0()
	require.NoError(t, err)
	require.Equal(t, expectedAddr, address)
	t.Cleanup(func() {
		_, _ = admin.CancelDelegation(context.WithoutCancel(ctx), &delegateev1.CancelDelegationRequest{Address: address})
	})

	// duplicate and invalid registrations are rejected
	_, err = client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{Tapscripts: tapscripts, RenewalWindow: renewalWindow})
	require.Equal(t, codes.AlreadyExists, status.Code(err))
	plainScript := script.NewDefaultVtxoScript(alicePubKey, serverPubKey,
		arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: exitDelay})
	plainTapscripts, err := plainScript.Encode()
	require.NoError(t, err)
	_, err = client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{Tapscripts: plainTapscripts, RenewalWindow: renewalWindow})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	// --- alice locks funds at the delegate address
	fundingTxid, err := alice.SendOffChain(ctx, []types.Receiver{{To: address, Amount: delegateAmount}})
	require.NoError(t, err)
	t.Logf("funded delegate vtxo in %s", fundingTxid)

	// --- the delegatee renews it through a batch, without alice
	noAssets := func(v types.Vtxo) bool { return len(v.Assets) == 0 }
	first := waitForRenewedVtxo(t, indexerSvc, pkScript, fundingTxid, noAssets)
	t.Logf("first renewal: %s", first.Outpoint.String())

	// and renews the batch leaf again, proving tree txs work as prev ark tx
	second := waitForRenewedVtxo(t, indexerSvc, pkScript, first.Txid, noAssets)
	t.Logf("second renewal: %s", second.Outpoint.String())

	// --- a vtxo carrying an asset is renewed with its asset intact
	_, assetIDs, err := alice.IssueAsset(ctx, assetAmount, nil, nil)
	require.NoError(t, err)
	require.Len(t, assetIDs, 1)
	assetID := assetIDs[0].String()
	assetFundingTxid, err := alice.SendOffChain(ctx, []types.Receiver{{
		To: address, Amount: delegateAmount, Assets: []types.Asset{{AssetId: assetID, Amount: assetAmount}},
	}})
	require.NoError(t, err)
	t.Logf("funded asset delegate vtxo in %s", assetFundingTxid)
	renewedAsset := waitForRenewedVtxo(t, indexerSvc, pkScript, assetFundingTxid, func(v types.Vtxo) bool {
		return len(v.Assets) == 1 && v.Assets[0].AssetId == assetID && v.Assets[0].Amount == assetAmount
	})
	t.Logf("asset renewal: %s", renewedAsset.Outpoint.String())

	detail, err := admin.GetDelegation(ctx, &delegateev1.GetDelegationRequest{Address: address})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(detail.GetRenewals()), 3)
	for _, ren := range detail.GetRenewals() {
		require.True(t, ren.GetSuccess(), "renewal failed: %+v", ren)
		require.NotEmpty(t, ren.GetCommitmentTxid())
	}
	oldest := detail.GetRenewals()[len(detail.GetRenewals())-1]
	require.Contains(t, oldest.GetOutpoints(), fundingTxid+":0")
	require.NotEmpty(t, detail.GetVtxos())

	// --- cancel stops renewals, re-registering resumes them
	_, err = admin.CancelDelegation(ctx, &delegateev1.CancelDelegationRequest{Address: address})
	require.NoError(t, err)
	detail, err = admin.GetDelegation(ctx, &delegateev1.GetDelegationRequest{Address: address})
	require.NoError(t, err)
	require.Equal(t, "cancelled", detail.GetDelegation().GetStatus())
	_, err = admin.CancelDelegation(ctx, &delegateev1.CancelDelegationRequest{Address: "tark1unknown"})
	require.Equal(t, codes.NotFound, status.Code(err))
	reg, err = client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{Tapscripts: tapscripts, RenewalWindow: renewalWindow})
	require.NoError(t, err)
	require.Equal(t, "active", reg.GetDelegation().GetStatus())

	list, err := admin.ListDelegations(ctx, &delegateev1.ListDelegationsRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, list.GetDelegations())
}

// waitForRenewedVtxo polls the indexer until a settled (non-preconfirmed),
// unspent vtxo of delegateAmount other than prevTxid matching match sits at pkScript.
func waitForRenewedVtxo(
	t *testing.T, indexerSvc indexer.Indexer, pkScript []byte, prevTxid string, match func(types.Vtxo) bool,
) types.Vtxo {
	t.Helper()
	var found types.Vtxo
	require.Eventually(t, func() bool {
		resp, err := indexerSvc.GetVtxos(t.Context(),
			indexer.WithScripts([]string{hex.EncodeToString(pkScript)}),
			indexer.WithSpendableOnly(),
		)
		if err != nil {
			return false
		}
		for _, v := range resp.Vtxos {
			if v.Txid != prevTxid && !v.Preconfirmed && !v.Spent && v.Amount == delegateAmount && match(v) {
				found = v
				return true
			}
		}
		return false
	}, 2*time.Minute, 500*time.Millisecond, "vtxo at %x not renewed after %s", pkScript, prevTxid)
	return found
}

func setupAlice(t *testing.T) (arksdk.Wallet, *btcec.PublicKey) {
	t.Helper()
	ctx := t.Context()

	store, err := inmemorystore.NewStore()
	require.NoError(t, err)
	identity, err := singlekeywallet.NewIdentity(store)
	require.NoError(t, err)
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	wallet, err := arksdk.NewWallet(t.TempDir(), arksdk.WithIdentity(identity))
	require.NoError(t, err)
	t.Cleanup(wallet.Stop)
	require.NoError(t, wallet.Init(
		ctx, arkURL, hex.EncodeToString(privKey.Serialize()), password,
		arksdk.WithExplorerURL(explorerURL),
	))
	require.NoError(t, wallet.Unlock(ctx, password))
	synced := <-wallet.IsSynced(ctx)
	require.NoError(t, synced.Err)
	require.True(t, synced.Synced)
	log.SetLevel(log.InfoLevel) // the sdk lowers the global level
	return wallet, privKey.PubKey()
}

func fundAndSettle(t *testing.T, wallet arksdk.Wallet, amount int64) {
	t.Helper()
	ctx := t.Context()
	boardingAddr, err := wallet.NewBoardingAddress(ctx)
	require.NoError(t, err)

	amountBtc := strings.TrimSuffix(btcutil.Amount(amount).Format(btcutil.AmountBTC), " BTC")
	out, err := exec.Command("nigiri", "faucet", boardingAddr, amountBtc).CombinedOutput()
	require.NoError(t, err, string(out))

	require.Eventually(t, func() bool {
		balance, err := wallet.Balance(ctx)
		return err == nil && balance.OnchainBalance.Total > 0
	}, 30*time.Second, 500*time.Millisecond, "boarding utxo not detected")

	_, err = wallet.Settle(ctx)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		balance, err := wallet.Balance(ctx)
		return err == nil && balance.OffchainBalance.Total > 0
	}, 30*time.Second, 500*time.Millisecond, "offchain balance not available")
}

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(out))
}

func freePort(t *testing.T) uint32 {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := lis.Addr().(*net.TCPAddr).Port
	require.NoError(t, lis.Close())
	return uint32(port)
}

func TestConcurrentDelegations(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the regtest stack")
	}
	ctx := t.Context()
	const n = 10

	dsn := os.Getenv("DELEGATEE_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres@localhost:5432/delegatee?sslmode=disable"
	}
	delegateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	port, adminPort := freePort(t), freePort(t)
	svc, err := grpcservice.NewService("e2e", &config.Config{
		ArkURL:            arkURL,
		EmulatorURL:       emulatorURL,
		DatabaseURL:       dsn,
		Port:              port,
		AdminPort:         adminPort,
		SecretKey:         delegateKey,
		PollInterval:      2 * time.Second,
		RenewalTimeout:    2 * time.Minute,
		MaxVtxosPerIntent: 16,
	})
	require.NoError(t, err)
	require.NoError(t, svc.Start())
	t.Cleanup(svc.Stop)

	conn, err := grpc.NewClient(
		net.JoinHostPort("localhost", strconv.Itoa(int(port))),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := delegateev1.NewDelegateeServiceClient(conn)
	adminConn, err := grpc.NewClient(
		net.JoinHostPort("localhost", strconv.Itoa(int(adminPort))),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = adminConn.Close() })
	admin := delegateev1.NewAdminServiceClient(adminConn)

	indexerSvc, err := grpcindexer.NewClient(arkURL)
	require.NoError(t, err)
	t.Cleanup(indexerSvc.Close)

	alice, _ := setupAlice(t)
	fundAndSettle(t, alice, 200_000)

	info, err := client.GetInfo(ctx, &delegateev1.GetInfoRequest{RenewalWindow: renewalWindow})
	require.NoError(t, err)
	serverPubKey, err := application.PubKeyFromHex(info.GetServerPubkey())
	require.NoError(t, err)
	tweakedPubKey, err := application.PubKeyFromHex(info.GetEmulatorTweakedPubkey())
	require.NoError(t, err)

	// one delegate address per user, all funded by a single tx
	pkScripts := make([][]byte, n)
	receivers := make([]types.Receiver, n)
	for i := range n {
		userKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		vtxoScript := script.TapscriptsVtxoScript{
			Closures: []script.Closure{
				&script.MultisigClosure{PubKeys: []*btcec.PublicKey{serverPubKey, tweakedPubKey}},
				&script.CSVMultisigClosure{
					MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{userKey.PubKey()}},
					Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: exitDelay},
				},
			},
		}
		tapscripts, err := vtxoScript.Encode()
		require.NoError(t, err)
		tapKey, _, err := vtxoScript.TapTree()
		require.NoError(t, err)
		pkScripts[i], err = script.P2TRScript(tapKey)
		require.NoError(t, err)

		reg, err := client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{Tapscripts: tapscripts, RenewalWindow: renewalWindow})
		require.NoError(t, err)
		address := reg.GetDelegation().GetAddress()
		receivers[i] = types.Receiver{To: address, Amount: delegateAmount}
		t.Cleanup(func() {
			_, _ = admin.CancelDelegation(context.WithoutCancel(ctx), &delegateev1.CancelDelegationRequest{Address: address})
		})
	}
	fundingTxid, err := alice.SendOffChain(ctx, receivers)
	require.NoError(t, err)
	t.Logf("funded %d delegate vtxos in %s", n, fundingTxid)

	renewed := make([]types.Vtxo, n)
	for i := range n {
		renewed[i] = waitForRenewedVtxo(t, indexerSvc, pkScripts[i], fundingTxid, func(types.Vtxo) bool { return true })
	}
	commitments := map[string]int{}
	for _, v := range renewed {
		require.Len(t, v.CommitmentTxids, 1)
		commitments[v.CommitmentTxids[0]]++
	}
	t.Logf("renewed %d vtxos across %d batches", n, len(commitments))
}

// TestRenewalWindows registers delegations with different windows: on regtest
// vtxos expire 512s after their batch, so windows above that renew right away
// while a 60s window must wait.
func TestRenewalWindows(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the regtest stack")
	}
	ctx := t.Context()

	dsn := os.Getenv("DELEGATEE_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres@localhost:5432/delegatee?sslmode=disable"
	}
	delegateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	port, adminPort := freePort(t), freePort(t)
	svc, err := grpcservice.NewService("e2e", &config.Config{
		ArkURL:            arkURL,
		EmulatorURL:       emulatorURL,
		DatabaseURL:       dsn,
		Port:              port,
		AdminPort:         adminPort,
		SecretKey:         delegateKey,
		PollInterval:      2 * time.Second,
		RenewalTimeout:    2 * time.Minute,
		MaxVtxosPerIntent: 16,
	})
	require.NoError(t, err)
	require.NoError(t, svc.Start())
	t.Cleanup(svc.Stop)

	conn, err := grpc.NewClient(
		net.JoinHostPort("localhost", strconv.Itoa(int(port))),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := delegateev1.NewDelegateeServiceClient(conn)
	adminConn, err := grpc.NewClient(
		net.JoinHostPort("localhost", strconv.Itoa(int(adminPort))),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = adminConn.Close() })
	admin := delegateev1.NewAdminServiceClient(adminConn)

	indexerSvc, err := grpcindexer.NewClient(arkURL)
	require.NoError(t, err)
	t.Cleanup(indexerSvc.Close)

	alice, alicePubKey := setupAlice(t)
	fundAndSettle(t, alice, 100_000)

	// different windows give different covenants, hence different addresses
	infoA, err := client.GetInfo(ctx, &delegateev1.GetInfoRequest{RenewalWindow: 600})
	require.NoError(t, err)
	infoB, err := client.GetInfo(ctx, &delegateev1.GetInfoRequest{RenewalWindow: 3000})
	require.NoError(t, err)
	infoDefault, err := client.GetInfo(ctx, &delegateev1.GetInfoRequest{})
	require.NoError(t, err)
	require.Equal(t, int64(application.DefaultRenewalWindow), infoDefault.GetRenewalWindow())
	require.NotEqual(t, infoA.GetDelegateTapscript(), infoB.GetDelegateTapscript())
	require.NotEqual(t, infoA.GetArkadeScript(), infoB.GetArkadeScript())

	type delegation struct {
		window   int64
		address  string
		pkScript []byte
	}
	var ds []delegation
	var receivers []types.Receiver
	for _, window := range []int64{600, 3000, 0, 60} {
		info, err := client.GetInfo(ctx, &delegateev1.GetInfoRequest{RenewalWindow: window})
		require.NoError(t, err)
		serverPubKey, err := application.PubKeyFromHex(info.GetServerPubkey())
		require.NoError(t, err)
		tweakedPubKey, err := application.PubKeyFromHex(info.GetEmulatorTweakedPubkey())
		require.NoError(t, err)
		vtxoScript := script.TapscriptsVtxoScript{
			Closures: []script.Closure{
				&script.MultisigClosure{PubKeys: []*btcec.PublicKey{serverPubKey, tweakedPubKey}},
				&script.CSVMultisigClosure{
					MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{alicePubKey}},
					Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: exitDelay},
				},
			},
		}
		tapscripts, err := vtxoScript.Encode()
		require.NoError(t, err)
		tapKey, _, err := vtxoScript.TapTree()
		require.NoError(t, err)
		pkScript, err := script.P2TRScript(tapKey)
		require.NoError(t, err)

		reg, err := client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{
			Tapscripts: tapscripts, RenewalWindow: window,
		})
		require.NoError(t, err)
		want := window
		if want == 0 {
			want = application.DefaultRenewalWindow
		}
		require.Equal(t, want, reg.GetDelegation().GetRenewalWindow())

		// a tapscript built for one window is refused under another
		_, err = client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{
			Tapscripts: tapscripts, RenewalWindow: window + 1,
		})
		require.Equal(t, codes.InvalidArgument, status.Code(err))

		address := reg.GetDelegation().GetAddress()
		ds = append(ds, delegation{window: want, address: address, pkScript: pkScript})
		receivers = append(receivers, types.Receiver{To: address, Amount: delegateAmount})
		t.Cleanup(func() {
			_, _ = admin.CancelDelegation(context.WithoutCancel(ctx), &delegateev1.CancelDelegationRequest{Address: address})
		})
	}
	fundingTxid, err := alice.SendOffChain(ctx, receivers)
	require.NoError(t, err)

	// windows wider than the 512s regtest expiry renew in the next batch
	for _, d := range ds[:3] {
		v := waitForRenewedVtxo(t, indexerSvc, d.pkScript, fundingTxid, func(types.Vtxo) bool { return true })
		t.Logf("window %d renewed: %s", d.window, v.Outpoint.String())
	}

	// the 60s window is still far from expiry: untouched, no renewal attempted
	small := ds[3]
	resp, err := indexerSvc.GetVtxos(ctx,
		indexer.WithScripts([]string{hex.EncodeToString(small.pkScript)}), indexer.WithSpendableOnly())
	require.NoError(t, err)
	require.Len(t, resp.Vtxos, 1)
	require.Equal(t, fundingTxid, resp.Vtxos[0].Txid)
	detail, err := admin.GetDelegation(ctx, &delegateev1.GetDelegationRequest{Address: small.address})
	require.NoError(t, err)
	require.Empty(t, detail.GetRenewals())
}

// TestManyDelegations registers more delegations than fit in one intent and
// expects them all renewed by a single batch through several intents.
func TestManyDelegations(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the regtest stack")
	}
	ctx := t.Context()
	const n, perIntent = 48, 16

	dsn := os.Getenv("DELEGATEE_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres@localhost:5432/delegatee?sslmode=disable"
	}
	delegateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	port, adminPort := freePort(t), freePort(t)
	svc, err := grpcservice.NewService("e2e", &config.Config{
		ArkURL:            arkURL,
		EmulatorURL:       emulatorURL,
		DatabaseURL:       dsn,
		Port:              port,
		AdminPort:         adminPort,
		SecretKey:         delegateKey,
		PollInterval:      15 * time.Second, // first scan after all funding txs landed
		RenewalTimeout:    3 * time.Minute,
		MaxVtxosPerIntent: perIntent,
	})
	require.NoError(t, err)
	require.NoError(t, svc.Start())
	t.Cleanup(svc.Stop)

	conn, err := grpc.NewClient(
		net.JoinHostPort("localhost", strconv.Itoa(int(port))),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := delegateev1.NewDelegateeServiceClient(conn)
	adminConn, err := grpc.NewClient(
		net.JoinHostPort("localhost", strconv.Itoa(int(adminPort))),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = adminConn.Close() })
	admin := delegateev1.NewAdminServiceClient(adminConn)

	indexerSvc, err := grpcindexer.NewClient(arkURL)
	require.NoError(t, err)
	t.Cleanup(indexerSvc.Close)

	alice, _ := setupAlice(t)
	fundAndSettle(t, alice, 1_000_000)

	info, err := client.GetInfo(ctx, &delegateev1.GetInfoRequest{})
	require.NoError(t, err)
	serverPubKey, err := application.PubKeyFromHex(info.GetServerPubkey())
	require.NoError(t, err)
	tweakedPubKey, err := application.PubKeyFromHex(info.GetEmulatorTweakedPubkey())
	require.NoError(t, err)

	pkScripts := make([][]byte, n)
	receivers := make([]types.Receiver, n)
	for i := range n {
		userKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		vtxoScript := script.TapscriptsVtxoScript{
			Closures: []script.Closure{
				&script.MultisigClosure{PubKeys: []*btcec.PublicKey{serverPubKey, tweakedPubKey}},
				&script.CSVMultisigClosure{
					MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{userKey.PubKey()}},
					Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: exitDelay},
				},
			},
		}
		tapscripts, err := vtxoScript.Encode()
		require.NoError(t, err)
		tapKey, _, err := vtxoScript.TapTree()
		require.NoError(t, err)
		pkScripts[i], err = script.P2TRScript(tapKey)
		require.NoError(t, err)
		reg, err := client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{Tapscripts: tapscripts})
		require.NoError(t, err)
		address := reg.GetDelegation().GetAddress()
		receivers[i] = types.Receiver{To: address, Amount: delegateAmount}
		t.Cleanup(func() {
			_, _ = admin.CancelDelegation(context.WithoutCancel(ctx), &delegateev1.CancelDelegationRequest{Address: address})
		})
	}
	// fund in a few txs to stay under arkd's tx weight limit
	for start := 0; start < n; start += 20 {
		_, err := alice.SendOffChain(ctx, receivers[start:min(start+20, n)])
		require.NoError(t, err)
	}

	commitments := map[string]int{}
	for i := range n {
		v := waitForRenewedVtxo(t, indexerSvc, pkScripts[i], "", func(v types.Vtxo) bool { return !v.Preconfirmed })
		require.Len(t, v.CommitmentTxids, 1)
		commitments[v.CommitmentTxids[0]]++
	}
	t.Logf("renewed %d vtxos across %d batches", n, len(commitments))
	require.Len(t, commitments, 1, "all intents should share one batch")
}
