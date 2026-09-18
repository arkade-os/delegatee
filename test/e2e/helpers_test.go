package e2e

import (
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/config"
	"github.com/arkade-os/delegatee/internal/core/application"
	grpcservice "github.com/arkade-os/delegatee/internal/interface/grpc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// delegatee is a delegateed running in-process on free ports, with a fresh
// random key, against the real regtest dependencies.
type delegatee struct {
	client    delegateev1.DelegateeServiceClient
	admin     delegateev1.AdminServiceClient
	indexer   indexer.Indexer
	addr      string // public host:port
	adminAddr string
	stop      func() // also runs at cleanup; blocks until the in-flight batch is done
}

func startDelegatee(t *testing.T, tweak ...func(*config.Config)) delegatee {
	t.Helper()
	dsn := os.Getenv("DELEGATEE_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres@localhost:5432/delegatee?sslmode=disable"
	}
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	cfg := &config.Config{
		ArkURL: arkURL, EmulatorURL: emulatorURL, DatabaseURL: dsn,
		Port: freePort(t), AdminPort: freePort(t), SecretKey: key,
		PollInterval: 2 * time.Second, RenewalTimeout: 2 * time.Minute, MaxVtxosPerIntent: 16,
		MaxDelegations: 50_000,
	}
	for _, f := range tweak {
		f(cfg)
	}
	svc, err := grpcservice.NewService("e2e", cfg)
	require.NoError(t, err)
	require.NoError(t, svc.Start())
	t.Cleanup(svc.Stop)

	d := delegatee{
		stop:      svc.Stop,
		addr:      net.JoinHostPort("localhost", strconv.Itoa(int(cfg.Port))),
		adminAddr: net.JoinHostPort("localhost", strconv.Itoa(int(cfg.AdminPort))),
	}
	dial := func(addr string) *grpc.ClientConn {
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	d.client = delegateev1.NewDelegateeServiceClient(dial(d.addr))
	d.admin = delegateev1.NewAdminServiceClient(dial(d.adminAddr))
	indexerSvc, err := grpcindexer.NewClient(arkURL)
	require.NoError(t, err)
	t.Cleanup(indexerSvc.Close)
	d.indexer = indexerSvc
	return d
}

// delegateScript is the vtxo script a wallet builds from GetInfo: the
// delegate leaf plus the user's own exit leaf.
func delegateScript(
	t *testing.T, info *delegateev1.GetInfoResponse, userPubKey *btcec.PublicKey,
) (vtxoScript script.TapscriptsVtxoScript, tapscripts []string, pkScript []byte) {
	t.Helper()
	serverPubKey, err := application.PubKeyFromHex(info.GetServerPubkey())
	require.NoError(t, err)
	tweakedPubKey, err := application.PubKeyFromHex(info.GetEmulatorTweakedPubkey())
	require.NoError(t, err)
	vtxoScript = script.TapscriptsVtxoScript{Closures: []script.Closure{
		&script.MultisigClosure{PubKeys: []*btcec.PublicKey{serverPubKey, tweakedPubKey}},
		&script.CSVMultisigClosure{
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{userPubKey}},
			Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: exitDelay},
		},
	}}
	tapscripts, err = vtxoScript.Encode()
	require.NoError(t, err)
	require.Contains(t, tapscripts, info.GetDelegateTapscript())
	tapKey, _, err := vtxoScript.TapTree()
	require.NoError(t, err)
	pkScript, err = script.P2TRScript(tapKey)
	require.NoError(t, err)
	return vtxoScript, tapscripts, pkScript
}

// spendable lists the unspent vtxos at pkScript.
func spendable(t *testing.T, d delegatee, pkScript []byte) []types.Vtxo {
	t.Helper()
	resp, err := d.indexer.GetVtxos(t.Context(),
		indexer.WithScripts([]string{hex.EncodeToString(pkScript)}), indexer.WithSpendableOnly())
	require.NoError(t, err)
	return resp.Vtxos
}

// registered is a delegation made the way a wallet does it over grpc.
type registered struct {
	address    string
	tapscripts []string
	pkScript   []byte
}

func registerDelegation(t *testing.T, d delegatee, userPubKey *btcec.PublicKey, window, maxFee int64) registered {
	t.Helper()
	info, err := d.client.GetInfo(t.Context(), &delegateev1.GetInfoRequest{RenewalWindow: window, MaxFee: maxFee})
	require.NoError(t, err)
	_, tapscripts, pkScript := delegateScript(t, info, userPubKey)
	reg, err := d.client.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{
		Tapscripts: tapscripts, RenewalWindow: window, MaxFee: maxFee,
	})
	require.NoError(t, err)
	return registered{reg.GetDelegation().GetAddress(), tapscripts, pkScript}
}

// neverRenewed asserts the vtxos at pkScript stay the preconfirmed ones of
// fundingTxid for a few polls and rounds.
func neverRenewed(t *testing.T, d delegatee, pkScript []byte, fundingTxid string) {
	t.Helper()
	require.Never(t, func() bool {
		for _, v := range spendable(t, d, pkScript) {
			if v.Txid != fundingTxid {
				return true
			}
		}
		return false
	}, 12*time.Second, time.Second, "vtxo was renewed")
}

func hexKeyPair(t *testing.T) (*btcec.PrivateKey, *btcec.PublicKey) {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return key, key.PubKey()
}
