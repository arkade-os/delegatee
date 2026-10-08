package e2e

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/config"
	"github.com/arkade-os/delegatee/internal/core/application"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/arkade-os/delegatee/internal/infrastructure/db/postgres"
	"github.com/arkade-os/delegatee/internal/infrastructure/explorer"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// the daemon dies once its boarding reached arkd, before the batch reported its end
func TestRestartMidBatch(t *testing.T) {
	d := startDelegatee(t)
	w, renewal := boardingWatch(t, d, newOwner(t, d))
	d.stop()
	faucet(t, w.Address, 20_000)

	crashAt(t, d.cfg, &crashingArk{afterForfeits: true})
	require.Len(t, pendingSettlements(t, d.cfg, w.Id), 1)

	again := restart(t, d)
	landed(t, again, renewal, renewal, 1)
	coins := landed(t, again, nil, renewal, 1)
	renewals, err := settlements(t, again, renewal.Id)
	require.NoError(t, err)
	boarded := slices.DeleteFunc(coins, func(v clientlib.Vtxo) bool { return slices.Contains(renewals, v.CommitmentTxids[0]) })
	require.Len(t, boarded, 1, "boarded once")
	// a scan waits for the renewal in flight before it settles the boarding
	require.Eventually(t, func() bool { return len(pendingSettlements(t, d.cfg, w.Id)) == 0 }, time.Minute, time.Second)
}

// arkd accepted the transfer and the daemon died before FinalizeTx
func TestRestartBeforeFinalize(t *testing.T) {
	d := startDelegatee(t)
	receiver := append([]byte{0x51, 0x20}, schnorr.SerializePubKey(pubKey(t))...)
	transfer := registerDocument(t, d, delegatedTransfer(t, receiver))
	_, err := d.admin.SetTemplateTrusted(t.Context(), &delegateev1.SetTemplateTrustedRequest{Id: transfer, Trusted: true})
	require.NoError(t, err)
	w := watch(t, d, transfer, nil)
	d.stop()
	alice := fundedWallet(t)
	funding, err := alice.SendOffChain(t.Context(), []clientlib.Receiver{{To: w.Address, Amount: 10_000}})
	require.NoError(t, err)

	crashAt(t, d.cfg, &crashingArk{beforeFinalize: true})
	pending := pendingSettlements(t, d.cfg, w.Id)
	require.Len(t, pending, 1)
	require.NotZero(t, pending[0], "final checkpoints recorded")

	again := restart(t, d)
	trust(t, again, transfer)
	paid := waitForVtxo(t, again, receiver, funding)
	require.EqualValues(t, 10_000, paid.Amount)
	require.Eventually(t, func() bool {
		txids, err := settlements(t, again, w.Id)
		return err == nil && len(txids) == 1 && txids[0] == paid.Txid
	}, time.Minute, time.Second, "one finalized transfer")
	require.Empty(t, pendingSettlements(t, d.cfg, w.Id))
}

// arkd accepted the transfer and the daemon died before it read the reply: the checkpoints are read back from arkd
func TestRestartAfterSubmit(t *testing.T) {
	d := startDelegatee(t)
	receiver := append([]byte{0x51, 0x20}, schnorr.SerializePubKey(pubKey(t))...)
	transfer := registerDocument(t, d, delegatedTransfer(t, receiver))
	_, err := d.admin.SetTemplateTrusted(t.Context(), &delegateev1.SetTemplateTrustedRequest{Id: transfer, Trusted: true})
	require.NoError(t, err)
	w := watch(t, d, transfer, nil)
	d.stop()
	alice := fundedWallet(t)
	funding, err := alice.SendOffChain(t.Context(), []clientlib.Receiver{{To: w.Address, Amount: 10_000}})
	require.NoError(t, err)

	crashAt(t, d.cfg, &crashingArk{afterSubmit: true})
	require.Equal(t, []int{0}, pendingSettlements(t, d.cfg, w.Id), "recorded without final checkpoints")

	again := restart(t, d)
	trust(t, again, transfer)
	paid := waitForVtxo(t, again, receiver, funding)
	require.EqualValues(t, 10_000, paid.Amount)
	require.Eventually(t, func() bool {
		txids, err := settlements(t, again, w.Id)
		return err == nil && len(txids) == 1 && txids[0] == paid.Txid
	}, time.Minute, time.Second, "one finalized transfer")
	require.Empty(t, pendingSettlements(t, d.cfg, w.Id))
}

// crashAt runs the daemon of cfg against ark until it crashes, then stops it.
func crashAt(t *testing.T, cfg *config.Config, ark *crashingArk) {
	t.Helper()
	ark.crashed = make(chan struct{})
	ctx := t.Context()
	repo, err := postgres.NewRepository(ctx, cfg.DatabaseURL)
	require.NoError(t, err)
	ark.Ark, err = client.NewClient(arkURL, "e2e")
	require.NoError(t, err)
	indexerSvc, err := indexer.NewClient(arkURL)
	require.NoError(t, err)
	t.Cleanup(indexerSvc.Close)
	emuConn, err := grpc.NewClient(emulatorURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = emuConn.Close() })
	explorerSvc, err := explorer.New(explorerURL, arklib.BitcoinRegTest)
	require.NoError(t, err)
	svc, err := application.NewServiceWithKeys(
		ctx, repo, ark, indexerSvc, emulatorclient.NewGRPCClient(emuConn), explorerSvc, cfg.OnchainPollInterval, cfg.MaxOnchainFeeRate,
		cfg.EncryptionKeys, cfg.DelegateKeys, cfg.PollInterval, cfg.RenewalTimeout, cfg.RenewalReserve, cfg.BoardingMaxWait,
		application.Limits{MaxDelegations: 100, MaxTemplates: 100, MaxArtifacts: 100, MaxDocumentBytes: 1 << 16, TemplateMaxFailures: 10},
	)
	require.NoError(t, err)
	require.NoError(t, svc.Bootstrap(ctx))
	svc.Start()
	select {
	case <-ark.crashed:
	case <-time.After(2 * time.Minute):
		t.Fatal("the daemon never reached its crash")
	}
	svc.Stop()
}

// pendingSettlements lists the final checkpoint count of each of the delegation's settlements.
func pendingSettlements(t *testing.T, cfg *config.Config, delegationID int64) []int {
	t.Helper()
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(t.Context(), `SELECT cardinality(finals) FROM settlements WHERE delegation_id = $1`, delegationID)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var out []int
	for rows.Next() {
		var n int
		require.NoError(t, rows.Scan(&n))
		out = append(out, n)
	}
	require.NoError(t, rows.Err())
	return out
}

// delegatedTransfer pays any coin at the default renewal's contract owned by the delegate key to receiver, offchain and without the emulator.
func delegatedTransfer(t *testing.T, receiver []byte) []byte {
	t.Helper()
	var def map[string]any
	require.NoError(t, json.Unmarshal(fixture(t, "artifacts/delegated_vtxo.json"), &def))
	forfeit := def["functions"].([]any)[0].(map[string]any)["leaves"].([]any)[0].(map[string]any)
	forfeit["witness"].([]any)[0].(map[string]any)["injected"] = true
	raw, err := json.Marshal(map[string]any{
		"format": "delegateed-template/v1",
		"type":   "offchain",
		"inputs": []any{map[string]any{
			"name": "funds",
			"contract": map[string]any{"definition": def, "arguments": map[string]any{
				"owner": cosigner, "exitDelay": 1<<22 | 1, "renewalWindow": 1024, "maxFee": 0,
			}},
			"spend": map[string]any{"function": "forfeit", "leaf": "forfeit"},
		}},
		"outputs": []any{map[string]any{"name": "payment", "index": 0, "value": map[string]any{"from": "funds"}, "locking": hex.EncodeToString(receiver)}},
	})
	require.NoError(t, err)
	return raw
}

func registerDocument(t *testing.T, d delegatee, doc []byte) string {
	t.Helper()
	resp, err := d.client.RegisterTemplate(t.Context(), &delegateev1.RegisterTemplateRequest{Document: string(doc)})
	require.NoError(t, err)
	return resp.Template.Id
}

// cosigner is the delegate key of every daemon in these tests.
const cosigner = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

// crashingArk is arkd as a daemon sees it until it dies: then its event stream ends.
type crashingArk struct {
	ports.Ark
	afterForfeits  bool // dies once its forfeits reached arkd
	beforeFinalize bool // dies before FinalizeTx
	afterSubmit    bool // dies once arkd accepted the tx, before reading the reply
	crashed        chan struct{}
	once           sync.Once
}

func (a *crashingArk) crash() { a.once.Do(func() { close(a.crashed) }) }

func (a *crashingArk) GetEventStream(ctx context.Context, topics []string) (<-chan clientlib.BatchEventChannel, func(), error) {
	events, stop, err := a.Ark.GetEventStream(ctx, topics)
	if err != nil {
		return nil, nil, err
	}
	out := make(chan clientlib.BatchEventChannel)
	go func() {
		defer close(out)
		for {
			select {
			case <-a.crashed:
				return
			case event, ok := <-events:
				if !ok {
					return
				}
				select {
				case out <- event:
				case <-a.crashed:
					return
				}
			}
		}
	}()
	return out, stop, nil
}

func (a *crashingArk) SubmitSignedForfeitTxs(ctx context.Context, forfeits []string, commitment string) error {
	err := a.Ark.SubmitSignedForfeitTxs(ctx, forfeits, commitment)
	if err == nil && a.afterForfeits {
		a.crash()
	}
	return err
}

func (a *crashingArk) SubmitTx(ctx context.Context, tx string, checkpoints []string) (string, string, []string, error) {
	txid, signed, signedCheckpoints, err := a.Ark.SubmitTx(ctx, tx, checkpoints)
	if err == nil && a.afterSubmit {
		a.crash()
		return "", "", nil, status.Error(codes.Unavailable, "crashed")
	}
	return txid, signed, signedCheckpoints, err
}

func (a *crashingArk) FinalizeTx(ctx context.Context, txid string, finals []string) error {
	if a.beforeFinalize {
		a.crash()
		return status.Error(codes.Unavailable, "crashed")
	}
	return a.Ark.FinalizeTx(ctx, txid, finals)
}
