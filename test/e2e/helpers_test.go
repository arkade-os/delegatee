package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	offchaintx "github.com/arkade-os/arkd/pkg/client-lib/offchain-tx"
	clientwallet "github.com/arkade-os/arkd/pkg/client-wallet"
	walletidentity "github.com/arkade-os/arkd/pkg/client-wallet/identity"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-wallet/identity/store/inmemory"
	walletstore "github.com/arkade-os/arkd/pkg/client-wallet/store/inmemory"
	wallettypes "github.com/arkade-os/arkd/pkg/client-wallet/types"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/config"
	"github.com/arkade-os/delegatee/internal/core/application"
	delegateeexplorer "github.com/arkade-os/delegatee/internal/infrastructure/explorer"
	grpcservice "github.com/arkade-os/delegatee/internal/interface/grpc"
	jsontemplate "github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/delegatee/pkg/template/ecies"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type delegatee struct {
	cfg       *config.Config
	afterID   int64
	client    delegateev1.DelegateeServiceClient
	admin     delegateev1.AdminServiceClient
	indexer   clientlib.Indexer
	addr      string // public host:port
	adminAddr string
	stop      func() // also runs at cleanup; blocks until the in-flight batch is done
}

func baseConfig(t *testing.T) *config.Config {
	dsn := os.Getenv("DELEGATEE_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres@localhost:5432/delegatee?sslmode=disable"
	}
	return &config.Config{
		ArkURL: arkURL, EmulatorURL: emulatorURL, DatabaseURL: dsn,
		Port: freePort(t), AdminPort: freePort(t),
		PollInterval: 2 * time.Second, OnchainPollInterval: time.Second, RenewalTimeout: 2 * time.Minute,
		MaxDelegations: 50_000,
		MaxTemplates:   1000, MaxArtifacts: 1000, MaxDocumentBytes: 65536, TemplateMaxFailures: 10,
		DefaultTemplates: true,
	}
}

func serve(t *testing.T, cfg *config.Config) delegatee {
	t.Helper()
	svc, err := grpcservice.NewService("e2e", cfg)
	require.NoError(t, err)
	require.NoError(t, svc.Start())
	t.Cleanup(svc.Stop)

	d := delegatee{
		cfg:       cfg,
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
	indexerSvc, err := indexer.NewClient(arkURL)
	require.NoError(t, err)
	t.Cleanup(indexerSvc.Close)
	d.indexer = indexerSvc
	return d
}

func pubKey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return key.PubKey()
}

// delegationsOf lists delegations created since d started; every template when templateID is empty.
func delegationsOf(t *testing.T, d delegatee, templateID string) ([]*delegateev1.Delegation, error) {
	all, err := listDelegations(t.Context(), d)
	if err != nil {
		return nil, err
	}
	var rows []*delegateev1.Delegation
	for _, row := range all {
		if (templateID == "" || row.Delegation.TemplateId == templateID) && row.Delegation.Id > d.afterID {
			rows = append(rows, row.Delegation)
		}
	}
	return rows, nil
}

// faucet pays sats onchain and mines a block.
func faucet(t *testing.T, address string, sats int64) {
	t.Helper()
	out, err := exec.Command("nigiri", "faucet", address, btc(sats)).CombinedOutput()
	require.NoError(t, err, string(out))
}

func startDelegatee(t *testing.T, tweak ...func(*config.Config)) delegatee {
	t.Helper()
	secrets, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	cfg := baseConfig(t)
	cfg.DatabaseURL = templatesDatabase(t, cfg.DatabaseURL)
	key, _ := btcec.PrivKeyFromBytes(append(make([]byte, 31), 1))
	cfg.DelegateKeys = []*btcec.PrivateKey{key}
	cfg.MaxOnchainFeeRate = 50
	cfg.ExplorerURL = explorerURL
	cfg.EncryptionKeys = []*btcec.PrivateKey{secrets}
	for _, f := range tweak {
		f(cfg)
	}
	d := serve(t, cfg)
	// every daemon of these tests holds the same key: none leaves an active delegation
	t.Cleanup(func() { expireActive(d) })
	rows, err := delegationsOf(t, d, "")
	require.NoError(t, err)
	for _, row := range rows {
		d.afterID = max(d.afterID, row.Id)
	}
	return d
}

func restart(t *testing.T, d delegatee, tweak ...func(*config.Config)) delegatee {
	t.Helper()
	cfg := *d.cfg
	cfg.Port, cfg.AdminPort = freePort(t), freePort(t)
	for _, f := range tweak {
		f(&cfg)
	}
	next := serve(t, &cfg)
	t.Cleanup(func() { expireActive(next) })
	next.afterID = d.afterID
	return next
}

// templatesDatabase isolates the suite: a daemon stopping mid-batch may create successors after cleanup.
func templatesDatabase(t *testing.T, dsn string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	u.Path = "/delegatee_templates"
	for _, stmt := range []struct{ dsn, sql string }{
		{dsn, "CREATE DATABASE delegatee_templates"},
		{u.String(), "DO $$ BEGIN IF to_regclass('delegations') IS NOT NULL THEN UPDATE delegations SET status = 'cancelled' WHERE status = 'active'; END IF; END $$"},
	} {
		db, err := sql.Open("postgres", stmt.dsn)
		require.NoError(t, err)
		if _, err := db.ExecContext(t.Context(), stmt.sql); err != nil {
			require.ErrorContains(t, err, "already exists")
		}
		require.NoError(t, db.Close())
	}
	return u.String()
}

// expireActive stops every watch without the refusal a cancel leaves: another test may register the same watch.
func expireActive(d delegatee) {
	db, err := sql.Open("postgres", d.cfg.DatabaseURL)
	if err != nil {
		return
	}
	defer func() { _ = db.Close() }()
	_, _ = db.Exec(`UPDATE delegations SET status = 'expired', updated_at = NOW() WHERE status = 'active'`)
}

func listDelegations(ctx context.Context, d delegatee) ([]*delegateev1.DelegationSummary, error) {
	var rows []*delegateev1.DelegationSummary
	for cursor := int64(0); ; {
		resp, err := d.admin.ListDelegations(ctx, &delegateev1.ListDelegationsRequest{PageSize: 1000, Cursor: cursor})
		if err != nil {
			return nil, err
		}
		rows = append(rows, resp.GetDelegations()...)
		if cursor = resp.GetNextCursor(); cursor == 0 {
			return rows, nil
		}
	}
}

func registerTemplate(t *testing.T, d delegatee, file string) string {
	t.Helper()
	doc := fixture(t, file)
	for id, artifact := range artifacts(t) {
		if bytes.Contains(doc, []byte(id)) {
			_, err := d.client.RegisterArtifact(t.Context(), &delegateev1.RegisterArtifactRequest{Document: string(artifact)})
			require.NoError(t, err)
		}
	}
	resp, err := d.client.RegisterTemplate(t.Context(), &delegateev1.RegisterTemplateRequest{Document: string(doc)})
	require.NoError(t, err)
	if id := fixtureID(t, file); id != "" {
		require.Equal(t, id, resp.Template.Id)
	}
	return resp.Template.Id
}

// fixtureID is the id ids.json lists for file; the daemon registers the default templates at startup.
func fixtureID(t *testing.T, file string) string {
	t.Helper()
	var ids map[string]string
	require.NoError(t, json.Unmarshal(fixture(t, "ids.json"), &ids))
	return ids[file]
}

// fixture is a pkg/template fixture, else a default template of templates/.
func fixture(t *testing.T, file string) []byte {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join("..", "..", "pkg", "template", "testdata", file))
	if errors.Is(err, fs.ErrNotExist) {
		doc, err = os.ReadFile(filepath.Join("..", "..", "templates", file))
	}
	require.NoError(t, err)
	return doc
}

func artifacts(t *testing.T) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "pkg", "template", "testdata", "artifacts", "*.json"))
	require.NoError(t, err)
	paths = append(paths, filepath.Join("..", "..", "templates", "artifacts", "delegated_vtxo.json"))
	docs := map[string][]byte{}
	for _, p := range paths {
		doc, err := os.ReadFile(p)
		require.NoError(t, err)
		// some fixtures are invalid on purpose
		if a, err := jsontemplate.ParseArtifact(doc); err == nil {
			docs[a.ID] = doc
		}
	}
	return docs
}

func trust(t *testing.T, d delegatee, id string) {
	t.Helper()
	set := func(ctx context.Context, trusted bool) {
		_, err := d.admin.SetTemplateTrusted(ctx, &delegateev1.SetTemplateTrustedRequest{Id: id, Trusted: trusted})
		require.NoError(t, err)
	}
	set(t.Context(), true)
	t.Cleanup(func() { set(context.Background(), false) })
}

func watch(t *testing.T, d delegatee, templateID string, variables map[string]string) *delegateev1.Delegation {
	t.Helper()
	resp, err := d.client.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{TemplateId: templateID, Variables: variables})
	require.NoError(t, err)
	return resp.Delegation
}

// renewalWatch watches o's address at the default renewal paying up to maxFee.
func renewalWatch(t *testing.T, d delegatee, o owner, maxFee int64) *delegateev1.Delegation {
	t.Helper()
	return watch(t, d, fixtureID(t, "renewal.json"), o.variables(maxFee))
}

// boardingWatch watches o's boarding address, and the renewal address it boards into.
func boardingWatch(t *testing.T, d delegatee, o owner) (boarding, renewal *delegateev1.Delegation) {
	t.Helper()
	return watch(t, d, fixtureID(t, "boarding.json"), o.boardingVariables()), renewalWatch(t, d, o, 0)
}

// landed waits for n coins, spent or not, at to's address from batches that settled by's coins, any batch when by is nil; oldest first.
func landed(t *testing.T, d delegatee, by, to *delegateev1.Delegation, n int) []clientlib.Vtxo {
	t.Helper()
	script := scriptOf(t, to)
	var coins []clientlib.Vtxo
	require.Eventually(t, func() bool {
		var err error
		var txids []string
		if by != nil {
			if txids, err = settlements(t, d, by.Id); err != nil {
				return false
			}
		}
		resp, err := d.indexer.GetVtxos(t.Context(), clientlib.WithScripts([]string{script}))
		if err != nil {
			return false
		}
		coins = slices.DeleteFunc(resp.Vtxos, func(v clientlib.Vtxo) bool {
			return by != nil && !slices.ContainsFunc(v.CommitmentTxids, func(c string) bool { return slices.Contains(txids, c) })
		})
		slices.SortFunc(coins, func(a, b clientlib.Vtxo) int { return a.CreatedAt.Compare(b.CreatedAt) })
		return len(coins) >= n
	}, 5*time.Minute, time.Second, "no %d coins landed at %d", n, to.Id)
	return coins
}

// scriptOf is the output script of an Ark watch address.
func scriptOf(t *testing.T, w *delegateev1.Delegation) string {
	t.Helper()
	addr, err := arklib.DecodeAddressV0(w.Address)
	require.NoError(t, err)
	script, err := txscript.PayToTaprootScript(addr.VtxoTapKey)
	require.NoError(t, err)
	return hex.EncodeToString(script)
}

// successor waits for an indexed delegation of templateID advertised by parent; any when parent is 0.
func successor(t *testing.T, d delegatee, templateID string, parent int64) *delegateev1.Delegation {
	t.Helper()
	var found *delegateev1.Delegation
	require.Eventually(t, func() bool {
		rows, err := delegationsOf(t, d, templateID)
		if err != nil {
			return false
		}
		for _, r := range rows {
			if r.ParentId == 0 || (parent != 0 && r.ParentId != parent) {
				continue
			}
			if _, err := vtxoAt(t, d, r.Slots[0].Outpoint); err == nil {
				found = r
				return true
			}
		}
		return false
	}, 5*time.Minute, time.Second, "no successor of %d for template %s", parent, templateID)
	return found
}

// settlements are the commitment txids of a delegation's successful renewals.
func settlements(t *testing.T, d delegatee, id int64) ([]string, error) {
	if id == 0 {
		return nil, nil
	}
	got, err := d.admin.GetDelegationById(t.Context(), &delegateev1.GetDelegationByIdRequest{Id: id})
	if err != nil {
		return nil, err
	}
	var txids []string
	for _, r := range got.Renewals {
		if r.Success {
			txids = append(txids, r.CommitmentTxid)
		}
	}
	return txids, nil
}

func coin(t *testing.T, d delegatee, outpoint string) clientlib.Vtxo {
	t.Helper()
	v, err := vtxoAt(t, d, outpoint)
	require.NoError(t, err)
	return v
}

func vtxoAt(t *testing.T, d delegatee, outpoint string) (clientlib.Vtxo, error) {
	op, err := wire.NewOutPointFromString(outpoint)
	if err != nil {
		return clientlib.Vtxo{}, err
	}
	resp, err := d.indexer.GetVtxos(t.Context(), clientlib.WithOutpoints([]clientlib.Outpoint{{Txid: op.Hash.String(), VOut: op.Index}}))
	if err != nil {
		return clientlib.Vtxo{}, err
	}
	if len(resp.Vtxos) != 1 {
		return clientlib.Vtxo{}, fmt.Errorf("%d vtxos at %s", len(resp.Vtxos), outpoint)
	}
	return resp.Vtxos[0], nil
}

// packet reads packet typ from the transaction that created outpoint.
func packet(t *testing.T, d delegatee, outpoint string, typ uint8) []byte {
	t.Helper()
	op, err := wire.NewOutPointFromString(outpoint)
	require.NoError(t, err)
	resp, err := d.indexer.GetVirtualTxs(t.Context(), []string{op.Hash.String()})
	require.NoError(t, err)
	require.Len(t, resp.Txs, 1)
	source, err := psbt.NewFromRawBytes(strings.NewReader(resp.Txs[0]), true)
	require.NoError(t, err)
	body, ok := packets.Find(source.UnsignedTx, typ)
	require.True(t, ok, "no packet %d in the transaction of %s", typ, outpoint)
	return body
}

func counterState(n uint64) []byte { return binary.LittleEndian.AppendUint64(nil, n) }

type owner struct {
	key  []byte
	keys jsontemplate.Keys
}

func newOwner(t *testing.T, d delegatee) owner {
	return owner{pubKey(t).SerializeCompressed(), fixtureKeys(t, d)}
}

// variables are the default renewal's for o: regtest arkd's 512-second exit, and a window above its 512-second VTXO life so a coin renews at the next scan.
func (o owner) variables(maxFee int64) map[string]string {
	return map[string]string{
		"owner": hex.EncodeToString(o.key), "exit_delay": scriptNum(1<<22 | 1),
		"renewal_window": scriptNum(1024), "max_fee": scriptNum(maxFee),
	}
}

// boardingVariables add regtest arkd's 1024-second boarding exit.
func (o owner) boardingVariables() map[string]string {
	v := o.variables(0)
	v["boarding_exit_delay"] = scriptNum(1<<22 | 2)
	return v
}

func scriptNum(n int64) string {
	b, _ := arkade.BigNumFromInt64(n).Bytes()
	return hex.EncodeToString(b)
}

func (o owner) boardingAddress(t *testing.T) string {
	t.Helper()
	docs := artifacts(t)
	resolve := func(_ context.Context, id string) ([]byte, error) { return docs[id], nil }
	boarding, err := jsontemplate.Parse(t.Context(), fixture(t, "boarding.json"), resolve)
	require.NoError(t, err)
	vars := map[string][]byte{}
	for n, v := range o.boardingVariables() {
		vars[n], _ = hex.DecodeString(v)
	}
	inst, err := boarding.Instantiate(t.Context(), jsontemplate.Context{Keys: o.keys, Variables: vars})
	require.NoError(t, err)
	addr, err := address.NewAddressTaproot(inst.PkScript(0)[2:], &chaincfg.RegressionNetParams)
	require.NoError(t, err)
	return addr.EncodeAddress()
}

func fixtureKeys(t *testing.T, d delegatee) jsontemplate.Keys {
	t.Helper()
	info, err := d.client.GetInfo(t.Context(), &delegateev1.GetInfoRequest{})
	require.NoError(t, err)
	return keysOf(t, info)
}

func keysOf(t *testing.T, info *delegateev1.GetInfoResponse) jsontemplate.Keys {
	t.Helper()
	server, err := application.PubKeyFromHex(info.ServerPubkey)
	require.NoError(t, err)
	emulator, err := application.PubKeyFromHex(info.EmulatorPubkey)
	require.NoError(t, err)
	delegate, err := application.PubKeyFromHex(info.DelegatePubkey)
	require.NoError(t, err)
	return jsontemplate.Keys{Server: server, Emulator: emulator, Delegate: delegate}
}

// counterPrograms derives each contract's program from counter.json reduced to that input.
func counterPrograms(t *testing.T, d delegatee) map[string]string {
	t.Helper()
	vars := map[string]string{}
	for i, name := range []string{"counter_program", "reserve_program"} {
		var doc map[string]any
		require.NoError(t, json.Unmarshal(fixture(t, "counter.json"), &doc))
		output := doc["outputs"].([]any)[i].(map[string]any)
		output["index"] = 0
		doc["inputs"] = doc["inputs"].([]any)[i : i+1]
		doc["outputs"] = []any{output}
		doc["packets"] = map[string]any{"output_index": 1, "rules": []any{}, "advertise": []any{}}
		raw, err := json.Marshal(doc)
		require.NoError(t, err)
		single, err := jsontemplate.Parse(t.Context(), raw, nil)
		require.NoError(t, err)
		inst, err := single.Instantiate(t.Context(), jsontemplate.Context{Keys: fixtureKeys(t, d)})
		require.NoError(t, err)
		vars[name] = hex.EncodeToString(inst.PkScript(0)[2:])
	}
	return vars
}

// swap is a VHTLC whose preimage is sealed to the daemon.
type swap struct {
	variables      map[string]string
	receiverScript []byte
}

func newSwap(t *testing.T, d delegatee) swap {
	t.Helper()
	info, err := d.client.GetInfo(t.Context(), &delegateev1.GetInfoRequest{})
	require.NoError(t, err)
	secrets, err := application.PubKeyFromHex(info.EncryptionPubkey)
	require.NoError(t, err)
	preimage := make([]byte, 32)
	_, err = rand.Read(preimage)
	require.NoError(t, err)
	ciphertext, err := ecies.Encrypt(secrets, preimage)
	require.NoError(t, err)
	sender, receiver := pubKey(t), pubKey(t)
	program := schnorr.SerializePubKey(receiver)
	return swap{
		variables: map[string]string{
			"sender":   hex.EncodeToString(sender.SerializeCompressed()),
			"receiver": hex.EncodeToString(receiver.SerializeCompressed()),
			// a timestamp is a minimal 4-byte script number until 2038
			"refund_locktime":                          hex.EncodeToString(binary.LittleEndian.AppendUint32(nil, uint32(time.Now().Add(24*time.Hour).Unix()))),
			"unilateral_claim_delay":                   "020040", // 1024 s
			"unilateral_refund_delay":                  "030040",
			"unilateral_refund_without_receiver_delay": "040040",
			"receiver_program":                         hex.EncodeToString(program),
			"sender_program":                           hex.EncodeToString(schnorr.SerializePubKey(sender)),
			"ciphertext":                               hex.EncodeToString(ciphertext),
		},
		receiverScript: append([]byte{0x51, 0x20}, program...),
	}
}

// swapClaim funds a VHTLC watched under file's template and waits for its claim.
func swapClaim(t *testing.T, d delegatee, file string) (clientlib.Vtxo, time.Duration) {
	t.Helper()
	claim := registerTemplate(t, d, file)
	trust(t, d, claim)
	swap := newSwap(t, d)

	w := watch(t, d, claim, swap.variables)
	alice := fundedWallet(t)
	funding, err := alice.SendOffChain(t.Context(), []clientlib.Receiver{{To: w.Address, Amount: 10_000}})
	require.NoError(t, err)
	sent := time.Now()
	return waitForVtxo(t, d, swap.receiverScript, funding), time.Since(sent)
}

func medianTime(t *testing.T) int64 {
	t.Helper()
	ex, err := delegateeexplorer.New(explorerURL, arklib.BitcoinRegTest)
	require.NoError(t, err)
	tip, err := ex.ChainTip()
	require.NoError(t, err)
	return tip.MedianTime
}

// waitForVtxo waits for a spendable vtxo at script not spent by funding.
func waitForVtxo(t *testing.T, d delegatee, script []byte, funding string) clientlib.Vtxo {
	t.Helper()
	var found clientlib.Vtxo
	require.Eventually(t, func() bool {
		resp, err := d.indexer.GetVtxos(t.Context(), clientlib.WithScripts([]string{hex.EncodeToString(script)}), clientlib.WithSpendableOnly())
		if err != nil {
			return false
		}
		for _, v := range resp.Vtxos {
			if v.Txid != funding {
				found = v
				return true
			}
		}
		return false
	}, 2*time.Minute, time.Second, "nothing paid to %x", script)
	return found
}

func waitForBroadcast(t *testing.T, d delegatee, id int64) *wire.MsgTx {
	t.Helper()
	var txids []string
	require.Eventually(t, func() bool {
		var err error
		txids, err = settlements(t, d, id)
		return err == nil && len(txids) > 0
	}, 2*time.Minute, time.Second, "delegation %d broadcast nothing", id)
	return onchainTx(t, txids[0])
}

func onchainTx(t *testing.T, txid string) *wire.MsgTx {
	t.Helper()
	ex, err := explorer.NewExplorer(explorerURL, arklib.BitcoinRegTest, explorer.WithTracker(false))
	require.NoError(t, err)
	raw, err := ex.GetTxHex(txid)
	require.NoError(t, err)
	tx := wire.NewMsgTx(2)
	require.NoError(t, tx.Deserialize(hex.NewDecoder(strings.NewReader(raw))))
	return tx
}

func feeOf(t *testing.T, tx *wire.MsgTx) int64 {
	t.Helper()
	var fee int64
	for _, in := range tx.TxIn {
		fee += onchainTx(t, in.PreviousOutPoint.Hash.String()).TxOut[in.PreviousOutPoint.Index].Value
	}
	for _, out := range tx.TxOut {
		fee -= out.Value
	}
	return fee
}

// boardingWatches are n owners' boarding and renewal watches.
func boardingWatches(t *testing.T, d delegatee, n int) (boardings, renewals []*delegateev1.Delegation) {
	t.Helper()
	boardings, renewals = make([]*delegateev1.Delegation, n), make([]*delegateev1.Delegation, n)
	for i := range n {
		boardings[i], renewals[i] = boardingWatch(t, d, newOwner(t, d))
	}
	return boardings, renewals
}

func fundMany(t *testing.T, watches []*delegateev1.Delegation, sats int64) {
	t.Helper()
	amounts := map[string]string{}
	for _, w := range watches {
		amounts[w.Address] = btc(sats)
	}
	raw, err := json.Marshal(amounts)
	require.NoError(t, err)
	for _, args := range [][]string{{"rpc", "sendmany", "", string(raw)}, {"rpc", "-generate", "1"}} {
		out, err := exec.Command("nigiri", args...).CombinedOutput()
		require.NoError(t, err, string(out))
	}
}

func btc(sats int64) string {
	return strings.TrimSuffix(btcutil.Amount(sats).Format(btcutil.AmountBTC), " BTC")
}

// pay sends delegateAmount to address.
func pay(t *testing.T, alice testWallet, address string, assets ...clientlib.Asset) string {
	t.Helper()
	txid, err := alice.SendOffChain(t.Context(), []clientlib.Receiver{{To: address, Amount: delegateAmount, Assets: assets}})
	require.NoError(t, err)
	return txid + ":0"
}

// chargeIntentFees stops the daemon first: arkd fails its registered intents on a fee change and keeps them.
func chargeIntentFees(t *testing.T, d delegatee, fees string) {
	t.Helper()
	code, _ := postJSON(t, arkdAdminURL+"/v1/admin/intentFees", map[string]any{"fees": json.RawMessage(fees)})
	require.Equal(t, http.StatusOK, code)
	t.Cleanup(func() {
		d.stop()
		clearIntentFees(t)
	})
}

func clearIntentFees(t *testing.T) {
	code, _ := postJSON(t, arkdAdminURL+"/v1/admin/intentFees/clear", map[string]any{})
	require.Equal(t, http.StatusOK, code)
}

func postJSON(t *testing.T, url string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return resp.StatusCode, out
}

func refused(t *testing.T, d delegatee, id int64, reason string) {
	t.Helper()
	require.Eventually(t, func() bool {
		got, err := d.admin.GetDelegationById(t.Context(), &delegateev1.GetDelegationByIdRequest{Id: id})
		return err == nil && slices.ContainsFunc(got.Renewals, func(r *delegateev1.Renewal) bool {
			return !r.Success && strings.Contains(r.Error, reason)
		})
	}, 2*time.Minute, time.Second, "no renewal of %d refused with %q", id, reason)
}

func neverSpent(t *testing.T, d delegatee, outpoint string) {
	t.Helper()
	require.False(t, coin(t, d, outpoint).Spent)
	require.Never(t, func() bool {
		v, err := vtxoAt(t, d, outpoint)
		return err != nil || v.Spent
	}, 25*time.Second, time.Second, "%s was spent or unreadable", outpoint)
}

func neverBoarded(t *testing.T, address string) {
	t.Helper()
	ex, err := explorer.NewExplorer(explorerURL, arklib.BitcoinRegTest, explorer.WithTracker(false))
	require.NoError(t, err)
	unspent := func() (bool, error) {
		utxos, err := ex.GetUtxos([]string{address})
		return len(utxos) > 0, err
	}
	require.Eventually(t, func() bool { ok, err := unspent(); return err == nil && ok }, 30*time.Second, time.Second, "%s not paid", address)
	require.Never(t, func() bool { ok, err := unspent(); return err == nil && !ok }, 25*time.Second, time.Second, "%s was boarded", address)
}

func setTemplateStatus(t *testing.T, d delegatee, id, to string) {
	t.Helper()
	set := func(ctx context.Context, to string) {
		_, err := d.admin.SetTemplateStatus(ctx, &delegateev1.SetTemplateStatusRequest{Id: id, Status: to})
		require.NoError(t, err)
	}
	set(t.Context(), to)
	t.Cleanup(func() { set(context.Background(), "active") })
}

func statusOf(t *testing.T, method, url string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func summaryOf(t *testing.T, d delegatee, id int64) (*delegateev1.DelegationSummary, error) {
	rows, err := listDelegations(t.Context(), d)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Delegation.Id == id {
			return row, nil
		}
	}
	return nil, fmt.Errorf("delegation %d not listed", id)
}

type testWallet struct{ clientwallet.Wallet }

func (w testWallet) SendOffChain(ctx context.Context, receivers []clientlib.Receiver, opts ...offchaintx.Option) (string, error) {
	// right after a send the indexer may not show the change yet
	var need uint64
	for _, r := range receivers {
		need += r.Amount
	}
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		spendable, _, err := w.ListVtxos(ctx)
		if err != nil {
			return "", err
		}
		var have uint64
		for _, v := range spendable {
			have += v.Amount
		}
		if have >= need || time.Now().After(deadline) {
			break
		}
	}
	// the wallet appends its change to the slice: spare capacity would be overwritten
	res, err := w.Wallet.SendOffChain(ctx, slices.Clone(receivers), opts...)
	if err != nil {
		return "", err
	}
	return res.Txid, nil
}

// onchainTotal includes boarding funds still inside their exit delay.
func onchainTotal(b *wallettypes.Balance) uint64 {
	total := b.OnchainBalance.SpendableAmount
	for _, l := range b.OnchainBalance.LockedAmount {
		total += l.Amount
	}
	return total
}

func fundedWallet(t *testing.T) testWallet {
	t.Helper()
	ctx := t.Context()
	idStore, err := inmemorystore.NewStore()
	require.NoError(t, err)
	identity, err := walletidentity.NewIdentity(idStore)
	require.NoError(t, err)
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	configStore, err := walletstore.NewStore()
	require.NoError(t, err)
	w, err := clientwallet.NewWallet(configStore, clientwallet.WithIdentity(identity))
	require.NoError(t, err)
	require.NoError(t, w.Init(ctx, clientwallet.InitArgs{
		ServerUrl: arkURL, Seed: hex.EncodeToString(privKey.Serialize()), Password: password, ExplorerURL: explorerURL,
	}))
	require.NoError(t, w.Unlock(ctx, password))
	t.Cleanup(w.Stop)           // Stop panics on a wallet that never initialised
	log.SetLevel(log.InfoLevel) // the sdk lowers the global level
	wallet := testWallet{w}
	_, _, boarding, err := wallet.Receive(ctx)
	require.NoError(t, err)
	faucet(t, boarding.Address, 100_000)

	require.Eventually(t, func() bool {
		balance, err := wallet.Balance(ctx)
		return err == nil && onchainTotal(balance) > 0
	}, 30*time.Second, 500*time.Millisecond, "boarding utxo not detected")

	_, err = wallet.Settle(ctx)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		balance, err := wallet.Balance(ctx)
		return err == nil && balance.OffchainBalance.Total > 0
	}, 30*time.Second, 500*time.Millisecond, "offchain balance not available")
	return wallet
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

const (
	arkURL         = "localhost:7070"
	emulatorURL    = "localhost:7073"
	explorerURL    = "http://localhost:3000"
	delegateAmount = uint64(10_000)
	assetAmount    = uint64(1_000)
	password       = "password"
	arkdAdminURL   = "http://localhost:7071"
	// releaseRecipient is the script onchain_release.json pays.
	releaseRecipient = "5120f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
)
