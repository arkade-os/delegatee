//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	offchaintx "github.com/arkade-os/arkd/pkg/client-lib/offchain-tx"
	clientwallet "github.com/arkade-os/arkd/pkg/client-wallet"
	walletidentity "github.com/arkade-os/arkd/pkg/client-wallet/identity"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-wallet/identity/store/inmemory"
	walletstore "github.com/arkade-os/arkd/pkg/client-wallet/store/inmemory"
	wallettypes "github.com/arkade-os/arkd/pkg/client-wallet/types"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	template "github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/delegatee/test/daemon"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/wire/v2"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const (
	delegateAmount = uint64(10_000)
	assetAmount    = uint64(1_000)
)

// registerTemplate registers the template file of pkg/template/testdata, else of templates/, with its artifacts.
func registerTemplate(t *testing.T, d delegatee, file string) string {
	t.Helper()
	doc := fixture(t, file)
	for id, artifact := range artifacts(t) {
		if bytes.Contains(doc, []byte(id)) {
			_, err := d.client.RegisterArtifact(t.Context(), &delegateev1.RegisterArtifactRequest{Document: string(artifact)})
			require.NoError(t, err)
		}
	}
	return registerDocument(t, d, doc)
}

func registerDocument(t *testing.T, d delegatee, doc []byte) string {
	t.Helper()
	resp, err := d.client.RegisterTemplate(t.Context(), &delegateev1.RegisterTemplateRequest{Document: string(doc)})
	require.NoError(t, err)
	return resp.Template.Id
}

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
		if a, err := template.ParseArtifact(doc); err == nil {
			docs[a.ID] = doc
		}
	}
	return docs
}

func registerDelegation(t *testing.T, d delegatee, templateID string, variables map[string]string) *delegateev1.Delegation {
	t.Helper()
	resp, err := d.client.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{TemplateId: templateID, Variables: variables})
	require.NoError(t, err)
	return resp.Delegation
}

// renewalDelegation registers a delegation on o's address at the default renewal paying up to maxFee.
func renewalDelegation(t *testing.T, d delegatee, o owner, maxFee int64) *delegateev1.Delegation {
	t.Helper()
	return registerDelegation(t, d, registerTemplate(t, d, "renewal.json"), o.variables(maxFee))
}

// boardingDelegations registers delegations on o's boarding address and on the renewal address it boards into.
func boardingDelegations(t *testing.T, d delegatee, o owner) (boarding, renewal *delegateev1.Delegation) {
	t.Helper()
	return registerDelegation(t, d, registerTemplate(t, d, "boarding.json"), o.boardingVariables()), renewalDelegation(t, d, o, 0)
}

func attemptsOf(t *testing.T, d delegatee, id int64) []*delegateev1.Attempt {
	t.Helper()
	resp, err := d.admin.ListAttempts(t.Context(), &delegateev1.ListAttemptsRequest{Id: id, Limit: 1000})
	require.NoError(t, err)
	return resp.Attempts
}

// landed waits for n coins at to's script from the batches of by's succeeded attempts, oldest first.
func landed(t *testing.T, d delegatee, by, to *delegateev1.Delegation, n int) []clientlib.Vtxo {
	t.Helper()
	var coins []clientlib.Vtxo
	require.Eventually(t, func() bool {
		var txids []string
		for _, a := range attemptsOf(t, d, by.Id) {
			if a.Status == "succeeded" {
				txids = append(txids, a.Txid)
			}
		}
		coins = slices.DeleteFunc(vtxosAt(t, d, to.Inputs[0].Script), func(v clientlib.Vtxo) bool {
			return !slices.ContainsFunc(v.CommitmentTxids, func(c string) bool { return slices.Contains(txids, c) })
		})
		slices.SortFunc(coins, func(a, b clientlib.Vtxo) int { return a.CreatedAt.Compare(b.CreatedAt) })
		return len(coins) >= n
	}, 6*time.Minute, time.Second, "no %d coins landed at %d", n, to.Id)
	return coins
}

// vtxosAt lists the vtxos at the script, spent ones included; none on an indexer error.
func vtxosAt(t *testing.T, d delegatee, script string) []clientlib.Vtxo {
	t.Helper()
	resp, err := d.indexer.GetVtxos(t.Context(), clientlib.WithScripts([]string{script}))
	if err != nil {
		return nil
	}
	return resp.Vtxos
}

// waitForVtxo waits for a spendable vtxo at script not made by funding.
func waitForVtxo(t *testing.T, d delegatee, script, funding string) clientlib.Vtxo {
	t.Helper()
	var found clientlib.Vtxo
	require.Eventually(t, func() bool {
		for _, v := range vtxosAt(t, d, script) {
			if !v.Spent && v.Txid != funding {
				found = v
				return true
			}
		}
		return false
	}, 2*time.Minute, time.Second, "nothing paid to %s", script)
	return found
}

func refused(t *testing.T, d delegatee, id int64, reason string) {
	t.Helper()
	require.Eventually(t, func() bool {
		return slices.ContainsFunc(attemptsOf(t, d, id), func(a *delegateev1.Attempt) bool {
			return a.Status == "failed" && strings.Contains(a.Error, reason)
		})
	}, 2*time.Minute, time.Second, "no attempt of %d refused with %q", id, reason)
}

func neverSpent(t *testing.T, d delegatee, outpoint string) {
	t.Helper()
	op, err := wire.NewOutPointFromString(outpoint)
	require.NoError(t, err)
	spent := func() bool {
		resp, err := d.indexer.GetVtxos(t.Context(), clientlib.WithOutpoints([]clientlib.Outpoint{{Txid: op.Hash.String(), VOut: op.Index}}))
		return err != nil || len(resp.Vtxos) != 1 || resp.Vtxos[0].Spent
	}
	require.False(t, spent())
	require.Never(t, spent, 25*time.Second, time.Second, "%s was spent or unreadable", outpoint)
}

func faucet(t *testing.T, address string, sats int64) {
	t.Helper()
	out, err := exec.Command("nigiri", "faucet", address, btc(sats)).CombinedOutput()
	require.NoError(t, err, string(out))
}

func fundMany(t *testing.T, delegations []*delegateev1.Delegation, sats int64) {
	t.Helper()
	amounts := map[string]string{}
	for _, w := range delegations {
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

// chargeIntentFees makes arkd charge fees until the test ends.
func chargeIntentFees(t *testing.T, fees string) {
	t.Helper()
	code, _ := postJSON(t, arkdAdminURL+"/v1/admin/intentFees", map[string]any{"fees": json.RawMessage(fees)})
	require.Equal(t, http.StatusOK, code)
	t.Cleanup(func() { clearIntentFees(t) })
}

func clearIntentFees(t *testing.T) {
	t.Helper()
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

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(out))
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

type owner struct {
	key  []byte
	keys template.Keys
}

func newOwner(t *testing.T, d delegatee) owner {
	t.Helper()
	return owner{pubKey(t).SerializeCompressed(), keysOf(t, d)}
}

func pubKey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return key.PubKey()
}

// variables are the default renewal's for o: regtest arkd's 512-second exit, and a window above its 512-second vtxo life so a coin renews at once.
func (o owner) variables(maxFee int64) map[string]string {
	return map[string]string{
		"owner": hex.EncodeToString(o.key), "exit_delay": daemon.ScriptNum(1<<22 | 1),
		"renewal_window": daemon.ScriptNum(1024), "max_fee": daemon.ScriptNum(maxFee),
	}
}

// boardingVariables add regtest arkd's 1024-second boarding exit.
func (o owner) boardingVariables() map[string]string {
	v := o.variables(0)
	v["boarding_exit_delay"] = daemon.ScriptNum(1<<22 | 2)
	return v
}

// boardingAddress derives the address of o's boarding delegation the way a wallet does.
func (o owner) boardingAddress(t *testing.T) string {
	t.Helper()
	inst := instantiate(t, "boarding.json", o.keys, o.boardingVariables(), nil)
	addr, err := address.NewAddressTaproot(inst.PkScript(0)[2:], &chaincfg.RegressionNetParams)
	require.NoError(t, err)
	return addr.EncodeAddress()
}

func keysOf(t *testing.T, d delegatee) template.Keys {
	t.Helper()
	info, err := d.client.GetInfo(t.Context(), &delegateev1.GetInfoRequest{})
	require.NoError(t, err)
	return template.Keys{Server: parseKey(t, info.ServerPubkey), Emulator: parseKey(t, info.EmulatorPubkey), Cosigner: parseKey(t, info.CosignerPubkey)}
}

// parseKey reads a hex key, x-only or compressed.
func parseKey(t *testing.T, s string) *btcec.PublicKey {
	t.Helper()
	raw, err := hex.DecodeString(s)
	require.NoError(t, err)
	key, err := btcec.ParsePubKey(raw)
	require.NoError(t, err)
	return key
}

func pay(t *testing.T, alice testWallet, address string, assets ...clientlib.Asset) string {
	t.Helper()
	txid, err := alice.SendOffChain(t.Context(), []clientlib.Receiver{{To: address, Amount: delegateAmount, Assets: assets}})
	require.NoError(t, err)
	return txid + ":0"
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

// fundedWallet is a wallet with a settled offchain balance.
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

// instantiate derives the instance of a template file the way a funder does.
func instantiate(t *testing.T, file string, keys template.Keys, variables map[string]string, decrypt func([]byte) ([]byte, error)) *template.Instance {
	t.Helper()
	tpl, err := template.Parse(fixture(t, file), artifacts(t))
	require.NoError(t, err)
	vars := map[string][]byte{}
	for n, v := range variables {
		vars[n], err = hex.DecodeString(v)
		require.NoError(t, err)
	}
	inst, err := tpl.Instantiate(template.Context{Keys: keys, Variables: vars, Decrypt: decrypt})
	require.NoError(t, err)
	return inst
}
