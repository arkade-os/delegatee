package daemon

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	tpl "github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/delegatee/pkg/template/ecies"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/arkade-os/delegatee/templates"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// the claim stream starts with the defaults and a streamed funding transaction gets its swap claimed.
func TestDefaultStreamSpawnsADelegationThatClaims(t *testing.T) {
	d := Start(t, WithEncryptionKey, WithDefaultTemplates)
	st := streamsOf(t, d)
	require.Len(t, st, 1)
	require.Equal(t, "active", st[0].Status)
	require.Equal(t, claimStreamTemplate(t, d), st[0].TemplateID)
	waitStreaming(t, d)

	sw := newSwap(t, d, st[0].TemplateID)
	script, funding := fundingTx(t, d, sw, 10_000)
	d.Arkd.Stream(funding)

	w := waitDelegations(t, d, 1)[0]
	require.Equal(t, st[0].ID, w.StreamID)
	require.Equal(t, hex.EncodeToString(script), w.Inputs[0].Script)
	require.Equal(t, 1, tableRows(t, d, "delegations"), "nobody registered anything")

	d.Arkd.Fund(w.Inputs[0].Script, 10_000, time.Now().Add(time.Hour))
	attempts := waitAttempts(t, d, w.ID, 1, "submitted")
	require.Equal(t, "offchain", attempts[0].Kind)
	var raw []byte
	require.NoError(t, d.DB.QueryRowContext(t.Context(), "SELECT decode(txs->0->>'raw', 'base64') FROM attempts").Scan(&raw))
	ptx, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
	require.NoError(t, err)
	require.Equal(t, sw.receiverScript, ptx.UnsignedTx.TxOut[0].PkScript, "the claim pays the receiver")
}

func TestStreamedTransactionsThatDoNotMatchSpawnNothing(t *testing.T) {
	d := Start(t, WithEncryptionKey, WithDefaultTemplates)
	waitStreaming(t, d)
	sw := newSwap(t, d, claimStreamTemplate(t, d))
	_, funding := fundingTx(t, d, sw, 10_000)
	funding.UnsignedTx.TxOut[0].PkScript = append([]byte{0x51, 0x20}, make([]byte, 32)...)
	d.Arkd.Stream(funding)
	_, funding = fundingTx(t, d, sw, 999)
	d.Arkd.Stream(funding)
	_, funding = fundingTx(t, d, sw, 10_000)
	funding.UnsignedTx.TxOut = funding.UnsignedTx.TxOut[:1]
	d.Arkd.Stream(funding)

	require.Never(t, func() bool { return rows(d, "delegations") > 0 }, 500*time.Millisecond, 50*time.Millisecond)
}

func TestDefaultStreamStartsOnceAndStaysCancelled(t *testing.T) {
	d := Start(t, WithEncryptionKey, WithDefaultTemplates)
	d = d.Restart(t, WithEncryptionKey, WithDefaultTemplates)
	st := streamsOf(t, d)
	require.Len(t, st, 1, "a restart registers it again as the same stream")

	code, body := post(t, d.AdminURL+"/v1/admin/stream/"+st[0].ID+"/cancel", map[string]any{})
	require.Equal(t, http.StatusOK, code, string(body))
	d = d.Restart(t, WithEncryptionKey, WithDefaultTemplates)
	st = streamsOf(t, d)
	require.Len(t, st, 1)
	require.Equal(t, "cancelled", st[0].Status)
	require.Equal(t, 0, d.Arkd.Streaming(), "nothing reads the transactions")

	code, body = post(t, d.AdminURL+"/v1/admin/stream", map[string]any{"templateId": st[0].TemplateID})
	require.Equal(t, http.StatusPreconditionFailed, code, string(body))
}

func TestNoDefaultStreamWithoutAnEncryptionKey(t *testing.T) {
	d := Start(t, WithDefaultTemplates)
	require.Empty(t, streamsOf(t, d))
}

func TestRegisterStreamOverREST(t *testing.T) {
	d := Start(t, WithEncryptionKey)
	id := registerStreamTemplate(t, d, 86400)

	code, body := post(t, d.AdminURL+"/v1/admin/stream", map[string]any{"templateId": id})
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, 1, len(streamsOf(t, d)))
	code, _ = post(t, d.RestURL+"/v1/admin/stream", map[string]any{"templateId": id})
	require.Equal(t, http.StatusNotFound, code, "admin routes stay off the public port")

	code, body = post(t, d.AdminURL+"/v1/admin/stream", map[string]any{"templateId": id, "variables": map[string]string{"ciphertext": "00"}})
	require.Equal(t, http.StatusBadRequest, code, string(body))
	_, renewal := registerRenewal(t, d)
	code, body = post(t, d.AdminURL+"/v1/admin/stream", map[string]any{"templateId": renewal})
	require.Equal(t, http.StatusPreconditionFailed, code, "no trigger: "+string(body))
	code, body = post(t, d.AdminURL+"/v1/admin/stream", map[string]any{"templateId": "missing"})
	require.Equal(t, http.StatusNotFound, code, string(body))
}

func TestSpawnedDelegationsHaveTheirOwnCap(t *testing.T) {
	d := Start(t, WithEncryptionKey, WithDefaultTemplates, WithMaxDelegations(1, 1))
	waitStreaming(t, d)
	streamed := claimStreamTemplate(t, d)
	_, first := fundingTx(t, d, newSwap(t, d, streamed), 10_000)
	_, second := fundingTx(t, d, newSwap(t, d, streamed), 10_000)
	d.Arkd.Stream(first)
	waitDelegations(t, d, 1)
	d.Arkd.Stream(second)
	require.Never(t, func() bool { return rows(d, "delegations") > 1 }, 500*time.Millisecond, 50*time.Millisecond, "the second hits the cap")

	claimDelegation(t, d)
	claim := registerClaim(t, d)
	code, body := post(t, d.RestURL+"/v1/delegation", map[string]any{"templateId": claim, "variables": newSwap(t, d, claim).variables})
	require.Equal(t, http.StatusTooManyRequests, code, string(body))
}

func TestPublicDelegationDoesNotTakeTheCoinOfASpawnedOne(t *testing.T) {
	d := Start(t, WithEncryptionKey, WithDefaultTemplates)
	waitStreaming(t, d)
	sw := newSwap(t, d, claimStreamTemplate(t, d))
	script, funding := fundingTx(t, d, sw, 10_000)

	// the claim template without its trigger locks the same script, and the public delegation is older
	public := registerUntriggeredClaim(t, d)
	vars := map[string]string{
		"taptree": hex.EncodeToString(funding.Outputs[0].TaprootTapTree), "receiver_program": sw.variables["receiver_program"],
		"ciphertext": seal(t, d, sw.preimage, public),
	}
	older := registerDelegationWith(t, d, public, vars)
	require.Equal(t, hex.EncodeToString(script), older.Inputs[0].Script)

	d.Arkd.Stream(funding)
	var spawned delegation
	require.Eventually(t, func() bool {
		for _, w := range listDelegationRows(t, d) {
			if w.StreamID != "0" {
				spawned = w
			}
		}
		return spawned.ID != ""
	}, 5*time.Second, 50*time.Millisecond)
	time.Sleep(300 * time.Millisecond)

	d.Arkd.Fund(older.Inputs[0].Script, 10_000, time.Now().Add(time.Hour))
	waitAttempts(t, d, spawned.ID, 1, "submitted")
	require.Len(t, waitCoins(t, d, spawned.ID, 1), 1)
	require.Empty(t, coinsOf(t, d, older.ID), "the spawned delegation owns the script's coins")
	require.Empty(t, listAttempts(t, d, older.ID))
}

func TestSpawnedDelegationExpiresAndIsPruned(t *testing.T) {
	d := Start(t, WithEncryptionKey, WithDelegationExpiry(time.Second, 100*time.Millisecond, time.Second))
	id := registerStreamTemplate(t, d, 2)
	code, body := post(t, d.AdminURL+"/v1/admin/stream", map[string]any{"templateId": id})
	require.Equal(t, http.StatusOK, code, string(body))
	waitStreaming(t, d)
	_, funding := fundingTx(t, d, newSwap(t, d, id), 10_000)
	d.Arkd.Stream(funding)

	w := waitDelegations(t, d, 1)[0]
	require.Equal(t, "active", w.Status)
	require.Eventually(t, func() bool {
		_, body := get(t, d.AdminURL+"/v1/admin/delegations")
		list := decodeDelegations(t, body)
		return len(list) == 1 && list[0].Status == "expired"
	}, 10*time.Second, 50*time.Millisecond)
	require.Eventually(t, func() bool { return tableRows(t, d, "delegations") == 0 }, 10*time.Second, 50*time.Millisecond, "pruned after the delay")
}

func TestRefundWaitsForTheTipToReachItsLocktime(t *testing.T) {
	now := time.Now()
	for name, tc := range map[string]struct {
		locktime int64
		prepare  func(*Daemon)
		reach    func(*Daemon)
	}{
		"timestamp": {
			locktime: now.Add(-time.Hour).Unix(),
			prepare:  func(d *Daemon) { d.Chain.SetMedianTime(now.Add(-2 * time.Hour)) },
			reach:    func(d *Daemon) { d.Chain.SetMedianTime(now) },
		},
		"height": {locktime: 150, reach: func(d *Daemon) { d.Chain.Mine(60) }},
	} {
		t.Run(name, func(t *testing.T) {
			d := Start(t, WithEncryptionKey)
			if tc.prepare != nil {
				tc.prepare(d)
			}
			refund := registerDoc(t, d, fixture(t, "vhtlc_refund.json"))
			sw := newSwap(t, d, refund)
			sw.variables["refund_locktime"] = ScriptNum(tc.locktime)
			w := registerDelegationWith(t, d, refund, sw.variables)

			d.Arkd.Fund(w.Inputs[0].Script, 10_000, time.Now().Add(time.Hour))
			waitCoins(t, d, w.ID, 1)
			require.Never(t, func() bool { return rows(d, "attempts") > 0 }, time.Second, 50*time.Millisecond)

			tc.reach(d)
			waitAttempts(t, d, w.ID, 1, "submitted")
			var raw []byte
			require.NoError(t, d.DB.QueryRowContext(t.Context(), "SELECT decode(txs->0->>'raw', 'base64') FROM attempts").Scan(&raw))
			ptx, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
			require.NoError(t, err)
			require.Equal(t, append([]byte{0x51, 0x20}, mustHex(t, sw.variables["sender_program"])...), ptx.UnsignedTx.TxOut[0].PkScript, "it pays the sender")
		})
	}
}

type streamRow struct {
	ID         string `json:"id"`
	TemplateID string `json:"templateId"`
	Status     string `json:"status"`
}

func streamsOf(t *testing.T, d *Daemon) []streamRow {
	t.Helper()
	code, body := get(t, d.AdminURL+"/v1/admin/streams")
	require.Equal(t, http.StatusOK, code, string(body))
	var resp struct {
		Streams []streamRow `json:"streams"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Streams
}

// rows counts the rows of table, 0 when the database cannot be read: it serves conditions that run past their test.
func rows(d *Daemon, table string) int {
	var n int
	_ = d.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
	return n
}

func waitStreaming(t *testing.T, d *Daemon) {
	t.Helper()
	require.Eventually(t, func() bool { return d.Arkd.Streaming() == 1 }, 5*time.Second, 20*time.Millisecond, "nothing reads the transactions")
}

func listDelegationRows(t *testing.T, d *Daemon) []delegation {
	t.Helper()
	code, body := get(t, d.AdminURL+"/v1/admin/delegations")
	require.Equal(t, http.StatusOK, code, string(body))
	return decodeDelegations(t, body)
}

func waitDelegations(t *testing.T, d *Daemon, n int) []delegation {
	t.Helper()
	var list []delegation
	require.Eventually(t, func() bool {
		list = listDelegationRows(t, d)
		return len(list) == n
	}, 5*time.Second, 50*time.Millisecond)
	return list
}

func claimStreamTemplate(t *testing.T, d *Daemon) string {
	t.Helper()
	code, body := post(t, d.RestURL+"/v1/template", map[string]string{"document": string(templates.Templates["noninteractiveclaim.json"])})
	require.Equal(t, http.StatusOK, code, string(body))
	return decodeTemplate(t, body).ID
}

// registerStreamTemplate registers the claim template with delegations living ttl seconds.
func registerStreamTemplate(t *testing.T, d *Daemon, ttl int) string {
	t.Helper()
	doc := editClaim(t, func(doc map[string]any) { doc["trigger"].(map[string]any)["expires_after_seconds"] = ttl })
	return registerDoc(t, d, doc)
}

// registerUntriggeredClaim registers the claim template without its trigger, which clients may register delegations of.
func registerUntriggeredClaim(t *testing.T, d *Daemon) string {
	t.Helper()
	return registerDoc(t, d, editClaim(t, func(doc map[string]any) { delete(doc, "trigger") }))
}

func editClaim(t *testing.T, edit func(map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(templates.Templates["noninteractiveclaim.json"], &doc))
	edit(doc)
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	return raw
}

func registerDoc(t *testing.T, d *Daemon, doc []byte) string {
	t.Helper()
	code, body := post(t, d.RestURL+"/v1/template", map[string]string{"document": string(doc)})
	require.Equal(t, http.StatusOK, code, string(body))
	return decodeTemplate(t, body).ID
}

// fundingTx is the transaction funding a swap's VHTLC the way covclaimd does: the output carries its
// taptree and the packet seals the preimage to the daemon. It returns the output's script.
func fundingTx(t *testing.T, d *Daemon, sw swap, amount int64) ([]byte, *psbt.Packet) {
	t.Helper()
	parsed, err := tpl.Parse(fixture(t, "vhtlc_claim.json"), artifactDocs())
	require.NoError(t, err)
	vars := map[string][]byte{}
	for name, value := range sw.variables {
		vars[name] = mustHex(t, value)
	}
	inst, err := parsed.Instantiate(tpl.Context{
		Keys:      tpl.Keys{Server: d.Server, Emulator: d.Emulator, Cosigner: d.Cosigner},
		Variables: vars,
		Decrypt: func(ciphertext []byte) ([]byte, error) {
			return ecies.Decrypt(newKey(9), ciphertext, sw.templateID)
		},
	})
	require.NoError(t, err)
	tree, err := txutils.TapTree(inst.Tapscripts(0)).Encode()
	require.NoError(t, err)
	program := mustHex(t, sw.variables["receiver_program"])
	body := TLV(mustHex(t, sw.variables["ciphertext"]), EnforcePayTo(t, program), encryptionKey(t, d))
	ext, err := extension.Extension{packets.Raw(4, body)}.TxOut()
	require.NoError(t, err)

	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: [32]byte(bytes.Repeat([]byte{byte(amount)}, 32)), Index: uint32(time.Now().UnixNano())}})
	tx.AddTxOut(wire.NewTxOut(amount, inst.PkScript(0)))
	tx.AddTxOut(ext)
	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	ptx.Outputs[0].TaprootTapTree = tree
	return inst.PkScript(0), ptx
}

func artifactDocs() map[string][]byte {
	docs := map[string][]byte{}
	for _, doc := range templates.Artifacts {
		if parsed, err := tpl.ParseArtifact(doc); err == nil {
			docs[parsed.ID] = doc
		}
	}
	return docs
}

func encryptionKey(t *testing.T, d *Daemon) []byte {
	t.Helper()
	_, body := get(t, d.RestURL+"/v1/info")
	var info struct {
		EncryptionPubkey string `json:"encryptionPubkey"`
	}
	require.NoError(t, json.Unmarshal(body, &info))
	return mustHex(t, info.EncryptionPubkey)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	doc, err := os.ReadFile("../../pkg/template/testdata/" + name)
	require.NoError(t, err)
	return doc
}
