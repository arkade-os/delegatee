package daemon

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/arkade-os/delegatee/pkg/template/ecies"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestClaimLandsThroughAnOffchainAttempt(t *testing.T) {
	d := Start(t, WithEncryptionKey)
	w, sw := claimDelegation(t, d)

	outpoint := d.Arkd.Fund(w.Inputs[0].Script, 10_000, time.Now().Add(time.Hour))
	var attempts []attempt
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, w.ID)
		return len(attempts) == 1 && attempts[0].Status == "submitted" && len(d.Arkd.submitted()) == 1
	}, 5*time.Second, 50*time.Millisecond)
	a := attempts[0]
	require.Equal(t, "offchain", a.Kind)
	require.Equal(t, w.ID, a.DelegationID)
	require.Equal(t, []string{outpoint}, a.Coins)
	require.Empty(t, a.Error)
	require.Equal(t, []string{a.Txid}, d.Arkd.submitted())
	require.Equal(t, 1, d.Emu.Signed)

	var raw []byte
	require.NoError(t, d.DB.QueryRowContext(t.Context(), "SELECT decode(txs->0->>'raw', 'base64') FROM attempts").Scan(&raw))
	ptx, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
	require.NoError(t, err)
	require.Equal(t, a.Txid, ptx.UnsignedTx.TxHash().String())
	require.Equal(t, sw.receiverScript, ptx.UnsignedTx.TxOut[0].PkScript, "the claim pays the receiver")
	require.Equal(t, int64(10_000), ptx.UnsignedTx.TxOut[0].Value)

	d.Arkd.Spend(outpoint, a.Txid)
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, w.ID)
		return len(attempts) == 1 && attempts[0].Status == "succeeded"
	}, 5*time.Second, 50*time.Millisecond)
	_, body := get(t, d.RestURL+"/v1/delegation?id="+w.ID)
	coins := decodeCoins(t, body)
	require.Len(t, coins, 1)
	require.Equal(t, "spent", coins[0].Status)
	require.Equal(t, a.Txid, coins[0].SpentBy)
	require.Equal(t, 1, attemptRows(t, d, "succeeded"))
}

// the daemon dies after recording the attempt, before the emulator reached arkd.
func TestRestartBeforeTheEmulatorFailsTheAttempt(t *testing.T) {
	d := Start(t, WithEncryptionKey)
	w, _ := claimDelegation(t, d)

	d.Emu.Hang(true, false)
	outpoint := d.Arkd.Fund(w.Inputs[0].Script, 10_000, time.Now().Add(time.Hour))
	var attempts []attempt
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, w.ID)
		return len(attempts) == 1 && attempts[0].Status == "submitted"
	}, 5*time.Second, 50*time.Millisecond)
	require.Empty(t, d.Arkd.submitted())

	d.Emu.Hang(false, false)
	d = d.Restart(t, WithEncryptionKey, WithLandingWindow(time.Second), WithRetryDelay(100*time.Millisecond))
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, w.ID)
		return len(attempts) == 2 && attempts[1].Status == "failed" && attempts[0].Status == "submitted"
	}, 10*time.Second, 50*time.Millisecond)
	require.NotEmpty(t, attempts[1].Error)
	require.Equal(t, []string{outpoint}, attempts[0].Coins)

	d.Arkd.Spend(outpoint, attempts[0].Txid)
	require.Eventually(t, func() bool {
		return attemptRows(t, d, "succeeded") == 1
	}, 5*time.Second, 50*time.Millisecond)
	require.Equal(t, 1, coinRows(t, d, "spent"))
}

// the emulator finalized at arkd and the daemon died before it heard back.
func TestRestartAfterTheEmulatorFinalizedSucceedsOnceTheCoinsAreSpent(t *testing.T) {
	d := Start(t, WithEncryptionKey)
	w, _ := claimDelegation(t, d)

	d.Emu.Hang(false, true)
	outpoint := d.Arkd.Fund(w.Inputs[0].Script, 10_000, time.Now().Add(time.Hour))
	var attempts []attempt
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, w.ID)
		return len(attempts) == 1 && len(d.Arkd.submitted()) == 1
	}, 5*time.Second, 50*time.Millisecond)
	require.Equal(t, "submitted", attempts[0].Status)
	txid := attempts[0].Txid

	d.Emu.Hang(false, false)
	d = d.Restart(t, WithEncryptionKey, WithLandingWindow(time.Minute))
	d.Arkd.Spend(outpoint, txid)
	require.Eventually(t, func() bool {
		return attemptRows(t, d, "succeeded") == 1
	}, 5*time.Second, 50*time.Millisecond)
	require.Equal(t, 1, attemptRows(t, d, ""))
	require.Empty(t, d.Arkd.submitted(), "the transaction is not submitted again")
	require.Equal(t, 1, coinRows(t, d, "spent"))
}

func TestRefusedAttemptsAreRetried(t *testing.T) {
	d := Start(t, WithEncryptionKey, WithRetryDelay(300*time.Millisecond))
	w, _ := claimDelegation(t, d)

	d.Emu.Refuse(status.Error(codes.InvalidArgument, "no preimage"))
	d.Arkd.RefuseSubmit(status.Error(codes.InvalidArgument, "bad tx"))
	outpoint := d.Arkd.Fund(w.Inputs[0].Script, 10_000, time.Now().Add(time.Hour))
	var attempts []attempt
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, w.ID)
		return len(attempts) == 1
	}, 5*time.Second, 50*time.Millisecond)
	require.Equal(t, "failed", attempts[0].Status)
	require.Contains(t, attempts[0].Error, "emulator")
	require.Contains(t, attempts[0].Error, "no preimage")
	_, body := get(t, d.RestURL+"/v1/delegation?id="+w.ID)
	require.Equal(t, "present", decodeCoins(t, body)[0].Status)

	d.Emu.Refuse(nil)
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, w.ID)
		return len(attempts) >= 2 && attempts[0].Error != "" && attempts[0].Error != attempts[len(attempts)-1].Error
	}, 5*time.Second, 50*time.Millisecond, "a retry reaches arkd")
	require.Equal(t, "failed", attempts[0].Status, "arkd refused")
	require.Contains(t, attempts[0].Error, "bad tx")
	require.Equal(t, []string{outpoint}, attempts[0].Coins)
	require.Empty(t, d.Arkd.submitted())

	d.Arkd.RefuseSubmit(nil)
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, w.ID)
		return attempts[0].Status == "submitted"
	}, 5*time.Second, 50*time.Millisecond)
	require.Equal(t, []string{attempts[0].Txid}, d.Arkd.submitted())

	cancelled, _ := claimDelegation(t, d)
	code, body := post(t, d.AdminURL+"/v1/admin/delegation/"+cancelled.ID+"/cancel", map[string]any{})
	require.Equal(t, http.StatusOK, code, string(body))
	d.Arkd.Fund(cancelled.Inputs[0].Script, 10_000, time.Now().Add(time.Hour))
	require.Never(t, func() bool {
		return len(listAttempts(t, d, cancelled.ID)) > 0 || len(d.Arkd.submitted()) > 1
	}, 950*time.Millisecond, 100*time.Millisecond, "a cancelled delegation's coins are never attempted")
}

type attempt struct {
	ID           string   `json:"id"`
	DelegationID string   `json:"delegationId"`
	Kind         string   `json:"kind"`
	Coins        []string `json:"coins"`
	Txid         string   `json:"txid"`
	Status       string   `json:"status"`
	Error        string   `json:"error"`
	CreatedAt    string   `json:"createdAt"`
	UpdatedAt    string   `json:"updatedAt"`
}

func listAttempts(t *testing.T, d *Daemon, delegationID string) []attempt {
	t.Helper()
	code, body := get(t, d.AdminURL+"/v1/admin/delegation/"+delegationID+"/attempts")
	require.Equal(t, http.StatusOK, code, string(body))
	var resp struct {
		Attempts []attempt `json:"attempts"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Attempts
}

// registerClaim registers the VHTLC claim template.
func registerClaim(t *testing.T, d *Daemon) string {
	t.Helper()
	return registerDoc(t, d, fixture(t, "vhtlc_claim.json"))
}

// claimDelegation registers a delegation for a new swap under the claim template.
func claimDelegation(t *testing.T, d *Daemon) (delegation, swap) {
	t.Helper()
	id := registerClaim(t, d)
	sw := newSwap(t, d, id)
	return registerDelegationWith(t, d, id, sw.variables), sw
}

// swap is a VHTLC whose preimage is sealed to the daemon.
type swap struct {
	variables      map[string]string
	receiverScript []byte
	preimage       []byte
	templateID     string // the template the preimage is sealed for
}

// newSwap seals the preimage of a new swap for the template templateID.
func newSwap(t *testing.T, d *Daemon, templateID string) swap {
	t.Helper()
	preimage := make([]byte, 32)
	_, err := rand.Read(preimage)
	require.NoError(t, err)
	sender, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	receiver, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	program := schnorr.SerializePubKey(receiver.PubKey())
	return swap{
		variables: map[string]string{
			"sender":                  hex.EncodeToString(sender.PubKey().SerializeCompressed()),
			"receiver":                hex.EncodeToString(receiver.PubKey().SerializeCompressed()),
			"refund_locktime":         hex.EncodeToString(binary.LittleEndian.AppendUint32(nil, uint32(time.Now().Add(24*time.Hour).Unix()))),
			"unilateral_claim_delay":  ScriptNum(1024),
			"unilateral_refund_delay": ScriptNum(1536),
			"unilateral_refund_without_receiver_delay": ScriptNum(2048),
			"receiver_program":                         hex.EncodeToString(program),
			"sender_program":                           hex.EncodeToString(schnorr.SerializePubKey(sender.PubKey())),
			"ciphertext":                               seal(t, d, preimage, templateID),
		},
		receiverScript: append([]byte{0x51, 0x20}, program...),
		preimage:       preimage,
		templateID:     templateID,
	}
}

// seal is the hex ciphertext of preimage for the template templateID, sealed to the daemon.
func seal(t *testing.T, d *Daemon, preimage []byte, templateID string) string {
	t.Helper()
	encryption, err := btcec.ParsePubKey(encryptionKey(t, d))
	require.NoError(t, err)
	ciphertext, err := ecies.Encrypt(encryption, preimage, templateID)
	require.NoError(t, err)
	return hex.EncodeToString(ciphertext)
}

// attemptRows counts the attempts with status, any when empty.
func attemptRows(t *testing.T, d *Daemon, status string) int {
	t.Helper()
	var n int
	require.NoError(t, d.DB.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM attempts WHERE $1 = '' OR status = $1", status).Scan(&n))
	return n
}
