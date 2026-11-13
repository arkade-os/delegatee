package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCoinLandsThenIsSpent(t *testing.T) {
	d := Start(t)
	_, templateID := registerRenewal(t, d)
	w := registerDelegationWith(t, d, templateID, renewalVariables(t))
	require.Empty(t, coinsOf(t, d, w.ID))

	outpoint := strings.Repeat("aa", 32) + ":1"
	expires := time.Now().Add(time.Hour)
	d.Arkd.Land(w.Inputs[0].Script, outpoint, 10_000, expires)
	var coins []coin
	require.Eventually(t, func() bool {
		_, body := get(t, d.RestURL+"/v1/delegation?id="+w.ID)
		coins = decodeCoins(t, body)
		return len(coins) == 1
	}, 5*time.Second, 50*time.Millisecond)
	require.Equal(t, outpoint, coins[0].Outpoint)
	require.Equal(t, 0, coins[0].Input)
	require.Equal(t, "10000", coins[0].Amount)
	require.Equal(t, fmt.Sprint(expires.Unix()), coins[0].ExpiresAt)
	require.Equal(
		t, fmt.Sprint(expires.Add(-1024*time.Second).Unix()), coins[0].Due,
		"the renewal window before expiry",
	)
	require.Equal(t, "present", coins[0].Status)
	require.Empty(t, coins[0].SpentBy)

	d.Arkd.Spend(outpoint, "bb")
	require.Eventually(t, func() bool {
		_, body := get(t, d.RestURL+"/v1/delegation?id="+w.ID)
		coins = decodeCoins(t, body)
		return len(coins) == 1 && coins[0].Status == "spent"
	}, 5*time.Second, 50*time.Millisecond)
	require.Equal(t, "bb", coins[0].SpentBy)
	require.Equal(t, 1, coinRows(t, d, "spent"))
	require.Equal(t, 0, coinRows(t, d, "present"))
}

func TestStartupServesStoredCoinsThenReconciles(t *testing.T) {
	d := Start(t)
	_, templateID := registerRenewal(t, d)
	variables, err := json.Marshal(renewalVariables(t))
	require.NoError(t, err)
	var first int64
	for i := range 1001 {
		script := fmt.Sprintf("5120%064x", i)
		inputs := fmt.Sprintf(
			`[{"Name":"funds","Onchain":false,"Script":"%s","Tapscripts":["51"]}]`, script,
		)
		var id int64
		require.NoError(t, d.DB.QueryRowContext(
			t.Context(),
			`
			INSERT INTO delegations (fingerprint, address, template_id, variables, inputs)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			fmt.Sprintf(
				"fp%d", i,
			),
			fmt.Sprintf("addr%d", i),
			templateID,
			variables,
			inputs,
		).Scan(&id))
		_, err := d.DB.ExecContext(
			t.Context(),
			`INSERT INTO claims (delegation_id, input, script, onchain, locktime) VALUES ($1, 0, $2, false, 0)`,
			id,
			script,
		)
		require.NoError(t, err)
		if i == 0 {
			first = id
		}
	}
	script := fmt.Sprintf("5120%064x", 0)
	kept, gone := strings.Repeat("aa", 32)+":0", strings.Repeat("bb", 32)+":0"
	for _, outpoint := range []string{kept, gone} {
		_, err := d.DB.ExecContext(t.Context(), `
			INSERT INTO coins (outpoint, delegation_id, input, script, amount, expiry, created_at, due, status)
			VALUES ($1, $2, 0, $3, 1000, now() + interval '1 hour', now(), now() + interval '30 minutes', 'present')`,
			outpoint, first, script)
		require.NoError(t, err)
	}
	d.Arkd.Land(script, kept, 1000, time.Now().Add(time.Hour))

	d = d.Restart(t, WithVtxosDelay(500*time.Millisecond))
	url := fmt.Sprintf("%s/v1/delegation?id=%d", d.RestURL, first)
	code, body := get(t, url)
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(
		t, []string{kept, gone}, coinOutpoints(decodeCoins(t, body)),
		"stored coins before any reconcile",
	)
	for _, c := range decodeCoins(t, body) {
		require.Equal(t, "present", c.Status)
	}
	require.Empty(t, d.Arkd.vtxosChunks(), "no GetVtxos answered yet")

	require.Eventually(t, func() bool {
		_, body := get(t, url)
		coins := decodeCoins(t, body)
		return len(coins) == 2 && coins[0].Status == "present" && coins[1].Status == "spent" &&
			len(d.Arkd.vtxosChunks()) == 2
	}, 5*time.Second, 50*time.Millisecond)
	require.Equal(t, []int{1000, 1}, d.Arkd.vtxosChunks())
	require.Equal(t, []int{1000, 1}, d.Arkd.subscriptionSizes())
	require.Equal(t, 2, d.Arkd.Subscriptions())

	d.Arkd.Reconnect()
	require.Eventually(
		t, func() bool { return len(d.Arkd.vtxosChunks()) >= 4 }, 5*time.Second,
		50*time.Millisecond,
	)
	for _, n := range d.Arkd.vtxosChunks() {
		require.LessOrEqual(t, n, 1000)
	}
	require.Equal(t, 2, d.Arkd.Subscriptions(), "a reconnect opens no subscription")
}

type coin struct {
	Outpoint  string `json:"outpoint"`
	Input     int    `json:"input"`
	Amount    string `json:"amount"`
	ExpiresAt string `json:"expiresAt"`
	Due       string `json:"due"`
	Status    string `json:"status"`
	SpentBy   string `json:"spentBy"`

	Confirmations int `json:"confirmations"`
}

func decodeCoins(t *testing.T, body []byte) []coin {
	t.Helper()
	var resp struct {
		Coins []coin `json:"coins"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Coins
}

func coinOutpoints(coins []coin) []string {
	out := make([]string, 0, len(coins))
	for _, c := range coins {
		out = append(out, c.Outpoint)
	}
	return out
}

func coinRows(t *testing.T, d *Daemon, status string) int {
	t.Helper()
	var n int
	require.NoError(
		t,
		d.DB.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM coins WHERE status = $1", status).
			Scan(&n),
	)
	return n
}
