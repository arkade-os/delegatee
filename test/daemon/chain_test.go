package daemon

import (
	"maps"
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/stretchr/testify/require"
)

func TestFundedUtxoAppearsThenConfirms(t *testing.T) {
	d := Start(t)
	d.Arkd.PauseBatches(true)
	_, templateID := registerShipped(t, d, "board.json")
	w := boardingDelegation(t, d, templateID)
	require.True(t, w.Inputs[0].Onchain)

	outpoint := d.Chain.Fund(w.Inputs[0].Script, 50_000)
	coins := waitCoins(t, d, w.ID, 1)
	require.Equal(t, outpoint, coins[0].Outpoint)
	require.Equal(t, "50000", coins[0].Amount)
	require.Zero(t, coins[0].Confirmations, "in the mempool")
	require.Greater(t, atoi(t, coins[0].Due), time.Now().Unix()+1800, "waiting for its confirmation")

	d.Chain.Mine(2)
	require.Eventually(t, func() bool { return coinsOf(t, d, w.ID)[0].Confirmations == 2 }, 5*time.Second, 50*time.Millisecond)
	require.LessOrEqual(t, atoi(t, coinsOf(t, d, w.ID)[0].Due), time.Now().Unix(), "confirmed, it is due")

	d.Chain.Mine(1)
	require.Eventually(t, func() bool { return coinsOf(t, d, w.ID)[0].Confirmations == 3 }, 5*time.Second, 50*time.Millisecond)
	require.Equal(t, 1, tableRows(t, d, "coins WHERE onchain"))
	require.Equal(t, 3, confirmationRows(t, d))
}

func TestRestartListsOnlyTheScriptsThatChanged(t *testing.T) {
	d := Start(t)
	_, templateID := registerShipped(t, d, "board.json")
	a, b := boardingDelegation(t, d, templateID), boardingDelegation(t, d, templateID)
	scriptA, scriptB := a.Inputs[0].Script, b.Inputs[0].Script
	d.Chain.Fund(scriptA, 1000)
	d.Chain.Fund(scriptB, 2000)
	waitCoins(t, d, a.ID, 1)
	waitCoins(t, d, b.ID, 1)
	require.Eventually(t, func() bool { return tableRows(t, d, "script_status WHERE status <> ''") == 2 }, 5*time.Second, 50*time.Millisecond)

	d.Stop()
	d.Chain.Fund(scriptB, 3000)
	d = d.Restart(t)
	require.Len(t, waitCoins(t, d, b.ID, 2), 2)
	require.Never(t, func() bool { return d.Chain.UnspentCalls(scriptA) > 0 }, 300*time.Millisecond, 20*time.Millisecond)
	require.Equal(t, 1, d.Chain.UnspentCalls(scriptB))
	require.Len(t, coinsOf(t, d, a.ID), 1, "its coin comes from the stored coins")
}

func TestReconnectListsOnlyTheScriptsThatChanged(t *testing.T) {
	d := Start(t)
	d.Arkd.PauseBatches(true)
	_, templateID := registerShipped(t, d, "board.json")
	a, b := boardingDelegation(t, d, templateID), boardingDelegation(t, d, templateID)
	scriptA, scriptB := a.Inputs[0].Script, b.Inputs[0].Script
	d.Chain.Fund(scriptA, 1000)
	d.Chain.Fund(scriptB, 2000)
	d.Chain.Mine(1)
	for _, id := range []string{a.ID, b.ID} {
		require.Eventually(t, func() bool { return len(coinsOf(t, d, id)) == 1 && coinsOf(t, d, id)[0].Confirmations == 1 }, 5*time.Second, 50*time.Millisecond)
	}
	require.Equal(t, int64(101), tipHeight(t, d))
	d.Chain.ResetCalls()

	d.Chain.Drop()
	d.Chain.Fund(scriptB, 3000)
	d.Chain.Mine(2)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, int64(101), tipHeight(t, d), "nothing reaches the daemon while it is down")
	d.Chain.Reconnect()

	require.Eventually(t, func() bool { return tipHeight(t, d) == 103 }, 5*time.Second, 50*time.Millisecond)
	coins := waitCoins(t, d, b.ID, 2)
	require.Equal(t, 2, coins[0].Confirmations, "mined at 102, the coin without a known time first")
	require.Equal(t, 3, coins[1].Confirmations)
	require.Eventually(t, func() bool { return coinsOf(t, d, a.ID)[0].Confirmations == 3 }, 5*time.Second, 50*time.Millisecond)
	require.Zero(t, d.Chain.UnspentCalls(scriptA), "its status did not change")
	require.Equal(t, 1, d.Chain.UnspentCalls(scriptB))
}

func TestBoardingInputBoardsThenRenews(t *testing.T) {
	d := Start(t, WithSessions(500*time.Millisecond, 128), WithVtxoLifetime(6*time.Second))
	d.Arkd.ChargeBoardingFee(500)
	board, renewal := boardingAndRenewal(t, d, 2)

	outpoint := d.Chain.Fund(board.Inputs[0].Script, 20_000)
	d.Chain.Mine(1)
	attempts := waitAttempts(t, d, board.ID, 1, "succeeded")
	require.Equal(t, "intent", attempts[0].Kind)
	require.Equal(t, []string{outpoint}, attempts[0].Coins)
	require.Equal(t, d.Arkd.Commitments()[0], attempts[0].Txid)
	require.Equal(t, "spent", coinsOf(t, d, board.ID)[0].Status, "the commitment spent the boarding input")
	require.Equal(t, 1, d.Emu.Intents)
	require.Equal(t, 1, d.Emu.Finalizations)

	require.Eventually(t, func() bool { return len(coinsOf(t, d, renewal.ID)) > 0 }, 5*time.Second, 20*time.Millisecond, "the vtxo landed at the renewal delegation's script")
	require.Equal(t, "19500", coinsOf(t, d, renewal.ID)[0].Amount, "the boarding input less the fee")

	waitAttempts(t, d, renewal.ID, 1, "succeeded")
	require.Eventually(t, func() bool {
		present := presentCoins(t, d, renewal.ID)
		return len(present) == 1 && present[0].Amount == "19500"
	}, 5*time.Second, 20*time.Millisecond, "the boarded vtxo renews like any other")
}

func TestSeveralBoardingInputsBoardAsSeparateCoins(t *testing.T) {
	d := Start(t, WithSessions(500*time.Millisecond, 128))
	board, renewal := boardingAndRenewal(t, d, 1024)
	for _, sats := range []uint64{10_000, 10_000, 30_000} {
		d.Chain.Fund(board.Inputs[0].Script, sats)
	}
	d.Chain.Mine(1)

	waitAttempts(t, d, board.ID, 3, "succeeded")
	var amounts []string
	for _, c := range presentCoins(t, d, renewal.ID) {
		amounts = append(amounts, c.Amount)
	}
	slices.Sort(amounts)
	require.Equal(t, []string{"10000", "10000", "30000"}, amounts)
	for _, c := range coinsOf(t, d, board.ID) {
		require.Equal(t, "spent", c.Status)
	}
}

func TestBoardingInputIsRegisteredAtOnce(t *testing.T) {
	d := Start(t, WithSessions(500*time.Millisecond, 128))
	d.Arkd.PauseBatches(true)
	board, renewal := boardingAndRenewal(t, d, 2)
	d.Arkd.FundAged(renewal.Inputs[0].Script, 10_000, time.Hour, time.Now().Add(6*time.Hour+time.Minute))
	waitCoins(t, d, renewal.ID, 1)

	d.Chain.Fund(board.Inputs[0].Script, 20_000)
	d.Chain.Mine(1)
	require.Eventually(t, func() bool { return d.Arkd.Registered() == 1 }, 2*time.Second, 20*time.Millisecond, "no renewal is waited for")
	require.Empty(t, d.Arkd.RegisteredCoins(), "the vtxo is not registered with it")
}

func boardingDelegation(t *testing.T, d *Daemon, templateID string) delegation {
	t.Helper()
	return registerDelegationWith(t, d, templateID, boardingVariables(t))
}

func boardingVariables(t *testing.T) map[string]string {
	t.Helper()
	variables := renewalVariables(t)
	variables["boarding_exit_delay"] = ScriptNum(1<<22 | 2)
	return variables
}

func coinsOf(t *testing.T, d *Daemon, id string) []coin {
	t.Helper()
	_, body := get(t, d.RestURL+"/v1/delegation?id="+id)
	return decodeCoins(t, body)
}

// waitCoins waits for the delegation to have n coins and returns them.
func waitCoins(t *testing.T, d *Daemon, id string, n int) []coin {
	t.Helper()
	var coins []coin
	require.Eventually(t, func() bool {
		coins = coinsOf(t, d, id)
		return len(coins) == n
	}, 5*time.Second, 50*time.Millisecond)
	return coins
}

func tipHeight(t *testing.T, d *Daemon) int64 {
	t.Helper()
	resp, err := d.Admin.GetStatus(t.Context(), &delegateev1.GetStatusRequest{})
	require.NoError(t, err)
	return resp.GetTipHeight()
}

func confirmationRows(t *testing.T, d *Daemon) int {
	t.Helper()
	var n int
	require.NoError(t, d.DB.QueryRowContext(t.Context(), "SELECT confirmations FROM coins WHERE onchain").Scan(&n))
	return n
}

func atoi(t *testing.T, s string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(s, 10, 64)
	require.NoError(t, err)
	return n
}

// boardingAndRenewal registers a boarding delegation and the renewal delegation whose script its boarding inputs board
// into; both renew in window seconds.
func boardingAndRenewal(t *testing.T, d *Daemon, window int64) (board, renewal delegation) {
	t.Helper()
	variables := boardingVariables(t)
	variables["renewal_window"] = ScriptNum(window)
	_, renewalID := registerRenewal(t, d)
	_, boardingID := registerShipped(t, d, "board.json")
	renewing := maps.Clone(variables)
	delete(renewing, "boarding_exit_delay")
	return registerDelegationWith(t, d, boardingID, variables), registerDelegationWith(t, d, renewalID, renewing)
}

func registerDelegationWith(t *testing.T, d *Daemon, templateID string, variables map[string]string) delegation {
	t.Helper()
	code, body := post(t, d.RestURL+"/v1/delegation", map[string]any{"templateId": templateID, "variables": variables})
	require.Equal(t, http.StatusOK, code, string(body))
	return decodeDelegation(t, body)
}

// waitAttempts waits for the delegation to have n attempts, the newest with status, and returns them.
func waitAttempts(t *testing.T, d *Daemon, id string, n int, status string) []attempt {
	t.Helper()
	var attempts []attempt
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, id)
		return len(attempts) >= n && attempts[0].Status == status
	}, 15*time.Second, 20*time.Millisecond)
	return attempts
}

func presentCoins(t *testing.T, d *Daemon, id string) []coin {
	t.Helper()
	var out []coin
	for _, c := range coinsOf(t, d, id) {
		if c.Status == "present" {
			out = append(out, c)
		}
	}
	return out
}
