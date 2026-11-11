package daemon

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/arkade-os/executor/internal/config"
	"github.com/stretchr/testify/require"
)

// the daemon dies while an intent is registered; its coins are not spent by the landing window and go again.
func TestRestartFailsARegisteredIntentAtTheLandingWindowAndRegistersAgain(t *testing.T) {
	d := Start(t, WithSessions(500*time.Millisecond, 128))
	d.Arkd.PauseBatches(true)
	d.Arkd.CrashAfterRegistration(true)
	_, templateID := registerRenewal(t, d)
	w := renewalDelegation(t, d, templateID, 1024, 1000)
	outpoint := d.Arkd.FundAged(w.Inputs[0].Script, 10_000, time.Hour, time.Now().Add(500*time.Second))
	require.Eventually(t, func() bool {
		attempts := listAttempts(t, d, w.ID)
		return len(attempts) == 1 && attempts[0].Status == "submitted"
	}, 5*time.Second, 20*time.Millisecond)
	require.Equal(t, []string{outpoint}, d.Arkd.RegisteredCoins())

	d.Arkd.CrashAfterRegistration(false)
	d.Arkd.ForgetIntents()
	d = d.Restart(t, WithLandingWindow(500*time.Millisecond))
	d.Arkd.PauseBatches(false)
	var attempts []attempt
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, w.ID)
		return len(attempts) == 2 && attempts[0].Status == "succeeded"
	}, 10*time.Second, 20*time.Millisecond)
	require.Equal(t, "failed", attempts[1].Status)
	require.Contains(t, attempts[1].Error, "did not spend")
	require.Equal(t, 2, d.Arkd.registeredCount())
	require.Equal(t, attempts[0].Txid, d.Arkd.Commitments()[0])
}

// the daemon dies after its forfeits reached arkd and the batch lands meanwhile.
func TestRestartLandsAForfeitedAttemptOnce(t *testing.T) {
	d := Start(t, WithSessions(500*time.Millisecond, 128))
	d.Arkd.HoldLanding(true)
	d.Arkd.CrashAfterForfeits(true)
	_, templateID := registerRenewal(t, d)
	w := renewalDelegation(t, d, templateID, 1024, 1000)
	outpoint := d.Arkd.FundAged(w.Inputs[0].Script, 10_000, time.Hour, time.Now().Add(500*time.Second))
	require.Eventually(t, func() bool { return len(d.Arkd.Commitments()) == 1 }, 10*time.Second, 20*time.Millisecond)
	require.Equal(t, "submitted", listAttempts(t, d, w.ID)[0].Status, "the daemon never saw the batch end")

	d.stop()
	d.Arkd.CrashAfterForfeits(false)
	d.Arkd.HoldLanding(false)
	require.Eventually(t, func() bool { return d.Arkd.spent(outpoint) }, 5*time.Second, 20*time.Millisecond)
	d = d.Restart(t)
	require.Eventually(t, func() bool { return attemptRows(t, d, "succeeded") == 1 }, 10*time.Second, 20*time.Millisecond)
	time.Sleep(300 * time.Millisecond)

	require.Equal(t, 1, attemptRows(t, d, ""))
	require.Equal(t, 1, attemptRows(t, d, "succeeded"), "recorded once")
	require.Equal(t, d.Arkd.Commitments()[0], listAttempts(t, d, w.ID)[0].Txid)
	coins := coinsOf(t, d, w.ID)
	require.Len(t, coins, 2)
	require.Contains(t, coinOutpoints(coins), outpoint)
	present := presentCoins(t, d, w.ID)
	require.Len(t, present, 1, "the renewed coin")
	require.Equal(t, "10000", present[0].Amount)
	require.NotEqual(t, outpoint, present[0].Outpoint)
}

// the daemon dies after its forfeits reached arkd and the batch fails.
func TestRestartFailsAForfeitedAttemptThatDidNotLand(t *testing.T) {
	window := WithLandingWindow(time.Second)
	d := Start(t, WithSessions(500*time.Millisecond, 128), window)
	d.Arkd.CrashAfterForfeits(true)
	d.Arkd.FailAfterForfeits(true)
	_, templateID := registerRenewal(t, d)
	w := renewalDelegation(t, d, templateID, 1024, 1000)
	outpoint := d.Arkd.FundAged(w.Inputs[0].Script, 10_000, time.Hour, time.Now().Add(500*time.Second))
	require.Eventually(t, func() bool {
		return slices.Contains(d.Arkd.batchCalls(), "forfeits") && !d.Arkd.InBatch()
	}, 10*time.Second, 20*time.Millisecond)
	require.Empty(t, d.Arkd.Commitments())

	d.Arkd.CrashAfterForfeits(false)
	d.Arkd.FailAfterForfeits(false)
	d = d.Restart(t, window)
	var attempts []attempt
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, w.ID)
		return len(attempts) == 2 && attempts[0].Status == "succeeded"
	}, 15*time.Second, 50*time.Millisecond)
	require.Equal(t, "failed", attempts[1].Status)
	require.Contains(t, attempts[1].Error, "did not spend")
	require.Equal(t, []string{outpoint}, attempts[0].Coins, "the coin was tried again")
	require.Len(t, d.Arkd.Commitments(), 1)
}

// a batch that fails on our intent bans its coin and sends the others to the next batch.
func TestBlamedCoinsWaitOutTheBan(t *testing.T) {
	d := Start(t, WithSessions(500*time.Millisecond, 128), WithBanDuration(4*time.Second))
	d.Arkd.PauseBatches(true)
	_, templateID := registerRenewal(t, d)
	late := renewalDelegation(t, d, templateID, 1024, 1000)
	other := renewalDelegation(t, d, templateID, 1024, 1000)
	lateCoin := d.Arkd.FundAged(late.Inputs[0].Script, 10_000, time.Hour, time.Now().Add(500*time.Second))
	d.Arkd.FundAged(other.Inputs[0].Script, 10_000, time.Hour, time.Now().Add(500*time.Second))
	require.Eventually(t, func() bool { return d.Arkd.Registered() == 2 }, 5*time.Second, 20*time.Millisecond)

	d.Arkd.FailNextBatchBlaming(lateCoin, "sent its forfeits late")
	d.Arkd.PauseBatches(false)
	require.Eventually(t, func() bool {
		attempts := listAttempts(t, d, other.ID)
		return len(attempts) == 2 && attempts[0].Status == "succeeded"
	}, 3*time.Second, 20*time.Millisecond, "the other intent goes to the next batch at once")
	attempts := listAttempts(t, d, late.ID)
	require.Len(t, attempts, 1)
	require.Equal(t, "failed", attempts[0].Status)
	require.Contains(t, attempts[0].Error, "sent its forfeits late")
	require.NotContains(t, d.Arkd.RegisteredCoins(), lateCoin, "banned")
	require.Equal(t, 3, d.Arkd.registeredCount())

	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, late.ID)
		return len(attempts) == 2 && attempts[0].Status == "succeeded"
	}, 10*time.Second, 50*time.Millisecond, "the ban ends")
	require.Equal(t, 4, d.Arkd.registeredCount())
}

func TestStopWaitsForTheBatchInFlight(t *testing.T) {
	d := Start(t, WithSessions(500*time.Millisecond, 128))
	d.Arkd.SlowPhases(300 * time.Millisecond)
	d.Arkd.HoldLanding(true)
	_, templateID := registerRenewal(t, d)
	w := renewalDelegation(t, d, templateID, 1024, 1000)
	d.Arkd.FundAged(w.Inputs[0].Script, 10_000, time.Hour, time.Now().Add(500*time.Second))
	require.Eventually(t, func() bool {
		attempts := listAttempts(t, d, w.ID)
		return len(attempts) == 1 && d.Arkd.InBatch()
	}, 10*time.Second, 5*time.Millisecond)

	d.stop()
	var status string
	require.NoError(t, d.DB.QueryRowContext(t.Context(), "SELECT status FROM attempts").Scan(&status))
	require.Contains(t, []string{"submitted", "succeeded"}, status)
	require.Len(t, d.Arkd.Commitments(), 1)
	require.Equal(t, []string{"register", "confirm", "nonces", "signatures", "forfeits"}, d.Arkd.batchCalls())
}

// An entry queued and not yet registered goes when its delegation is cancelled or its coin is spent.
func TestQueuedEntriesAreWithdrawn(t *testing.T) {
	d := Start(t, WithSessions(time.Second, 1), func(c *config.Config) { c.IntentsPerBatch = 1 })
	d.Arkd.PauseBatches(true)
	_, templateID := registerRenewal(t, d)
	var delegations []delegation
	var coins []string
	for i := range 3 {
		w := renewalDelegation(t, d, templateID, 8*3600, 1000)
		delegations = append(delegations, w)
		coins = append(coins, d.Arkd.FundAged(w.Inputs[0].Script, 10_000, 14*time.Hour, time.Now().Add(reserve+time.Duration(i)*time.Second)))
		if i == 0 {
			// the first entry queued is the one registered
			require.Eventually(t, func() bool { return readStatus(t, d).Registered == 1 }, 10*time.Second, 20*time.Millisecond)
		}
	}
	require.Eventually(t, func() bool {
		st := readStatus(t, d)
		return st.Registered == 1 && st.Queued == 2
	}, 10*time.Second, 20*time.Millisecond)

	code, body := post(t, d.AdminURL+"/v1/admin/delegation/"+delegations[1].ID+"/cancel", map[string]any{})
	require.Equal(t, http.StatusOK, code, string(body))
	require.Eventually(t, func() bool { return readStatus(t, d).Queued == 1 }, 5*time.Second, 20*time.Millisecond)
	d.Arkd.Spend(coins[2], "elsewhere")
	require.Eventually(t, func() bool { return readStatus(t, d).Queued == 0 }, 5*time.Second, 20*time.Millisecond)
	require.Equal(t, 1, readStatus(t, d).Registered)

	d.Arkd.PauseBatches(false)
	require.Eventually(t, func() bool { return attemptRows(t, d, "succeeded") == 1 }, 10*time.Second, 20*time.Millisecond)
	require.Never(t, func() bool { return d.Arkd.registeredCount() > 1 }, 2500*time.Millisecond, 100*time.Millisecond)
	require.Equal(t, 1, attemptRows(t, d, ""), "no attempt fails at registration")
}
