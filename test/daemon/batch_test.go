package daemon

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/arkade-os/executor/internal/config"
	"github.com/stretchr/testify/require"
)

func TestRenewalGoesThroughARound(t *testing.T) {
	d := Start(t, WithSessions(time.Second, 128))
	d.Arkd.SlowPhases(150 * time.Millisecond)
	d.Arkd.HoldLanding(true)
	_, templateID := registerRenewal(t, d)
	w := renewalDelegation(t, d, templateID, 1024, 1000)

	script := w.Inputs[0].Script
	outpoint := d.Arkd.FundAged(script, 10_000, time.Hour, time.Now().Add(500*time.Second))
	require.Eventually(t, func() bool {
		attempts := listAttempts(t, d, w.ID)
		return len(attempts) == 1 && len(d.Arkd.Commitments()) == 1 &&
			attempts[0].Txid == d.Arkd.Commitments()[0]
	}, 15*time.Second, 10*time.Millisecond, "the attempt keeps the commitment of its batch")

	attempts := listAttempts(t, d, w.ID)
	require.Len(t, attempts, 1)
	a := attempts[0]
	require.Equal(t, "proof", a.Kind)
	require.Equal(t, "submitted", a.Status)
	require.Equal(t, []string{outpoint}, a.Coins)
	require.Equal(t, d.Arkd.Commitments(), []string{a.Txid})
	require.Equal(
		t, []string{"register", "confirm", "nonces", "signatures", "forfeits"}, d.Arkd.batchCalls(),
	)
	require.Equal(t, 1, d.Emu.Intents)
	require.Equal(t, 1, d.Emu.Finalizations)

	d.Arkd.HoldLanding(false)
	require.Eventually(
		t, func() bool { return listAttempts(t, d, w.ID)[0].Status == "succeeded" }, 5*time.Second,
		20*time.Millisecond,
	)
	coins := coinsOf(t, d, w.ID)
	require.Len(t, coins, 2)
	spent, renewed := coins[0], coins[1]
	if spent.Status != "spent" {
		spent, renewed = renewed, spent
	}
	require.Equal(t, outpoint, spent.Outpoint)
	require.Equal(t, a.Txid, spent.SpentBy)
	require.Equal(t, "present", renewed.Status)
	require.Equal(t, "10000", renewed.Amount)
	require.Equal(t, 1, attemptRows(t, d, "succeeded"))
}

// at most one batch's worth stays registered, oldest deadline first, and the next worth follows a
// batch.
func TestOneBatchesWorthIsRegistered(t *testing.T) {
	d := Start(t, WithSessions(time.Second, 3), func(c *config.Config) { c.IntentsPerBatch = 3 })
	d.Arkd.PauseBatches(true)
	d.Arkd.SlowPhases(100 * time.Millisecond)
	_, templateID := registerRenewal(t, d)
	var outpoints []string
	for i := range 7 {
		w := renewalDelegation(t, d, templateID, 8*3600, 1000)
		outpoints = append(
			outpoints,
			d.Arkd.FundAged(
				w.Inputs[0].Script, 10_000, 14*time.Hour,
				time.Now().Add(reserve+5*time.Second+time.Duration(i)*100*time.Millisecond),
			),
		)
	}

	require.Eventually(
		t, func() bool { return d.Arkd.Registered() == 3 && readStatus(t, d).Queued == 4 },
		10*time.Second, 20*time.Millisecond,
	)
	time.Sleep(300 * time.Millisecond)
	require.ElementsMatch(t, outpoints[:3], d.Arkd.RegisteredCoins(), "the earliest deadlines")
	st := readStatus(t, d)
	require.Equal(t, 7, st.Active)
	require.Equal(t, 3, st.Registered)
	require.Equal(t, 4, st.Queued)
	require.Zero(t, st.Late)
	require.Len(t, st.Batches, 3)
	require.Equal(
		t, []int{3, 3, 1},
		[]int{st.Batches[0].Intents, st.Batches[1].Intents, st.Batches[2].Intents},
	)

	d.Arkd.PauseBatches(false)
	require.Eventually(t, func() bool {
		return d.Arkd.InBatch() && d.Arkd.Registered() == 3
	}, 10*time.Second, 5*time.Millisecond, "the next batch's worth is registered while the first one runs")
	require.Eventually(
		t, func() bool { return attemptRows(t, d, "succeeded") == 7 }, 20*time.Second,
		50*time.Millisecond,
	)
	require.Len(t, d.Arkd.Commitments(), 3)
}

// 128 delegations funded together land within eight batches, and the plan forecasts them.
func TestManyDelegationsLandWithinEightBatches(t *testing.T) {
	d := Start(
		t, WithSessions(700*time.Millisecond, 20),
		func(c *config.Config) { c.IntentsPerBatch = 20 },
	)
	d.Arkd.PauseBatches(true)
	_, templateID := registerRenewal(t, d)
	for range 128 {
		w := renewalDelegation(t, d, templateID, 8*3600, 1000)
		d.Arkd.FundAged(
			w.Inputs[0].Script, 10_000, 14*time.Hour, time.Now().Add(reserve+12*time.Second),
		)
	}
	require.Eventually(
		t, func() bool { return readStatus(t, d).Queued == 108 }, 30*time.Second,
		50*time.Millisecond,
	)
	st := readStatus(t, d)
	require.Equal(t, 20, st.Registered)
	require.Zero(t, st.Late, "the batches fit before the deadlines")
	require.Len(t, st.Batches, 7)
	total := 0
	for _, r := range st.Batches {
		total += r.Coins
		require.LessOrEqual(t, r.Intents, 20)
	}
	require.Equal(t, 128, total, "a batch is forecast for every coin")

	d.Arkd.PauseBatches(false)
	require.Eventually(
		t, func() bool { return attemptRows(t, d, "succeeded") == 128 }, 40*time.Second,
		100*time.Millisecond,
	)
	require.LessOrEqual(t, len(d.Arkd.Commitments()), 8)
	require.Equal(t, 0, readStatus(t, d).Registered)
}

// a coin whose deadline has passed before its batch is late.
func TestLateCoinsAreCounted(t *testing.T) {
	d := Start(t, WithSessions(2*time.Second, 128))
	d.Arkd.PauseBatches(true)
	_, templateID := registerRenewal(t, d)
	far := renewalDelegation(t, d, templateID, 8*3600, 1000)
	d.Arkd.FundAged(far.Inputs[0].Script, 10_000, 14*time.Hour, time.Now().Add(7*time.Hour))
	require.Eventually(
		t, func() bool { return readStatus(t, d).Queued == 1 }, 5*time.Second, 20*time.Millisecond,
	)
	require.Zero(t, readStatus(t, d).Late)
	require.Zero(t, d.Arkd.Registered(), "its deadline is an hour away")

	soon := renewalDelegation(t, d, templateID, 8*3600, 1000)
	d.Arkd.FundAged(
		soon.Inputs[0].Script, 10_000, 14*time.Hour, time.Now().Add(reserve-time.Second),
	)
	require.Eventually(
		t, func() bool { return readStatus(t, d).Late == 1 }, 5*time.Second, 20*time.Millisecond,
	)
	st := readStatus(t, d)
	require.Equal(t, 2, st.Registered+st.Queued)
	require.Eventually(
		t, func() bool { return d.Arkd.Registered() == 2 }, 5*time.Second, 20*time.Millisecond,
		"the batch carries the far one too",
	)
}

// nothing is registered before the batch time; the earliest deadline forces a batch of
// everything due by then, registered one batch ahead, and it settles in one batch.
func TestRenewalsWaitForTheEarliestDeadlineThenShareARound(t *testing.T) {
	d := Start(t, WithSessions(time.Second, 128))
	d.Arkd.PauseBatches(true)
	_, templateID := registerRenewal(t, d)
	start := time.Now()
	// due one second apart, one after the other; the first deadline is at 6s, the others up to a
	// second later
	var delegations []delegation
	var outpoints []string
	for i := range 4 {
		due, deadline := time.Duration(
			i+1,
		)*time.Second, 6*time.Second+time.Duration(
			i,
		)*time.Second/3
		expiry := start.Add(reserve + deadline)
		w := renewalDelegation(
			t, d, templateID, int64((expiry.Sub(start.Add(due))+time.Second-1)/time.Second), 1000,
		)
		outpoints = append(
			outpoints, d.Arkd.FundAged(w.Inputs[0].Script, 10_000, 14*time.Hour, expiry),
		)
		delegations = append(delegations, w)
	}

	require.Never(
		t, func() bool { return d.Arkd.Registered() > 0 }, 4*time.Second, 50*time.Millisecond,
		"the coins are due and wait",
	)
	require.Eventually(
		t, func() bool { return d.Arkd.Registered() == 4 }, 4*time.Second, 20*time.Millisecond,
		"all registered together",
	)
	require.GreaterOrEqual(
		t, time.Since(start), 4500*time.Millisecond,
		"a batch ahead of the first deadline, not earlier",
	)
	require.ElementsMatch(t, outpoints, d.Arkd.RegisteredCoins())

	d.Arkd.PauseBatches(false)
	var txids []string
	for _, w := range delegations {
		attempts := waitAttempts(t, d, w.ID, 1, "succeeded")
		txids = append(txids, attempts[0].Txid)
	}
	require.Len(t, d.Arkd.Commitments(), 1, "one batch took them")
	require.Equal(t, []string{txids[0], txids[0], txids[0], txids[0]}, txids)
}

// a group over the batch capacity splits into consecutive batches, and no coin misses its deadline.
func TestGroupOverTheBatchCapacitySplitsIntoBatches(t *testing.T) {
	d := Start(t, WithSessions(time.Second, 2), func(c *config.Config) { c.IntentsPerBatch = 2 })
	_, templateID := registerRenewal(t, d)
	start := time.Now()
	deadlines := []time.Duration{
		9 * time.Second, 10 * time.Second, 10500 * time.Millisecond, 11 * time.Second,
		11500 * time.Millisecond,
	}
	delegations := make([]delegation, len(deadlines))
	for i, deadline := range deadlines {
		expiry := start.Add(reserve + deadline)
		delegations[i] = renewalDelegation(
			t, d, templateID, int64((expiry.Sub(start)+time.Second-1)/time.Second), 1000,
		)
		d.Arkd.FundAged(delegations[i].Inputs[0].Script, 10_000, 14*time.Hour, expiry)
	}

	require.Never(
		t, func() bool { return d.Arkd.Registered() > 0 }, 5*time.Second, 50*time.Millisecond,
		"the first batch is registered three batches before the group",
	)
	for i, w := range delegations {
		attempts := waitAttempts(t, d, w.ID, 1, "succeeded")
		landed := time.Unix(atoi(t, attempts[0].UpdatedAt), 0)
		require.True(
			t, landed.Before(start.Add(deadlines[i])), "coin %d landed at %s, deadline %s", i,
			landed.Sub(start), deadlines[i],
		)
	}
	require.GreaterOrEqual(t, len(d.Arkd.Commitments()), 3, "two intents per batch")
}

// a renewal pays at most its cap; a cap of zero is refused and the coin never spent.
func TestIntentFeeIsCapped(t *testing.T) {
	d := Start(t, WithSessions(500*time.Millisecond, 128), WithRetryDelay(time.Hour))
	d.Arkd.ChargeIntentFee(500)
	_, templateID := registerRenewal(t, d)

	paid := renewalDelegation(t, d, templateID, 1024, 1000)
	d.Arkd.FundAged(paid.Inputs[0].Script, 10_000, time.Hour, time.Now().Add(500*time.Second))
	require.Eventually(
		t, func() bool { return attemptRows(t, d, "succeeded") == 1 }, 10*time.Second,
		20*time.Millisecond,
	)
	present := presentCoins(t, d, paid.ID)
	require.Len(t, present, 1)
	require.Equal(t, "9500", present[0].Amount, "the renewal pays the fee, within its cap")

	refused := renewalDelegation(t, d, templateID, 1024, 0)
	outpoint := d.Arkd.Fund(refused.Inputs[0].Script, 10_000, time.Now().Add(500*time.Second))
	var attempts []attempt
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, refused.ID)
		return len(attempts) == 1
	}, 5*time.Second, 20*time.Millisecond)
	require.Equal(t, "failed", attempts[0].Status)
	require.Equal(t, "proof", attempts[0].Kind)
	require.Contains(t, attempts[0].Error, "exceeds the cap 0")
	coins := coinsOf(t, d, refused.ID)
	require.Len(t, coins, 1)
	require.Equal(t, outpoint, coins[0].Outpoint)
	require.Equal(t, "present", coins[0].Status)
	require.Equal(t, 1, d.Emu.Intents, "the emulator saw only the paying intent")
	require.Equal(t, 1, d.Arkd.registeredCount(), "arkd saw only the paying intent")
}

// arkd may select an intent before its registration returned to the daemon.
func TestIntentSelectedAtRegistrationIsConfirmed(t *testing.T) {
	d := Start(t, WithSessions(time.Second, 128))
	d.Arkd.SelectAtRegistration(true)
	_, templateID := registerRenewal(t, d)
	w := renewalDelegation(t, d, templateID, 1024, 1000)
	d.Arkd.FundAged(w.Inputs[0].Script, 10_000, time.Hour, time.Now().Add(500*time.Second))

	require.Eventually(
		t, func() bool { return attemptRows(t, d, "succeeded") == 1 }, 15*time.Second,
		50*time.Millisecond,
	)
	require.Equal(t, 1, attemptRows(t, d, ""))
	require.Equal(
		t, []string{"register", "confirm", "nonces", "signatures", "forfeits"}, d.Arkd.batchCalls(),
	)
}

func TestFailedBatchIsRetried(t *testing.T) {
	d := Start(t, WithSessions(500*time.Millisecond, 128))
	d.Arkd.FailNextBatch("not enough participants")
	_, templateID := registerRenewal(t, d)
	w := renewalDelegation(t, d, templateID, 1024, 1000)
	d.Arkd.FundAged(w.Inputs[0].Script, 10_000, time.Hour, time.Now().Add(500*time.Second))

	var attempts []attempt
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, w.ID)
		return len(attempts) == 2 && attempts[0].Status == "succeeded"
	}, 15*time.Second, 50*time.Millisecond)
	require.Equal(t, "failed", attempts[1].Status)
	require.Contains(t, attempts[1].Error, "not enough participants")
	require.Len(t, d.Arkd.Commitments(), 1)
}

// An intent no batch selects within the timeout fails and its coins are queued again.
func TestUnselectedIntentFailsAndItsCoinsAreQueuedAgain(t *testing.T) {
	d := Start(
		t, WithSessions(500*time.Millisecond, 128),
		func(c *config.Config) { c.IntentTimeout = 300 * time.Millisecond },
	)
	d.Arkd.PauseBatches(true)
	_, templateID := registerRenewal(t, d)
	w := renewalDelegation(t, d, templateID, 1024, 1000)
	d.Arkd.FundAged(w.Inputs[0].Script, 10_000, time.Hour, time.Now().Add(500*time.Second))

	var attempts []attempt
	require.Eventually(t, func() bool {
		attempts = listAttempts(t, d, w.ID)
		return len(attempts) >= 2 // the second attempt registers the coins again
	}, 10*time.Second, 20*time.Millisecond)
	require.Equal(t, "failed", attempts[len(attempts)-1].Status)
	require.Contains(t, attempts[len(attempts)-1].Error, "not selected")
}

// reserve is how long before its expiry the daemon's default settings hold a coin back.
var reserve = config.Default().Reserve

type batchForecast struct {
	Intents int
	Coins   int
}

type statusResponse struct {
	Active     int
	Queued     int
	Registered int
	Late       int
	Batches    []batchForecast
}

func readStatus(t *testing.T, d *Daemon) statusResponse {
	t.Helper()
	code, body := get(t, d.AdminURL+"/v1/admin/status")
	require.Equal(t, http.StatusOK, code, string(body))
	var raw struct {
		Active, Queued, Registered, Late string
		Batches                          []struct{ Intents, Coins string }
	}
	require.NoError(t, json.Unmarshal(body, &raw))
	num := func(s string) int {
		n, err := strconv.Atoi(s)
		require.NoError(t, err)
		return n
	}
	out := statusResponse{
		Active: num(raw.Active), Queued: num(raw.Queued), Registered: num(raw.Registered),
		Late: num(raw.Late),
	}
	for _, r := range raw.Batches {
		out.Batches = append(
			out.Batches, batchForecast{Intents: num(r.Intents), Coins: num(r.Coins)},
		)
	}
	return out
}

func renewalDelegation(
	t *testing.T, d *Daemon, templateID string, windowSeconds, maxFee int64,
) delegation {
	t.Helper()
	variables := renewalVariables(t)
	variables["renewal_window"], variables["max_fee"] = ScriptNum(windowSeconds), ScriptNum(maxFee)
	code, body := post(
		t, d.RestURL+"/v1/delegation",
		map[string]any{"templateId": templateID, "variables": variables},
	)
	require.Equal(t, http.StatusOK, code, string(body))
	return decodeDelegation(t, body)
}
