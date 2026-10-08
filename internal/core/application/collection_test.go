package application

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestDeadline(t *testing.T) {
	now := time.Now()
	s := &service{renewalReserve: time.Hour}
	expiry := now.Add(3 * time.Hour)
	require.Equal(t, expiry.Add(-time.Hour), s.deadline(coin{Expiry: expiry}, now.Add(time.Hour)), "the reserve before expiry")
	due := now.Add(150 * time.Minute)
	require.Equal(t, due, s.deadline(coin{Expiry: expiry}, due), "a window shorter than the reserve goes at due")
	require.Equal(t, expiry, s.deadline(coin{Expiry: expiry}, expiry.Add(time.Second)), "a locktime past expiry is overdue at once")
	require.Equal(t, due, s.deadline(coin{}, due), "no expiry, nothing to keep a reserve from")
}

func TestPlanBatches(t *testing.T) {
	now := time.Now()
	s := &service{renewalReserve: 6 * time.Hour, boardingMaxWait: 10 * time.Minute}
	day := 24 * time.Hour
	entry := func(op string, id int64, due, deadline time.Duration) planEntry {
		return planEntry{outpoints: []string{op}, delegation: id, amount: 1000, due: now.Add(due), deadline: now.Add(deadline)}
	}
	// the three vtxos of one address: due in 4h, 5h and 3d, expiring in 4d, 4d and 6d
	a, b, c := entry("a:0", 1, 4*time.Hour, 4*day-6*time.Hour), entry("b:0", 1, 5*time.Hour, 4*day-6*time.Hour), entry("c:0", 1, 3*day, 6*day-6*time.Hour)
	p := s.planBatches([]planEntry{c, b, a}, now)
	require.Len(t, p.batches, 1, "one batch carries the three")
	require.Equal(t, PlannedBatch{At: now.Add(4*day - 6*time.Hour), Vtxos: 3, Amount: 3000, Delegations: 3, ForcedBy: "a:0", ForcedByDelegation: 1}, p.batches[0])
	require.Equal(t, now.Add(4*day-6*time.Hour), p.batchAt["c:0"])
	require.Equal(t, now.Add(4*day-6*time.Hour), p.submitAt(now))
	require.True(t, p.submitAt(now.Add(4*day)).IsZero(), "past the batch time, submit now")

	// a short window coin goes at due, before the others
	short := entry("s:0", 2, time.Hour, time.Hour)
	p = s.planBatches([]planEntry{a, b, c, short}, now)
	require.Len(t, p.batches, 2)
	require.Equal(t, "s:0", p.batches[0].ForcedBy)
	require.Equal(t, 1, p.batches[0].Vtxos, "a's deadline is far: it waits for its own batch")

	// a deposit rides along with a batch within its max wait, else boards at once
	deposit := planEntry{outpoints: []string{"d:0"}, delegation: 3, amount: 500, due: now.Add(-time.Hour), deposit: true, confirmed: now.Add(-time.Hour)}
	p = s.planBatches([]planEntry{short, deposit}, now)
	require.Len(t, p.batches, 2)
	require.Equal(t, now, p.batches[0].At, "a batch in the past is now")
	require.Equal(t, "d:0", p.batches[0].ForcedBy)
	require.True(t, p.submitAt(now).IsZero())
	s.boardingMaxWait = 3 * time.Hour
	p = s.planBatches([]planEntry{short, deposit}, now)
	require.Len(t, p.batches, 1)
	require.Equal(t, 2, p.batches[0].Vtxos, "the deposit joined the short coin's batch")
	require.Equal(t, now.Add(time.Hour), p.batchAt["d:0"])

	// a batch forced by an overdue coin
	overdue := entry("o:0", 4, -time.Hour, -time.Minute)
	p = s.planBatches([]planEntry{overdue, a}, now)
	require.Equal(t, now, p.batches[0].At)
	require.Equal(t, now.Add(-time.Minute), p.batchAt["o:0"], "the map keeps the time it was due")
	require.Empty(t, s.planBatches(nil, now).batches)
}

func TestEntriesOfAPair(t *testing.T) {
	now := time.Now()
	coins := []plannedCoin{
		{coin: coin{Amount: 1}, slot: 0, due: now, deadline: now.Add(time.Hour)},
		{coin: coin{Amount: 2}, slot: 1, due: now.Add(2 * time.Hour), deadline: now.Add(3 * time.Hour)},
	}
	entries := entriesOf(9, 2, coins)
	require.Len(t, entries, 1, "a pair is one intent")
	require.Equal(t, uint64(3), entries[0].amount)
	require.Equal(t, now.Add(2*time.Hour), entries[0].due, "due once both are")
	require.Equal(t, now.Add(2*time.Hour), entries[0].deadline, "never before due")
	require.Len(t, entriesOf(9, 1, coins), 2, "a watch's coins are an intent each")
}

// the window is 1024s: a reserve of 5m leaves a coin expiring in 15m waiting 10m
func waiting(env *testEnv) {
	env.svc.renewalReserve = 5 * time.Minute
}

func TestCollectionTimerBundlesFreshInputs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newTestEnv(t)
		waiting(env)
		first := env.coin(t, env.userKey.PubKey(), 1000, 15*time.Minute)
		second := env.coin(t, env.userKey.PubKey(), 1000, 16*time.Minute)
		env.advertised(t, first)
		env.advertised(t, second)
		// the poll is an hour: the batch timer submits
		env.indexer.serve(first, second)
		env.svc.Start()
		synctest.Wait()
		require.Empty(t, env.emulator.submitted)
		st := env.svc.Status()
		require.Len(t, st.Batches, 1)
		require.Equal(t, 2, st.Batches[0].Vtxos)
		require.Equal(t, first.Outpoint.String(), st.Batches[0].ForcedBy)
		env.indexer.serve(first, second)
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		env.svc.Stop()
		require.Len(t, env.emulator.submitted, 2, "both coins collected into one cycle, one intent each")
		records := env.repo.recorded()
		require.Len(t, records, 1, "one watch")
		require.Equal(t, []string{first.Outpoint.String(), second.Outpoint.String()}, records[0].Outpoints)
	})
}

func TestCollectionRefreshDropsSpentInputs(t *testing.T) {
	env := newTestEnv(t)
	waiting(env)
	v := env.coin(t, env.userKey.PubKey(), 1000, 15*time.Minute)
	env.advertised(t, v)
	env.indexer.serve(v)
	env.svc.scan(t.Context())
	require.False(t, env.svc.collectUntil.IsZero())
	require.Equal(t, env.svc.collectUntil, env.svc.Status().Batches[0].At)
	// the coin is gone, as if its owner spent it while it was collected
	env.svc.scan(t.Context())
	require.True(t, env.svc.collectUntil.IsZero())
	require.Empty(t, env.svc.Status().Batches)
	require.Empty(t, env.emulator.submitted)
	require.Equal(t, env.svc.pollInterval, env.svc.nextScanDelay(time.Now()))
}

func TestCollectionDeadlineFlushesWaitingInputs(t *testing.T) {
	env := newTestEnv(t)
	waiting(env)
	later := env.coin(t, env.userKey.PubKey(), 1000, 15*time.Minute)
	urgent := env.coin(t, env.userKey.PubKey(), 1000, 3*time.Minute)
	env.advertised(t, later)
	env.advertised(t, urgent)
	env.indexer.serve(later)
	env.svc.scan(t.Context())
	require.Empty(t, env.emulator.submitted)
	env.indexer.serve(later, urgent)
	env.scan(t)
	require.True(t, env.svc.collectUntil.IsZero())
	require.Len(t, env.emulator.submitted, 2, "the urgent coin's deadline takes the waiting one along")
	records := env.repo.recorded()
	require.Len(t, records, 1, "one watch")
	require.Equal(t, []string{urgent.Outpoint.String(), later.Outpoint.String()}, records[0].Outpoints, "the soonest expiry first")
}

func TestCollectionFailedScanRetriesAtNormalInterval(t *testing.T) {
	env := newTestEnv(t)
	env.svc.collectUntil = time.Now().Add(-time.Second)
	env.repo.err = errBoom
	env.svc.scan(t.Context())
	require.True(t, env.svc.collectUntil.IsZero())
	require.Equal(t, env.svc.pollInterval, env.svc.nextScanDelay(time.Now()), "expired timer must not spin on failure")
}

func TestDepositWaitsForANearBatchOnly(t *testing.T) {
	env := newTestEnv(t)
	waiting(env)
	v := env.coin(t, env.userKey.PubKey(), 1000, 15*time.Minute)
	env.advertised(t, v)
	other, _ := hexKey(t)
	d := env.boarding(t, other.PubKey())
	u := env.deposit(t, d, 10_000) // confirmed an hour ago
	env.indexer.serve(v)
	env.svc.boardingMaxWait = 2 * time.Hour
	env.svc.scan(t.Context())
	require.Empty(t, env.emulator.submitted, "the deposit waits for the batch in ten minutes")
	st := env.svc.Status()
	require.Len(t, st.Batches, 1)
	require.Equal(t, 2, st.Batches[0].Vtxos)
	require.Equal(t, st.Batches[0].At, st.BatchAt[u.Txid+":0"])
	require.Equal(t, st.Batches[0].At, st.Holdings[d.ID].NextBatchAt)

	env.svc.boardingMaxWait = 10 * time.Minute
	env.svc.collectUntil = time.Time{}
	env.indexer.serve(v)
	env.scan(t)
	require.Len(t, env.emulator.submitted, 2, "no batch within its wait: the deposit boards now, the vtxo rides along")
}

func TestInFlightCoinsLeaveThePlan(t *testing.T) {
	env := newTestEnv(t)
	waiting(env)
	v := env.coin(t, env.userKey.PubKey(), 1000, 15*time.Minute)
	d := env.advertised(t, v)
	env.indexer.serve(v)
	env.svc.inFlight[d.ID] = true
	env.svc.scan(t.Context())
	st := env.svc.Status()
	require.Empty(t, st.Batches)
	require.True(t, st.Holdings[d.ID].Renewing)
	require.Zero(t, st.Holdings[d.ID].Late)
}

func TestQuarantinedCoinSitsOutOneRetry(t *testing.T) {
	env := newTestEnv(t)
	v := env.coin(t, env.userKey.PubKey(), 1000, 3*time.Minute)
	env.advertised(t, v)
	env.indexer.serve(v)
	env.svc.quarantine([]renewalInput{{coin: vtxoCoin(0, v)}})
	env.scan(t)
	require.Empty(t, env.emulator.submitted, "kept out of the retry right after the failure")
	require.Len(t, env.svc.Status().Batches, 1, "still planned")
	env.svc.quarantined[v.Outpoint.String()] = time.Now() // the quarantine ends with the poll
	env.indexer.serve(v)
	env.scan(t)
	require.Len(t, env.emulator.submitted, 1)
}

func TestFailedResultsBlameOneIntent(t *testing.T) {
	sunk, other := &pendingIntent{inputs: []renewalInput{{}}}, &pendingIntent{inputs: []renewalInput{{}}}
	h := &batchHandler{svc: &service{}, pending: []*pendingIntent{other}, inBatch: nil}
	h.blame(sunk, errors.New("bad forfeit"))
	h.pending = append(h.pending, sunk)
	results := h.failedResults(t.Context(), errBoom)
	require.Len(t, results, 2)
	require.False(t, results[0].blamed)
	require.True(t, results[1].blamed)
}

func TestReserveMustCoverARetry(t *testing.T) {
	env := newTestEnv(t)
	key, _ := btcec.NewPrivateKey()
	for _, bad := range [][2]time.Duration{{0, 0}, {2*time.Minute - time.Second, 0}, {2 * time.Hour, -time.Second}} {
		_, err := NewServiceWithKeys(t.Context(), env.repo, env.ark, env.indexer, env.emulator, env.explorer, 30*time.Second, 50, nil,
			[]*btcec.PrivateKey{key}, time.Hour, time.Minute, bad[0], bad[1], env.svc.limits)
		require.Error(t, err)
	}
	_, err := NewServiceWithKeys(t.Context(), env.repo, env.ark, env.indexer, env.emulator, env.explorer, 30*time.Second, 50, nil,
		[]*btcec.PrivateKey{key}, time.Hour, time.Minute, 2*time.Minute, 0, env.svc.limits)
	require.NoError(t, err)
}
