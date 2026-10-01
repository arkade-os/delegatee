package application

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCollectionDeadline(t *testing.T) {
	now := time.Now()
	s := &service{collectionWindow: 30 * time.Second}
	input := func(due time.Time, window time.Duration) renewalInput {
		return renewalInput{coin: coin{Expiry: due.Add(window)}, due: due}
	}
	first := input(now.Add(-10*time.Second), 10*time.Minute)
	second := input(now, 10*time.Minute)
	deadline := now.Add(20 * time.Second)
	require.Equal(t, deadline, s.collectionDeadline([]renewalInput{first}, now))
	require.Equal(t, deadline, s.collectionDeadline([]renewalInput{second, first}, now), "new arrivals cannot extend the wait")
	require.True(t, s.collectionDeadline([]renewalInput{first}, deadline).IsZero())
	require.True(t, s.collectionDeadline(nil, now).IsZero())

	for _, window := range []time.Duration{time.Minute, 2 * time.Minute} {
		require.True(t, s.collectionDeadline([]renewalInput{input(now, window)}, now).IsZero(), "short windows never wait")
	}
	s.collectionWindow = time.Hour
	require.Equal(t, now.Add(5*time.Minute), s.collectionDeadline([]renewalInput{second}, now), "keep half the renewal window")

	s.collectionWindow = 0
	require.True(t, s.collectionDeadline([]renewalInput{first}, now).IsZero())
}

func TestCollectionTimerBundlesFreshInputs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newTestEnv(t)
		env.svc.collectionWindow = 30 * time.Second
		// renewable 1024s before expiry: the first since a second, the second in ten
		first := env.coin(t, env.userKey.PubKey(), 1000, 1023*time.Second)
		second := env.coin(t, env.userKey.PubKey(), 1000, 1034*time.Second)
		env.advertised(t, first)
		env.advertised(t, second)
		// the poll is an hour: the collection timer submits
		env.indexer.serve(first, second)
		env.svc.Start()
		synctest.Wait()
		require.Empty(t, env.emulator.submitted)
		env.indexer.serve(first, second)
		time.Sleep(30 * time.Second)
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
	env.svc.collectionWindow = 30 * time.Second
	v := env.coin(t, env.userKey.PubKey(), 1000, 1023*time.Second)
	env.advertised(t, v)
	env.indexer.serve(v)
	env.svc.scan(t.Context())
	require.False(t, env.svc.collectUntil.IsZero())
	// the coin is gone, as if its owner spent it while it was collected
	env.svc.scan(t.Context())
	require.True(t, env.svc.collectUntil.IsZero())
	require.Empty(t, env.emulator.submitted)
	require.Equal(t, env.svc.pollInterval, env.svc.nextScanDelay(time.Now()))
}

func TestCollectionUrgentInputFlushesWaitingInputs(t *testing.T) {
	env := newTestEnv(t)
	env.svc.collectionWindow = 30 * time.Second
	waiting := env.coin(t, env.userKey.PubKey(), 1000, 1023*time.Second)
	urgent := env.coin(t, env.userKey.PubKey(), 1000, time.Minute)
	env.advertised(t, waiting)
	env.advertised(t, urgent)
	env.indexer.serve(waiting)
	env.svc.scan(t.Context())
	require.Empty(t, env.emulator.submitted)
	env.indexer.serve(waiting, urgent)
	env.scan(t)
	require.True(t, env.svc.collectUntil.IsZero())
	require.Len(t, env.emulator.submitted, 2)
	records := env.repo.recorded()
	require.Len(t, records, 1, "one watch")
	require.Equal(t, []string{urgent.Outpoint.String(), waiting.Outpoint.String()}, records[0].Outpoints, "the soonest expiry first")
}

func TestCollectionFailedScanRetriesAtNormalInterval(t *testing.T) {
	env := newTestEnv(t)
	env.svc.collectUntil = time.Now().Add(-time.Second)
	env.repo.err = errBoom
	env.svc.scan(t.Context())
	require.True(t, env.svc.collectUntil.IsZero())
	require.Equal(t, env.svc.pollInterval, env.svc.nextScanDelay(time.Now()), "expired timer must not spin on failure")
}
