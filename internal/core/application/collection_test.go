package application

import (
	"testing"
	"testing/synctest"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"

	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/stretchr/testify/require"
)

func TestCollectionDeadline(t *testing.T) {
	now := time.Now()
	key := &cosigner{}
	s := &service{collectionWindow: 30 * time.Second, maxVtxosPerIntent: 16, cosigners: []*cosigner{key}}
	input := func(due time.Time, window time.Duration) renewalInput {
		return renewalInput{
			vtxo:       clientlib.Vtxo{ExpiresAt: due.Add(window)},
			delegation: &domain.Delegation{Params: domain.Params{RenewalWindow: int64(window / time.Second)}},
		}
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
	paid := second
	paid.delegation = &domain.Delegation{Params: domain.Params{RenewalWindow: 600, MaxFee: 100}}
	paid.vtxo.CreatedAt = now.Add(-10 * time.Minute)
	paid.vtxo.ExpiresAt = now.Add(10 * time.Minute)
	// The fee-paying VTXO is only eligible halfway through its lifetime.
	paid.delegation.RenewalWindow = 3600
	require.Equal(t, now.Add(5*time.Minute), s.collectionDeadline([]renewalInput{paid}, now))

	s.maxVtxosPerIntent = 2
	require.True(t, s.collectionDeadline([]renewalInput{first, second}, now).IsZero(), "full intent submits early")
	second.cosigner = &cosigner{}
	require.False(t, s.collectionDeadline([]renewalInput{first, second}, now).IsZero(), "different keys do not fill one intent")
	s.collectionWindow = 0
	require.True(t, s.collectionDeadline([]renewalInput{first}, now).IsZero())
}

func TestCollectionTimerBundlesFreshInputs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newTestEnv(t)
		env.svc.collectionWindow = 30 * time.Second
		// The ordinary poll is an hour: submission must use the collection timer.
		d := env.register(t, domain.Params{RenewalWindow: 600})
		first := env.vtxo(t, d, 1, 1000, 599*time.Second)
		second := env.vtxo(t, d, 2, 1000, 610*time.Second)
		env.indexer.serve(first, second)
		env.svc.Start()
		synctest.Wait()
		require.Empty(t, env.emulator.submitted)
		env.indexer.serve(first, second)
		time.Sleep(30 * time.Second)
		synctest.Wait()
		env.svc.Stop()
		require.Len(t, env.emulator.submitted, 1, "both inputs collected into one intent")
		records := env.repo.recorded()
		require.Len(t, records, 1)
		require.Equal(t, []string{first.Outpoint.String(), second.Outpoint.String()}, records[0].Outpoints)
	})
}

func TestCollectionRefreshDropsSpentInputs(t *testing.T) {
	env := newTestEnv(t)
	env.svc.collectionWindow = 30 * time.Second
	d := env.register(t, domain.Params{RenewalWindow: 600})
	env.indexer.serve(env.vtxo(t, d, 1, 1000, 599*time.Second))
	env.svc.scan(t.Context())
	require.False(t, env.svc.collectUntil.IsZero())
	// The fake now returns no VTXOs, as if the user spent it during collection.
	env.svc.scan(t.Context())
	require.True(t, env.svc.collectUntil.IsZero())
	require.Empty(t, env.emulator.submitted)
	require.Equal(t, env.svc.pollInterval, env.svc.nextScanDelay(time.Now()))
}

func TestCollectionUrgentInputFlushesWaitingInputs(t *testing.T) {
	env := newTestEnv(t)
	env.svc.collectionWindow = 30 * time.Second
	d := env.register(t, domain.Params{RenewalWindow: 600})
	waiting := env.vtxo(t, d, 1, 1000, 599*time.Second)
	urgent := env.vtxo(t, d, 2, 1000, time.Minute)
	env.indexer.serve(waiting)
	env.svc.scan(t.Context())
	require.Empty(t, env.emulator.submitted)
	env.indexer.serve(waiting, urgent)
	env.svc.scan(t.Context())
	env.svc.wg.Wait()
	require.True(t, env.svc.collectUntil.IsZero())
	require.Len(t, env.emulator.submitted, 1)
	records := env.repo.recorded()
	require.Len(t, records, 1)
	require.Equal(t, []string{urgent.Outpoint.String(), waiting.Outpoint.String()}, records[0].Outpoints)
}

func TestCollectionFailedScanRetriesAtNormalInterval(t *testing.T) {
	env := newTestEnv(t)
	env.svc.collectUntil = time.Now().Add(-time.Second)
	env.repo.err = errBoom
	env.svc.scan(t.Context())
	require.True(t, env.svc.collectUntil.IsZero())
	require.Equal(t, env.svc.pollInterval, env.svc.nextScanDelay(time.Now()), "expired timer must not spin on failure")
}
