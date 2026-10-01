package application

import (
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"

	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/stretchr/testify/require"
)

func BenchmarkScan5000(b *testing.B) {
	env := newTestEnv(b)
	manyDelegations(b, env, 5000)
	env.svc.scan(b.Context()) // the first scan derives every covenant and proof, once
	b.ResetTimer()
	for range b.N {
		env.indexer.serve(env.indexer.vtxos...)
		env.svc.scan(b.Context())
	}
	require.Len(b, env.svc.Status().Holdings, 5000)
}

// TestScale pins requests made, not wall time.
func TestScale(t *testing.T) {
	total, due := scaleSize()
	env := newTestEnv(t)
	env.svc.limits.MaxDelegations = total + 1
	vtxos := make([]clientlib.Vtxo, 0, total)
	var first, last *domain.Delegation
	for i := range total {
		expiresIn := 400 * 24 * time.Hour
		if i < due {
			expiresIn = time.Minute
		}
		owner, _ := hexKey(t)
		v := env.coin(t, owner.PubKey(), 1000, expiresIn)
		last = env.advertised(t, v)
		if i == 0 {
			first = last
		}
		vtxos = append(vtxos, v)
	}

	env.indexer.txLookups = 0
	env.indexer.serve(vtxos...)
	env.scan(t)

	require.Equal(t, total/100, env.indexer.calls, "100 scripts per indexer request")
	require.Len(t, env.svc.Status().Holdings, total)
	require.Len(t, env.emulator.submitted, due, "one intent per coin")
	require.Equal(t, due, env.indexer.txLookups, "watches derive nothing from sources: one lookup per intent")
	require.Len(t, env.ark.registered, due)
	require.Len(t, env.repo.recorded(), due, "one row per delegation and outcome (the fake stream closes before any batch)")

	// the next scan derives nothing again, and forgets a cancelled delegation
	cached := env.svc.watched[first.ID]
	require.NotNil(t, cached)
	require.NoError(t, env.svc.CancelDelegationByID(t.Context(), last.ID))
	lookups := env.indexer.txLookups
	env.indexer.serve(vtxos[due:]...)
	env.scan(t)
	require.Len(t, env.svc.watched, total-1)
	require.NotContains(t, env.svc.watched, last.ID)
	require.Same(t, cached, env.svc.watched[first.ID], "kept, not rebuilt")
	require.Equal(t, lookups, env.indexer.txLookups, "no source fetched again")
	require.Len(t, env.repo.recorded(), due, "nothing due, nothing new")
}

// manyDelegations binds n renewals, each to its own coin, not yet due.
func manyDelegations(t testing.TB, env *testEnv, n int) {
	env.svc.limits.MaxDelegations = n + 1
	vtxos := make([]clientlib.Vtxo, 0, n)
	for range n {
		owner, _ := hexKey(t)
		v := env.coin(t, owner.PubKey(), 1000, 400*24*time.Hour)
		env.advertised(t, v)
		vtxos = append(vtxos, v)
	}
	env.indexer.serve(vtxos...)
}
