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

// TestScale pins how the work grows with thousands of delegations: by
// requests made, not by wall time.
func TestScale(t *testing.T) {
	total, due := scaleSize() // BenchmarkScan5000 is the big one
	env := newTestEnv(t)
	env.svc.maxDelegations = total + 1
	vtxos := make([]clientlib.Vtxo, 0, total)
	var last *domain.Delegation
	for i := range total {
		last = env.register(t, domain.Params{RenewalWindow: int64(i + 1)})
		expiresIn := 400 * 24 * time.Hour
		if i < due {
			expiresIn = 0
		}
		vtxos = append(vtxos, env.vtxo(t, last, i, 1000, expiresIn))
	}

	env.indexer.serve(vtxos...)
	env.svc.scan(t.Context())
	env.svc.wg.Wait()

	require.Equal(t, total/100, env.indexer.calls, "100 scripts per indexer request")
	require.Len(t, env.svc.Status().Holdings, total)
	intents := (due + 15) / 16
	require.Len(t, env.emulator.submitted, intents, "16 coins per intent")
	require.Equal(t, intents, env.indexer.txLookups, "one previous-tx lookup per intent, not per coin")
	require.Len(t, env.ark.registered, intents)
	require.Len(t, env.repo.recorded(), due, "one row per delegation (the fake stream closes before any batch)")

	// the next scan derives nothing again, and forgets a cancelled delegation
	first := env.svc.watched[1]
	require.NotNil(t, first)
	require.NoError(t, env.svc.CancelDelegation(t.Context(), last.Address))
	env.indexer.serve(vtxos[due:]...)
	env.svc.scan(t.Context())
	env.svc.wg.Wait()
	require.Len(t, env.svc.watched, total-1)
	require.NotContains(t, env.svc.watched, last.ID)
	require.Same(t, first, env.svc.watched[1], "kept, not rebuilt")
	require.Len(t, env.repo.recorded(), due, "nothing due, nothing new")
}

// manyDelegations registers n delegations with distinct scripts (one window
// each) and puts one vtxo, not yet due, at every one of them.
func manyDelegations(t testing.TB, env *testEnv, n int) {
	env.svc.maxDelegations = n + 1
	vtxos := make([]clientlib.Vtxo, 0, n)
	for i := range n {
		d := env.register(t, domain.Params{RenewalWindow: int64(i + 1)})
		vtxos = append(vtxos, env.vtxo(t, d, i, 1000, 400*24*time.Hour))
	}
	env.indexer.serve(vtxos...)
}
