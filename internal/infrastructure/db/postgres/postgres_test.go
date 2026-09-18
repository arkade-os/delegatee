package postgres

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/stretchr/testify/require"
)

// Runs against the compose postgres (make regtest-up), like the e2e suite.
func testRepo(t *testing.T) (domain.DelegationRepository, *sql.DB) {
	t.Helper()
	if testing.Short() {
		t.Skip("requires postgres")
	}
	dsn := os.Getenv("DELEGATEE_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres@localhost:5432/delegatee?sslmode=disable"
	}
	repo, err := NewRepository(t.Context(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.Close() })
	raw, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	return repo, raw
}

func TestDelegationLifecycle(t *testing.T) {
	repo, _ := testRepo(t)
	ctx := t.Context()
	require.NoError(t, repo.Ping(ctx))
	address := fmt.Sprintf("tark1test%d", time.Now().UnixNano())
	params := domain.Params{RenewalWindow: 600, MaxFee: 42}

	before, err := repo.CountActive(ctx)
	require.NoError(t, err)
	d, err := repo.Create(ctx, address, []string{"aa", "bb"}, params)
	require.NoError(t, err)
	require.Equal(t, params, d.Params)
	require.Equal(t, []string{"aa", "bb"}, d.Tapscripts)
	require.Equal(t, domain.DelegationStatusActive, d.Status)
	after, err := repo.CountActive(ctx)
	require.NoError(t, err)
	require.Equal(t, before+1, after)

	_, err = repo.Create(ctx, address, []string{"aa", "bb"}, params)
	require.ErrorIs(t, err, domain.ErrDelegationAlreadyExists)

	got, err := repo.Get(ctx, address)
	require.NoError(t, err)
	require.Equal(t, d.ID, got.ID)
	_, err = repo.Get(ctx, address+"nope")
	require.ErrorIs(t, err, domain.ErrDelegationNotFound)

	require.NoError(t, repo.Cancel(ctx, address, domain.DelegationStatusRevoked))
	require.ErrorIs(t, repo.Cancel(ctx, address+"nope", domain.DelegationStatusCancelled), domain.ErrDelegationNotFound)
	stopped, err := repo.Get(ctx, address)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusRevoked, stopped.Status)
	active, err := repo.List(ctx, domain.DelegationStatusActive)
	require.NoError(t, err)
	for _, a := range active {
		require.NotEqual(t, address, a.Address)
	}
	all, err := repo.List(ctx, "")
	require.NoError(t, err)
	require.Greater(t, len(all), len(active)-1)

	// registering a cancelled address resumes it, keeping its id
	again, err := repo.Create(ctx, address, []string{"aa", "bb"}, params)
	require.NoError(t, err)
	require.Equal(t, d.ID, again.ID)
	require.Equal(t, domain.DelegationStatusActive, again.Status)
}

func TestRenewalHistory(t *testing.T) {
	repo, raw := testRepo(t)
	ctx := t.Context()
	d, err := repo.Create(ctx, fmt.Sprintf("tark1hist%d", time.Now().UnixNano()), []string{"aa"}, domain.Params{RenewalWindow: 1})
	require.NoError(t, err)
	lonely, err := repo.Create(ctx, fmt.Sprintf("tark1lone%d", time.Now().UnixNano()), []string{"aa"}, domain.Params{RenewalWindow: 1})
	require.NoError(t, err)

	for _, ren := range []domain.Renewal{
		{DelegationID: d.ID, Outpoints: []string{"a:0"}, Error: "old failure"},
		{DelegationID: d.ID, Outpoints: []string{"a:0", "b:1"}, CommitmentTxid: "cc", Success: true},
		{DelegationID: lonely.ID, Outpoints: []string{"z:0"}, Error: "still failing"},
	} {
		require.NoError(t, repo.RecordRenewal(ctx, ren))
	}
	// age the first of d and the only one of lonely
	_, err = raw.ExecContext(ctx, `UPDATE renewals SET attempted_at = NOW() - INTERVAL '90 days'
		WHERE (delegation_id = $1 AND error = 'old failure') OR delegation_id = $2`, d.ID, lonely.ID)
	require.NoError(t, err)

	history, err := repo.ListRenewals(ctx, d.ID, 10)
	require.NoError(t, err)
	require.Len(t, history, 2)
	require.True(t, history[0].Success, "newest first")
	require.Equal(t, []string{"a:0", "b:1"}, history[0].Outpoints)
	limited, err := repo.ListRenewals(ctx, d.ID, 1)
	require.NoError(t, err)
	require.Len(t, limited, 1)

	last, err := repo.LastRenewals(ctx)
	require.NoError(t, err)
	require.Equal(t, "cc", last[d.ID].CommitmentTxid)
	require.Equal(t, "still failing", last[lonely.ID].Error)

	// pruning drops old history but never a delegation's latest state
	require.NoError(t, repo.PruneRenewals(ctx, time.Now().Add(-30*24*time.Hour)))
	history, err = repo.ListRenewals(ctx, d.ID, 10)
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.True(t, history[0].Success)
	kept, err := repo.ListRenewals(ctx, lonely.ID, 10)
	require.NoError(t, err)
	require.Len(t, kept, 1, "a failure stored once must survive while it is the latest")
}

func TestNewRepositoryErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("requires postgres")
	}
	_, err := NewRepository(t.Context(), "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	require.Error(t, err)
}
