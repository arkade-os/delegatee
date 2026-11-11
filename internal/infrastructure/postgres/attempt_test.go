package postgres

import (
	"errors"
	"testing"

	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/stretchr/testify/require"
)

func TestAttemptCreateThenUpdate(t *testing.T) {
	repo, id := testAttempts(t)
	a := delegation.Attempt{DelegationID: id, Txs: []delegation.Tx{{Raw: []byte{1, 2}, Txid: "tx", Spends: true}}, Coins: []string{"a:0", "b:1"}, Status: delegation.Submitted}
	require.NoError(t, repo.AddOrUpdate(t.Context(), &a))
	require.NotZero(t, a.ID)
	require.Equal(t, delegation.Submitted, a.Status)
	require.Equal(t, []string{"a:0", "b:1"}, a.Coins)
	require.Equal(t, []delegation.Tx{{Raw: []byte{1, 2}, Txid: "tx", Spends: true}}, a.Txs)
	require.Equal(t, []string{"tx"}, a.Spenders())
	require.False(t, a.CreatedAt.IsZero())
	require.Equal(t, a.CreatedAt, a.UpdatedAt)

	pending, err := repo.ListPending(t.Context())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, delegation.Submitted, pending[0].Status)

	require.NoError(t, a.Succeeded())
	require.NoError(t, repo.AddOrUpdate(t.Context(), &a))
	pending, err = repo.ListPending(t.Context())
	require.NoError(t, err)
	require.Empty(t, pending)
	list, err := repo.ListByDelegation(t.Context(), id, 0, 10)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, delegation.Succeeded, list[0].Status)

	a.ID++
	require.ErrorIs(t, repo.AddOrUpdate(t.Context(), &a), delegation.ErrAttemptNotFound)
}

func TestBatchedAttemptKeepsItsIntentThroughTheBatch(t *testing.T) {
	repo, id := testAttempts(t)
	a := delegation.Attempt{DelegationID: id, Txs: []delegation.Tx{{Raw: []byte{3}, Txid: "proof"}}, Coins: []string{"a:0"}, Status: delegation.Submitted}
	require.NoError(t, repo.AddOrUpdate(t.Context(), &a))
	require.Equal(t, delegation.Submitted, a.Status)
	proof, ok := a.Proof()
	require.True(t, ok)
	require.Equal(t, "proof", proof.Txid)

	a.AddTx(delegation.Tx{Txid: "commitment", Onchain: true, Spends: true})
	require.NoError(t, repo.AddOrUpdate(t.Context(), &a))
	pending, err := repo.ListPending(t.Context())
	require.NoError(t, err)
	require.Len(t, pending, 1, "it waits for its coins to be seen spent")
	require.Equal(t, delegation.Submitted, pending[0].Status)
	require.Equal(t, []string{"commitment"}, pending[0].Spenders())
	proof, ok = pending[0].Proof()
	require.True(t, ok)
	require.Equal(t, delegation.Tx{Raw: []byte{3}, Txid: "proof"}, proof)

	require.NoError(t, a.Succeeded())
	require.NoError(t, repo.AddOrUpdate(t.Context(), &a))
	pending, err = repo.ListPending(t.Context())
	require.NoError(t, err)
	require.Empty(t, pending)
}

func TestAttemptListPendingAndByDelegation(t *testing.T) {
	repo, id := testAttempts(t)
	var ids []int64
	for i := range 5 {
		a := delegation.Attempt{DelegationID: id, Txs: []delegation.Tx{{Txid: "tx"}}, Coins: []string{"a:0"}, Status: delegation.Submitted}
		require.NoError(t, repo.AddOrUpdate(t.Context(), &a))
		ids = append(ids, a.ID)
		if i == 1 {
			require.NoError(t, a.Fail(errors.New("refused")))
			require.NoError(t, repo.AddOrUpdate(t.Context(), &a))
		}
	}
	pending, err := repo.ListPending(t.Context())
	require.NoError(t, err)
	require.Equal(t, []int64{ids[0], ids[2], ids[3], ids[4]}, attemptIDs(pending))

	all, err := repo.ListByDelegation(t.Context(), id, 0, 10)
	require.NoError(t, err)
	require.Equal(t, []int64{ids[4], ids[3], ids[2], ids[1], ids[0]}, attemptIDs(all))
	require.Equal(t, "refused", all[3].Error)
	page, err := repo.ListByDelegation(t.Context(), id, ids[3], 2)
	require.NoError(t, err)
	require.Equal(t, []int64{ids[2], ids[1]}, attemptIDs(page))
	none, err := repo.ListByDelegation(t.Context(), id+1, 0, 10)
	require.NoError(t, err)
	require.Empty(t, none)
}

func TestAttemptNeedsItsDelegation(t *testing.T) {
	repo, id := testAttempts(t)
	orphan := delegation.Attempt{DelegationID: id + 1, Txs: []delegation.Tx{{Txid: "tx"}}, Coins: []string{"a:0"}, Status: delegation.Submitted}
	require.Error(t, repo.AddOrUpdate(t.Context(), &orphan))
}

func testAttempts(t *testing.T) (*AttemptRepository, int64) {
	t.Helper()
	db := testDB(t)
	tpl := testTemplate("t")
	require.NoError(t, db.Templates().AddOrUpdate(t.Context(), &tpl))
	d := testDelegation("a")
	require.NoError(t, db.Delegations().AddOrUpdate(t.Context(), &d))
	return db.Attempts(), d.ID
}

func attemptIDs(list []delegation.Attempt) []int64 {
	ids := make([]int64, 0, len(list))
	for _, a := range list {
		ids = append(ids, a.ID)
	}
	return ids
}
