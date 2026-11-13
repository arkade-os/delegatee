package postgres

import (
	"testing"

	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/internal/core/domain/registry"
	"github.com/stretchr/testify/require"
)

func TestStreamCreateThenGet(t *testing.T) {
	repo := testDelegations(t).db.Streams()
	created := testStream()
	require.NoError(t, repo.AddOrUpdate(t.Context(), &created))
	require.NotZero(t, created.ID)
	require.False(t, created.CreatedAt.IsZero())
	require.Equal(t, delegation.StatusActive, created.Status)
	require.Equal(t, testStream().Variables, created.Variables)

	got, err := repo.Get(t.Context(), created.ID)
	require.NoError(t, err)
	require.Equal(t, &created, got)
	_, err = repo.Get(t.Context(), created.ID+1)
	require.ErrorIs(t, err, delegation.ErrStreamNotFound)
}

func TestStreamCreateReturnsTheSameRule(t *testing.T) {
	repo := testDelegations(t).db.Streams()
	first := testStream()
	require.NoError(t, repo.AddOrUpdate(t.Context(), &first))
	first.Status = delegation.StatusCancelled
	require.NoError(t, repo.AddOrUpdate(t.Context(), &first))

	again := testStream()
	require.NoError(t, repo.AddOrUpdate(t.Context(), &again))
	require.Equal(t, first.ID, again.ID)
	require.Equal(t, delegation.StatusCancelled, again.Status, "a cancelled stream stays cancelled")

	other := testStream()
	other.Variables = nil
	second := other
	require.NoError(t, repo.AddOrUpdate(t.Context(), &second))
	require.NotEqual(t, first.ID, second.ID)
	require.Equal(t, map[string]string{}, second.Variables)
}

func TestStreamListAndSetStatus(t *testing.T) {
	repo := testDelegations(t).db.Streams()
	a := testStream()
	require.NoError(t, repo.AddOrUpdate(t.Context(), &a))
	other := testStream()
	other.Variables = map[string]string{}
	b := other
	require.NoError(t, repo.AddOrUpdate(t.Context(), &b))
	b.Status = delegation.StatusCancelled
	require.NoError(t, repo.AddOrUpdate(t.Context(), &b))

	all, err := repo.List(t.Context(), "")
	require.NoError(t, err)
	require.Equal(t, []int64{a.ID, b.ID}, streamIDs(all))
	active, err := repo.List(t.Context(), delegation.StatusActive)
	require.NoError(t, err)
	require.Equal(t, []int64{a.ID}, streamIDs(active))

	require.ErrorIs(
		t, repo.AddOrUpdate(t.Context(), &delegation.Stream{ID: b.ID + 1}),
		delegation.ErrStreamNotFound,
	)
}

func TestTemplateDeleteRefusedWhileAStreamReferencesIt(t *testing.T) {
	db := testDelegations(t).db
	st := testStream()
	require.NoError(t, db.Streams().AddOrUpdate(t.Context(), &st))
	require.ErrorIs(t, db.Templates().Delete(t.Context(), "t"), registry.ErrTemplateInUse)
}

func streamIDs(list []delegation.Stream) []int64 {
	ids := make([]int64, 0, len(list))
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	return ids
}
