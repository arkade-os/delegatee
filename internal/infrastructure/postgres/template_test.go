package postgres

import (
	"testing"

	"github.com/arkade-os/delegatee/internal/core/domain/registry"
	"github.com/stretchr/testify/require"
)

func TestTemplateAddOrUpdate(t *testing.T) {
	repo := testDB(t).Templates()
	tpl := testTemplate("a")
	require.NoError(t, repo.AddOrUpdate(t.Context(), &tpl))
	require.False(t, tpl.CreatedAt.IsZero())
	got, err := repo.Get(t.Context(), "a")
	require.NoError(t, err)
	require.Equal(t, &tpl, got)

	tpl.Status, tpl.Failures = registry.TemplateStatusDisabled, 2
	tpl.Document = []byte("ignored")
	require.NoError(t, repo.AddOrUpdate(t.Context(), &tpl))
	got, err = repo.Get(t.Context(), "a")
	require.NoError(t, err)
	require.Equal(t, registry.TemplateStatusDisabled, got.Status)
	require.Equal(t, 2, got.Failures)
	require.Equal(t, testTemplate("a").Document, got.Document, "a template's document never changes")

	n, err := repo.Count(t.Context())
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
}

func TestTemplateAddWithoutArtifacts(t *testing.T) {
	repo := testDB(t).Templates()
	tpl := testTemplate("a")
	tpl.ArtifactIDs = nil
	require.NoError(t, repo.AddOrUpdate(t.Context(), &tpl))
	got, err := repo.Get(t.Context(), "a")
	require.NoError(t, err)
	require.Empty(t, got.ArtifactIDs)
}

func TestTemplateList(t *testing.T) {
	repo := testDB(t).Templates()
	for _, id := range []string{"a", "b", "c"} {
		tpl := testTemplate(id)
		require.NoError(t, repo.AddOrUpdate(t.Context(), &tpl))
	}
	_, err := repo.db.db.ExecContext(t.Context(), "UPDATE templates SET status = 'disabled' WHERE id = 'b'")
	require.NoError(t, err)

	active, err := repo.List(t.Context(), registry.TemplateStatusActive)
	require.NoError(t, err)
	require.Len(t, active, 2)
	for _, tpl := range active {
		require.Nil(t, tpl.Document)
		require.Equal(t, registry.TemplateStatusActive, tpl.Status)
		require.Equal(t, testTemplate(tpl.ID).Params, tpl.Params)
	}
	require.False(t, active[0].CreatedAt.Before(active[1].CreatedAt))

	all, err := repo.List(t.Context(), "")
	require.NoError(t, err)
	require.Len(t, all, 3)

	none, err := repo.List(t.Context(), registry.TemplateStatusDisabled)
	require.NoError(t, err)
	require.Len(t, none, 1)
	require.Equal(t, "b", none[0].ID)
}

func TestTemplateDelete(t *testing.T) {
	repo := testDB(t).Templates()
	tpl := testTemplate("a")
	require.NoError(t, repo.AddOrUpdate(t.Context(), &tpl))
	require.NoError(t, repo.Delete(t.Context(), "a"))
	require.Equal(t, 0, templateCount(t, repo))
	require.ErrorIs(t, repo.Delete(t.Context(), "a"), registry.ErrTemplateNotFound)
}

func TestTemplateDeleteRefusedWhileReferenced(t *testing.T) {
	db := testDB(t)
	repo := db.Templates()
	tpl := testTemplate("t")
	require.NoError(t, repo.AddOrUpdate(t.Context(), &tpl))
	created := testDelegation("a")
	require.NoError(t, db.Delegations().AddOrUpdate(t.Context(), &created))
	require.NoError(t, created.Cancel())
	require.NoError(t, db.Delegations().AddOrUpdate(t.Context(), &created))

	require.ErrorIs(t, repo.Delete(t.Context(), "t"), registry.ErrTemplateInUse)
	require.Equal(t, 1, templateCount(t, repo))
}

func TestTemplateGetNotFound(t *testing.T) {
	_, err := testDB(t).Templates().Get(t.Context(), "missing")
	require.ErrorIs(t, err, registry.ErrTemplateNotFound)
}

func testTemplate(id string) registry.Template {
	return registry.Template{
		ID: id, Document: []byte("doc " + id), ArtifactIDs: []string{"x"},
		Params: []registry.Param{{Name: "owner", Type: "pubkey"}}, Type: "intent", Status: registry.TemplateStatusActive,
	}
}

func templateCount(t *testing.T, repo *TemplateRepository) int {
	t.Helper()
	var n int
	require.NoError(t, repo.db.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM templates").Scan(&n))
	return n
}
