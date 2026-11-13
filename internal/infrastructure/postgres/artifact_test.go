package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/arkade-os/executor/internal/core/domain/registry"
	"github.com/stretchr/testify/require"
)

func TestArtifactAddThenGet(t *testing.T) {
	repo := testDB(t).Artifacts()
	a := registry.Artifact{ID: "a", Document: []byte("one")}
	require.NoError(t, repo.Add(t.Context(), &a))
	require.False(t, a.CreatedAt.IsZero())
	again := registry.Artifact{ID: "a", Document: []byte("other")}
	require.Error(t, repo.Add(t.Context(), &again))

	got, err := repo.Get(t.Context(), "a")
	require.NoError(t, err)
	require.Equal(t, &a, got)
	n, err := repo.Count(t.Context())
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
}

func TestArtifactListOmitsDocumentsNewestFirst(t *testing.T) {
	repo := testDB(t).Artifacts()
	for _, id := range []string{"a", "b"} {
		require.NoError(t, repo.Add(t.Context(), &registry.Artifact{ID: id, Document: []byte(id)}))
	}
	list, err := repo.List(t.Context())
	require.NoError(t, err)
	require.Len(t, list, 2)
	for _, a := range list {
		require.Nil(t, a.Document)
		require.False(t, a.CreatedAt.IsZero())
	}
	require.False(t, list[0].CreatedAt.Before(list[1].CreatedAt))
}

func TestArtifactDelete(t *testing.T) {
	db := testDB(t)
	repo := db.Artifacts()
	require.NoError(t, repo.Add(t.Context(), &registry.Artifact{ID: "a", Document: []byte("a")}))
	tpl := testTemplate("t")
	tpl.ArtifactIDs = []string{"other", "a"}
	require.NoError(t, db.Templates().AddOrUpdate(t.Context(), &tpl))

	require.ErrorIs(t, repo.Delete(t.Context(), "a"), registry.ErrArtifactInUse)
	require.Equal(t, 1, count(t, repo))

	require.NoError(t, db.Templates().Delete(t.Context(), "t"))
	require.NoError(t, repo.Delete(t.Context(), "a"))
	require.Equal(t, 0, count(t, repo))
	require.ErrorIs(t, repo.Delete(t.Context(), "a"), registry.ErrArtifactNotFound)
}

func TestArtifactGetNotFound(t *testing.T) {
	_, err := testDB(t).Artifacts().Get(t.Context(), "missing")
	require.ErrorIs(t, err, registry.ErrArtifactNotFound)
}

func TestOpenErrors(t *testing.T) {
	_, err := Open(
		t.Context(),
		"postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1",
	)
	require.Error(t, err)
}

// testDB opens the database at EXECUTOR_DATABASE_URL on a fresh public schema.
func testDB(t *testing.T) *DB {
	t.Helper()
	dsn := testDSN()
	raw, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	_, err = raw.ExecContext(t.Context(), "DROP SCHEMA public CASCADE; CREATE SCHEMA public")
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	db, err := Open(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func count(t *testing.T, repo *ArtifactRepository) int {
	t.Helper()
	var n int
	require.NoError(
		t, repo.db.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM artifacts").Scan(&n),
	)
	return n
}

func testDSN() string {
	if dsn := os.Getenv("EXECUTOR_DATABASE_URL"); dsn != "" {
		return dsn
	}
	return "postgres://postgres@localhost:5432/executor?sslmode=disable"
}
