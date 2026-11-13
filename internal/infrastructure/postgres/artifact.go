package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/arkade-os/executor/internal/core/domain/registry"
	"github.com/arkade-os/executor/internal/infrastructure/postgres/sqlc/queries"
)

type ArtifactRepository struct{ db *DB }

func (d *DB) Artifacts() *ArtifactRepository { return &ArtifactRepository{db: d} }

func (r *ArtifactRepository) Add(ctx context.Context, a *registry.Artifact) error {
	row, err := r.db.querier.InsertArtifact(
		ctx, queries.InsertArtifactParams{ID: a.ID, Document: a.Document},
	)
	if err != nil {
		return err
	}
	a.CreatedAt = row.CreatedAt
	return nil
}

func (r *ArtifactRepository) Count(ctx context.Context) (int64, error) {
	return r.db.querier.CountArtifacts(ctx)
}

func (r *ArtifactRepository) Get(ctx context.Context, id string) (*registry.Artifact, error) {
	row, err := r.db.querier.SelectArtifact(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, registry.ErrArtifactNotFound
	}
	if err != nil {
		return nil, err
	}
	return &registry.Artifact{ID: row.ID, Document: row.Document, CreatedAt: row.CreatedAt}, nil
}

func (r *ArtifactRepository) List(ctx context.Context) ([]registry.Artifact, error) {
	rows, err := r.db.querier.ListArtifacts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]registry.Artifact, 0, len(rows))
	for _, row := range rows {
		out = append(out, registry.Artifact{ID: row.ID, CreatedAt: row.CreatedAt})
	}
	return out, nil
}

func (r *ArtifactRepository) Delete(ctx context.Context, id string) error {
	inUse, err := r.db.querier.DeleteArtifact(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return registry.ErrArtifactNotFound
	}
	if err != nil {
		return err
	}
	if inUse {
		return registry.ErrArtifactInUse
	}
	return nil
}
