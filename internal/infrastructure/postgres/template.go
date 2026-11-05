package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/arkade-os/delegatee/internal/core/domain/registry"
	"github.com/arkade-os/delegatee/internal/infrastructure/postgres/sqlc/queries"
	"github.com/arkade-os/delegatee/pkg/template"
)

type TemplateRepository struct{ db *DB }

func (d *DB) Templates() *TemplateRepository { return &TemplateRepository{db: d} }

func (r *TemplateRepository) AddOrUpdate(ctx context.Context, t *registry.Template) error {
	params, err := json.Marshal(t.Params)
	if err != nil {
		return err
	}
	row, err := r.db.querier.UpsertTemplate(ctx, queries.UpsertTemplateParams{
		ID: t.ID, Document: t.Document, ArtifactIds: orEmpty(t.ArtifactIDs), Params: params, Type: string(t.Type),
		Status: t.Status, Failures: int32(t.Failures),
	})
	if err != nil {
		return err
	}
	t.CreatedAt = row.CreatedAt
	return nil
}

func (r *TemplateRepository) Count(ctx context.Context) (int64, error) {
	return r.db.querier.CountTemplates(ctx)
}

func (r *TemplateRepository) Get(ctx context.Context, id string) (*registry.Template, error) {
	row, err := r.db.querier.SelectTemplate(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, registry.ErrTemplateNotFound
	}
	if err != nil {
		return nil, err
	}
	return toTemplate(row)
}

func (r *TemplateRepository) List(ctx context.Context, status string) ([]registry.Template, error) {
	rows, err := r.db.querier.ListTemplates(ctx, status)
	if err != nil {
		return nil, err
	}
	out := make([]registry.Template, 0, len(rows))
	for _, row := range rows {
		t, err := toTemplate(queries.Template{
			ID: row.ID, ArtifactIds: row.ArtifactIds, Params: row.Params, Type: row.Type,
			Status: row.Status, Failures: row.Failures, CreatedAt: row.CreatedAt,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, nil
}

func toTemplate(row queries.Template) (*registry.Template, error) {
	t := registry.Template{
		ID: row.ID, Document: row.Document, ArtifactIDs: row.ArtifactIds, Type: template.Type(row.Type),
		Status: row.Status, Failures: int(row.Failures), CreatedAt: row.CreatedAt,
	}
	if err := json.Unmarshal(row.Params, &t.Params); err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *TemplateRepository) Delete(ctx context.Context, id string) error {
	inUse, err := r.db.querier.DeleteTemplate(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return registry.ErrTemplateNotFound
	}
	if err != nil {
		return err
	}
	if inUse {
		return registry.ErrTemplateInUse
	}
	return nil
}
