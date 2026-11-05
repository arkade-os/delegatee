package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/internal/infrastructure/postgres/sqlc/queries"
)

type StreamRepository struct{ db *DB }

func (d *DB) Streams() *StreamRepository { return &StreamRepository{db: d} }

func (r *StreamRepository) AddOrUpdate(ctx context.Context, s *delegation.Stream) error {
	if s.ID != 0 {
		n, err := r.db.querier.UpdateStreamStatus(ctx, queries.UpdateStreamStatusParams{ID: s.ID, Status: s.Status})
		if err != nil {
			return err
		}
		if n == 0 {
			return delegation.ErrStreamNotFound
		}
		return nil
	}
	if s.Variables == nil {
		s.Variables = map[string]string{}
	}
	variables, err := json.Marshal(s.Variables)
	if err != nil {
		return err
	}
	row, err := r.db.querier.InsertStream(ctx, queries.InsertStreamParams{
		TemplateID: s.TemplateID, Variables: variables,
	})
	if err != nil {
		return err
	}
	stored, err := toStream(queries.Stream(row))
	if err != nil {
		return err
	}
	*s = *stored
	return nil
}

func (r *StreamRepository) Get(ctx context.Context, id int64) (*delegation.Stream, error) {
	row, err := r.db.querier.SelectStream(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, delegation.ErrStreamNotFound
	}
	if err != nil {
		return nil, err
	}
	return toStream(row)
}

func (r *StreamRepository) List(ctx context.Context, status string) ([]delegation.Stream, error) {
	rows, err := r.db.querier.ListStreams(ctx, status)
	if err != nil {
		return nil, err
	}
	out := make([]delegation.Stream, 0, len(rows))
	for _, row := range rows {
		s, err := toStream(row)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, nil
}

func toStream(row queries.Stream) (*delegation.Stream, error) {
	s := delegation.Stream{
		ID: row.ID, TemplateID: row.TemplateID, Status: row.Status, CreatedAt: row.CreatedAt,
	}
	if err := json.Unmarshal(row.Variables, &s.Variables); err != nil {
		return nil, err
	}
	return &s, nil
}
