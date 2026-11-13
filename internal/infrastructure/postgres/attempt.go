package postgres

import (
	"context"
	"encoding/json"

	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/internal/infrastructure/postgres/sqlc/queries"
)

type AttemptRepository struct{ db *DB }

func (d *DB) Attempts() *AttemptRepository { return &AttemptRepository{db: d} }

func (r *AttemptRepository) AddOrUpdate(ctx context.Context, a *delegation.Attempt) error {
	txs, err := json.Marshal(orEmpty(a.Txs))
	if err != nil {
		return err
	}
	if a.ID == 0 {
		row, err := r.db.querier.InsertAttempt(ctx, queries.InsertAttemptParams{
			DelegationID: a.DelegationID, Coins: a.Coins, Txs: txs,
			Status: string(a.Status), Error: a.Error,
		})
		if err != nil {
			return err
		}
		*a, err = toAttempt(row)
		return err
	}
	n, err := r.db.querier.UpdateAttempt(ctx, queries.UpdateAttemptParams{
		ID: a.ID, Txs: txs, Status: string(a.Status), Error: a.Error,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return delegation.ErrAttemptNotFound
	}
	return nil
}

func (r *AttemptRepository) ListPending(ctx context.Context) ([]delegation.Attempt, error) {
	rows, err := r.db.querier.ListPendingAttempts(ctx)
	if err != nil {
		return nil, err
	}
	return toAttempts(rows)
}

func (r *AttemptRepository) ListByDelegation(
	ctx context.Context, id, cursor int64, limit int,
) ([]delegation.Attempt, error) {
	rows, err := r.db.querier.ListAttemptsByDelegation(ctx, queries.ListAttemptsByDelegationParams{
		DelegationID: id, Cursor: cursor, MaxCount: int32(limit),
	})
	if err != nil {
		return nil, err
	}
	return toAttempts(rows)
}

func toAttempts(rows []queries.Attempt) ([]delegation.Attempt, error) {
	out := make([]delegation.Attempt, 0, len(rows))
	for _, row := range rows {
		a, err := toAttempt(row)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func toAttempt(row queries.Attempt) (delegation.Attempt, error) {
	a := delegation.Attempt{
		ID: row.ID, DelegationID: row.DelegationID, Coins: row.Coins,
		Status: delegation.AttemptStatus(row.Status), Error: row.Error,
		CreatedAt: row.CreatedAt.UTC(), UpdatedAt: row.UpdatedAt.UTC(),
	}
	err := json.Unmarshal(row.Txs, &a.Txs)
	return a, err
}

// orEmpty: pq sends a nil slice as NULL.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
