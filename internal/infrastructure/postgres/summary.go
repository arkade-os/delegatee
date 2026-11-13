package postgres

import (
	"context"
	"time"

	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/internal/core/ports"
	"github.com/arkade-os/executor/internal/infrastructure/postgres/sqlc/queries"
)

type SummaryRepository struct{ db *DB }

func (d *DB) Summaries() *SummaryRepository { return &SummaryRepository{db: d} }

func (r *SummaryRepository) List(
	ctx context.Context, f ports.SummaryFilter,
) ([]ports.Summary, error) {
	params := queries.ListDelegationSummariesParams{
		Status: f.Status, StreamID: f.StreamID, TemplateID: f.TemplateID, MaxCount: int32(f.Limit),
		AfterDue: time.Unix(0, 0), AfterID: f.After.ID,
	}
	switch {
	case f.After.ID == 0:
	case f.After.NextDue.IsZero():
		params.SkipHeld, params.IdleAfter = true, f.After.ID
	default:
		params.AfterDue = f.After.NextDue
	}
	rows, err := r.db.querier.ListDelegationSummaries(ctx, params)
	if err != nil {
		return nil, err
	}
	out := make([]ports.Summary, 0, len(rows))
	for _, row := range rows {
		d, err := toDelegation(queries.Delegation{
			ID: row.ID, Fingerprint: row.Fingerprint, Address: row.Address,
			TemplateID: row.TemplateID, Variables: row.Variables, Inputs: row.Inputs,
			StreamID: row.StreamID, ExpiresAt: row.ExpiresAt, Status: row.Status,
			CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		})
		if err != nil {
			return nil, err
		}
		s := ports.Summary{
			Delegation: *d, Coins: int(row.Coins), Amount: uint64(row.Amount),
			LastAttempt: delegation.AttemptStatus(row.LastAttempt),
		}
		if row.Coins > 0 {
			s.NextDue = row.NextDue.UTC()
		}
		out = append(out, s)
	}
	return out, nil
}

func (r *SummaryRepository) Spawned(ctx context.Context) (map[int64]ports.Spawned, error) {
	rows, err := r.db.querier.ListSpawned(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]ports.Spawned, len(rows))
	for _, row := range rows {
		out[row.StreamID] = ports.Spawned{
			Delegations: int(row.Spawned), Active: int(row.Active), Last: row.LastAt.UTC(),
		}
	}
	return out, nil
}
