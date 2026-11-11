package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/internal/infrastructure/postgres/sqlc/queries"
)

type DelegationRepository struct{ db *DB }

func (d *DB) Delegations() *DelegationRepository { return &DelegationRepository{db: d} }

func (r *DelegationRepository) AddOrUpdate(ctx context.Context, d *delegation.Delegation) error {
	if d.ID != 0 {
		n, err := r.db.querier.UpdateDelegationStatus(ctx, queries.UpdateDelegationStatusParams{ID: d.ID, Status: d.Status})
		if err != nil {
			return err
		}
		if n == 0 {
			return delegation.ErrDelegationNotFound
		}
		return nil
	}
	if d.Variables == nil {
		d.Variables = map[string]string{}
	}
	if d.Inputs == nil {
		d.Inputs = []delegation.Input{}
	}
	variables, err := json.Marshal(d.Variables)
	if err != nil {
		return err
	}
	inputs, err := json.Marshal(d.Inputs)
	if err != nil {
		return err
	}
	var expiresAt sql.NullTime
	if d.ExpiresAt != nil {
		expiresAt = sql.NullTime{Time: *d.ExpiresAt, Valid: true}
	}
	return r.db.inTx(ctx, func(q *queries.Queries) error {
		row, err := q.InsertDelegation(ctx, queries.InsertDelegationParams{
			Fingerprint: d.Fingerprint, Address: d.Address, TemplateID: d.TemplateID, Variables: variables, Inputs: inputs,
			StreamID:  sql.NullInt64{Int64: d.StreamID, Valid: d.StreamID != 0},
			ExpiresAt: expiresAt,
		})
		if err != nil {
			return err
		}
		for i, in := range d.Inputs {
			if in.Script == "" {
				continue
			}
			err := q.InsertClaim(ctx, queries.InsertClaimParams{
				DelegationID: row.ID, Input: int32(i), Script: in.Script, Onchain: in.Onchain, Locktime: int64(in.Locktime),
			})
			if err != nil {
				return err
			}
		}
		stored, err := toDelegation(row)
		if err != nil {
			return err
		}
		*d = *stored
		return nil
	})
}

func (r *DelegationRepository) Get(ctx context.Context, id int64) (*delegation.Delegation, error) {
	return r.one(r.db.querier.SelectDelegation(ctx, id))
}

func (r *DelegationRepository) GetByAddress(ctx context.Context, address string) (*delegation.Delegation, error) {
	return r.one(r.db.querier.SelectDelegationByAddress(ctx, address))
}

func (r *DelegationRepository) GetByFingerprint(ctx context.Context, fingerprint string) (*delegation.Delegation, error) {
	return r.one(r.db.querier.SelectDelegationByFingerprint(ctx, fingerprint))
}

func (r *DelegationRepository) Expire(ctx context.Context, before time.Time) ([]delegation.Delegation, error) {
	rows, err := r.db.querier.ExpireDelegations(ctx, before)
	if err != nil {
		return nil, err
	}
	return toDelegations(rows)
}

func (r *DelegationRepository) List(ctx context.Context, f delegation.ListFilter) ([]delegation.Delegation, error) {
	rows, err := r.db.querier.ListDelegations(ctx, queries.ListDelegationsParams{
		Status: f.Status, Cursor: f.Cursor, MaxCount: int32(f.Limit),
	})
	if err != nil {
		return nil, err
	}
	return toDelegations(rows)
}

func (r *DelegationRepository) Prune(ctx context.Context, before time.Time) (int64, error) {
	return r.db.querier.PruneDelegations(ctx, before)
}

func toDelegations(rows []queries.Delegation) ([]delegation.Delegation, error) {
	out := make([]delegation.Delegation, 0, len(rows))
	for _, row := range rows {
		d, err := toDelegation(row)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, nil
}

func (r *DelegationRepository) CountActive(ctx context.Context) (clients, spawned int64, err error) {
	row, err := r.db.querier.CountActiveDelegations(ctx)
	return row.Clients, row.Spawned, err
}

func (r *DelegationRepository) one(row queries.Delegation, err error) (*delegation.Delegation, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return nil, delegation.ErrDelegationNotFound
	}
	if err != nil {
		return nil, err
	}
	return toDelegation(row)
}

func toDelegation(row queries.Delegation) (*delegation.Delegation, error) {
	d := delegation.Delegation{
		ID: row.ID, Fingerprint: row.Fingerprint, Address: row.Address, TemplateID: row.TemplateID,
		StreamID: row.StreamID.Int64, Status: row.Status, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
	if row.ExpiresAt.Valid {
		at := row.ExpiresAt.Time
		d.ExpiresAt = &at
	}
	if err := json.Unmarshal(row.Variables, &d.Variables); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(row.Inputs, &d.Inputs); err != nil {
		return nil, err
	}
	return &d, nil
}
