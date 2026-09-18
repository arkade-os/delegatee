package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/internal/infrastructure/db/postgres/sqlc/queries"
	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/lib/pq"
)

//go:embed migration/*.sql
var migrations embed.FS

type repository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewRepository(ctx context.Context, dsn string) (domain.DelegationRepository, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	// the service runs a handful of queries at a time: don't let a burst of
	// API calls take every connection the server has
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	db.SetConnMaxIdleTime(5 * time.Minute)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}
	if err := migrateUp(db); err != nil {
		return nil, err
	}
	return &repository{db: db, querier: queries.New(db)}, nil
}

func migrateUp(db *sql.DB) error {
	source, err := iofs.New(migrations, "migration")
	if err != nil {
		return err
	}
	driver, err := migratepg.WithInstance(db, &migratepg.Config{})
	if err != nil {
		return err
	}
	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migration failed: %w", err)
	}
	return nil
}

func (r *repository) Close() error                   { return r.db.Close() }
func (r *repository) Ping(ctx context.Context) error { return r.db.PingContext(ctx) }

func (r *repository) Create(
	ctx context.Context, address string, tapscripts []string, params domain.Params,
) (*domain.Delegation, error) {
	row, err := r.querier.UpsertDelegation(ctx, queries.UpsertDelegationParams{
		Address: address, Tapscripts: tapscripts,
		RenewalWindow: params.RenewalWindow, MaxFee: params.MaxFee,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrDelegationAlreadyExists
	}
	if err != nil {
		return nil, err
	}
	return toDelegation(row), nil
}

func (r *repository) Get(ctx context.Context, address string) (*domain.Delegation, error) {
	row, err := r.querier.SelectDelegation(ctx, address)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrDelegationNotFound
	}
	if err != nil {
		return nil, err
	}
	return toDelegation(row), nil
}

func (r *repository) List(ctx context.Context, status string) ([]domain.Delegation, error) {
	rows, err := r.querier.SelectDelegations(ctx, status)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Delegation, len(rows))
	for i, row := range rows {
		out[i] = *toDelegation(row)
	}
	return out, nil
}

func (r *repository) CountActive(ctx context.Context) (int64, error) {
	return r.querier.CountActiveDelegations(ctx)
}

func (r *repository) Cancel(ctx context.Context, address, status string) error {
	n, err := r.querier.CancelDelegation(ctx, queries.CancelDelegationParams{Address: address, Status: status})
	if err != nil {
		return err
	}
	if n == 0 {
		return domain.ErrDelegationNotFound
	}
	return nil
}

func (r *repository) RecordRenewal(ctx context.Context, ren domain.Renewal) error {
	return r.querier.InsertRenewal(ctx, queries.InsertRenewalParams{
		DelegationID:   ren.DelegationID,
		Outpoints:      ren.Outpoints,
		CommitmentTxid: ren.CommitmentTxid,
		Success:        ren.Success,
		Error:          ren.Error,
	})
}

func (r *repository) PruneRenewals(ctx context.Context, before time.Time) error {
	return r.querier.DeleteRenewalsBefore(ctx, before)
}

func (r *repository) ListRenewals(ctx context.Context, delegationID int64, limit int) ([]domain.Renewal, error) {
	rows, err := r.querier.SelectRenewals(ctx, queries.SelectRenewalsParams{
		DelegationID: delegationID, MaxRows: int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Renewal, len(rows))
	for i, row := range rows {
		out[i] = toRenewal(row)
	}
	return out, nil
}

func (r *repository) LastRenewals(ctx context.Context) (map[int64]domain.Renewal, error) {
	rows, err := r.querier.SelectLastRenewals(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]domain.Renewal, len(rows))
	for _, row := range rows {
		out[row.DelegationID] = toRenewal(row)
	}
	return out, nil
}

func toRenewal(row queries.Renewal) domain.Renewal {
	return domain.Renewal{
		ID:             row.ID,
		DelegationID:   row.DelegationID,
		Outpoints:      row.Outpoints,
		CommitmentTxid: row.CommitmentTxid,
		Success:        row.Success,
		Error:          row.Error,
		AttemptedAt:    row.AttemptedAt,
	}
}

func toDelegation(row queries.Delegation) *domain.Delegation {
	return &domain.Delegation{
		ID:         row.ID,
		Address:    row.Address,
		Tapscripts: row.Tapscripts,
		Params:     domain.Params{RenewalWindow: row.RenewalWindow, MaxFee: row.MaxFee},
		Status:     row.Status,
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
	}
}
