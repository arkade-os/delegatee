package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/arkade-os/delegatee/internal/infrastructure/postgres/sqlc/queries"
	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/lib/pq"
)

//go:embed migration/*.sql
var migrations embed.FS

// DB is the pool every repository works over, migrated on Open.
type DB struct {
	db      *sql.DB
	querier *queries.Queries
}

func Open(ctx context.Context, dsn string) (*DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	db.SetConnMaxIdleTime(5 * time.Minute)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	if err := migrateUp(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &DB{db: db, querier: queries.New(db)}, nil
}

func (d *DB) Close() error { return d.db.Close() }

func (d *DB) Ping(ctx context.Context) error { return d.db.PingContext(ctx) }

func (d *DB) inTx(ctx context.Context, fn func(*queries.Queries) error) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(d.querier.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit()
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
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}
