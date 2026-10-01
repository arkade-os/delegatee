package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
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

// ErrKeyInUse is another process holding the same delegate key.
var ErrKeyInUse = errors.New("another delegateed instance holds this delegate key")

// Repository implements the delegation, template and artifact repositories over one pool.
type Repository struct {
	db      *sql.DB
	querier *queries.Queries
	lockMu  sync.Mutex
	lock    *sql.Conn // holds the advisory lock of lockKey
	lockKey string
}

func NewRepository(ctx context.Context, dsn string) (*Repository, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	// a burst of API calls must not take every connection the server has
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
	return &Repository{db: db, querier: queries.New(db)}, nil
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

func (r *Repository) Close() error {
	r.lockMu.Lock()
	if r.lock != nil {
		_ = r.lock.Close()
	}
	r.lock, r.lockKey = nil, ""
	r.lockMu.Unlock()
	return r.db.Close()
}

// LockKey takes a session lock on key, held until Close.
func (r *Repository) LockKey(ctx context.Context, key string) error {
	r.lockMu.Lock()
	defer r.lockMu.Unlock()
	return r.takeLock(ctx, key)
}

// CheckLock takes the lock again once, on a new connection, when its connection no longer holds it.
func (r *Repository) CheckLock(ctx context.Context) error {
	r.lockMu.Lock()
	defer r.lockMu.Unlock()
	if r.lockKey == "" {
		return nil
	}
	var held bool
	err := r.lock.QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted)").Scan(&held)
	if err == nil && held {
		return nil
	}
	_ = r.lock.Close()
	r.lock = nil
	return r.takeLock(ctx, r.lockKey)
}

// WatchLock runs CheckLock every interval until ctx ends or Close, and returns the error of a lock it could not take again.
func (r *Repository) WatchLock(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.CheckLock(ctx); err != nil {
				return err
			}
			r.lockMu.Lock()
			closed := r.lockKey == ""
			r.lockMu.Unlock()
			if closed {
				return nil
			}
		}
	}
}

func (r *Repository) takeLock(ctx context.Context, key string) error {
	if r.lock == nil {
		conn, err := r.db.Conn(ctx)
		if err != nil {
			return err
		}
		r.lock = conn
	}
	sum := sha256.Sum256([]byte(key))
	var locked bool
	if err := r.lock.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", int64(binary.BigEndian.Uint64(sum[:8]))).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return fmt.Errorf("%w: %s", ErrKeyInUse, key)
	}
	r.lockKey = key
	return nil
}

func (r *Repository) Ping(ctx context.Context) error { return r.db.PingContext(ctx) }

func (r *Repository) Create(ctx context.Context, d domain.Delegation, max int) (*domain.Delegation, error) {
	if d.Variables == nil {
		d.Variables = map[string]string{}
	}
	if d.Slots == nil {
		d.Slots = []domain.SlotBinding{}
	}
	variables, err := json.Marshal(d.Variables)
	if err != nil {
		return nil, err
	}
	slots, err := json.Marshal(d.Slots)
	if err != nil {
		return nil, err
	}
	var expiresAt sql.NullTime
	if d.ExpiresAt != nil {
		expiresAt = sql.NullTime{Time: *d.ExpiresAt, Valid: true}
	}
	row, err := r.querier.InsertDelegation(ctx, queries.InsertDelegationParams{
		Fingerprint: d.Fingerprint, Address: d.Address, TemplateID: d.TemplateID, Variables: variables,
		ParentID: sql.NullInt64{Int64: d.ParentID, Valid: d.ParentID != 0}, ExpiresAt: expiresAt, DelegatePubkey: d.DelegatePubKey, Slots: slots, MaxActive: int32(max),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrCapReached
	}
	if err != nil {
		return nil, err
	}
	return toDelegation(queries.Delegation(row))
}

func (r *Repository) Get(ctx context.Context, address string) (*domain.Delegation, error) {
	if address == "" {
		return nil, domain.ErrDelegationNotFound // advertisements have no address
	}
	return r.one(r.querier.SelectDelegation(ctx, address))
}

func (r *Repository) GetByID(ctx context.Context, id int64) (*domain.Delegation, error) {
	return r.one(r.querier.SelectDelegationByID(ctx, id))
}

func (r *Repository) GetByFingerprint(ctx context.Context, fingerprint string) (*domain.Delegation, error) {
	return r.one(r.querier.SelectLatestDelegationByFingerprint(ctx, fingerprint))
}

func (r *Repository) GetActiveByOutpoint(ctx context.Context, outpoint string) (*domain.Delegation, error) {
	return r.one(r.querier.SelectActiveDelegationByOutpoint(ctx, outpoint))
}

func (r *Repository) one(row queries.Delegation, err error) (*domain.Delegation, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrDelegationNotFound
	}
	if err != nil {
		return nil, err
	}
	return toDelegation(row)
}

func (r *Repository) List(ctx context.Context, status string) ([]domain.Delegation, error) {
	rows, err := r.querier.SelectDelegations(ctx, status)
	if err != nil {
		return nil, err
	}
	return toDelegations(rows)
}

func toDelegations(rows []queries.Delegation) ([]domain.Delegation, error) {
	out := make([]domain.Delegation, len(rows))
	for i, row := range rows {
		d, err := toDelegation(row)
		if err != nil {
			return nil, err
		}
		out[i] = *d
	}
	return out, nil
}

func (r *Repository) ListPage(ctx context.Context, status string, cursor int64, limit int) ([]domain.Delegation, error) {
	rows, err := r.querier.SelectDelegationPage(ctx, queries.SelectDelegationPageParams{Status: status, Cursor: cursor, MaxRows: int32(limit)})
	if err != nil {
		return nil, err
	}
	return toDelegations(rows)
}

func (r *Repository) CountActive(ctx context.Context) (int64, error) {
	return r.querier.CountActiveDelegations(ctx)
}

func (r *Repository) CountDelegationsByTemplate(ctx context.Context) (map[string]int64, error) {
	rows, err := r.querier.CountDelegationsByTemplate(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(rows))
	for _, row := range rows {
		out[row.TemplateID] = row.N
	}
	return out, nil
}

func (r *Repository) SetStatus(ctx context.Context, id int64, status string) error {
	n, err := r.querier.SetDelegationStatus(ctx, queries.SetDelegationStatusParams{ID: id, Status: status})
	if err != nil {
		return err
	}
	if n == 0 {
		_, err := r.GetByID(ctx, id) // stopped already is left as is, unknown is not found
		return err
	}
	return nil
}

func (r *Repository) Resume(ctx context.Context, id int64) error {
	n, err := r.querier.ResumeDelegation(ctx, id)
	if err != nil || n > 0 {
		return err
	}
	if _, err := r.GetByID(ctx, id); err != nil {
		return err
	}
	return domain.ErrNotCancelled
}

func (r *Repository) Expire(ctx context.Context, before time.Time) (int64, error) {
	return r.querier.ExpireDelegations(ctx, sql.NullTime{Time: before, Valid: true})
}

func (r *Repository) CreateArtifact(ctx context.Context, id string, document []byte, max int) (*domain.Artifact, error) {
	row, err := r.querier.UpsertArtifact(ctx, queries.UpsertArtifactParams{ID: id, Document: document, MaxCount: int32(max)})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrCapReached
	}
	if err != nil {
		return nil, err
	}
	return toArtifact(queries.Artifact(row)), nil
}

func (r *Repository) GetArtifact(ctx context.Context, id string) (*domain.Artifact, error) {
	row, err := r.querier.SelectArtifact(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrArtifactNotFound
	}
	if err != nil {
		return nil, err
	}
	return toArtifact(row), nil
}

func (r *Repository) ListArtifacts(ctx context.Context) ([]domain.Artifact, error) {
	rows, err := r.querier.SelectArtifactSummaries(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Artifact, len(rows))
	for i, row := range rows {
		out[i] = domain.Artifact{ID: row.ID, CreatedAt: row.CreatedAt}
	}
	return out, nil
}

func (r *Repository) DeleteArtifact(ctx context.Context, id string) error {
	if used, err := r.querier.ArtifactReferenced(ctx, id); err != nil {
		return err
	} else if used {
		return domain.ErrArtifactInUse
	}
	n, err := r.querier.DeleteArtifact(ctx, id)
	return oneRow(n, err, domain.ErrArtifactNotFound)
}

func (r *Repository) CreateTemplate(ctx context.Context, t domain.Template, max int) (*domain.Template, error) {
	if t.Params == nil {
		t.Params = []domain.Param{}
	}
	params, err := json.Marshal(t.Params)
	if err != nil {
		return nil, err
	}
	artifactIDs := t.ArtifactIDs
	if artifactIDs == nil {
		artifactIDs = []string{}
	}
	row, err := r.querier.UpsertTemplate(ctx, queries.UpsertTemplateParams{
		ID: t.ID, Document: t.Document, ArtifactIds: artifactIDs, Params: params, MaxCount: int32(max),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrCapReached
	}
	if err != nil {
		return nil, err
	}
	return toTemplate(queries.Template(row))
}

func (r *Repository) GetTemplate(ctx context.Context, id string) (*domain.Template, error) {
	row, err := r.querier.SelectTemplate(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrTemplateNotFound
	}
	if err != nil {
		return nil, err
	}
	return toTemplate(row)
}

func (r *Repository) ListTemplates(ctx context.Context, status string) ([]domain.Template, error) {
	rows, err := r.querier.SelectTemplateSummaries(ctx, status)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Template, len(rows))
	for i, row := range rows {
		t, err := toTemplate(queries.Template{
			ID: row.ID, ArtifactIds: row.ArtifactIds, Params: row.Params, Status: row.Status,
			Failures: row.Failures, Trusted: row.Trusted, CreatedAt: row.CreatedAt,
		})
		if err != nil {
			return nil, err
		}
		out[i] = *t
	}
	return out, nil
}

func (r *Repository) SetTemplateStatus(ctx context.Context, id, status string) error {
	n, err := r.querier.SetTemplateStatus(ctx, queries.SetTemplateStatusParams{ID: id, Status: status})
	return oneRow(n, err, domain.ErrTemplateNotFound)
}

func (r *Repository) SetTemplateTrusted(ctx context.Context, id string, trusted bool) error {
	n, err := r.querier.SetTemplateTrusted(ctx, queries.SetTemplateTrustedParams{ID: id, Trusted: trusted})
	return oneRow(n, err, domain.ErrTemplateNotFound)
}

func (r *Repository) DeleteTemplate(ctx context.Context, id string) error {
	if used, err := r.querier.TemplateReferenced(ctx, id); err != nil {
		return err
	} else if used {
		return domain.ErrTemplateInUse
	}
	n, err := r.querier.DeleteTemplate(ctx, id)
	return oneRow(n, err, domain.ErrTemplateNotFound)
}

func (r *Repository) RecordTemplateOutcome(ctx context.Context, id string, success bool, maxFailures int) (int, string, error) {
	row, err := r.querier.RecordTemplateOutcome(ctx, queries.RecordTemplateOutcomeParams{
		ID: id, Success: success, MaxFailures: int32(maxFailures),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", domain.ErrTemplateNotFound
	}
	if err != nil {
		return 0, "", err
	}
	return int(row.Failures), row.Status, nil
}

func (r *Repository) RecordRenewal(ctx context.Context, ren domain.Renewal) error {
	return r.querier.InsertRenewal(ctx, queries.InsertRenewalParams{
		DelegationID:   ren.DelegationID,
		Outpoints:      ren.Outpoints,
		CommitmentTxid: ren.CommitmentTxid,
		Success:        ren.Success,
		Error:          ren.Error,
	})
}

func (r *Repository) PruneRenewals(ctx context.Context, before time.Time) error {
	return r.querier.DeleteRenewalsBefore(ctx, before)
}

func (r *Repository) ListRenewals(ctx context.Context, delegationID int64, limit int) ([]domain.Renewal, error) {
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

func (r *Repository) LastRenewals(ctx context.Context) (map[int64]domain.Renewal, error) {
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

func (r *Repository) SaveSettlement(ctx context.Context, s domain.Settlement) error {
	outpoints, err := json.Marshal(s.Outpoints)
	if err != nil {
		return err
	}
	return r.querier.UpsertSettlement(ctx, queries.UpsertSettlementParams{
		Txid: s.Txid, SpentBy: s.SpentBy, DelegationID: s.DelegationID, Tx: s.Tx, Outpoints: outpoints,
		Sources: s.Sources, Coins: append([]string{}, s.Coins...), Checkpoints: append([]string{}, s.Checkpoints...),
		Finals: append([]string{}, s.Finals...), Landed: s.Landed,
	})
}

func (r *Repository) ListSettlements(ctx context.Context) ([]domain.Settlement, error) {
	rows, err := r.querier.SelectSettlements(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Settlement, len(rows))
	for i, row := range rows {
		out[i] = domain.Settlement{
			Txid: row.Txid, SpentBy: row.SpentBy, DelegationID: row.DelegationID, Tx: row.Tx,
			Sources: row.Sources, Coins: row.Coins, Checkpoints: row.Checkpoints, Finals: row.Finals, Landed: row.Landed, CreatedAt: row.CreatedAt,
		}
		if err := json.Unmarshal(row.Outpoints, &out[i].Outpoints); err != nil {
			return nil, fmt.Errorf("settlement %s outpoints: %w", row.Txid, err)
		}
	}
	return out, nil
}

func (r *Repository) DeleteSettlement(ctx context.Context, txid, spentBy string) error {
	return r.querier.DeleteSettlement(ctx, queries.DeleteSettlementParams{Txid: txid, SpentBy: spentBy})
}

// oneRow is notFound when a statement matched no row.
func oneRow(n int64, err, notFound error) error {
	if err == nil && n == 0 {
		return notFound
	}
	return err
}

func toArtifact(row queries.Artifact) *domain.Artifact {
	return &domain.Artifact{ID: row.ID, Document: row.Document, CreatedAt: row.CreatedAt}
}

func toRenewal(row queries.Renewal) domain.Renewal {
	return domain.Renewal{
		DelegationID:   row.DelegationID,
		Outpoints:      row.Outpoints,
		CommitmentTxid: row.CommitmentTxid,
		Success:        row.Success,
		Error:          row.Error,
		AttemptedAt:    row.AttemptedAt,
	}
}

func toTemplate(row queries.Template) (*domain.Template, error) {
	var params []domain.Param
	if err := json.Unmarshal(row.Params, &params); err != nil {
		return nil, fmt.Errorf("template %s params: %w", row.ID, err)
	}
	return &domain.Template{
		ID: row.ID, Document: row.Document, ArtifactIDs: row.ArtifactIds, Params: params,
		Status: row.Status, Failures: int(row.Failures), Trusted: row.Trusted, CreatedAt: row.CreatedAt,
	}, nil
}

func toDelegation(row queries.Delegation) (*domain.Delegation, error) {
	var variables map[string]string
	if err := json.Unmarshal(row.Variables, &variables); err != nil {
		return nil, fmt.Errorf("delegation %d variables: %w", row.ID, err)
	}
	var slots []domain.SlotBinding
	if err := json.Unmarshal(row.Slots, &slots); err != nil {
		return nil, fmt.Errorf("delegation %d slots: %w", row.ID, err)
	}
	d := &domain.Delegation{
		ID: row.ID, Fingerprint: row.Fingerprint, Address: row.Address, TemplateID: row.TemplateID,
		Variables: variables, ParentID: row.ParentID.Int64, DelegatePubKey: row.DelegatePubkey, Slots: slots,
		Status: row.Status, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
	if row.ExpiresAt.Valid {
		d.ExpiresAt = &row.ExpiresAt.Time
	}
	return d, nil
}
