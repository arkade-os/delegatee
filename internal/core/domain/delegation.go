package domain

import (
	"context"
	"errors"
	"time"
)

var (
	ErrDelegationNotFound      = errors.New("delegation not found")
	ErrDelegationAlreadyExists = errors.New("address already registered")
	ErrRevocationAlreadyUsed   = errors.New("revocation timestamp already used")
)

// A delegation is active, or stopped by the operator (cancelled) or by its
// owner (revoked). Registering it again makes it active.
const (
	DelegationStatusActive    = "active"
	DelegationStatusCancelled = "cancelled"
	DelegationStatusRevoked   = "revoked"
)

// Params are the user's choices baked into the covenant, so they are part
// of the address.
type Params struct {
	// RenewalWindow is how many seconds before expiry the covenant allows renewal.
	RenewalWindow int64
	// MaxFee is the most one renewal may deduct from a vtxo to pay arkd's intent fee.
	MaxFee int64
}

type Delegation struct {
	ID         int64
	Address    string
	Tapscripts []string
	Params
	Status                  string
	LastRevocationTimestamp int64
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

type Renewal struct {
	ID             int64
	DelegationID   int64
	Outpoints      []string
	CommitmentTxid string
	Success        bool
	Error          string
	AttemptedAt    time.Time
}

type DelegationRepository interface {
	// Create re-activates a cancelled delegation, and fails if it is already active.
	Create(ctx context.Context, address string, tapscripts []string, params Params) (*Delegation, error)
	Get(ctx context.Context, address string) (*Delegation, error)
	// List filters by status when it is not empty.
	List(ctx context.Context, status string) ([]Delegation, error)
	// Cancel sets a non-active status.
	Cancel(ctx context.Context, address, status string) error
	// Revoke sets the owner-revoked status and atomically consumes a timestamp.
	Revoke(ctx context.Context, address string, timestamp int64) error
	CountActive(ctx context.Context) (int64, error)
	RecordRenewal(ctx context.Context, renewal Renewal) error
	ListRenewals(ctx context.Context, delegationID int64, limit int) ([]Renewal, error)
	// LastRenewals is the most recent renewal of every delegation that has one, by delegation id.
	LastRenewals(ctx context.Context) (map[int64]Renewal, error)
	// PruneRenewals drops the history older than before, except each delegation's latest renewal.
	PruneRenewals(ctx context.Context, before time.Time) error
	Ping(ctx context.Context) error
	Close() error
}
