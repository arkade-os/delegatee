package domain

import (
	"context"
	"errors"
	"time"
)

var (
	ErrDelegationNotFound      = errors.New("delegation not found")
	ErrDelegationAlreadyExists = errors.New("address already registered")
)

const DelegationStatusActive = "active"

type Delegation struct {
	ID         int64
	Address    string
	Tapscripts []string
	// RenewalWindow is how many seconds before expiry the covenant allows renewal.
	RenewalWindow int64
	Status        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
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
	Create(ctx context.Context, address string, tapscripts []string, renewalWindow int64) (*Delegation, error)
	Get(ctx context.Context, address string) (*Delegation, error)
	// List filters by status when it is not empty.
	List(ctx context.Context, status string) ([]Delegation, error)
	Cancel(ctx context.Context, address string) error
	RecordRenewal(ctx context.Context, renewal Renewal) error
	ListRenewals(ctx context.Context, delegationID int64, limit int) ([]Renewal, error)
	Ping(ctx context.Context) error
	Close() error
}
