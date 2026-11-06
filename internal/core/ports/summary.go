package ports

import (
	"context"
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
)

// Summary is a delegation with what its present coins and its attempts come to.
type Summary struct {
	delegation.Delegation
	Coins       int
	Amount      uint64
	NextDue     time.Time // the earliest due of the present coins, zero without any
	LastAttempt delegation.AttemptStatus
}

// Cursor is a place in the order of summaries: by NextDue, then by id, those without coins last.
type Cursor struct {
	NextDue time.Time
	ID      int64
}

// SummaryFilter selects summaries: an empty or zero field matches any, a non-zero After the ones that follow it.
type SummaryFilter struct {
	Status     string
	StreamID   int64
	TemplateID string
	After      Cursor
	Limit      int
}

// Spawned is what a stream spawned: its delegations, the active ones and when the last one was.
type Spawned struct {
	Delegations int
	Active      int
	Last        time.Time
}

type SummaryRepository interface {
	// List returns the delegations by the earliest due of their present coins, those without coins last by id.
	List(ctx context.Context, f SummaryFilter) ([]Summary, error)
	// Spawned returns what each stream spawned, by stream id; a stream that spawned nothing is missing.
	Spawned(ctx context.Context) (map[int64]Spawned, error)
}
