package execution

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/internal/core/domain/execution"
)

// Status is what the loop publishes about the work in hand.
type Status struct {
	Active     int64 // delegations being served
	Queued     int   // entries waiting to be registered
	Registered int   // entries registered at arkd
	Late       int   // coins forecast to miss their deadline
	NextDue    time.Time
	Tip        delegation.Tip
	Batches    []BatchForecast
	// entries are the queued entries the forecast starts from.
	entries   []execution.Entry
	Coins     int    // present coins watched
	Amount    uint64 // of those coins
	Succeeded uint64 // attempts ended since the daemon started
	Failed    uint64
	// TemplateFailures counts the failed attempts charged to their template since the daemon started.
	TemplateFailures uint64
	Reserve          time.Duration // before expiry, the latest a coin enters a batch
	Session          execution.Session
}

// BatchForecast is what a coming batch is expected to carry of ours.
type BatchForecast struct {
	At      time.Time
	Intents int
	Coins   int
	Amount  uint64
	Entries []ForecastEntry
}

// ForecastEntry is a delegation's coins in a forecast batch.
type ForecastEntry struct {
	DelegationID int64
	Coins        int
	Amount       uint64
	Due          time.Time
	Deadline     time.Time
}

const (
	forecastLimit = 10000
	// forecastSpan outlasts any expiry or locktime, so the forecast takes every present coin.
	forecastSpan       = 100 * 365 * 24 * time.Hour
	maxForecastEntries = 100
)

// Status reads the last published aggregates and counts the active delegations and their coins.
// With forecast it plans the batches again, with every present coin whenever it becomes due.
func (s *Service) Status(ctx context.Context, forecast bool) (Status, error) {
	var out Status
	if p := s.status.Load(); p != nil {
		out = *p
	}
	var err error
	if out.Active, err = s.delegations.CountActive(ctx); err != nil {
		return out, err
	}
	if out.Coins, out.Amount, err = s.coins.Totals(ctx); err != nil {
		return out, err
	}
	if forecast {
		err = s.forecast(ctx, &out)
	}
	return out, err
}

// forecast plans the published entries with every present coin not yet due.
func (s *Service) forecast(ctx context.Context, st *Status) error {
	now := time.Now()
	entries := slices.Clone(st.entries)
	upcoming, err := s.coins.Ready(ctx, now.Add(forecastSpan), st.Tip, forecastLimit)
	if err != nil {
		return err
	}
	for _, coins := range upcoming {
		entries = append(entries, execution.NewEntry(coins, s.limits.Reserve))
	}
	plan := execution.NewPlan(entries, s.session, now)
	st.Late = len(plan.Late)
	st.Batches = forecastBatches(plan)
	return nil
}

// plan lays out the queued entries.
func (s *Service) plan(now time.Time) execution.Plan {
	return execution.NewPlan(slices.Collect(maps.Values(s.entries)), s.session, now)
}

// counts is how many entries are reserved and how many wait.
func (s *Service) counts() (reserved, queued int) {
	for _, e := range s.entries {
		if e.Reserved {
			reserved++
		} else {
			queued++
		}
	}
	return reserved, queued
}

func (s *Service) publish(now time.Time) {
	plan := s.plan(now)
	reserved, queued := s.counts()
	st := Status{
		entries: slices.Collect(maps.Values(s.entries)),
		Queued:  queued, Registered: reserved, Late: len(plan.Late),
		NextDue: s.nextDue, Tip: s.tip,
		Succeeded: s.attemptsSucceeded, Failed: s.attemptsFailed, TemplateFailures: s.templateFailures,
		Reserve: s.limits.Reserve, Session: s.session,
	}
	st.Batches = forecastBatches(plan)
	s.status.Store(&st)
}

func forecastBatches(plan execution.Plan) []BatchForecast {
	out := make([]BatchForecast, len(plan.Batches))
	for i, b := range plan.Batches {
		out[i] = BatchForecast{At: b.At, Intents: len(b.Entries)}
		for j, e := range b.Entries {
			out[i].Coins += len(e.Coins)
			out[i].Amount += e.Amount()
			if j < maxForecastEntries {
				out[i].Entries = append(out[i].Entries, ForecastEntry{
					DelegationID: e.DelegationID, Coins: len(e.Coins), Amount: e.Amount(), Due: e.Due, Deadline: e.Deadline,
				})
			}
		}
	}
	return out
}

// Alive fails when the loop has been silent for LoopStall past the time its timer should have fired.
func (s *Service) Alive(now time.Time) error {
	wake := s.wake.Load()
	if wake == 0 {
		return nil
	}
	since := time.Unix(0, max(wake, s.beat.Load()))
	if silent := now.Sub(since); silent > s.limits.LoopStall {
		return fmt.Errorf("nothing handled for %s with work due", silent.Round(time.Second))
	}
	return nil
}

func (s *Service) ChainConnected() error {
	if s.chainSub == nil || !s.chainSub.Connected() {
		return errors.New("not connected")
	}
	return nil
}
