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
	Coins      int    // present coins watched
	Amount     uint64 // of those coins
	Succeeded  uint64 // attempts ended since the daemon started
	Failed     uint64
	// TemplateFailures counts the failed attempts charged to their template since the daemon started.
	TemplateFailures uint64
}

// BatchForecast is what a coming batch is expected to carry of ours.
type BatchForecast struct {
	At      time.Time
	Intents int
	Coins   int
	Amount  uint64
}

// Status reads the last published aggregates and counts the active delegations and their coins.
func (s *Service) Status(ctx context.Context) (Status, error) {
	var out Status
	if p := s.status.Load(); p != nil {
		out = *p
	}
	var err error
	if out.Active, err = s.delegations.CountActive(ctx); err != nil {
		return out, err
	}
	out.Coins, out.Amount, err = s.coins.Totals(ctx)
	return out, err
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
		Queued: queued, Registered: reserved, Late: len(plan.Late),
		NextDue: s.nextDue, Tip: s.tip, Batches: make([]BatchForecast, len(plan.Batches)),
		Succeeded: s.attemptsSucceeded, Failed: s.attemptsFailed, TemplateFailures: s.templateFailures,
	}
	for i, b := range plan.Batches {
		st.Batches[i] = BatchForecast{At: b.At, Intents: len(b.Entries)}
		for _, e := range b.Entries {
			st.Batches[i].Coins += len(e.Coins)
			st.Batches[i].Amount += e.Amount()
		}
	}
	s.status.Store(&st)
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
