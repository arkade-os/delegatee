// Package health tells which of the daemon's dependencies answer.
package health

import (
	"context"
	"slices"
	"sync"
	"time"

	executionapp "github.com/arkade-os/delegatee/internal/core/application/execution"
	"github.com/arkade-os/delegatee/internal/core/ports"
)

const defaultTimeout = 3 * time.Second

// Entry is what a dependency answers: Err is nil when it is healthy.
type Entry struct {
	Name string
	Err  error
}

type Checker struct {
	db       ports.Database
	ark      ports.Signer
	emulator ports.Emulator
	loop     *executionapp.Service
	timeout  time.Duration
}

func NewChecker(db ports.Database, ark ports.Signer, emulator ports.Emulator, loop *executionapp.Service) *Checker {
	return &Checker{db: db, ark: ark, emulator: emulator, loop: loop, timeout: defaultTimeout}
}

// Check asks every dependency at once, each within a short timeout, and lists the answers in a fixed order.
func (c *Checker) Check(ctx context.Context) []Entry {
	checks := []struct {
		name string
		run  func(ctx context.Context) error
	}{
		{"db", c.db.Ping},
		{"arkd", func(ctx context.Context) error { _, err := c.ark.Info(ctx); return err }},
		{"electrum", func(context.Context) error { return c.loop.ChainConnected() }},
		{"emulator", func(ctx context.Context) error { _, err := c.emulator.Info(ctx); return err }},
		{"loop", func(context.Context) error { return c.loop.Alive(time.Now()) }},
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	entries := make([]Entry, len(checks))
	var wg sync.WaitGroup
	for i, check := range checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entries[i] = Entry{Name: check.name, Err: check.run(ctx)}
		}()
	}
	wg.Wait()
	return entries
}

// Healthy is true when no entry failed.
func Healthy(entries []Entry) bool {
	return !slices.ContainsFunc(entries, func(e Entry) bool { return e.Err != nil })
}
