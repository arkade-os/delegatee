package application

import (
	"context"
	"maps"
	"slices"
	"sync/atomic"
	"time"

	"github.com/arkade-os/delegatee/pkg/template"
)

// lane runs one group of inputs at a time.
type lane struct {
	busy    atomic.Int64 // vtxos in flight
	wasBusy bool         // as the scan began; the scan's alone
	queued  map[string]*pendingIntent
}

// failure is how a coin keeps failing; lost on restart, when it is recorded again.
type failure struct {
	delegation  int64
	err         string
	since, last time.Time
	count       int
}

func queuedKey(p *pendingIntent) string { return p.inputs[0].coin.Outpoint.String() }

// laneOf: intents share a batch session, anything else is a transaction of its own.
func (s *service) laneOf(in renewalInput) *lane {
	if in.watched.tmpl.Type() != template.Intent {
		return &s.direct
	}
	return &s.batch
}

// sampleLanes: a lane busy now may end at any point of the scan, after the scan listed what it writes.
// A lane idle now stays idle until the scan dispatches to it.
func (s *service) sampleLanes() {
	// a lane clears its delegations before it reports idle
	s.batch.wasBusy, s.direct.wasBusy = s.batch.busy.Load() > 0, s.direct.busy.Load() > 0
	s.shared.Lock()
	defer s.shared.Unlock()
	s.sampled = maps.Clone(s.inFlight)
}

// dispatch runs inputs on l unless l was busy when the scan began. Stop waits for it: an abandoned intent stalls arkd rounds.
func (s *service) dispatch(l *lane, inputs []renewalInput) {
	if len(inputs) == 0 {
		return
	}
	if l.wasBusy {
		return // the lane's end wakes the scan
	}
	// only the scan dispatches
	l.busy.Store(int64(len(inputs)))
	s.setInFlight(inputs, true)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.renewAndRecord(context.Background(), inputs)
		s.setInFlight(inputs, false)
		l.busy.Store(0)
		s.wakeScan() // its results and whatever waited for it
	}()
}

func (s *service) setInFlight(inputs []renewalInput, on bool) {
	s.shared.Lock()
	defer s.shared.Unlock()
	for _, in := range inputs {
		if on {
			s.inFlight[in.watched.delegation.ID] = true
		} else {
			delete(s.inFlight, in.watched.delegation.ID)
		}
	}
}

func (s *service) consume(ops ...string) {
	s.shared.Lock()
	defer s.shared.Unlock()
	for _, op := range ops {
		s.consumed[op] = time.Now()
	}
}

func (s *service) release(ops ...string) {
	s.shared.Lock()
	defer s.shared.Unlock()
	for _, op := range ops {
		delete(s.consumed, op)
	}
}

func (s *service) isConsumed(op string) bool {
	s.shared.Lock()
	defer s.shared.Unlock()
	_, ok := s.consumed[op]
	return ok
}

func (s *service) pruneConsumed(now time.Time) {
	s.shared.Lock()
	defer s.shared.Unlock()
	maps.DeleteFunc(s.consumed, func(_ string, at time.Time) bool { return now.Sub(at) > 24*time.Hour })
}

func (s *service) keepUnsaved(st settlement) {
	s.shared.Lock()
	defer s.shared.Unlock()
	s.unsaved = append(s.unsaved, st)
}

func (s *service) listUnsaved() []settlement {
	s.shared.Lock()
	defer s.shared.Unlock()
	return slices.Clone(s.unsaved)
}

// dropUnsaved forgets txid's record still to write.
func (s *service) dropUnsaved(txid string) {
	s.shared.Lock()
	defer s.shared.Unlock()
	s.unsaved = slices.DeleteFunc(s.unsaved, func(st settlement) bool { return st.tx.TxHash().String() == txid })
}

// cachedOnchain also returns the drops so far, for cacheOnchain.
func (s *service) cachedOnchain(script string) (onchainSnapshot, uint64, bool) {
	s.shared.Lock()
	defer s.shared.Unlock()
	cached, ok := s.onchainCache[script]
	return cached, s.onchainDrops, ok
}

// cacheOnchain skips a snapshot fetched across a drop: it may show a coin just spent.
func (s *service) cacheOnchain(script string, snapshot onchainSnapshot, drops uint64) {
	s.shared.Lock()
	defer s.shared.Unlock()
	if drops == s.onchainDrops {
		s.onchainCache[script] = snapshot
	}
}

func (s *service) dropOnchain(script string) {
	s.shared.Lock()
	defer s.shared.Unlock()
	delete(s.onchainCache, script)
	s.onchainDrops++
}

// quarantine keeps the coins of an intent that sank a batch out of the retry right after it.
func (s *service) quarantine(inputs []renewalInput) {
	s.shared.Lock()
	defer s.shared.Unlock()
	until := time.Now().Add(retryScanDelay)
	for _, in := range inputs {
		s.quarantined[in.coin.Outpoint.String()] = until
	}
}

// earliestQuarantine is when the next quarantined coin is free again, zero for none.
func (s *service) earliestQuarantine(now time.Time) time.Time {
	s.shared.Lock()
	defer s.shared.Unlock()
	var at time.Time
	for op, until := range s.quarantined {
		if !now.Before(until) {
			delete(s.quarantined, op)
		} else if at.IsZero() || until.Before(at) {
			at = until
		}
	}
	return at
}

func (s *service) isQuarantined(op string, now time.Time) bool {
	s.shared.Lock()
	defer s.shared.Unlock()
	maps.DeleteFunc(s.quarantined, func(_ string, until time.Time) bool { return !now.Before(until) })
	_, ok := s.quarantined[op]
	return ok
}

// noteAttempt tracks the coins that keep failing, and reports whether the attempt is worth a record: a repeated failure is not.
func (s *service) noteAttempt(delegation int64, op, err string, now time.Time) bool {
	s.shared.Lock()
	defer s.shared.Unlock()
	f := s.failing[op]
	if err == "" {
		delete(s.failing, op)
		return true
	}
	if f == nil {
		f = &failure{delegation: delegation, since: now}
		s.failing[op] = f
	}
	repeat := f.err == err
	f.err, f.last = err, now
	f.count++
	return !repeat
}

// forgetMoved drops the failures of coins the scan no longer finds, nor a lane holds: they moved, or their delegation ended.
func (s *service) forgetMoved(inputs []renewalInput) {
	due := make(map[string]bool, len(inputs))
	for _, in := range inputs {
		due[in.coin.Outpoint.String()] = true
	}
	s.shared.Lock()
	defer s.shared.Unlock()
	maps.DeleteFunc(s.failing, func(op string, f *failure) bool { return !due[op] && !s.held[op] && !s.sampled[f.delegation] })
}

// failingByDelegation keeps, for each delegation, the coin failing the longest.
func (s *service) failingByDelegation() map[int64]failure {
	s.shared.Lock()
	defer s.shared.Unlock()
	out := map[int64]failure{}
	for _, f := range s.failing {
		if cur, ok := out[f.delegation]; !ok || f.since.Before(cur.since) {
			out[f.delegation] = *f
		}
	}
	return out
}
