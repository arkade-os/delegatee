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
	waiting atomic.Bool  // a scan left it inputs while busy; batch inputs wait for the poll instead
	wasBusy bool         // as the scan began; the scan's alone
	// lost on restart: the failure is then reported again
	lastFailure map[string]string
}

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
		l.waiting.Store(true)
		// the lane may have ended since the scan began
		if l.busy.Load() == 0 && l.waiting.Swap(false) {
			s.wakeScan()
		}
		return
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
		if l.waiting.Swap(false) {
			s.wakeScan()
		}
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
