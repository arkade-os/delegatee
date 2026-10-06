package application

import (
	"context"
	"maps"
	"slices"
	"sync/atomic"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/delegatee/pkg/template"
	log "github.com/sirupsen/logrus"
)

// woken scans are at least this far apart
const minScanGap = time.Second

// subscription wakes the scan when a coin reaches a watched script.
type subscription struct {
	id      string
	scripts map[string]struct{}
	stop    func()
	dead    atomic.Bool // its stream ended: the next scan opens another
}

// wakeScan asks for a scan now; one request is enough for any number of callers.
func (s *service) wakeScan() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// wakeScripts are the offchain scripts of the watches the direct lane serves.
func (s *service) wakeScripts() []string {
	var scripts []string
	for _, w := range s.watched {
		if w == nil || !w.delegation.IsWatch() || w.tmpl.Type() == template.Intent {
			continue
		}
		for _, sl := range w.delegation.Slots {
			if !sl.Onchain {
				scripts = append(scripts, sl.Script)
			}
		}
	}
	return scripts
}

// syncSubscription never fails a scan: without it a claim waits for the poll.
func (s *service) syncSubscription(ctx context.Context, want []string) {
	wanted := make(map[string]struct{}, len(want))
	for _, script := range want {
		wanted[script] = struct{}{}
	}
	dead := s.sub != nil && s.sub.dead.Load()
	if s.sub != nil && (dead || len(wanted) == 0) {
		s.sub.stop()
		s.sub = nil
	}
	if len(wanted) == 0 {
		return
	}
	if s.sub != nil {
		var add, remove []string
		for script := range wanted {
			if _, ok := s.sub.scripts[script]; !ok {
				add = append(add, script)
			}
		}
		for script := range s.sub.scripts {
			if _, ok := wanted[script]; !ok {
				remove = append(remove, script)
			}
		}
		if len(add)+len(remove) == 0 {
			return
		}
		err := s.indexer.UpdateSubscription(ctx, s.sub.id, add, remove)
		if err == nil {
			s.sub.scripts = wanted
			if len(add) > 0 {
				s.wakeScan() // a coin may have reached an added script unseen
			}
			return
		}
		log.WithError(err).Warn("update the script subscription")
		s.sub.stop()
		s.sub = nil
	}
	id, events, stop, err := s.indexer.NewSubscription(ctx, slices.Collect(maps.Keys(wanted)))
	if err != nil {
		log.WithError(err).Warn("subscribe to watched scripts")
		return
	}
	s.sub = &subscription{id: id, scripts: wanted, stop: stop}
	go s.follow(s.sub, events)
	// a stream that keeps ending would otherwise scan in a loop
	if !dead {
		s.wakeScan() // a coin may have arrived before the stream opened
	}
}

func (s *service) follow(sub *subscription, events <-chan clientlib.ScriptEvent) {
	defer sub.dead.Store(true)
	for ev := range events {
		if ev.Err != nil {
			log.WithError(ev.Err).Warn("script subscription")
		}
		if wakes(ev) {
			s.wakeScan()
		}
	}
}

// wakes: a new coin, or a connection change that may have hidden one.
func wakes(ev clientlib.ScriptEvent) bool {
	return ev.Connection != nil || (ev.Data != nil && len(ev.Data.NewVtxos) > 0)
}
