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

const maxSubscriptionScripts = 1000

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

// syncSubscription keeps each shard within the indexer's 1000-script limit.
func (s *service) syncSubscription(ctx context.Context, want []string) {
	wanted := make(map[string]struct{}, len(want))
	for _, script := range want {
		wanted[script] = struct{}{}
	}
	var live []*subscription
	var plans []map[string]struct{}
	assigned := make(map[string]struct{}, len(wanted))
	dead := false
	for _, sub := range s.subs {
		if sub.dead.Load() {
			sub.stop()
			dead = true
			continue
		}
		kept := map[string]struct{}{}
		for script := range sub.scripts {
			if _, ok := wanted[script]; ok {
				kept[script] = struct{}{}
				assigned[script] = struct{}{}
			}
		}
		live = append(live, sub)
		plans = append(plans, kept)
	}
	remaining := make([]string, 0, len(wanted)-len(assigned))
	for script := range wanted {
		if _, ok := assigned[script]; !ok {
			remaining = append(remaining, script)
		}
	}
	slices.Sort(remaining)
	for n := 0; len(remaining) > 0; n++ {
		if n == len(plans) {
			plans = append(plans, map[string]struct{}{})
		}
		count := min(maxSubscriptionScripts-len(plans[n]), len(remaining))
		for _, script := range remaining[:count] {
			plans[n][script] = struct{}{}
		}
		remaining = remaining[count:]
	}
	var next []*subscription
	for n, plan := range plans {
		var sub *subscription
		if n < len(live) {
			sub = live[n]
		}
		if len(plan) == 0 {
			if sub != nil {
				sub.stop()
			}
			continue
		}
		if sub != nil {
			var add, remove []string
			for script := range plan {
				if _, ok := sub.scripts[script]; !ok {
					add = append(add, script)
				}
			}
			for script := range sub.scripts {
				if _, ok := plan[script]; !ok {
					remove = append(remove, script)
				}
			}
			if len(add)+len(remove) == 0 {
				next = append(next, sub)
				continue
			}
			if err := s.indexer.UpdateSubscription(ctx, sub.id, add, remove); err == nil {
				sub.scripts = plan
				next = append(next, sub)
				if len(add) > 0 {
					s.invalidateScripts(add...)
				}
				continue
			} else {
				log.WithError(err).Warn("update the script subscription")
				s.invalidateAllScripts()
				sub.stop()
			}
		}
		id, events, stop, err := s.indexer.NewSubscription(ctx, slices.Collect(maps.Keys(plan)))
		if err != nil {
			log.WithError(err).Warn("subscribe to watched scripts")
			continue
		}
		sub = &subscription{id: id, scripts: plan, stop: stop}
		next = append(next, sub)
		go s.follow(sub, events)
		if !dead {
			s.invalidateScripts(slices.Collect(maps.Keys(plan))...)
		}
	}
	s.subs = next
}

func (s *service) follow(sub *subscription, events <-chan clientlib.ScriptEvent) {
	defer func() {
		sub.dead.Store(true)
		s.markScriptsStale()
	}()
	for ev := range events {
		if ev.Err != nil {
			log.WithError(ev.Err).Warn("script subscription")
		}
		if ev.Connection != nil || ev.Err != nil {
			s.invalidateAllScripts()
			continue
		}
		if !wakes(ev) {
			continue
		}
		scripts := slices.Clone(ev.Data.Scripts)
		for _, v := range ev.Data.NewVtxos {
			if v.Script != "" {
				scripts = append(scripts, v.Script)
			}
		}
		for _, v := range ev.Data.SpentVtxos {
			if v.Script != "" {
				scripts = append(scripts, v.Script)
			}
		}
		if len(scripts) == 0 {
			s.invalidateAllScripts()
		} else {
			s.invalidateScripts(scripts...)
		}
	}
}

func wakes(ev clientlib.ScriptEvent) bool {
	return ev.Connection != nil || (ev.Data != nil && len(ev.Data.NewVtxos)+len(ev.Data.SpentVtxos) > 0)
}
