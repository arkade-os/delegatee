package arkd

import (
	"cmp"
	"context"
	"sync"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/delegatee/internal/core/ports"
	log "github.com/sirupsen/logrus"
)

// subscription merges one arkd subscription per shard of at most ports.MaxScripts scripts.
type subscription struct {
	ctx        context.Context
	cancel     context.CancelFunc
	indexer    clientlib.Indexer
	events     chan ports.ScriptEvent
	reconnects chan struct{}
	wg         sync.WaitGroup

	mu     sync.Mutex
	shards shards
	ids    []string
	stops  []func()
}

func subscribe(ctx context.Context, indexer clientlib.Indexer, scripts []string) (*subscription, error) {
	ctx, cancel := context.WithCancel(ctx)
	s := &subscription{
		ctx: ctx, cancel: cancel, indexer: indexer, shards: shards{size: ports.MaxScripts},
		events: make(chan ports.ScriptEvent, 64), reconnects: make(chan struct{}, 1),
	}
	if err := s.Update(ctx, scripts, nil); err != nil {
		s.Stop()
		return nil, err
	}
	return s, nil
}

func (s *subscription) Events() <-chan ports.ScriptEvent { return s.events }
func (s *subscription) Reconnects() <-chan struct{}      { return s.reconnects }

func (s *subscription) Update(ctx context.Context, add, remove []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, scripts := range s.shards.drop(remove) {
		if len(scripts) == 0 {
			continue
		}
		if err := s.indexer.UpdateSubscription(ctx, s.ids[i], nil, scripts); err != nil {
			if err := s.reopen(ctx, i); err != nil {
				return err
			}
		}
	}
	for i, scripts := range s.shards.place(add) {
		if len(scripts) == 0 {
			continue
		}
		if i == len(s.ids) {
			if err := s.open(ctx, i); err != nil {
				return err
			}
			continue
		}
		if err := s.indexer.UpdateSubscription(ctx, s.ids[i], scripts, nil); err != nil {
			if err := s.reopen(ctx, i); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *subscription) Stop() {
	s.cancel()
	s.mu.Lock()
	for _, stop := range s.stops {
		stop()
	}
	s.stops = nil
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *subscription) open(ctx context.Context, i int) error {
	id, events, stop, err := s.indexer.NewSubscription(ctx, s.shards.scripts(i))
	if err != nil {
		return err
	}
	if i == len(s.ids) {
		s.ids, s.stops = append(s.ids, id), append(s.stops, stop)
	} else {
		s.ids[i], s.stops[i] = id, stop
	}
	s.wg.Add(1)
	go s.forward(events)
	return nil
}

// reopen replaces a shard's subscription its id no longer serves; events may have been missed.
func (s *subscription) reopen(ctx context.Context, i int) error {
	s.stops[i]()
	if err := s.open(ctx, i); err != nil {
		return err
	}
	s.signalReconnect()
	return nil
}

func (s *subscription) forward(events <-chan clientlib.ScriptEvent) {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			switch {
			case ev.Err != nil:
				log.WithError(ev.Err).Warn("script subscription")
			case ev.Connection != nil && ev.Connection.State == clientlib.StreamConnectionStateReconnected:
				s.signalReconnect()
			case ev.Data != nil:
				select {
				case s.events <- toScriptEvent(ev.Data):
				case <-s.ctx.Done():
					return
				}
			}
		}
	}
}

func (s *subscription) signalReconnect() {
	select {
	case s.reconnects <- struct{}{}:
	default:
	}
}

// toScriptEvent lists the created vtxos, then the spent ones, spent by the event's transaction when arkd names nothing else.
func toScriptEvent(d *clientlib.ScriptEventData) ports.ScriptEvent {
	ev := ports.ScriptEvent{Txid: d.Txid}
	for _, v := range d.NewVtxos {
		ev.Outputs = append(ev.Outputs, toOutput(v))
	}
	for _, v := range d.SpentVtxos {
		v.Spent = true
		o := toOutput(v)
		o.SpentBy = cmp.Or(o.SpentBy, d.Txid)
		ev.Outputs = append(ev.Outputs, o)
	}
	return ev
}
