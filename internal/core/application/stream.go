package application

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/btcsuite/btcd/psbt/v2"
	log "github.com/sirupsen/logrus"
)

type stream struct {
	delegation domain.Delegation
	trigger    *template.Trigger
}

func splitStreams(ds []domain.Delegation) (watches, streams []domain.Delegation) {
	for _, d := range ds {
		if d.IsStream() {
			streams = append(streams, d)
		} else {
			watches = append(watches, d)
		}
	}
	return watches, streams
}

// setStreams hands the usable stream delegations of this instance's keys to the watcher and returns why the others are not.
func (s *service) setStreams(ctx context.Context, ds []domain.Delegation) map[int64]string {
	unusable := map[int64]string{}
	var next []stream
	for _, d := range ds {
		if s.cosignerFor(d.DelegatePubKey) == nil {
			continue
		}
		t, err := s.parseTemplate(ctx, d.TemplateID)
		if err == nil && t.Trigger() == nil {
			err = ErrNotStream
		}
		if err != nil {
			unusable[d.ID] = err.Error()
			continue
		}
		next = append(next, stream{delegation: d, trigger: t.Trigger()})
	}
	s.streamsMu.Lock()
	changed := !slices.EqualFunc(s.streams, next, func(a, b stream) bool { return a.delegation.ID == b.delegation.ID })
	s.streams = next
	s.streamsMu.Unlock()
	if changed {
		select {
		case s.streamsChanged <- struct{}{}:
		default:
		}
	}
	return unusable
}

func (s *service) streamSet() []stream {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	return s.streams
}

const streamRetry = time.Second

// watchStreams follows matching packets while a stream delegation is active.
func (s *service) watchStreams(ctx context.Context) {
	failing := false
	for {
		if len(s.streamSet()) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-s.streamsChanged:
				continue
			}
		}
		err := s.readTransactions(ctx)
		switch {
		case err == nil:
			failing = false
		case !failing:
			log.WithError(err).Warn("open the transaction stream")
			failing = true
		default:
			log.WithError(err).Debug("open the transaction stream")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(streamRetry):
		}
	}
}

// readTransactions fails only to open; it returns when the stream ends or the last stream delegation goes.
func (s *service) readTransactions(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	select {
	case <-s.streamsChanged:
	default:
	}
	filters, err := s.streamFilters()
	if err != nil {
		return err
	}
	if len(filters) == 0 {
		return nil
	}
	id, events, stop, err := s.indexer.NewTransactionSubscription(ctx, filters)
	if err != nil {
		return err
	}
	defer stop()
	type filterUpdate struct {
		filters []string
		err     error
	}
	var updating <-chan filterUpdate
	pending, retryUpdate := false, false
	retry := time.NewTicker(streamRetry)
	defer retry.Stop()
	for {
		if pending && updating == nil {
			pending = false
			next, err := s.streamFilters()
			switch {
			case err != nil:
				log.WithError(err).Warn("prepare transaction filters")
				retryUpdate = true
			case len(next) == 0:
				return nil
			case slices.Equal(filters, next) && !retryUpdate:
				retryUpdate = false
			default:
				result := make(chan filterUpdate, 1)
				updating = result
				go func() {
					updateCtx, cancelUpdate := context.WithTimeout(ctx, 10*time.Second)
					defer cancelUpdate()
					err := s.indexer.UpdateTransactionSubscription(updateCtx, id, next)
					result <- filterUpdate{filters: next, err: err}
				}()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-s.streamsChanged:
			pending = true
		case <-retry.C:
			pending = pending || retryUpdate
		case update := <-updating:
			updating = nil
			retryUpdate = update.err != nil
			if update.err != nil {
				log.WithError(update.err).Warn("update transaction filters")
			} else {
				filters = update.filters
			}
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			if ev.Err != nil {
				return ev.Err
			}
			if ev.ArkTx != nil {
				s.react(ctx, ev.ArkTx.Tx)
			}
		}
	}
}

func (s *service) streamFilters() ([]string, error) {
	unique := map[string]struct{}{}
	for _, st := range s.streamSet() {
		unique[st.trigger.Filter(s.triggerKeys())] = struct{}{}
	}
	var filters []string
	expression := ""
	for _, filter := range slices.Sorted(maps.Keys(unique)) {
		if len(expression)+len(filter)+6 > 64<<10 {
			filters = append(filters, expression)
			expression = ""
		}
		if expression != "" {
			expression += " || "
		}
		expression += "(" + filter + ")"
	}
	if expression != "" {
		filters = append(filters, expression)
	}
	if len(filters) > 64 {
		return nil, fmt.Errorf("stream templates exceed the indexer's 64 filter limit")
	}
	return filters, nil
}

// react spawns a watch for every output of a streamed transaction that a trigger binds and its template locks.
func (s *service) react(ctx context.Context, raw string) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
	if err != nil {
		log.WithError(err).Debug("streamed transaction is not a psbt")
		return
	}
	keys := s.triggerKeys()
	for _, st := range s.streamSet() {
		bindings, err := st.trigger.Match(ptx, keys)
		if err != nil {
			continue // most transactions are someone else's
		}
		for _, b := range bindings {
			vars := map[string]string{}
			maps.Copy(vars, st.delegation.Variables)
			maps.Copy(vars, b.Variables)
			expires := time.Now().Add(st.trigger.TTL())
			from := &spawn{parent: st.delegation.ID, script: ptx.UnsignedTx.TxOut[b.Output].PkScript}
			if _, err := s.registerWatch(ctx, st.delegation.TemplateID, vars, &expires, from); err != nil {
				level := log.WarnLevel
				if errors.Is(err, ErrIneligible) || errors.Is(err, ErrInvalidArgs) || errors.Is(err, domain.ErrBlocked) || errors.Is(err, context.Canceled) {
					level = log.DebugLevel
				}
				log.WithError(err).WithFields(log.Fields{"stream": st.delegation.ID, "output": b.Output}).Log(level, "no watch spawned")
			}
		}
	}
}

func (s *service) triggerKeys() template.TriggerKeys {
	k := template.TriggerKeys{Keys: template.Keys{Server: s.serverPubKey, Emulator: s.emulatorPubKey, Delegate: s.cosigners[0].key.PubKey()}}
	for _, e := range s.encryptionKeys {
		k.Encryption = append(k.Encryption, e.PubKey())
	}
	return k
}
