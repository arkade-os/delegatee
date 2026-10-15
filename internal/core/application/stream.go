package application

import (
	"context"
	"errors"
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

// watchStreams follows arkd's transactions while a stream delegation is active.
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
	events, stop, err := s.ark.GetTransactionsStream(ctx)
	if err != nil {
		return err
	}
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.streamsChanged:
			if len(s.streamSet()) == 0 {
				return nil
			}
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			if ev.Err != nil {
				log.WithError(ev.Err).Debug("transaction stream")
				continue
			}
			if ev.ArkTx != nil {
				s.react(ctx, ev.ArkTx.Tx)
			}
		}
	}
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
