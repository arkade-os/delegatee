package delegation

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/btcsuite/btcd/psbt/v2"
	log "github.com/sirupsen/logrus"
)

const streamRetry = time.Second

// RegisterStream has the daemon run a template's trigger against arkd's transactions. The same
// template and variables give the stream already registered; an operator's cancel keeps it cancelled.
func (s *Service) RegisterStream(ctx context.Context, templateID string, variables map[string]string) (*delegation.Stream, error) {
	tmpl, err := s.registry.Usable(ctx, templateID)
	if err != nil {
		return nil, err
	}
	st, err := delegation.NewStream(delegation.StreamParams{
		Template: tmpl, Variables: variables, MinExpiry: s.limits.MinDelegationExpiry,
		Encryption: s.encryption != nil,
	})
	if err != nil {
		return nil, err
	}
	if err := s.streams.AddOrUpdate(ctx, st); err != nil {
		return nil, err
	}
	if st.Status != delegation.StatusActive {
		return nil, delegation.ErrBlocked
	}
	log.WithFields(log.Fields{"id": st.ID, "template": st.TemplateID}).Info("stream registered")
	s.streamsChanged()
	return st, nil
}

func (s *Service) ListStreams(ctx context.Context) ([]delegation.Stream, error) {
	return s.streams.List(ctx, "")
}

func (s *Service) CancelStream(ctx context.Context, id int64) error {
	st, err := s.streams.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := st.Cancel(); err != nil {
		return err
	}
	if err := s.streams.AddOrUpdate(ctx, st); err != nil {
		return err
	}
	log.WithField("id", id).Info("stream cancelled")
	s.streamsChanged()
	return nil
}

// StartStreams registers a stream for each document with a trigger. It runs at startup, so a stream the
// operator cancelled stays cancelled.
func (s *Service) StartStreams(ctx context.Context, documents map[string][]byte) {
	for name, doc := range documents {
		stored, err := s.registry.RegisterTemplate(ctx, doc)
		if err != nil {
			log.WithError(err).Error("register default template " + name)
			continue
		}
		if _, tmpl, err := s.registry.Parsed(ctx, stored.ID); err != nil || tmpl.Trigger() == nil {
			continue
		}
		_, err = s.RegisterStream(ctx, stored.ID, nil)
		switch {
		case err == nil, errors.Is(err, delegation.ErrBlocked):
		case errors.Is(err, delegation.ErrNoEncryptionKey):
			log.WithError(err).Info("default stream " + name + " not started")
		default:
			log.WithError(err).Warn("start default stream " + name)
		}
	}
}

func (s *Service) streamsChanged() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

type active struct {
	stream  delegation.Stream
	trigger *template.Trigger
}

func (s *Service) activeStreams(ctx context.Context) []active {
	streams, err := s.streams.List(ctx, delegation.StatusActive)
	if err != nil {
		log.WithError(err).Error("list streams")
		return nil
	}
	var out []active
	for _, st := range streams {
		tmpl, err := s.registry.Usable(ctx, st.TemplateID)
		if err != nil || tmpl.Trigger() == nil {
			log.WithError(err).WithField("stream", st.ID).Warn("stream template unusable")
			continue
		}
		out = append(out, active{stream: st, trigger: tmpl.Trigger()})
	}
	return out
}

// followTransactions reads arkd's transactions while a stream is active; a change of the streams is
// picked up without reopening the subscription.
func (s *Service) followTransactions(ctx context.Context) {
	var txs <-chan string // nil, so never ready, while no stream is active
	stop := func() {}
	unsubscribe := func() { stop(); txs, stop = nil, func() {} }
	defer unsubscribe()
	streams := s.activeStreams(ctx)
	for ctx.Err() == nil {
		if len(streams) > 0 && txs == nil {
			subscribed, cancel, err := s.indexer.Transactions(ctx)
			if err != nil {
				log.WithError(err).Warn("transaction stream")
				s.wait(ctx, streamRetry)
				continue
			}
			txs, stop = subscribed, cancel
		}
		select {
		case <-ctx.Done():
		case <-s.changed:
			if streams = s.activeStreams(ctx); len(streams) == 0 {
				unsubscribe()
			}
		case raw, ok := <-txs:
			if !ok {
				log.Warn("transaction stream ended")
				unsubscribe()
				s.wait(ctx, streamRetry)
				continue
			}
			s.react(ctx, streams, raw)
		}
	}
}

func (s *Service) wait(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// react spawns a delegation for every output of a streamed transaction that a trigger captures and its template locks.
func (s *Service) react(ctx context.Context, streams []active, raw string) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
	if err != nil {
		log.WithError(err).Debug("streamed transaction is not a psbt")
		return
	}
	for _, st := range streams {
		captures, err := st.trigger.Match(ptx, s.keys)
		if err != nil {
			continue
		}
		for _, c := range captures {
			if err := s.spawn(ctx, st, ptx.UnsignedTx.TxOut[c.Output].PkScript, c.Variables); err != nil {
				level := log.WarnLevel
				if errors.Is(err, delegation.ErrIneligible) || errors.Is(err, delegation.ErrInvalidArgs) || errors.Is(err, delegation.ErrBlocked) || ctx.Err() != nil {
					level = log.DebugLevel
				}
				log.WithError(err).WithFields(log.Fields{"stream": st.stream.ID, "output": c.Output}).Log(level, "no delegation spawned")
			}
		}
	}
}

func (s *Service) spawn(ctx context.Context, st active, output []byte, captured map[string]string) error {
	tmpl, err := s.registry.Usable(ctx, st.stream.TemplateID)
	if err != nil {
		return err
	}
	d, err := delegation.Spawn(delegation.SpawnParams{
		Stream: st.stream, Template: tmpl, Output: output, Captured: captured, Now: time.Now(),
		Keys: s.keys.Keys, Decrypt: s.decryptFor(st.stream.TemplateID), Network: s.network,
	})
	if err != nil {
		return err
	}
	created, err := s.add(ctx, d, s.limits.MaxStreamChildren)
	if err != nil {
		return err
	}
	log.WithFields(log.Fields{"id": created.ID, "stream": st.stream.ID, "address": created.Address}).Info("delegation spawned")
	s.notify(*created)
	return nil
}
