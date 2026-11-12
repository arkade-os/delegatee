package execution

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	delegationapp "github.com/arkade-os/executor/internal/core/application/delegation"
	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/internal/core/domain/execution"
	"github.com/arkade-os/executor/internal/core/ports"
	"github.com/arkade-os/executor/pkg/template"
	"github.com/btcsuite/btcd/wire/v2"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// spendOffchain spends coins as an offchain transaction of their own; the deadline covers building and
// the emulator, not arkd once the transaction is persisted. An intent delegation's coins go to the queue.
func (s *Service) spendOffchain(coins []delegation.Coin) {
	select {
	case s.slots <- struct{}{}:
	case <-s.ctx.Done():
		return
	}
	defer func() { <-s.slots }()
	outpoints := outpointsOf(coins)
	ctx, cancel := context.WithTimeout(s.ctx, s.limits.AttemptTimeout)
	defer cancel()
	inst, err := s.delegations.Instance(ctx, coins[0].DelegationID)
	if err != nil {
		log.WithError(err).WithField("delegation", coins[0].DelegationID).Error("instantiate template")
		s.send(skipped{coins: outpoints})
		return
	}
	switch {
	case inst.Disabled || inst.Type != template.Offchain && inst.Type != template.Intent:
		s.send(skipped{coins: outpoints})
		return
	case inst.Type == template.Intent:
		s.send(intentReady{coins: coins})
		return
	}
	a, err := inst.Delegation.Attempt(coins)
	if err != nil {
		log.WithError(err).WithField("delegation", coins[0].DelegationID).Warn("no attempt")
		s.send(skipped{coins: outpoints})
		return
	}
	fail := func(err error) { s.send(attemptFailed{attempt: a, err: err, retryIn: s.limits.RetryDelay}) }
	txs, sources, err := s.build(ctx, inst, coins)
	if err != nil {
		fail(err)
		return
	}
	if err := a.Submit(txs...); err != nil {
		fail(err)
		return
	}
	if err := s.attempts.AddOrUpdate(ctx, &a); err != nil {
		log.WithError(err).WithField("delegation", coins[0].DelegationID).Error("record attempt")
		s.send(skipped{coins: outpoints})
		return
	}
	s.send(attemptUpdate{attempt: a})
	// the emulator signing last submits and finalizes at arkd
	if err := s.cosign(ctx, txs, sources); err != nil {
		fail(err)
		return
	}
	log.WithFields(log.Fields{"delegation": a.DelegationID, "txid": strings.Join(a.Spenders(), ",")}).Info("offchain tx finalized by the emulator")
	s.send(attemptDone{attempt: a})
}

// build fetches the sources of the coins and builds the signed transaction over them.
func (s *Service) build(ctx context.Context, inst *delegationapp.Instance, coins []delegation.Coin) ([]delegation.Tx, []*wire.MsgTx, error) {
	txs, err := s.sources(ctx, coins)
	if err != nil {
		return nil, nil, err
	}
	fee := template.Fee{Intent: s.info.IntentFees, Dust: s.info.Dust}
	built, err := execution.BuildOffchain(inst.Template, inst.Delegation.Inputs, coins, txs, fee, s.info.CheckpointTapscript)
	if err != nil {
		return nil, nil, err
	}
	sources := make([]*wire.MsgTx, len(coins))
	for i, c := range coins {
		txid, _, _ := strings.Cut(c.Outpoint, ":")
		sources[i] = txs[txid]
	}
	return built, sources, nil
}

// sources fetches the transactions that created the coins: the virtual ones from arkd, the onchain from the chain.
func (s *Service) sources(ctx context.Context, coins []delegation.Coin) (map[string]*wire.MsgTx, error) {
	txs := map[string]*wire.MsgTx{}
	var virtual []string
	for _, c := range coins {
		txid, _, _ := strings.Cut(c.Outpoint, ":")
		if _, ok := txs[txid]; ok || slices.Contains(virtual, txid) {
			continue
		}
		if !c.Onchain {
			virtual = append(virtual, txid)
			continue
		}
		tx, err := s.chain.Transaction(ctx, txid)
		if err != nil {
			return nil, fmt.Errorf("transaction %s: %w", txid, err)
		}
		txs[txid] = tx
	}
	if len(virtual) > 0 {
		found, err := s.indexer.VirtualTxs(ctx, virtual)
		if err != nil {
			return nil, err
		}
		maps.Copy(txs, found)
	}
	return txs, nil
}

// swept asks arkd which of the coins it swept: a batch recovers those without a forfeit.
func (s *Service) swept(ctx context.Context, coins []delegation.Coin) ([]bool, error) {
	var scripts []string
	for _, c := range coins {
		if !c.Onchain && !slices.Contains(scripts, c.Script) {
			scripts = append(scripts, c.Script)
		}
	}
	swept := make([]bool, len(coins))
	if len(scripts) == 0 {
		return swept, nil
	}
	vtxos, err := s.indexer.Vtxos(ctx, scripts)
	if err != nil {
		return nil, fmt.Errorf("vtxos: %w", err)
	}
	for i, c := range coins {
		swept[i] = slices.ContainsFunc(vtxos, func(v ports.Output) bool { return v.Outpoint == c.Outpoint && v.Swept })
	}
	return swept, nil
}

// cosign has the emulator sign the transaction last: it submits and finalizes it at arkd.
func (s *Service) cosign(ctx context.Context, txs []delegation.Tx, sources []*wire.MsgTx) error {
	ark, checkpoints, err := forEmulator(txs, sources)
	if err != nil {
		return err
	}
	if _, _, err := s.emulator.SubmitTx(ctx, ark, checkpoints); err != nil {
		return fmt.Errorf("emulator: %w", refusal(ctx, err))
	}
	return nil
}

// refusal marks err as a refusal when the remote side turned the request down for good.
func refusal(ctx context.Context, err error) error {
	if ctx.Err() != nil || strings.Contains(err.Error(), "duplicated offchain tx") {
		return err
	}
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound, codes.AlreadyExists, codes.OutOfRange:
		return refused{err}
	}
	return err
}

// errRefused marks what arkd or the emulator turned down for good.
var errRefused = errors.New("refused")

// refused is an error that is a refusal; its text stays the same.
type refused struct{ error }

func (r refused) Unwrap() error { return r.error }

func (refused) Is(target error) bool { return target == errRefused }

// chargesTemplate says a failed attempt counts against its template: the template could not build
// it, or arkd or the emulator refused it. Outages, the daemon's own shutdown and sources fees or dust refuse do not.
func chargesTemplate(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, template.ErrUnaffordable) {
		return false
	}
	return errors.Is(err, template.ErrIneligible) || errors.Is(err, execution.ErrBadTx) || errors.Is(err, errRefused)
}
