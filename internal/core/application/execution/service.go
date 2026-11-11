// Package execution runs the loop that keeps the coins and the attempts it dispatches.
package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	delegationapp "github.com/arkade-os/executor/internal/core/application/delegation"
	registryapp "github.com/arkade-os/executor/internal/core/application/registry"
	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/internal/core/domain/execution"
	"github.com/arkade-os/executor/internal/core/domain/registry"
	"github.com/arkade-os/executor/internal/core/ports"
	"github.com/arkade-os/executor/pkg/template"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	log "github.com/sirupsen/logrus"
)

const (
	pageSize    = 1000
	stopMargin  = 10 * time.Second // on top of a session's duration, what Stop waits for the batch in flight
	maxListings = 8                // unspent listings at once
)

var (
	errNotSelected = errors.New("not selected by a batch within the intent timeout")
	errNotLanded   = errors.New("its batch did not spend the coins")
)

type Limits struct {
	OffchainConcurrency int           // offchain attempts in flight at once
	AttemptTimeout      time.Duration // building and signing an offchain attempt
	RetryDelay          time.Duration // before the coins of a failed attempt are ready again
	IntentsPerBatch     int           // intents arkd takes per batch
	IntentTimeout       time.Duration // an intent not selected by then is forgotten and queued again
	Reserve             time.Duration // before expiry, the latest a coin enters a batch
	BanDuration         time.Duration // the coins of an intent a batch failed on keep out of the queue
	LandingWindow       time.Duration // after a restart, how long a batched attempt waits to see its coins spent
	TemplateMaxFailures int           // consecutive failed attempts that disable a template
	LoopStall           time.Duration // how long the loop may stay silent past a due time before it is unhealthy
}

type Service struct {
	delegations *delegationapp.Service
	templates   *registryapp.Service
	ark         ports.Signer
	indexer     ports.Indexer
	chain       ports.ChainWatcher
	emulator    ports.Emulator
	cosignerKey *btcec.PrivateKey // signs arkd's vtxo tree
	cosigner    string            // its public key, compressed hex, as arkd names tree cosigners
	coins       delegation.CoinRepository
	attempts    delegation.AttemptRepository
	summaries   ports.SummaryRepository
	limits      Limits
	info        ports.ArkInfo
	nextDue     time.Time // the next coin to become ready, zero when none will
	dispatched  time.Time
	sub         ports.Subscription
	chainSub    ports.ChainSubscription
	tip         delegation.Tip
	inflight    map[string]string // the status each script is being listed for
	listing     chan struct{}     // the unspent listings in flight
	events      chan any
	ctx         context.Context
	stop        context.CancelFunc
	done        chan struct{}
	wg          sync.WaitGroup
	slots       chan struct{} // the offchain worker pool
	timer       *time.Timer
	pending     map[int64]*pending
	entries     map[int64]execution.Entry // queued by delegation, touched by the loop only
	session     execution.Session
	batch       *batchWorker
	status      atomic.Pointer[Status]
	beat        atomic.Int64 // when the loop last handled something, unix nanoseconds
	wake        atomic.Int64 // when its timer is set to fire, zero when unset
	started     time.Time

	attemptsSucceeded, attemptsFailed uint64 // since the daemon started
	templateFailures                  uint64 // failures charged to a template

	reconciling, reconcileAgain bool // a reconnect during a full reconcile queues one more
}

// pending is an attempt the loop follows until it lands or fails.
type pending struct {
	attempt delegation.Attempt
	busy    bool              // a worker is talking to arkd about it
	spent   map[string]string // its stored coins seen spent, by what spent them
	landBy  time.Time         // when a batched attempt of a previous run must have landed, zero for the others
}

// reconnected says the subscription may have missed events.
type reconnected struct{}

type reconcileDone struct{}

// reconciled is what arkd reports at scripts, empty lists included.
type reconciled map[string][]ports.Output

// unspents is what the chain lists at a script whose status hash became status.
type unspents struct {
	script, status string
	utxos          []ports.Output
}

type tick struct{}

// attemptUpdate is a state a worker persisted.
type attemptUpdate struct{ attempt delegation.Attempt }

// attemptDone says arkd finalized the attempt: it waits for its coins to be seen spent.
type attemptDone struct{ attempt delegation.Attempt }

// attemptFailed carries a worker's failure.
type attemptFailed struct {
	attempt delegation.Attempt // ID is zero when nothing was persisted yet
	err     error
	retryIn time.Duration // the coins are ready again after this long
}

// skipped releases coins no attempt can spend for now; delegation is the one whose queued entry goes, if any.
type skipped struct {
	coins      []string
	delegation int64
}

// intentReady says every coin of an intent delegation is ready for a batch.
type intentReady struct{ coins []delegation.Coin }

// selected says batches took these delegations' intents.
type selected struct{ delegations []int64 }

func NewService(
	delegations *delegationapp.Service, templates *registryapp.Service, ark ports.Signer, indexer ports.Indexer, chain ports.ChainWatcher, emulator ports.Emulator,
	key *btcec.PrivateKey, coins delegation.CoinRepository, attempts delegation.AttemptRepository, summaries ports.SummaryRepository,
	limits Limits,
) *Service {
	s := &Service{
		delegations: delegations, templates: templates, ark: ark, indexer: indexer, chain: chain, emulator: emulator, cosignerKey: key, coins: coins, attempts: attempts,
		summaries: summaries, limits: limits, events: make(chan any, 256), slots: make(chan struct{}, limits.OffchainConcurrency),
		pending: map[int64]*pending{}, entries: map[int64]execution.Entry{}, inflight: map[string]string{},
		listing: make(chan struct{}, maxListings),
	}
	if key != nil {
		s.cosigner = hex.EncodeToString(key.PubKey().SerializeCompressed())
	}
	s.batch = newBatchWorker(s)
	return s
}

// Start loads the pending attempts, watches the active delegations and runs the loop; the pending
// attempts are asked about and the first reconcile runs behind.
func (s *Service) Start(ctx context.Context) error {
	s.ctx, s.stop = context.WithCancel(ctx)
	s.done = make(chan struct{})
	s.started = time.Now()
	info, err := s.ark.Info(ctx)
	if err != nil {
		return fmt.Errorf("arkd info: %w", err)
	}
	s.info = info
	s.session = execution.Session{Duration: info.SessionDuration, MaxIntents: s.limits.IntentsPerBatch}
	if s.tip, err = s.chain.Tip(ctx); err != nil {
		return fmt.Errorf("chain tip: %w", err)
	}
	if err := s.coins.ResetHolds(ctx); err != nil {
		return err
	}
	stranded, err := s.coins.Stranded(ctx)
	if err != nil {
		return err
	}
	if err := s.rehome(stranded); err != nil {
		return err
	}
	attempts, err := s.attempts.ListPending(ctx)
	if err != nil {
		return err
	}
	for _, a := range attempts {
		if err := s.await(s.track(a)); err != nil {
			return err
		}
	}
	scripts, err := s.coins.Scripts(ctx, false)
	if err != nil {
		return err
	}
	onchain, err := s.coins.Scripts(ctx, true)
	if err != nil {
		return err
	}
	if s.sub, err = s.indexer.Subscribe(s.ctx, scripts); err != nil {
		return err
	}
	if s.chainSub, err = s.chain.Subscribe(s.ctx, onchain); err != nil {
		s.sub.Stop()
		return fmt.Errorf("chain subscribe: %w", err)
	}
	events, stopEvents, err := s.ark.BatchEvents(s.ctx)
	if err != nil {
		s.sub.Stop()
		s.chainSub.Stop()
		return fmt.Errorf("batch events: %w", err)
	}
	log.WithFields(log.Fields{"scripts": len(scripts), "onchain": len(onchain), "pending": len(attempts)}).Info("coins loaded")
	s.delegations.OnChange(func(d delegation.Delegation) { s.send(d) })
	s.wg.Go(s.forward)
	s.wg.Go(func() { s.batch.run(events, stopEvents) })
	s.reconciling = true
	s.wg.Go(func() { s.reconcile(scripts, reconcileDone{}) })
	s.timer = time.NewTimer(time.Hour)
	s.timer.Stop()
	go s.run()
	return nil
}

// Stop registers no more intents, waits for the batch in flight to end, then ends the loop and
// waits for it and its workers.
func (s *Service) Stop() {
	if s.stop == nil {
		return
	}
	s.batch.quiesce(s.session.Duration + stopMargin)
	s.stop()
	s.sub.Stop()
	s.chainSub.Stop()
	<-s.done
}

func (s *Service) Coins(ctx context.Context, delegationID int64) ([]delegation.Coin, error) {
	return s.coins.ListByDelegation(ctx, delegationID)
}

// Summaries lists the delegations by the earliest due of their coins.
func (s *Service) Summaries(ctx context.Context, f ports.SummaryFilter) ([]ports.Summary, error) {
	return s.summaries.List(ctx, f)
}

// Spawned returns what each stream spawned, by stream id.
func (s *Service) Spawned(ctx context.Context) (map[int64]ports.Spawned, error) {
	return s.summaries.Spawned(ctx)
}

// Attempts lists the attempts of a delegation newest first, below cursor when not zero.
func (s *Service) Attempts(ctx context.Context, delegationID, cursor int64, limit int) ([]delegation.Attempt, error) {
	return s.attempts.ListByDelegation(ctx, delegationID, cursor, limit)
}

func (s *Service) run() {
	defer close(s.done)
	defer s.wg.Wait()
	now := time.Now()
	for _, p := range s.pending {
		if !p.landBy.IsZero() {
			s.settle(p, now)
		}
	}
	s.beat.Store(now.UnixNano())
	s.dispatch(now)
	s.publish(now)
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.timer.C:
			s.handle(tick{}, time.Now())
		case ev := <-s.events:
			s.handle(ev, time.Now())
		}
	}
}

func (s *Service) handle(ev any, now time.Time) {
	s.beat.Store(now.UnixNano())
	switch ev := ev.(type) {
	case ports.ScriptEvent:
		log.WithFields(log.Fields{"txid": ev.Txid, "outputs": len(ev.Outputs)}).Debug("script event")
		s.update(scriptsOf(ev.Outputs), now, func(w delegation.Watched) []delegation.Coin {
			return syncVtxos(w, ev.Outputs, false)
		})
	case ports.ChainEvent:
		s.chainEvent(ev, now)
	case unspents:
		s.reconcileOnchain(ev, now)
	case reconnected:
		log.Info("script subscription reconnected")
		if s.reconciling {
			s.reconcileAgain = true
		} else {
			s.reconcileAll()
		}
	case reconcileDone:
		log.Info("reconcile done")
		s.reconciling = false
		if s.reconcileAgain {
			s.reconcileAgain = false
			s.reconcileAll()
		}
	case reconciled:
		s.update(slices.Collect(maps.Keys(ev)), now, func(w delegation.Watched) []delegation.Coin { return syncVtxos(w, ev[w.Script], true) })
	case delegation.Delegation:
		s.follow(ev)
	case tick:
		for _, p := range s.pending {
			if !p.landBy.IsZero() && !p.landBy.After(now) {
				s.settle(p, now)
			}
		}
	case attemptUpdate:
		s.track(ev.attempt)
	case attemptDone:
		p := s.track(ev.attempt)
		p.busy = false
		s.settle(p, now)
	case attemptFailed:
		s.failed(ev, now)
	case skipped:
		s.dequeue(ev.delegation)
		s.release(ev.coins, now.Add(s.limits.RetryDelay))
	case intentReady:
		s.enqueue(ev)
	case selected:
		for _, id := range ev.delegations {
			s.dequeue(id)
		}
	}
	// a burst of events dispatches once, at its end or every second
	if len(s.events) == 0 || now.Sub(s.dispatched) >= time.Second {
		s.dispatch(now)
	}
	if len(s.events) == 0 {
		s.publish(now)
	}
}

// dispatch starts a worker for every ready delegation, registers what the plan says is due and arms the timer for the next one.
func (s *Service) dispatch(now time.Time) {
	s.dispatched = now
	for {
		ready, err := s.coins.Ready(s.ctx, now, s.tip, pageSize)
		if err == nil {
			err = s.coins.Hold(s.ctx, outpointsOf(slices.Concat(ready...)))
		}
		if err != nil {
			if s.ctx.Err() == nil {
				log.WithError(err).Error("dispatch ready coins")
			}
			break
		}
		for _, coins := range ready {
			s.wg.Go(func() { s.spendOffchain(coins) })
		}
		if len(ready) < pageSize {
			break
		}
	}
	reserved, _ := s.counts()
	if entries := s.plan(now).Registrations(now, max(s.session.MaxIntents-reserved, 0)); len(entries) > 0 {
		for i := range entries {
			entries[i].Reserved = true
			s.entries[entries[i].DelegationID] = entries[i]
		}
		s.batch.register(entries)
	}
	plan := s.plan(now)
	next, err := s.coins.NextReady(s.ctx, now, s.tip)
	if err != nil && s.ctx.Err() == nil {
		log.WithError(err).Error("next ready coin")
	}
	s.nextDue = next
	earlier := func(at time.Time) {
		if !at.IsZero() && (next.IsZero() || at.Before(next)) {
			next = at
		}
	}
	earlier(plan.NextRegistration(now))
	for _, p := range s.pending {
		earlier(p.landBy)
	}
	s.timer.Stop()
	s.wake.Store(0)
	if !next.IsZero() {
		s.timer.Reset(max(next.Sub(now), 0))
		s.wake.Store(next.UnixNano())
	}
}

// track is the pending entry of an attempt, created on its first report.
func (s *Service) track(a delegation.Attempt) *pending {
	p, ok := s.pending[a.ID]
	if !ok {
		p = &pending{busy: true, spent: map[string]string{}}
		s.pending[a.ID] = p
	}
	p.attempt = a
	return p
}

func (s *Service) failed(ev attemptFailed, now time.Time) {
	a := ev.attempt
	fields := log.Fields{"delegation": a.DelegationID, "txid": strings.Join(a.Spenders(), ",")}
	err := a.Fail(ev.err)
	if err == nil {
		err = s.attempts.AddOrUpdate(s.ctx, &a)
	}
	if err != nil && s.ctx.Err() == nil {
		log.WithError(err).WithFields(fields).Error("record failed attempt")
	}
	delete(s.pending, a.ID)
	s.attemptsFailed++
	if chargesTemplate(ev.err) {
		s.templateFailures++
		s.record(a.DelegationID, false)
	}
	s.dequeue(a.DelegationID)
	s.release(a.Coins, now.Add(ev.retryIn))
	log.WithError(ev.err).WithFields(fields).Warn("attempt failed")
}

func (s *Service) succeed(p *pending) {
	a := p.attempt
	for _, by := range p.spent {
		if len(a.Spenders()) == 0 && by != "" {
			_, batched := a.Proof()
			a.AddTx(delegation.Tx{Txid: by, Onchain: batched, Spends: true})
		}
	}
	fields := log.Fields{"delegation": a.DelegationID, "txid": strings.Join(a.Spenders(), ",")}
	if err := a.Succeeded(); err != nil {
		log.WithError(err).WithFields(fields).Error("land attempt")
		return
	}
	if err := s.attempts.AddOrUpdate(s.ctx, &a); err != nil && s.ctx.Err() == nil {
		log.WithError(err).WithFields(fields).Error("record succeeded attempt")
	}
	delete(s.pending, a.ID)
	s.attemptsSucceeded++
	s.record(a.DelegationID, true)
	log.WithFields(fields).Info("attempt succeeded")
}

// record tells the template of the delegation how an attempt ended.
func (s *Service) record(delegationID int64, success bool) {
	d, err := s.delegations.GetDelegation(s.ctx, delegationID)
	if err == nil {
		var failures int
		var status string
		if failures, status, err = s.templates.RecordOutcome(s.ctx, d.TemplateID, success, s.limits.TemplateMaxFailures); err == nil &&
			status == registry.TemplateStatusDisabled && failures == s.limits.TemplateMaxFailures {
			log.WithFields(log.Fields{"template": d.TemplateID, "failures": failures}).Warn("template disabled by its failures")
		}
	}
	if err != nil && s.ctx.Err() == nil {
		log.WithError(err).WithField("delegation", delegationID).Error("record template outcome")
	}
}

// landing matches a spent coin with the pending attempts holding it.
func (s *Service) landing(c delegation.Coin, now time.Time) {
	for _, p := range s.pending {
		if slices.Contains(p.attempt.Coins, c.Outpoint) {
			p.spent[c.Outpoint] = c.SpentBy
			s.settle(p, now)
		}
	}
}

// settle succeeds p once every coin is seen spent by its transaction and nothing is left to do at
// arkd. It fails p when another transaction spent a coin, or when an attempt of a previous run still
// has coins unspent at landBy; a batched attempt knows its transaction late.
func (s *Service) settle(p *pending, now time.Time) {
	for outpoint, by := range p.spent {
		if spenders := p.attempt.Spenders(); len(spenders) > 0 && by != "" && !slices.Contains(spenders, by) {
			s.failed(attemptFailed{attempt: p.attempt, err: fmt.Errorf("coin %s spent by %s", outpoint, by), retryIn: s.retryIn(p.attempt, false)}, now)
			return
		}
	}
	switch {
	case !p.busy && len(p.spent) == len(p.attempt.Coins):
		s.succeed(p)
	case !p.landBy.IsZero() && !now.Before(p.landBy):
		s.failed(attemptFailed{attempt: p.attempt, err: errNotLanded, retryIn: s.retryIn(p.attempt, true)}, now)
	}
}

// retryIn is how long the coins of a pending attempt wait: a batched attempt waits for the next session
// unless a batch, not the coins, is at fault.
func (s *Service) retryIn(a delegation.Attempt, again bool) time.Duration {
	switch _, batched := a.Proof(); {
	case !batched:
		return s.limits.RetryDelay
	case again:
		return 0
	}
	return s.session.Duration
}

// await has the attempt of a previous run wait for the stored coins to show where theirs went.
func (s *Service) await(p *pending) error {
	coins, err := s.coins.ListByDelegation(s.ctx, p.attempt.DelegationID)
	if err != nil {
		return err
	}
	for _, c := range coins {
		if c.Status == delegation.Spent && slices.Contains(p.attempt.Coins, c.Outpoint) {
			p.spent[c.Outpoint] = c.SpentBy
		}
	}
	p.busy, p.landBy = false, s.started.Add(s.limits.LandingWindow)
	return nil
}

// follow watches or forgets the scripts of a changed delegation and gives their coins to their owners.
func (s *Service) follow(d delegation.Delegation) {
	active := d.Status == delegation.StatusActive
	if !active {
		s.withdraw(d.ID)
	}
	onchain := map[string]bool{}
	for _, in := range d.Inputs {
		if in.Script != "" {
			onchain[in.Script] = in.Onchain
		}
	}
	scripts := slices.Sorted(maps.Keys(onchain))
	watched, err := s.coins.Watched(s.ctx, scripts)
	if err == nil {
		err = s.move(watched)
	}
	if err != nil {
		if s.ctx.Err() == nil {
			log.WithError(err).WithField("id", d.ID).Error("follow delegation")
		}
		return
	}
	claimed := map[string]delegation.Watched{}
	for _, w := range watched {
		claimed[w.Script] = w
	}
	var arkAdd, arkRemove, chainAdd, chainRemove []string
	for _, script := range scripts {
		add, remove := &arkAdd, &arkRemove
		if onchain[script] {
			add, remove = &chainAdd, &chainRemove
		}
		w, ok := claimed[script]
		switch {
		case !active && !ok:
			*remove = append(*remove, script)
		case active && ok && !slices.ContainsFunc(w.Claims, func(c delegation.Claim) bool { return c.DelegationID != d.ID }):
			*add = append(*add, script)
		}
	}
	if len(arkAdd)+len(arkRemove)+len(chainAdd)+len(chainRemove) == 0 {
		return
	}
	log.WithFields(log.Fields{"id": d.ID, "status": d.Status, "add": len(arkAdd) + len(chainAdd), "remove": len(arkRemove) + len(chainRemove)}).Debug("delegation changed")
	if len(arkAdd)+len(arkRemove) > 0 {
		if err := s.sub.Update(s.ctx, arkAdd, arkRemove); err != nil && s.ctx.Err() == nil {
			log.WithError(err).Error("update the script subscription")
		}
	}
	if len(arkAdd) > 0 {
		s.wg.Go(func() { s.reconcile(arkAdd, nil) })
	}
	if len(chainAdd)+len(chainRemove) > 0 {
		if err := s.chainSub.Update(s.ctx, chainAdd, chainRemove); err != nil && s.ctx.Err() == nil {
			log.WithError(err).Error("update the chain subscription")
		}
	}
}

// rehome gives the coins at scripts to their owners.
func (s *Service) rehome(scripts []string) error {
	if len(scripts) == 0 {
		return nil
	}
	watched, err := s.coins.Watched(s.ctx, scripts)
	if err != nil {
		return err
	}
	return s.move(watched)
}

func (s *Service) move(watched []delegation.Watched) error {
	for _, w := range watched {
		moved, err := s.coins.Move(s.ctx, w.Script, w.Owner())
		if err != nil {
			return err
		}
		for _, c := range moved {
			log.WithFields(log.Fields{"outpoint": c.Outpoint, "delegation": c.DelegationID}).Debug("coin moved")
		}
	}
	return nil
}

// chainEvent applies a new tip to the onchain coins, or has the script listed when its status is not the stored one.
func (s *Service) chainEvent(ev ports.ChainEvent, now time.Time) {
	if ev.Tip != nil {
		s.tip = *ev.Tip
		coins, err := s.coins.Onchain(s.ctx)
		if err != nil {
			if s.ctx.Err() == nil {
				log.WithError(err).Error("list onchain coins")
			}
			return
		}
		var changes []delegation.Coin
		for _, c := range coins {
			if next, changed := refresh(c, c.Height, s.tip, now); changed {
				changes = append(changes, next)
			}
		}
		s.persist(changes, now)
		return
	}
	known, watched, err := s.coins.ScriptStatus(s.ctx, ev.Script)
	if err != nil {
		if s.ctx.Err() == nil {
			log.WithError(err).WithField("script", ev.Script).Error("read script status")
		}
		return
	}
	if !watched || known == ev.Status {
		return
	}
	s.inflight[ev.Script] = ev.Status
	s.wg.Go(func() { s.list(ev.Script, ev.Status) })
}

// list asks the chain for the utxos at script and feeds them back to the loop.
func (s *Service) list(script, status string) {
	select {
	case s.listing <- struct{}{}:
		defer func() { <-s.listing }()
	case <-s.ctx.Done():
		return
	}
	utxos, err := s.chain.Unspents(s.ctx, script)
	if err != nil {
		if s.ctx.Err() == nil {
			log.WithError(err).WithField("script", script).Error("list unspents")
		}
		return
	}
	s.send(unspents{script: script, status: status, utxos: utxos})
}

// reconcileOnchain applies a listing unless a newer status was seen since it was asked for.
func (s *Service) reconcileOnchain(ev unspents, now time.Time) {
	if want, ok := s.inflight[ev.script]; !ok || want != ev.status {
		return
	}
	delete(s.inflight, ev.script)
	if !s.update([]string{ev.script}, now, func(w delegation.Watched) []delegation.Coin {
		return syncUtxos(w, ev.utxos, s.tip, now)
	}) {
		return
	}
	if err := s.coins.SetScriptStatus(s.ctx, ev.script, ev.status); err != nil && s.ctx.Err() == nil {
		log.WithError(err).Error("store script status")
	}
}

func (s *Service) reconcileAll() {
	s.reconciling = true
	s.wg.Go(func() { s.reconcile(nil, reconcileDone{}) })
}

// reconcile asks arkd for the vtxos at scripts, every offchain one when nil, in chunks and feeds them
// back to the loop, then sends done when it is not nil.
func (s *Service) reconcile(scripts []string, done any) {
	if done != nil {
		defer s.send(done)
	}
	if scripts == nil {
		var err error
		if scripts, err = s.coins.Scripts(s.ctx, false); err != nil {
			if s.ctx.Err() == nil {
				log.WithError(err).Error("list scripts to reconcile")
			}
			return
		}
	}
	vtxos := 0
	for start := 0; start < len(scripts); start += ports.MaxScripts {
		chunk := scripts[start:min(start+ports.MaxScripts, len(scripts))]
		found, err := s.indexer.Vtxos(s.ctx, chunk)
		if err != nil {
			if s.ctx.Err() == nil {
				log.WithError(err).Error("reconcile coins")
			}
			return
		}
		result := make(reconciled, len(chunk))
		for _, script := range chunk {
			result[script] = nil
		}
		for _, v := range found {
			result[v.Script] = append(result[v.Script], v)
		}
		vtxos += len(found)
		s.send(result)
	}
	log.WithFields(log.Fields{"scripts": len(scripts), "vtxos": vtxos}).Info("coins reconciled")
}

func (s *Service) forward() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case ev, ok := <-s.sub.Events():
			if !ok {
				return
			}
			s.send(ev)
		case ev, ok := <-s.chainSub.Events():
			if !ok {
				return
			}
			s.send(ev)
		case <-s.sub.Reconnects():
			s.send(reconnected{})
		}
	}
}

func (s *Service) send(ev any) {
	select {
	case s.events <- ev:
	case <-s.ctx.Done():
	}
}

// update applies f to those of scripts the active delegations claim and stores what it changed; false
// when none is claimed or they could not be read.
func (s *Service) update(scripts []string, now time.Time, f func(delegation.Watched) []delegation.Coin) bool {
	watched, err := s.coins.Watched(s.ctx, scripts)
	if err != nil {
		if s.ctx.Err() == nil {
			log.WithError(err).Error("read watched scripts")
		}
		return false
	}
	var changes []delegation.Coin
	for _, w := range watched {
		changes = append(changes, f(w)...)
	}
	s.persist(changes, now)
	return len(watched) > 0
}

// release gives the coins back, ready again from retry.
func (s *Service) release(outpoints []string, retry time.Time) {
	if err := s.coins.Release(s.ctx, outpoints, retry); err != nil && s.ctx.Err() == nil {
		log.WithError(err).Error("release coins")
	}
}

func (s *Service) persist(changes []delegation.Coin, now time.Time) {
	for i, c := range changes {
		if c.Status == delegation.Present && c.Due.IsZero() {
			changes[i].Due = s.due(c, now)
		}
	}
	// stored before anything lands on them, so a succeeded attempt never shows a present coin
	if err := s.coins.Upsert(s.ctx, changes...); err != nil && s.ctx.Err() == nil {
		log.WithError(err).Error("store coins")
	}
	for _, c := range changes {
		fields := log.Fields{"outpoint": c.Outpoint, "delegation": c.DelegationID}
		if c.Status != delegation.Spent {
			log.WithFields(fields).WithField("due", c.Due).Debug("coin stored")
			continue
		}
		log.WithFields(fields).WithField("spent_by", c.SpentBy).Debug("coin spent")
		s.withdraw(c.DelegationID, c.Outpoint)
		s.landing(c, now)
	}
}

// due asks the delegation's template instance; a failure makes the coin due now and is logged.
func (s *Service) due(c delegation.Coin, now time.Time) time.Time {
	inst, err := s.delegations.Instance(s.ctx, c.DelegationID)
	if err != nil {
		log.WithError(err).WithField("delegation", c.DelegationID).Error("instantiate template")
		return now
	}
	return dueAt(inst.Template, c, now)
}

// dueAt is when the template instance becomes eligible to spend c.
func dueAt(inst *template.Instance, c delegation.Coin, now time.Time) time.Time {
	src := &template.Source{Amount: c.Amount, Expiry: c.ExpiresAt, CreatedAt: c.CreatedAt, Confirms: c.Confirmations}
	if op, err := wire.NewOutPointFromString(c.Outpoint); err == nil {
		src.Outpoint = *op
	}
	return inst.DueAt(c.Input, src, now)
}

// scriptsOf lists the scripts of outputs, once each.
func scriptsOf(outputs []ports.Output) []string {
	var out []string
	for _, o := range outputs {
		if !slices.Contains(out, o.Script) {
			out = append(out, o.Script)
		}
	}
	return out
}

func outpointsOf(coins []delegation.Coin) []string {
	out := make([]string, 0, len(coins))
	for _, c := range coins {
		out = append(out, c.Outpoint)
	}
	return out
}
