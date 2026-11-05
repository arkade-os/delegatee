package execution

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	delegationapp "github.com/arkade-os/delegatee/internal/core/application/delegation"
	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/internal/core/domain/execution"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// registration is an intent registered at arkd, with what signs for it.
type registration struct {
	attempt delegation.Attempt
	intent  *execution.Intent
	dead    atomic.Bool // arkd refused the intent
}

func (r *registration) proofTxid() string {
	proof, _ := r.attempt.Proof()
	return proof.Txid
}

// current is the batch that carries our intents.
type current struct {
	id      string
	expiry  arklib.RelativeLocktime
	intents []*registration    // the ones we confirmed
	session tree.SignerSession // nil until arkd asks our key to cosign
	topics  []string           // our cosigner key and coin outpoints, which arkd sends our trees for
}

// batchWorker owns the intents registered at arkd and follows the batches that take them.
type batchWorker struct {
	s        *Service
	commands chan []execution.Entry
	built    chan *registration
	intents  map[string]*registration // by proof txid
	inFlight *current
	quiet    chan chan struct{}
	exited   chan struct{}
	idle     chan struct{} // closed once no batch holds our intents, when Stop waits for it
	closing  bool          // no new intent is registered or confirmed
}

func newBatchWorker(s *Service) *batchWorker {
	return &batchWorker{
		s: s, commands: make(chan []execution.Entry, 256), built: make(chan *registration, 256), intents: map[string]*registration{},
		quiet: make(chan chan struct{}), exited: make(chan struct{}),
	}
}

// register asks the worker to register the entries' intents.
func (b *batchWorker) register(entries []execution.Entry) {
	select {
	case b.commands <- entries:
	case <-b.s.ctx.Done():
	}
}

// adopt takes the intents already registered, so a batch event never misses one arkd knows.
func (b *batchWorker) adopt() {
	for {
		select {
		case h := <-b.built:
			b.intents[h.proofTxid()] = h
		default:
			return
		}
	}
}

func (b *batchWorker) run(events <-chan ports.BatchEvent, stop func()) {
	defer stop()
	defer close(b.exited)
	tick := time.NewTicker(max(b.s.limits.IntentTimeout/4, 10*time.Millisecond))
	defer tick.Stop()
	for {
		select {
		case <-b.s.ctx.Done():
			return
		case idle := <-b.quiet:
			b.closing, b.idle = true, idle
			b.settled()
		case entries := <-b.commands:
			if b.closing {
				continue
			}
			for _, e := range entries {
				b.s.wg.Go(func() { b.build(e) })
			}
		case h := <-b.built:
			b.intents[h.proofTxid()] = h
		case ev, ok := <-events:
			if !ok {
				if b.s.ctx.Err() == nil {
					log.Error("batch events ended")
				}
				return
			}
			b.adopt()
			b.handle(ev)
		case now := <-tick.C:
			b.expire(now)
		}
	}
}

// quiesce stops the worker from taking part in new batches and waits at most d for the batch in flight.
func (b *batchWorker) quiesce(d time.Duration) {
	idle := make(chan struct{})
	timeout := time.After(d)
	select {
	case b.quiet <- idle:
	case <-b.exited:
		return
	case <-timeout:
		return
	}
	select {
	case <-idle:
	case <-b.exited:
	case <-timeout:
	}
}

// settled tells Stop that no batch holds our intents.
func (b *batchWorker) settled() {
	if b.inFlight == nil && b.idle != nil {
		close(b.idle)
		b.idle = nil
	}
}

// build registers the entry's intent at arkd and persists the attempt; a failure ends the attempt.
func (b *batchWorker) build(e execution.Entry) {
	s := b.s
	select {
	case s.slots <- struct{}{}:
	case <-s.ctx.Done():
		return
	}
	defer func() { <-s.slots }()
	ctx, cancel := context.WithTimeout(s.ctx, s.limits.AttemptTimeout)
	defer cancel()
	outpoints := e.Outpoints()
	inst, err := s.delegations.Instance(ctx, e.DelegationID)
	if err != nil {
		log.WithError(err).WithField("delegation", e.DelegationID).Error("instantiate template")
		s.send(skipped{coins: outpoints, delegation: e.DelegationID})
		return
	}
	a, err := inst.Delegation.Attempt(e.Coins)
	if err != nil {
		log.WithError(err).WithField("delegation", e.DelegationID).Warn("no attempt")
		s.send(skipped{coins: outpoints, delegation: e.DelegationID})
		return
	}
	fail := func(err error) { s.send(attemptFailed{attempt: a, err: err, retryIn: s.session.Duration}) }
	if inst.Disabled {
		s.send(skipped{coins: outpoints, delegation: e.DelegationID})
		return
	}
	in, err := b.intentOf(ctx, inst, e)
	if err != nil {
		fail(err)
		return
	}
	proof, err := psbt.NewFromRawBytes(strings.NewReader(in.Proof), true)
	if err != nil {
		fail(fmt.Errorf("intent proof: %w", err))
		return
	}
	proofTxid := proof.UnsignedTx.TxHash().String()
	var raw bytes.Buffer
	if err := in.Tx.Serialize(&raw); err != nil {
		fail(err)
		return
	}
	if err := a.Submit(delegation.Tx{Raw: raw.Bytes(), Txid: proofTxid}); err != nil {
		fail(err)
		return
	}
	if err := s.attempts.AddOrUpdate(ctx, &a); err != nil {
		log.WithError(err).WithField("delegation", e.DelegationID).Error("record attempt")
		fail(err)
		return
	}
	h := &registration{attempt: a, intent: in}
	select {
	case b.built <- h:
	case <-s.ctx.Done():
		return
	}
	s.send(attemptUpdate{attempt: a})
	if err := s.ark.RegisterIntent(ctx, in.Proof, in.Message); err != nil {
		h.dead.Store(true)
		fail(fmt.Errorf("arkd: %w", refusal(ctx, err)))
		return
	}
	log.WithFields(log.Fields{"delegation": e.DelegationID, "intent": proofTxid}).Info("intent registered")
}

// intentOf builds the intent of the entry's coins, cosigned by the emulator when the covenant needs it.
func (b *batchWorker) intentOf(ctx context.Context, inst *delegationapp.Instance, e execution.Entry) (*execution.Intent, error) {
	s := b.s
	txs, err := s.sources(ctx, e.Coins)
	if err != nil {
		return nil, err
	}
	info, err := s.ark.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("arkd info: %w", err)
	}
	in, err := execution.BuildIntent(inst.Template, inst.Delegation.Inputs, e.Coins, txs, template.Fee{Intent: info.IntentFees, Dust: info.Dust}, s.cosignerKey.PubKey())
	if err != nil {
		return nil, err
	}
	if in.HasArkadePacket {
		if in.Proof, err = s.emulator.SubmitIntent(ctx, *in); err != nil {
			return nil, fmt.Errorf("emulator: %w", refusal(ctx, err))
		}
	}
	return in, nil
}

func (b *batchWorker) handle(ev ports.BatchEvent) {
	switch ev := ev.(type) {
	case ports.BatchStarted:
		b.started(ev)
	case ports.TreeSigningStarted:
		b.signing(ev)
	case ports.TreeNoncesAggregated:
		b.signatures(ev)
	case ports.BatchFinalization:
		b.finalization(ev)
	case ports.BatchFinalized:
		b.finalized(ev)
	case ports.BatchFailed:
		if b.inFlight != nil && b.inFlight.id == ev.ID {
			b.abort(fmt.Errorf("batch %s failed: %s", ev.ID, ev.Reason), ev.Blamed...)
		}
	case ports.StreamReconnected:
		if b.inFlight != nil {
			b.abort(errors.New("batch events interrupted"))
		}
	}
}

// started confirms the intents the batch selected and tells the loop to register the next ones.
func (b *batchWorker) started(ev ports.BatchStarted) {
	if b.closing {
		return
	}
	if b.inFlight != nil {
		b.abort(fmt.Errorf("batch %s started before %s ended", ev.ID, b.inFlight.id))
	}
	b.adopt()
	var ours []*registration
	for _, id := range ev.Selected {
		if h, ok := b.intents[id]; ok && !h.dead.Load() {
			ours = append(ours, h)
			delete(b.intents, id)
		}
	}
	if len(ours) == 0 {
		return
	}
	topics := topicsOf(b.s.cosigner, ours)
	if err := b.s.ark.UpdateTopics(b.s.ctx, topics, nil); err != nil {
		log.WithError(err).Warn("follow the trees of a batch")
	}
	errs := make([]error, len(ours))
	var g errgroup.Group
	g.SetLimit(cap(b.s.slots))
	for i, h := range ours {
		g.Go(func() error {
			errs[i] = b.s.ark.ConfirmRegistration(b.s.ctx, h.proofTxid())
			return nil
		})
	}
	_ = g.Wait()
	r := &current{id: ev.ID, expiry: ev.BatchExpiry, topics: topics}
	var taken []int64
	for i, h := range ours {
		if errs[i] != nil {
			b.s.send(attemptFailed{attempt: h.attempt, err: fmt.Errorf("confirm intent: %w", errs[i]), retryIn: b.s.session.Duration})
			continue
		}
		r.intents = append(r.intents, h)
		taken = append(taken, h.attempt.DelegationID)
	}
	log.WithFields(log.Fields{"batch": ev.ID, "ours": len(ours), "confirmed": len(r.intents)}).Info("batch started")
	b.s.send(selected{delegations: taken})
	if len(r.intents) > 0 {
		b.inFlight = r
		return
	}
	b.unfollow(r)
}

func topicsOf(cosigner string, intents []*registration) []string {
	topics := []string{cosigner}
	for _, h := range intents {
		topics = append(topics, h.attempt.Coins...)
	}
	slices.Sort(topics)
	return slices.Compact(topics)
}

// unfollow stops the trees of a batch coming.
func (b *batchWorker) unfollow(r *current) {
	if b.s.ctx.Err() != nil {
		return
	}
	if err := b.s.ark.UpdateTopics(b.s.ctx, nil, r.topics); err != nil {
		log.WithError(err).Warn("unfollow the trees of a batch")
	}
}

// signing sends our key's nonces when the batch asks it to cosign.
func (b *batchWorker) signing(ev ports.TreeSigningStarted) {
	r := b.inFlight
	if r == nil || r.id != ev.ID {
		return
	}
	commitment, err := psbt.NewFromRawBytes(strings.NewReader(ev.UnsignedCommitmentTx), true)
	if err != nil || commitment.UnsignedTx == nil || len(commitment.UnsignedTx.TxOut) == 0 {
		b.abort(errors.New("commitment tx has no batch output"))
		return
	}
	root, err := sweepTapTreeRoot(b.s.info.ForfeitPubkey, r.expiry)
	if err != nil {
		b.abort(err)
		return
	}
	if r.session != nil || !slices.Contains(ev.CosignersPubkeys, b.s.cosigner) {
		return
	}
	session := tree.NewTreeSignerSession(b.s.cosignerKey)
	if err := session.Init(root, commitment.UnsignedTx.TxOut[0].Value, ev.VtxoTree); err != nil {
		b.abort(err)
		return
	}
	nonces, err := session.GetNonces()
	if err == nil {
		err = b.s.ark.SubmitTreeNonces(b.s.ctx, ev.ID, b.s.cosigner, nonces)
	}
	if err != nil {
		b.abort(fmt.Errorf("tree nonces: %w", err))
		return
	}
	r.session = session
}

// signatures answers the aggregated nonces with our partial signatures.
func (b *batchWorker) signatures(ev ports.TreeNoncesAggregated) {
	r := b.inFlight
	if r == nil || r.id != ev.ID || r.session == nil {
		return
	}
	r.session.SetAggregatedNonces(ev.TreeNonces)
	sigs, err := r.session.Sign()
	if err == nil {
		err = b.s.ark.SubmitTreeSignatures(b.s.ctx, ev.ID, b.s.cosigner, sigs)
	}
	if err != nil {
		b.abort(fmt.Errorf("tree signatures: %w", err))
		return
	}
}

// finalization hands arkd the forfeits of every intent.
func (b *batchWorker) finalization(ev ports.BatchFinalization) {
	r := b.inFlight
	if r == nil || r.id != ev.ID || r.session == nil {
		return
	}
	var connectors []*psbt.Packet
	var flat tree.FlatTxTree
	if ev.ConnectorTree != nil {
		var err error
		if flat, err = ev.ConnectorTree.Serialize(); err != nil {
			b.abort(err)
			return
		}
		connectors = ev.ConnectorTree.Leaves()
	}
	forfeits := make([][]string, len(r.intents))
	for i, h := range r.intents {
		n := h.intent.Vtxos()
		if len(connectors) < n {
			b.abort(fmt.Errorf("got %d connectors for %d vtxos", len(connectors), n))
			return
		}
		var err error
		if forfeits[i], err = h.intent.Forfeits(connectors[:n], b.s.info.ForfeitOutputScript); err != nil {
			b.abort(err)
			return
		}
		connectors = connectors[n:]
	}
	var g errgroup.Group
	g.SetLimit(cap(b.s.slots))
	for i, h := range r.intents {
		g.Go(func() error { return b.forfeit(h, forfeits[i], flat, ev.CommitmentTx) })
	}
	if err := g.Wait(); err != nil {
		b.abort(err)
	}
}

// forfeit has the emulator cosign the forfeits and the boarding inputs when the covenant needs it, signs
// them and submits them.
func (b *batchWorker) forfeit(h *registration, forfeits []string, connectors tree.FlatTxTree, commitmentTx string) error {
	signed, remoteCommitment := forfeits, ""
	if h.intent.HasArkadePacket {
		boarding, err := boardingCommitment(h.intent, commitmentTx)
		if err != nil {
			return err
		}
		if signed, remoteCommitment, err = b.s.emulator.SubmitFinalization(b.s.ctx, *h.intent, forfeits, connectors, boarding); err != nil {
			return fmt.Errorf("emulator finalization: %w", refusal(b.s.ctx, err))
		}
	}
	signed, err := signForfeits(forfeits, signed)
	if err != nil {
		return err
	}
	signedCommitment, err := signCommitment(h.intent, commitmentTx, remoteCommitment)
	if err != nil {
		return err
	}
	if err := b.s.ark.SubmitSignedForfeitTxs(b.s.ctx, signed, signedCommitment); err != nil {
		return fmt.Errorf("forfeits: %w", err)
	}
	return nil
}

// finalized ends the batch: our attempts wait for the coins table to show them spent.
func (b *batchWorker) finalized(ev ports.BatchFinalized) {
	r := b.inFlight
	if r == nil || r.id != ev.ID {
		return
	}
	b.inFlight = nil
	defer b.settled()
	b.unfollow(r)
	for _, h := range r.intents {
		h.attempt.AddTx(delegation.Tx{Txid: ev.CommitmentTxid, Onchain: true, Spends: true})
		if err := b.s.attempts.AddOrUpdate(b.s.ctx, &h.attempt); err != nil {
			b.s.send(attemptFailed{attempt: h.attempt, err: err, retryIn: b.s.session.Duration})
			continue
		}
		b.s.send(attemptDone{attempt: h.attempt})
	}
	log.WithFields(log.Fields{"batch": ev.ID, "commitment_txid": ev.CommitmentTxid, "intents": len(r.intents)}).Info("batch finalized")
}

// abort fails the attempts of the batch: their coins are tried again on a later one, the blamed ones after a ban.
// A daemon that is stopping leaves them as they are.
func (b *batchWorker) abort(err error, blamed ...string) {
	r := b.inFlight
	b.inFlight = nil
	defer b.settled()
	if r == nil || b.s.ctx.Err() != nil {
		return
	}
	b.unfollow(r)
	log.WithError(err).WithField("batch", r.id).Warn("batch ended for our intents")
	for _, h := range r.intents {
		ev := attemptFailed{attempt: h.attempt, err: err}
		if slices.Contains(blamed, h.proofTxid()) {
			ev.retryIn = max(ev.retryIn, b.s.limits.BanDuration)
		}
		b.s.send(ev)
	}
}

// expire forgets the intents no batch selected within the timeout; their coins are queued again.
func (b *batchWorker) expire(now time.Time) {
	for id, h := range b.intents {
		a := h.attempt
		if h.dead.Load() {
			delete(b.intents, id)
			continue
		}
		if now.Before(a.CreatedAt.Add(b.s.limits.IntentTimeout)) {
			continue
		}
		delete(b.intents, id)
		b.s.send(attemptFailed{attempt: h.attempt, err: errNotSelected, retryIn: b.s.session.Duration})
	}
}

// enqueue puts the ready coins of an intent delegation in the queue; the plan decides when they go.
func (s *Service) enqueue(ev intentReady) {
	e := execution.NewEntry(ev.coins, s.limits.Reserve)
	if _, ok := s.entries[e.DelegationID]; !ok {
		s.entries[e.DelegationID] = e
		log.WithFields(log.Fields{"delegation": e.DelegationID, "deadline": e.Deadline}).Debug("queued")
	}
}

func (s *Service) dequeue(delegationID int64) {
	delete(s.entries, delegationID)
}

// withdraw takes the delegation's entry out of the queue while it is not reserved, only when it holds one
// of outpoints if any are given, and gives its coins back.
func (s *Service) withdraw(delegationID int64, outpoints ...string) {
	e, ok := s.entries[delegationID]
	if !ok || e.Reserved {
		return
	}
	if len(outpoints) > 0 && !slices.ContainsFunc(e.Outpoints(), func(op string) bool { return slices.Contains(outpoints, op) }) {
		return
	}
	delete(s.entries, delegationID)
	s.release(e.Outpoints(), time.Time{})
}

func sweepTapTreeRoot(forfeitKey *btcec.PublicKey, expiry arklib.RelativeLocktime) ([]byte, error) {
	sweep, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{forfeitKey}},
		Locktime:        expiry,
	}).Script()
	if err != nil {
		return nil, err
	}
	root := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(sweep)).RootNode.TapHash()
	return root.CloneBytes(), nil
}
