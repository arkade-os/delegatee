package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/delegatee/internal/config"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// batchExpiry is what the stand-in gives every batch.
var batchExpiry = arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1024}

// registered is an intent the stand-in holds for a batch.
type registered struct {
	id        string
	outpoints []string // the vtxos it spends
	boardings []boardingInput
	outputs   []*wire.TxOut // the offchain ones
	cosigners []string
}

// boardingInput is an onchain input of an intent.
type boardingInput struct {
	outpoint wire.OutPoint
	prevOut  *wire.TxOut
}

func (r *registered) spends(outpoint string) bool {
	return slices.Contains(r.outpoints, outpoint) ||
		slices.ContainsFunc(r.boardings, func(d boardingInput) bool { return d.outpoint.String() == outpoint })
}

// batch is a batch in flight: who was selected, confirmed and what they sent.
type batch struct {
	id        string
	selected  []*registered
	confirmed map[string]bool
	nonces    map[string]tree.TreeNonces
	sigs      map[string]tree.TreePartialSigs
	forfeits  map[string]int // forfeits received by vtxo outpoint
	boardings map[string]bool
	boarding  int // intents with boarding inputs
	signed    int // commitment transactions received with their boarding leaves
}

// Sessions stand in for arkd's: every duration it takes the oldest registered intents, up to a cap,
// asks them to confirm within half a duration, then runs the batch with the cosigners.
type sessions struct {
	duration  time.Duration
	cap       int
	queue     []*registered
	cur       *batch
	batches   int
	events    map[int]chan ports.BatchEvent
	listeners int
	failNext  string // fails the next batch with this reason once its intents confirmed
	paused    bool   // no batch takes any intent
	held      bool   // finalized batches do not land
	slow      time.Duration
	lifetime  time.Duration // of the vtxos a batch creates
	calls     []string
	commits   []string

	immediate                            bool   // a registration starts a batch before it returns
	blamed                               string // the outpoint whose intent the failure names
	dropAfter                            bool   // a batch fails once its forfeits arrived
	crashAtRegistration, crashAtForfeits bool   // the daemon's batch events end after the step
}

func newSessions() sessions {
	return sessions{duration: 2 * time.Second, cap: 128, lifetime: 30 * 24 * time.Hour, events: map[int]chan ports.BatchEvent{}}
}

// WithVtxoLifetime is how long the vtxos a batch creates live.
func WithVtxoLifetime(d time.Duration) func(*config.Config) {
	return func(c *config.Config) {
		a := c.Ark.(*ark)
		a.mu.Lock()
		defer a.mu.Unlock()
		a.sessions.lifetime = d
	}
}

// WithSessions sets how often the stand-in runs a batch and how many intents one takes.
func WithSessions(duration time.Duration, maxIntents int) func(*config.Config) {
	return func(c *config.Config) {
		a := c.Ark.(*ark)
		a.mu.Lock()
		defer a.mu.Unlock()
		a.sessions.duration, a.sessions.cap = duration, maxIntents
	}
}

// ForgetIntents drops the registered intents, as an arkd that restarted would.
func (a *ark) ForgetIntents() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions.queue = nil
}

// SelectAtRegistration makes the stand-in start a batch with an intent before its registration returns, while on.
func (a *ark) SelectAtRegistration(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions.immediate = on
}

func (a *ark) RegisterIntent(_ context.Context, proof, message string) error {
	if err := a.register(proof, message); err != nil {
		return err
	}
	a.mu.Lock()
	immediate, duration := a.sessions.immediate, a.sessions.duration
	a.mu.Unlock()
	if !immediate {
		return nil
	}
	if b := a.take(); b != nil {
		a.announce(b)
		go a.run(context.Background(), b, duration)
	}
	return nil
}

func (a *ark) register(proof, message string) error {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(proof), true)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	var msg intent.RegisterMessage
	if err := msg.Decode(message); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	r := &registered{id: ptx.UnsignedTx.TxHash().String(), cosigners: msg.CosignersPublicKeys}
	for i, in := range ptx.UnsignedTx.TxIn[1:] {
		if _, ok := a.chain.confirmed(in.PreviousOutPoint.String()); ok {
			r.boardings = append(r.boardings, boardingInput{outpoint: in.PreviousOutPoint, prevOut: ptx.Inputs[i+1].WitnessUtxo})
			continue
		}
		r.outpoints = append(r.outpoints, in.PreviousOutPoint.String())
	}
	for i, out := range ptx.UnsignedTx.TxOut {
		if !extension.IsExtension(out.PkScript) && !slices.Contains(msg.OnchainOutputIndexes, i) {
			r.outputs = append(r.outputs, out)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, op := range r.outpoints {
		if v, ok := a.vtxos[op]; !ok || v.Spent {
			return status.Errorf(codes.InvalidArgument, "vtxo %s is not spendable", op)
		}
	}
	for _, other := range a.sessions.queue {
		for _, d := range r.boardings {
			if other.spends(d.outpoint.String()) {
				return status.Errorf(codes.AlreadyExists, "duplicated input %s", d.outpoint)
			}
		}
		for _, op := range r.outpoints {
			if other.spends(op) {
				return status.Errorf(codes.AlreadyExists, "duplicated input %s", op)
			}
		}
	}
	a.sessions.queue = append(a.sessions.queue, r)
	a.sessions.calls = append(a.sessions.calls, "register")
	if a.sessions.crashAtRegistration {
		a.crashLocked()
	}
	return nil
}

func (a *ark) ConfirmRegistration(_ context.Context, id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	b := a.sessions.cur
	if b == nil || !slices.ContainsFunc(b.selected, func(r *registered) bool { return r.id == id }) {
		return status.Errorf(codes.FailedPrecondition, "intent %s is not awaiting confirmation", id)
	}
	b.confirmed[id] = true
	a.sessions.calls = append(a.sessions.calls, "confirm")
	return nil
}

func (a *ark) BatchEvents(ctx context.Context) (<-chan ports.BatchEvent, func(), error) {
	ch := make(chan ports.BatchEvent, 1024)
	a.mu.Lock()
	a.sessions.listeners++
	id := a.sessions.listeners
	a.sessions.events[id] = ch
	a.mu.Unlock()
	stop := func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		delete(a.sessions.events, id)
	}
	go func() {
		<-ctx.Done()
		stop()
	}()
	return ch, stop, nil
}

func (a *ark) UpdateTopics(context.Context, []string, []string) error { return nil }

func (a *ark) SubmitTreeNonces(_ context.Context, id, cosigner string, nonces tree.TreeNonces) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	b := a.sessions.cur
	if b == nil || b.id != id {
		return status.Errorf(codes.FailedPrecondition, "no batch %s", id)
	}
	b.nonces[cosigner] = nonces
	a.sessions.calls = append(a.sessions.calls, "nonces")
	return nil
}

func (a *ark) SubmitTreeSignatures(_ context.Context, id, cosigner string, sigs tree.TreePartialSigs) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	b := a.sessions.cur
	if b == nil || b.id != id {
		return status.Errorf(codes.FailedPrecondition, "no batch %s", id)
	}
	b.sigs[cosigner] = sigs
	a.sessions.calls = append(a.sessions.calls, "signatures")
	return nil
}

func (a *ark) SubmitSignedForfeitTxs(_ context.Context, forfeits []string, signedCommitment string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	b := a.sessions.cur
	if b == nil {
		return status.Error(codes.FailedPrecondition, "no batch")
	}
	if signedCommitment != "" {
		commitment, err := psbt.NewFromRawBytes(strings.NewReader(signedCommitment), true)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		leaves := 0
		for i, in := range commitment.UnsignedTx.TxIn {
			if b.boardings[in.PreviousOutPoint.String()] && len(commitment.Inputs[i].TaprootLeafScript) == 1 {
				leaves++
			}
		}
		if leaves == 0 {
			return status.Error(codes.InvalidArgument, "no boarding input of the commitment tx carries its leaf")
		}
		b.signed++
	}
	for _, raw := range forfeits {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		b.forfeits[ptx.UnsignedTx.TxIn[0].PreviousOutPoint.String()]++
	}
	a.sessions.calls = append(a.sessions.calls, "forfeits")
	if a.sessions.crashAtForfeits {
		a.crashLocked()
	}
	return nil
}

// runSessions takes a batch every duration until ctx ends.
func (a *ark) runSessions(ctx context.Context) {
	for {
		a.mu.Lock()
		duration := a.sessions.duration
		a.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(duration):
			a.session(ctx, duration)
		}
	}
}

func (a *ark) session(ctx context.Context, duration time.Duration) {
	b := a.take()
	if b == nil {
		return
	}
	a.announce(b)
	a.run(ctx, b, duration)
}

// announce tells the listeners which intents the batch selected.
func (a *ark) announce(b *batch) {
	selected := make([]string, len(b.selected))
	for i, r := range b.selected {
		selected[i] = r.id
	}
	a.emit(ports.BatchStarted{ID: b.id, Selected: selected, BatchExpiry: batchExpiry})
}

// run asks the selected intents to confirm, then settles the batch.
func (a *ark) run(ctx context.Context, b *batch, duration time.Duration) {
	defer func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.sessions.cur = nil
	}()
	a.until(ctx, duration/2, func() bool { return len(b.confirmed) == len(b.selected) })
	a.mu.Lock()
	var taking []*registered
	for _, r := range b.selected {
		if b.confirmed[r.id] {
			taking = append(taking, r)
		}
	}
	failure := a.sessions.failNext
	var blamed []string
	if a.sessions.blamed != "" {
		for _, r := range b.selected {
			if slices.Contains(r.outpoints, a.sessions.blamed) {
				blamed = append(blamed, r.id)
			}
		}
		a.sessions.blamed = ""
	}
	if len(taking) == 0 {
		failure = "no intent confirmed"
	}
	a.sessions.failNext = ""
	a.mu.Unlock()
	if failure != "" {
		a.emit(ports.BatchFailed{ID: b.id, Reason: failure, Blamed: blamed})
		return
	}
	if err := a.settle(ctx, b, taking, duration); err != nil {
		a.emit(ports.BatchFailed{ID: b.id, Reason: err.Error(), Blamed: ourFault(err.Error(), taking)})
	}
}

// ourFault blames all of taking when the reason says our nonces, signatures or forfeits were wrong or late.
func ourFault(reason string, taking []*registered) []string {
	if !strings.Contains(reason, "nonce") && !strings.Contains(reason, "signature") && !strings.Contains(reason, "forfeit") {
		return nil
	}
	var ids []string
	for _, r := range taking {
		ids = append(ids, r.id)
	}
	return ids
}

// take pops the oldest intents into the next batch, nil when there is none.
func (a *ark) take() *batch {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sessions.paused || len(a.sessions.queue) == 0 {
		return nil
	}
	n := min(a.sessions.cap, len(a.sessions.queue))
	a.sessions.batches++
	b := &batch{
		id: fmt.Sprintf("batch-%d", a.sessions.batches), selected: a.sessions.queue[:n], confirmed: map[string]bool{},
		nonces: map[string]tree.TreeNonces{}, sigs: map[string]tree.TreePartialSigs{}, forfeits: map[string]int{},
	}
	a.sessions.queue = slices.Clone(a.sessions.queue[n:])
	a.sessions.cur = b
	return b
}

// settle runs the batch of the intents that confirmed: trees, nonces, signatures, forfeits, landing.
func (a *ark) settle(ctx context.Context, b *batch, taking []*registered, duration time.Duration) error {
	forfeitKey := newKey(2).PubKey()
	forfeitScript, err := txscript.PayToTaprootScript(forfeitKey)
	if err != nil {
		return err
	}
	sweepRoot, err := sweepTapTreeRoot(forfeitKey, batchExpiry)
	if err != nil {
		return err
	}
	var leaves []tree.Leaf
	var boardings []boardingInput
	vtxos := 0
	cosigners := map[string]*btcec.PublicKey{}
	a.mu.Lock()
	b.boardings = map[string]bool{}
	a.mu.Unlock()
	for _, r := range taking {
		vtxos += len(r.outpoints)
		boardings = append(boardings, r.boardings...)
		a.mu.Lock()
		for _, d := range r.boardings {
			b.boardings[d.outpoint.String()] = true
		}
		if len(r.boardings) > 0 {
			b.boarding++
		}
		a.mu.Unlock()
		for _, out := range r.outputs {
			leaves = append(leaves, tree.Leaf{
				Outputs:             []tree.LeafOutput{{Amount: uint64(out.Value), Script: hex.EncodeToString(out.PkScript)}},
				CosignersPublicKeys: r.cosigners,
			})
		}
		for _, c := range r.cosigners {
			raw, err := hex.DecodeString(c)
			if err != nil {
				return err
			}
			if cosigners[c], err = btcec.ParsePubKey(raw); err != nil {
				return err
			}
		}
	}
	connectorLeaves := make([]tree.Leaf, vtxos)
	for i := range connectorLeaves {
		connectorLeaves[i] = tree.Leaf{
			Outputs:             []tree.LeafOutput{{Amount: 330, Script: hex.EncodeToString(forfeitScript)}},
			CosignersPublicKeys: []string{hex.EncodeToString(forfeitKey.SerializeCompressed())},
		}
	}
	batchScript, batchAmount, err := tree.BuildBatchOutput(leaves, sweepRoot)
	if err != nil {
		return err
	}
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: [32]byte{byte(len(b.id))}, Index: 7}, nil, nil))
	for _, d := range boardings {
		tx.AddTxIn(wire.NewTxIn(&d.outpoint, nil, nil))
	}
	tx.AddTxOut(wire.NewTxOut(batchAmount, batchScript))
	connectorAmount := int64(0)
	if vtxos > 0 {
		var connectorScript []byte
		if connectorScript, connectorAmount, err = tree.BuildConnectorOutput(connectorLeaves); err != nil {
			return err
		}
		tx.AddTxOut(wire.NewTxOut(connectorAmount, connectorScript))
	}
	commitment, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return err
	}
	commitment.Inputs[0].WitnessUtxo = wire.NewTxOut(batchAmount+connectorAmount, forfeitScript)
	for i, d := range boardings {
		commitment.Inputs[i+1].WitnessUtxo = d.prevOut
	}
	rawCommitment, err := commitment.B64Encode()
	if err != nil {
		return err
	}
	txid := tx.TxHash()
	vtxoTree, err := tree.BuildVtxoTree(&wire.OutPoint{Hash: txid, Index: 0}, leaves, sweepRoot, batchExpiry)
	if err != nil {
		return err
	}
	var connectorTree *tree.TxTree
	if vtxos > 0 {
		if connectorTree, err = tree.BuildConnectorTree(&wire.OutPoint{Hash: txid, Index: 1}, connectorLeaves); err != nil {
			return err
		}
	}
	coordinator, err := tree.NewTreeCoordinatorSession(sweepRoot, batchAmount, vtxoTree)
	if err != nil {
		return err
	}

	keys := slices.Collect(maps.Keys(cosigners))
	a.pause()
	a.emit(ports.TreeSigningStarted{ID: b.id, UnsignedCommitmentTx: rawCommitment, CosignersPubkeys: keys, VtxoTree: vtxoTree})
	if !a.until(ctx, duration, func() bool { return len(b.nonces) == len(keys) }) {
		return fmt.Errorf("missing nonces")
	}
	a.mu.Lock()
	for c, nonces := range b.nonces {
		coordinator.AddNonce(cosigners[c], nonces)
	}
	a.mu.Unlock()
	aggregated, err := coordinator.AggregateNonces()
	if err != nil {
		return err
	}
	a.pause()
	a.emit(ports.TreeNoncesAggregated{ID: b.id, TreeNonces: aggregated})
	if !a.until(ctx, duration, func() bool { return len(b.sigs) == len(keys) }) {
		return fmt.Errorf("missing signatures")
	}
	a.mu.Lock()
	for c, sigs := range b.sigs {
		if _, err := coordinator.AddSignatures(cosigners[c], sigs); err != nil {
			a.mu.Unlock()
			return fmt.Errorf("invalid signatures: %w", err)
		}
	}
	a.mu.Unlock()
	if _, err := coordinator.SignTree(); err != nil {
		return err
	}

	a.pause()
	a.emit(ports.BatchFinalization{ID: b.id, CommitmentTx: rawCommitment, ConnectorTree: connectorTree})
	owed := func() bool {
		if b.signed < b.boarding {
			return false
		}
		for _, r := range taking {
			for _, op := range r.outpoints {
				if b.forfeits[op] == 0 {
					return false
				}
			}
		}
		return true
	}
	if !a.until(ctx, duration, owed) {
		return fmt.Errorf("missing forfeits")
	}
	a.mu.Lock()
	if a.sessions.dropAfter {
		a.mu.Unlock()
		return fmt.Errorf("batch failed after the forfeits")
	}
	a.sessions.commits = append(a.sessions.commits, txid.String())
	a.mu.Unlock()
	a.pause()
	a.emit(ports.BatchFinalized{ID: b.id, CommitmentTxid: txid.String()})
	a.until(ctx, time.Hour, func() bool { return !a.sessions.held })
	a.land(txid.String(), taking, vtxoTree)
	return nil
}

// land spends the vtxos of the intents and creates the ones of the leaves, then tells the subscriptions.
func (a *ark) land(commitment string, taking []*registered, vtxoTree *tree.TxTree) {
	a.mu.Lock()
	defer a.mu.Unlock()
	events := map[string]*clientlib.ScriptEventData{}
	event := func(script string) *clientlib.ScriptEventData {
		if events[script] == nil {
			events[script] = &clientlib.ScriptEventData{Txid: commitment}
		}
		return events[script]
	}
	for _, r := range taking {
		for _, op := range r.outpoints {
			v := a.vtxos[op]
			v.Spent, v.SpentBy, v.SettledBy = true, "forfeit-"+op, commitment
			a.vtxos[op] = v
			event(v.Script).SpentVtxos = append(event(v.Script).SpentVtxos, v)
		}
		for _, d := range r.boardings {
			a.chain.spend(d.outpoint.String())
		}
	}
	for _, leaf := range vtxoTree.Leaves() {
		raw, err := leaf.B64Encode()
		if err != nil {
			panic(err)
		}
		txid := leaf.UnsignedTx.TxHash().String()
		a.txs[txid] = raw
		out := leaf.UnsignedTx.TxOut[0]
		script := hex.EncodeToString(out.PkScript)
		v := clientlib.Vtxo{
			Script: script, Amount: uint64(out.Value), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(a.sessions.lifetime),
			CommitmentTxids: []string{commitment}, Outpoint: clientlib.Outpoint{Txid: txid},
		}
		a.vtxos[txid+":0"] = v
		event(script).NewVtxos = append(event(script).NewVtxos, v)
	}
	for script, data := range events {
		a.push(script, clientlib.ScriptEvent{Data: data})
	}
}

func (a *ark) emit(ev ports.BatchEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ch := range a.sessions.events {
		ch <- ev
	}
}

// crashLocked ends every listener's batch events, as the daemon dying would.
func (a *ark) crashLocked() {
	for id, ch := range a.sessions.events {
		delete(a.sessions.events, id)
		close(ch)
	}
}

// until polls cond until it holds or timeout passes; false on a timeout or when ctx ends.
func (a *ark) until(ctx context.Context, timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		a.mu.Lock()
		ok := cond()
		a.mu.Unlock()
		if ok {
			return true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// SlowPhases makes the stand-in wait d before it moves a batch to its next phase.
func (a *ark) SlowPhases(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions.slow = d
}

func (a *ark) pause() {
	a.mu.Lock()
	d := a.sessions.slow
	a.mu.Unlock()
	time.Sleep(d)
}

func (a *ark) InBatch() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessions.cur != nil
}

// RegisteredCoins lists the vtxos the registered intents spend, oldest intent first.
func (a *ark) RegisteredCoins() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, r := range a.sessions.queue {
		out = append(out, r.outpoints...)
	}
	return out
}

// FailNextBatch fails the next batch, once its intents confirmed, with reason.
func (a *ark) FailNextBatch(reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions.failNext = reason
}

// FailNextBatchBlaming fails the next batch with reason, naming the intent that spends outpoint.
func (a *ark) FailNextBatchBlaming(outpoint, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions.failNext, a.sessions.blamed = reason, outpoint
}

// CrashAfterRegistration ends the batch events of the daemon once an intent is registered, while on.
func (a *ark) CrashAfterRegistration(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions.crashAtRegistration = on
}

// CrashAfterForfeits ends the batch events of the daemon once forfeits arrived, while on.
func (a *ark) CrashAfterForfeits(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions.crashAtForfeits = on
}

// FailAfterForfeits makes batches fail once their forfeits arrived, while on: nothing is spent.
func (a *ark) FailAfterForfeits(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions.dropAfter = on
}

// PauseBatches makes the batches take no intent while on.
func (a *ark) PauseBatches(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions.paused = on
}

// HoldLanding keeps finalized batches from landing while on.
func (a *ark) HoldLanding(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions.held = on
}

func (a *ark) Registered() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.sessions.queue)
}

func (a *ark) batchCalls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.sessions.calls)
}

// Commitments lists the commitment txids of the batches that finalized.
func (a *ark) Commitments() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.sessions.commits)
}

func (a *ark) registeredCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, c := range a.sessions.calls {
		if c == "register" {
			n++
		}
	}
	return n
}

// sweepTapTreeRoot is the root of the sweep path arkd gives every vtxo tree output: itself alone, once the batch expired.
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
