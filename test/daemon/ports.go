package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/executor/internal/core/domain/execution"
	"github.com/arkade-os/executor/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ark stands in for arkd and its indexer: fixed keys on regtest, vtxos the test lands and spends,
// arkd's cap of 1000 scripts per call, offchain transactions it signs as the server, and counters
// of what the daemon asked.
type ark struct {
	clientlib.Indexer

	mu                sync.Mutex
	server            *btcec.PrivateKey
	vtxos             map[string]clientlib.Vtxo
	txs               map[string]string // virtual transactions by txid, base64 psbt
	subs              map[string]*subscription
	txStreams         map[int]chan clientlib.TransactionEvent
	vtxosDelay        time.Duration
	SubscriptionSizes []int // scripts per subscription opened
	VtxosChunks       []int // scripts per GetVtxos call answered

	Submitted    []string // txids in order of submission
	refuseSubmit error
	unreachable  bool // Info fails
	intentFee    string
	boardingFee  string
	chain        *chain // where the boarding inputs boarded by a batch are spent
	sessions     sessions
	once         sync.Once // starts the batches
}

type subscription struct {
	scripts map[string]struct{}
	events  chan clientlib.ScriptEvent
}

// emulator stands in for the emulator: a fixed signer key. It submits and finalizes the
// transactions it signs at arkd, and returns the other messages as they came.
type emulator struct {
	signer        *btcec.PublicKey
	ark           *ark
	mu            sync.Mutex
	refuse        error
	hangBefore    bool // SubmitTx waits for its context before reaching arkd
	hangAfter     bool // SubmitTx waits for its context once arkd finalized
	Signed        int
	Intents       int // intents cosigned
	Finalizations int // forfeits cosigned
}

func (a *ark) Info(context.Context) (ports.ArkInfo, error) {
	a.mu.Lock()
	down := a.unreachable
	a.mu.Unlock()
	if down {
		return ports.ArkInfo{}, status.Error(codes.Unavailable, "connection refused")
	}
	unroll, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{a.server.PubKey()}},
		Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
	}).Script()
	if err != nil {
		return ports.ArkInfo{}, err
	}
	forfeitScript, err := txscript.PayToTaprootScript(newKey(2).PubKey())
	if err != nil {
		return ports.ArkInfo{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return ports.ArkInfo{
		Network:             arklib.BitcoinRegTest,
		SignerPubkey:        a.server.PubKey(),
		ForfeitPubkey:       newKey(2).PubKey(),
		ForfeitOutputScript: forfeitScript,
		Dust:                330,
		CheckpointTapscript: unroll,
		SessionDuration:     a.sessions.duration,
		IntentFees: arkfee.Config{
			IntentOffchainInputProgram: a.intentFee, IntentOnchainInputProgram: a.boardingFee,
		},
	}, nil
}

// Unreachable makes the daemon's question about arkd fail as an arkd that cannot be reached would
// answer.
func (a *ark) Unreachable(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.unreachable = on
}

// ChargeIntentFee makes arkd charge sats per vtxo an intent spends, none when zero.
func (a *ark) ChargeIntentFee(sats int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.intentFee = feeProgram(sats)
}

// ChargeBoardingFee makes arkd charge sats per boarding input an intent spends, none when zero.
func (a *ark) ChargeBoardingFee(sats int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.boardingFee = feeProgram(sats)
}

// Fund lands a vtxo at script created by a real transaction the daemon can fetch, and returns its
// outpoint.
func (a *ark) Fund(script string, amount uint64, expiresAt time.Time) string {
	return a.FundAged(script, amount, 0, expiresAt)
}

// FundAged is Fund for a vtxo created age ago.
func (a *ark) FundAged(
	script string, amount uint64, age time.Duration, expiresAt time.Time,
) string {
	pkScript, err := hex.DecodeString(script)
	if err != nil {
		panic(err)
	}
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(
		&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: [32]byte{byte(len(a.txs))}, Index: 0}},
	)
	tx.AddTxOut(wire.NewTxOut(int64(amount), pkScript))
	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		panic(err)
	}
	raw, err := ptx.B64Encode()
	if err != nil {
		panic(err)
	}
	txid := tx.TxHash().String()
	a.mu.Lock()
	a.txs[txid] = raw
	a.mu.Unlock()
	outpoint := txid + ":0"
	a.landAt(script, outpoint, amount, time.Now().Add(-age), expiresAt)
	return outpoint
}

// RefuseSubmit makes SubmitTx fail with err, nil accepting again.
func (a *ark) RefuseSubmit(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refuseSubmit = err
}

func (a *ark) SubmitTx(
	_ context.Context, arkTx string, checkpoints []string,
) (string, string, []string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.refuseSubmit != nil {
		return "", "", nil, a.refuseSubmit
	}
	txid, signedArk, err := a.signAsServer(arkTx)
	if err != nil {
		return "", "", nil, status.Error(codes.InvalidArgument, err.Error())
	}
	signed := make([]string, len(checkpoints))
	for i, cp := range checkpoints {
		if _, signed[i], err = a.signAsServer(cp); err != nil {
			return "", "", nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	a.Submitted = append(a.Submitted, txid)
	return txid, signedArk, signed, nil
}

func (a *ark) GetVirtualTxs(
	_ context.Context, txids []string, _ ...clientlib.PageOption,
) (*clientlib.VirtualTxsResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	resp := &clientlib.VirtualTxsResponse{}
	for _, txid := range txids {
		if raw, ok := a.txs[txid]; ok {
			resp.Txs = append(resp.Txs, raw)
		}
	}
	return resp, nil
}

// Land puts a vtxo at script and tells the subscriptions.
func (a *ark) Land(script, outpoint string, amount uint64, expiresAt time.Time) {
	a.landAt(script, outpoint, amount, time.Now(), expiresAt)
}

// Spend marks a vtxo spent by txid and tells the subscriptions.
func (a *ark) Spend(outpoint, txid string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := a.vtxos[outpoint]
	v.Spent, v.SpentBy = true, txid
	a.vtxos[outpoint] = v
	a.push(
		v.Script,
		clientlib.ScriptEvent{
			Data: &clientlib.ScriptEventData{Txid: txid, SpentVtxos: []clientlib.Vtxo{v}},
		},
	)
}

// Reconnect tells every subscription its stream came back.
func (a *ark) Reconnect() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, sub := range a.subs {
		sub.events <- clientlib.ScriptEvent{Connection: &clientlib.StreamConnectionEvent{State: clientlib.StreamConnectionStateReconnected}}
	}
}

func (a *ark) GetVtxos(
	ctx context.Context, opts ...clientlib.GetVtxosOption,
) (*clientlib.VtxosResponse, error) {
	o, err := clientlib.ApplyGetVtxosOptions(opts...)
	if err != nil {
		return nil, err
	}
	if len(o.Scripts) == 0 || len(o.Scripts) > ports.MaxScripts {
		return nil, fmt.Errorf(
			"arkd takes 1 to %d scripts, got %d", ports.MaxScripts, len(o.Scripts),
		)
	}
	a.mu.Lock()
	delay := a.vtxosDelay
	a.mu.Unlock()
	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.VtxosChunks = append(a.VtxosChunks, len(o.Scripts))
	resp := &clientlib.VtxosResponse{}
	asked := make(map[string]struct{}, len(o.Scripts))
	for _, script := range o.Scripts {
		asked[script] = struct{}{}
	}
	for _, v := range a.vtxos {
		if _, ok := asked[v.Script]; ok {
			resp.Vtxos = append(resp.Vtxos, v)
		}
	}
	return resp, nil
}

func (a *ark) NewSubscription(
	_ context.Context, scripts []string,
) (string, <-chan clientlib.ScriptEvent, func(), error) {
	if len(scripts) == 0 || len(scripts) > ports.MaxScripts {
		return "", nil, nil, fmt.Errorf(
			"arkd takes 1 to %d scripts, got %d", ports.MaxScripts, len(scripts),
		)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	id := fmt.Sprint(len(a.SubscriptionSizes) + 1)
	a.SubscriptionSizes = append(a.SubscriptionSizes, len(scripts))
	sub := &subscription{
		scripts: map[string]struct{}{},
		events:  make(chan clientlib.ScriptEvent, 1024),
	}
	for _, script := range scripts {
		sub.scripts[script] = struct{}{}
	}
	a.subs[id] = sub
	stop := func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		delete(a.subs, id)
	}
	return id, sub.events, stop, nil
}

func (a *ark) UpdateSubscription(_ context.Context, id string, add, remove []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	sub, ok := a.subs[id]
	if !ok {
		return fmt.Errorf("subscription %s not found", id)
	}
	for _, script := range remove {
		delete(sub.scripts, script)
	}
	for _, script := range add {
		sub.scripts[script] = struct{}{}
	}
	if len(sub.scripts) > ports.MaxScripts {
		return fmt.Errorf("subscription %s exceeds %d scripts", id, ports.MaxScripts)
	}
	return nil
}

func (a *ark) Close() {}

func (a *ark) GetTransactionsStream(
	context.Context,
) (<-chan clientlib.TransactionEvent, func(), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := len(a.txStreams) + 1
	for a.txStreams[id] != nil {
		id++
	}
	ch := make(chan clientlib.TransactionEvent, 64)
	a.txStreams[id] = ch
	return ch, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.txStreams[id] == ch {
			delete(a.txStreams, id)
			close(ch)
		}
	}, nil
}

// Stream puts an ark transaction on the transaction stream.
func (a *ark) Stream(tx *psbt.Packet) {
	raw, err := tx.B64Encode()
	if err != nil {
		panic(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ch := range a.txStreams {
		ch <- clientlib.TransactionEvent{ArkTx: &clientlib.TxNotification{TxData: clientlib.TxData{Txid: tx.UnsignedTx.TxHash().String(), Tx: raw}}}
	}
}

// Streaming is how many readers the transaction stream has.
func (a *ark) Streaming() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.txStreams)
}

// Subscriptions is how many are open.
func (a *ark) Subscriptions() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.subs)
}

func (e *emulator) Info(context.Context) (ports.EmulatorInfo, error) {
	return ports.EmulatorInfo{SignerPubkey: e.signer}, nil
}

func (e *emulator) SubmitTx(
	ctx context.Context, tx string, checkpoints []string,
) (string, []string, error) {
	e.mu.Lock()
	refuse, before, after := e.refuse, e.hangBefore, e.hangAfter
	e.mu.Unlock()
	if refuse != nil {
		return "", nil, refuse
	}
	if before {
		<-ctx.Done()
		return "", nil, ctx.Err()
	}
	_, signed, signedCheckpoints, err := e.ark.SubmitTx(ctx, tx, checkpoints)
	if err != nil {
		return "", nil, err
	}
	if after {
		<-ctx.Done()
		return "", nil, ctx.Err()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Signed++
	return signed, signedCheckpoints, nil
}

func (e *emulator) SubmitIntent(_ context.Context, in execution.Intent) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.refuse != nil {
		return "", e.refuse
	}
	e.Intents++
	return in.Proof, nil
}

func (e *emulator) SubmitFinalization(
	_ context.Context, _ execution.Intent, forfeits []string, _ tree.FlatTxTree, _ string,
) ([]string, string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.refuse != nil {
		return nil, "", e.refuse
	}
	e.Finalizations++
	return forfeits, "", nil
}

// Refuse makes every call fail with err, nil signing again.
func (e *emulator) Refuse(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refuse = err
}

// Hang makes SubmitTx wait for its context, before it reaches arkd or once arkd finalized the
// transaction.
func (e *emulator) Hang(before, after bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hangBefore, e.hangAfter = before, after
}

// signAsServer signs every input whose leaf pushes the server key, as arkd does.
func (a *ark) signAsServer(raw string) (string, string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
	if err != nil {
		return "", "", err
	}
	prevouts := map[wire.OutPoint]*wire.TxOut{}
	for i, in := range ptx.Inputs {
		prevouts[ptx.UnsignedTx.TxIn[i].PreviousOutPoint] = in.WitnessUtxo
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	hashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)
	xOnly := schnorr.SerializePubKey(a.server.PubKey())
	for i := range ptx.Inputs {
		in := &ptx.Inputs[i]
		if len(in.TaprootLeafScript) != 1 ||
			!bytes.Contains(in.TaprootLeafScript[0].Script, xOnly) {
			continue
		}
		leaf := txscript.NewBaseTapLeaf(in.TaprootLeafScript[0].Script)
		sighash, err := txscript.CalcTapscriptSignaturehash(
			hashes, txscript.SigHashDefault, ptx.UnsignedTx, i, fetcher, leaf,
		)
		if err != nil {
			return "", "", err
		}
		sig, err := schnorr.Sign(a.server, sighash)
		if err != nil {
			return "", "", err
		}
		hash := leaf.TapHash()
		in.TaprootScriptSpendSig = append(in.TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: xOnly, LeafHash: hash[:], Signature: sig.Serialize(),
			SigHash: txscript.SigHashDefault,
		})
	}
	signed, err := ptx.B64Encode()
	return ptx.UnsignedTx.TxHash().String(), signed, err
}

func (a *ark) landAt(script, outpoint string, amount uint64, createdAt, expiresAt time.Time) {
	v := clientlib.Vtxo{Script: script, Amount: amount, CreatedAt: createdAt, ExpiresAt: expiresAt}
	txid, vout, _ := strings.Cut(outpoint, ":")
	n, _ := strconv.Atoi(vout)
	v.Txid, v.VOut = txid, uint32(n)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.vtxos[outpoint] = v
	a.push(
		script,
		clientlib.ScriptEvent{
			Data: &clientlib.ScriptEventData{Txid: v.Txid, NewVtxos: []clientlib.Vtxo{v}},
		},
	)
}

func (a *ark) push(script string, ev clientlib.ScriptEvent) {
	for _, sub := range a.subs {
		if _, ok := sub.scripts[script]; ok {
			sub.events <- ev
		}
	}
}

func (a *ark) vtxosChunks() []int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.VtxosChunks)
}

func (a *ark) subscriptionSizes() []int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.SubscriptionSizes)
}

func (a *ark) submitted() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.Submitted)
}

func (a *ark) spent(outpoint string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.vtxos[outpoint].Spent
}

func newArk() *ark {
	return &ark{
		server:    newKey(1),
		vtxos:     map[string]clientlib.Vtxo{},
		txs:       map[string]string{},
		subs:      map[string]*subscription{},
		txStreams: map[int]chan clientlib.TransactionEvent{},
		sessions:  newSessions(),
	}
}

func feeProgram(sats int) string {
	if sats <= 0 {
		return ""
	}
	return fmt.Sprintf("%d.0", sats)
}

func newKey(scalar uint32) *btcec.PrivateKey {
	var s btcec.ModNScalar
	s.SetInt(scalar)
	return btcec.PrivKeyFromScalar(&s)
}
