package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsessionhandler "github.com/arkade-os/arkd/pkg/client-lib/batch-session/handler"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/emulator/pkg/arkade"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// the only failure that counts against a template
var errIntentRejected = errors.New("intent rejected")

type renewalResult struct {
	inputs         []renewalInput
	commitmentTxid string
	err            error
	registered     bool // arkd accepted the intent, whatever became of its batch
}

type pendingIntent struct {
	logical        *wire.MsgTx
	hasEmulator    bool
	onchainOutputs []*wire.TxOut
	settled        map[int]wire.OutPoint
	sources        map[string]*wire.MsgTx
	commitment     string // the txid of the batch that settles it
	id             string
	registered     bool // arkd accepted it: the template did its part
	forfeitSent    bool // its forfeits may have reached arkd
	intent         emulatorclient.Intent
	inputs         []renewalInput
	// the template tx's outputs and the assets its packet puts on each
	outputs []*wire.TxOut
	assets  [][]clientlib.Asset
}

func (p *pendingIntent) settlement() settlement {
	st := owned(p.inputs, p.logical, p.commitment)
	st.outpoints, st.sources = p.settled, p.sources
	return st
}

func (s *service) renew(ctx context.Context, inputs []renewalInput) []renewalResult {
	inputs = uniqueInputs(inputs)
	slices.SortStableFunc(inputs, func(a, b renewalInput) int { return a.coin.Expiry.Compare(b.coin.Expiry) })
	groups := make([][]renewalInput, len(s.cosigners))
	for _, in := range inputs {
		i := slices.Index(s.cosigners, in.watched.cosigner)
		groups[i] = append(groups[i], in)
	}
	order := make([]int, 0, len(groups))
	for i, group := range groups {
		if len(group) > 0 {
			order = append(order, i)
		}
	}
	slices.SortStableFunc(order, func(a, b int) int {
		return groups[a][0].coin.Expiry.Compare(groups[b][0].coin.Expiry)
	})
	var results []renewalResult
	for _, i := range order {
		results = append(results, s.renewForCosigner(ctx, s.cosigners[i], groups[i])...)
	}
	return results
}

// arkd refuses an intent spending an outpoint twice
func uniqueInputs(inputs []renewalInput) []renewalInput {
	seen := make(map[string]struct{}, len(inputs))
	out := inputs[:0:0]
	for _, in := range inputs {
		op := in.coin.Outpoint.String()
		if _, ok := seen[op]; ok {
			log.WithFields(log.Fields{"vtxo": op, "delegation": in.watched.delegation.ID}).Warn("vtxo met twice in one renewal: dropped the duplicate")
			continue
		}
		seen[op] = struct{}{}
		out = append(out, in)
	}
	return out
}

func (s *service) renewForCosigner(ctx context.Context, cosigner *cosigner, inputs []renewalInput) []renewalResult {
	// arkd's fee programs can change at any time: read them every cycle
	fees, err := s.IntentFees(ctx)
	if err != nil {
		return []renewalResult{{inputs: inputs, err: err}}
	}
	var results []renewalResult
	var intents [][]renewalInput
	for _, chunk := range spends(inputs) {
		if chunk[0].watched.tmpl.Type() != template.Intent {
			results = append(results, s.runDirect(ctx, cosigner, chunk, fees))
			continue
		}
		slices.SortStableFunc(chunk, func(a, b renewalInput) int { return a.coin.Slot - b.coin.Slot })
		intents = append(intents, chunk)
	}
	pending, failed := s.buildIntents(ctx, cosigner, intents, fees)
	results = append(results, failed...)
	if len(pending) == 0 {
		return results
	}

	var topics []string
	for _, p := range pending {
		for _, in := range p.inputs {
			topics = append(topics, in.coin.Outpoint.String())
		}
	}
	eventsCh, stop, err := s.ark.GetEventStream(ctx, append(topics, cosigner.pubKey))
	if err != nil {
		for _, p := range pending {
			results = append(results, renewalResult{inputs: p.inputs, err: fmt.Errorf("event stream: %w", err)})
		}
		return results
	}
	defer stop()

	// register everything before the first batch so they can share it
	registered := make([]*pendingIntent, 0, len(pending))
	for _, p := range pending {
		id, err := s.ark.RegisterIntent(ctx, p.intent.Proof, p.intent.Message)
		if err != nil {
			results = append(results, renewalResult{inputs: p.inputs, err: refusal(ctx, "arkd", err)})
			continue
		}
		p.id, p.registered = id, true
		log.WithField("intent_id", p.id).Info("intent registered")
		registered = append(registered, p)
	}
	return append(results, s.followBatches(ctx, cosigner, eventsCh, registered)...)
}

// spends groups inputs one per coin, or one per delegation with several slots.
func spends(inputs []renewalInput) [][]renewalInput {
	var chunks [][]renewalInput
	byDelegation := map[int64]int{}
	for _, in := range inputs {
		id := in.watched.delegation.ID
		i, ok := byDelegation[id]
		if !ok || len(in.watched.delegation.Slots) == 1 {
			chunks = append(chunks, nil)
			i = len(chunks) - 1
			byDelegation[id] = i
		}
		chunks[i] = append(chunks[i], in)
	}
	return chunks
}

func (s *service) buildIntents(ctx context.Context, cosigner *cosigner, chunks [][]renewalInput, fees arkfee.Config) ([]*pendingIntent, []renewalResult) {
	built := make([]*pendingIntent, len(chunks))
	errs := make([]error, len(chunks))
	var g errgroup.Group
	g.SetLimit(concurrency)
	for i, chunk := range chunks {
		g.Go(func() error {
			built[i], errs[i] = s.buildIntent(ctx, cosigner, chunk, fees)
			return nil
		})
	}
	_ = g.Wait()
	var pending []*pendingIntent
	var failed []renewalResult
	for i, p := range built {
		if errs[i] != nil {
			failed = append(failed, renewalResult{inputs: chunks[i], err: errs[i]})
			continue
		}
		pending = append(pending, p)
	}
	return pending, failed
}

func (s *service) followBatches(ctx context.Context, cosigner *cosigner, events <-chan clientlib.BatchEventChannel, registered []*pendingIntent) []renewalResult {
	var results []renewalResult
	h := &batchHandler{svc: s, pending: registered}
	for len(h.pending) > 0 {
		h.signerSession = tree.NewTreeSignerSession(cosigner.key)
		commitmentTxid, _, _, _, _, err := batchsessionhandler.JoinBatchSession(ctx, events, h)
		if err != nil {
			return append(results, h.failedResults(ctx, err)...)
		}
		for _, p := range h.inBatch {
			s.settle(ctx, p.settlement())
			results = append(results, renewalResult{inputs: p.inputs, commitmentTxid: commitmentTxid, registered: p.registered})
		}
		h.inBatch = nil
	}
	return results
}

// failedResults blames the intent that sank the batch, and drops the settlements that cannot land.
func (h *batchHandler) failedResults(ctx context.Context, err error) []renewalResult {
	var results []renewalResult
	for _, p := range h.inBatch {
		if h.batchFailed || !p.forfeitSent {
			h.svc.forget(context.WithoutCancel(ctx), p.settlement())
		}
	}
	for _, p := range append(h.inBatch, h.pending...) {
		res := renewalResult{inputs: p.inputs, err: fmt.Errorf("batch session: %w", err), registered: p.registered}
		if p == h.failed && ctx.Err() == nil && (isRejection(ctx, h.failure) || status.Code(h.failure) == codes.Unknown) {
			res.err, res.registered = fmt.Errorf("%w: finalization: %v", errIntentRejected, h.failure), false
		}
		results = append(results, res)
	}
	return results
}

// outages, shutdowns and the daemon's own misconfiguration must not count against a template
func isRejection(ctx context.Context, err error) bool {
	// arkd holds the transaction already, or its tip has not reached the locktime yet
	if ctx.Err() != nil || strings.Contains(err.Error(), "duplicated offchain tx") || strings.Contains(err.Error(), "FORFEIT_CLOSURE_LOCKED") {
		return false
	}
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound, codes.AlreadyExists, codes.OutOfRange:
		return true
	}
	return false
}

func refusal(ctx context.Context, who string, err error) error {
	if isRejection(ctx, err) {
		return fmt.Errorf("%w: %s: %v", errIntentRejected, who, err)
	}
	return fmt.Errorf("%s: %w", who, err)
}

func (s *service) buildIntent(ctx context.Context, cosigner *cosigner, inputs []renewalInput, fees arkfee.Config) (*pendingIntent, error) {
	tx, coins, err := s.templateTx(ctx, inputs, fees)
	if err != nil {
		return nil, err
	}
	return s.intentOf(ctx, cosigner, inputs, tx, coins)
}

func (s *service) intentOf(ctx context.Context, cosigner *cosigner, inputs []renewalInput, tx *psbt.Packet, coins []coin) (*pendingIntent, error) {
	if err := checkTemplateTx(tx, coins, inputs[0].watched.delegation); err != nil {
		return nil, err
	}
	extensionIndex, err := extensionOutput(tx.UnsignedTx)
	if err != nil {
		return nil, err
	}
	ext, err := extension.NewExtensionFromTx(tx.UnsignedTx)
	if err != nil {
		return nil, err
	}
	hasEmulator := ext.GetPacketByType(arkade.PacketType) != nil
	if hasEmulator {
		emu, err := arkade.FindEmulatorPacket(tx.UnsignedTx)
		if err != nil {
			return nil, err
		}
		ext = withEmulatorPacket(ext, emu)
	}
	onchainIndexes := []int{}
	for i := extensionIndex + 1; i < len(tx.UnsignedTx.TxOut); i++ {
		onchainIndexes = append(onchainIndexes, i)
	}
	message, err := intent.RegisterMessage{
		BaseMessage:          intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		OnchainOutputIndexes: onchainIndexes,
		CosignersPublicKeys:  []string{cosigner.pubKey},
	}.Encode()
	if err != nil {
		return nil, err
	}
	proof, shifted, err := intentProof(tx, coins, message, ext, extensionIndex, hasEmulator)
	if err != nil {
		return nil, err
	}
	for i := range inputs {
		inputs[i].leaf = tx.Inputs[i].TaprootLeafScript[0]
		inputs[i].prevOut = tx.Inputs[i].WitnessUtxo
	}
	if err := s.signForTemplate(ctx, inputs[0].watched.delegation.TemplateID, cosigner, proof); err != nil {
		return nil, err
	}
	signedProof, err := proof.B64Encode()
	if err != nil {
		return nil, err
	}
	if hasEmulator {
		signedProof, err = s.emulator.SubmitIntent(ctx, emulatorclient.Intent{Proof: signedProof, Message: message})
		if err != nil {
			return nil, refusal(ctx, "emulator", err)
		}
	}
	return &pendingIntent{
		intent:         emulatorclient.Intent{Proof: signedProof, Message: message},
		inputs:         inputs,
		outputs:        tx.UnsignedTx.TxOut[:extensionIndex],
		onchainOutputs: tx.UnsignedTx.TxOut[extensionIndex+1:],
		logical:        tx.UnsignedTx, hasEmulator: hasEmulator,
		assets: assetsByOutput(shifted.GetAssetPacket(), extensionIndex),
	}, nil
}

func extensionOutput(tx *wire.MsgTx) (int, error) {
	index := -1
	for i, out := range tx.TxOut {
		if !extension.IsExtension(out.PkScript) {
			continue
		}
		if index >= 0 {
			return 0, errors.New("multiple extension outputs")
		}
		index = i
	}
	if index < 0 {
		return 0, errors.New("template tx has no extension output")
	}
	return index, nil
}

// the proof's message is input 0: every template input and packet input reference shifts by one
func intentProof(
	tx *psbt.Packet, coins []coin, message string, ext extension.Extension, extensionIndex int, hasEmulator bool,
) (*psbt.Packet, extension.Extension, error) {
	proofInputs := make([]intent.Input, len(coins))
	for i := range coins {
		proofInputs[i] = intent.Input{
			OutPoint:    &tx.UnsignedTx.TxIn[i].PreviousOutPoint,
			Sequence:    tx.UnsignedTx.TxIn[i].Sequence,
			WitnessUtxo: tx.Inputs[i].WitnessUtxo,
		}
	}
	proof, err := intent.New(message, proofInputs, slices.Clone(tx.UnsignedTx.TxOut))
	if err != nil {
		return nil, nil, fmt.Errorf("build intent proof: %w", err)
	}
	ptx := &proof.Packet
	for i := range ptx.Inputs {
		src := tx.Inputs[max(i-1, 0)] // the message shares input 1's script
		ptx.Inputs[i].TaprootLeafScript = src.TaprootLeafScript
		ptx.Inputs[i].Unknowns = append(ptx.Inputs[i].Unknowns, src.Unknowns...)
		if i == 0 || !hasEmulator {
			continue
		}
		// the emulator reads the transaction funding each input
		if err := txutils.SetArkPsbtField(ptx, i, arkade.PrevArkTxField, *coins[i-1].Source); err != nil {
			return nil, nil, err
		}
	}
	shifted, err := shiftInputs(ext, 1)
	if err != nil {
		return nil, nil, err
	}
	extOut, err := shifted.TxOut()
	if err != nil {
		return nil, nil, err
	}
	ptx.UnsignedTx.TxOut[extensionIndex] = extOut
	return ptx, shifted, nil
}

// the extension package parses the emulator packet as opaque bytes
func withEmulatorPacket(ext extension.Extension, emu arkade.EmulatorPacket) extension.Extension {
	out := make(extension.Extension, 0, len(ext))
	for _, p := range ext {
		if p.Type() != arkade.PacketType {
			out = append(out, p)
		}
	}
	return append(out, emu)
}

func shiftInputs(ext extension.Extension, by uint16) (extension.Extension, error) {
	out := make(extension.Extension, 0, len(ext))
	for _, p := range ext {
		switch p := p.(type) {
		case arkade.EmulatorPacket:
			entries := make([]arkade.EmulatorEntry, len(p))
			for i, e := range p {
				e.Vin += by
				entries[i] = e
			}
			shifted, err := arkade.NewPacket(entries...)
			if err != nil {
				return nil, err
			}
			out = append(out, shifted)
		case asset.Packet:
			groups := make([]asset.AssetGroup, 0, len(p))
			for _, g := range p {
				ins := slices.Clone(g.Inputs)
				for i := range ins {
					if ins[i].Type == asset.AssetInputTypeLocal {
						ins[i].Vin += by
					}
				}
				shiftedGroup, err := asset.NewAssetGroup(g.AssetId, g.ControlAsset, ins, g.Outputs, g.Metadata)
				if err != nil {
					return nil, err
				}
				groups = append(groups, *shiftedGroup)
			}
			shifted, err := asset.NewPacket(groups)
			if err != nil {
				return nil, err
			}
			out = append(out, shifted)
		default:
			// other packets (2, 5) reference outputs, which do not move
			out = append(out, p)
		}
	}
	return out, nil
}

// a renewal issues nothing
func assetsByOutput(packet asset.Packet, n int) [][]clientlib.Asset {
	out := make([][]clientlib.Asset, n)
	for i := range out {
		out[i] = []clientlib.Asset{}
	}
	for _, g := range packet {
		if g.IsIssuance() {
			continue
		}
		for _, o := range g.Outputs {
			if int(o.Vout) < n {
				out[o.Vout] = append(out[o.Vout], clientlib.Asset{AssetId: g.AssetId.String(), Amount: o.Amount})
			}
		}
	}
	return out
}

func (s *service) virtualTx(ctx context.Context, txid string) (*wire.MsgTx, error) {
	txs, err := s.virtualTxs(ctx, []string{txid})
	if err != nil {
		return nil, err
	}
	return txs[txid], nil
}

// the indexer owes no order: txs are matched by txid
func (s *service) virtualTxs(ctx context.Context, txids []string) (map[string]*wire.MsgTx, error) {
	resp, err := s.indexer.GetVirtualTxs(ctx, txids)
	if err != nil {
		return nil, fmt.Errorf("get virtual txs: %w", err)
	}
	txs := make(map[string]*wire.MsgTx, len(txids))
	for _, raw := range resp.Txs {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
		if err != nil {
			return nil, fmt.Errorf("virtual tx: %w", err)
		}
		txs[ptx.UnsignedTx.TxHash().String()] = ptx.UnsignedTx
	}
	for _, txid := range txids {
		if txs[txid] == nil {
			return nil, fmt.Errorf("virtual tx %s not found", txid)
		}
	}
	return txs, nil
}

// pending holds intents not yet included; inBatch those the current batch took.
type batchHandler struct {
	svc           *service
	signerSession tree.SignerSession
	pending       []*pendingIntent
	inBatch       []*pendingIntent

	batchID     string
	batchExpiry arklib.RelativeLocktime
	batchFailed bool // arkd failed it: its forfeits are void

	mu      sync.Mutex
	failed  *pendingIntent // the first intent whose finalization failed
	failure error
}

func (h *batchHandler) blame(p *pendingIntent, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failed == nil {
		h.failed, h.failure = p, err
	}
}

func (h *batchHandler) OnStreamStarted(context.Context, clientlib.StreamStartedEvent) error {
	return nil
}
func (h *batchHandler) OnBatchFinalized(context.Context, clientlib.BatchFinalizedEvent) error {
	return nil
}
func (h *batchHandler) OnTreeTxEvent(context.Context, clientlib.TreeTxEvent) error { return nil }
func (h *batchHandler) OnTreeSignatureEvent(context.Context, clientlib.TreeSignatureEvent) error {
	return nil
}
func (h *batchHandler) OnTreeNonces(context.Context, clientlib.TreeNoncesEvent) (bool, error) {
	return false, nil
}

func (h *batchHandler) OnBatchStarted(ctx context.Context, event clientlib.BatchStartedEvent) (bool, time.Duration, error) {
	var inBatch, pending []*pendingIntent
	for _, p := range h.pending {
		sum := sha256.Sum256([]byte(p.id))
		if slices.Contains(event.HashedIntentIds, hex.EncodeToString(sum[:])) {
			inBatch = append(inBatch, p)
		} else {
			pending = append(pending, p)
		}
	}
	if len(inBatch) == 0 {
		return true, -1, nil
	}
	for _, p := range inBatch {
		if err := h.svc.ark.ConfirmRegistration(ctx, p.id); err != nil {
			return false, -1, err
		}
	}
	h.inBatch, h.pending = inBatch, pending
	h.batchID = event.Id
	h.batchExpiry = arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: uint32(event.BatchExpiry)}
	if event.BatchExpiry >= 512 {
		h.batchExpiry.Type = arklib.LocktimeTypeSecond
	}
	return false, time.Duration(event.BatchExpiry) * time.Second, nil
}

func (h *batchHandler) OnBatchFailed(_ context.Context, event clientlib.BatchFailedEvent) error {
	if event.Id == h.batchID {
		h.batchFailed = true
		return fmt.Errorf("batch %s failed: %s", event.Id, event.Reason)
	}
	return nil
}

func (h *batchHandler) OnTreeSigningStarted(
	ctx context.Context, event clientlib.TreeSigningStartedEvent, vtxoTree *tree.TxTree,
) (bool, error) {
	if !slices.Contains(event.CosignersPubkeys, h.signerSession.GetPublicKey()) {
		return true, nil
	}
	root, err := sweepTapTreeRoot(h.svc.forfeitPubKey, h.batchExpiry)
	if err != nil {
		return false, err
	}
	commitmentTx, err := psbt.NewFromRawBytes(strings.NewReader(event.UnsignedCommitmentTx), true)
	if err != nil {
		return false, err
	}
	if commitmentTx.UnsignedTx == nil || len(commitmentTx.UnsignedTx.TxOut) == 0 {
		return false, fmt.Errorf("commitment tx has no batch output")
	}
	if err := h.signerSession.Init(root, commitmentTx.UnsignedTx.TxOut[0].Value, vtxoTree); err != nil {
		return false, err
	}
	nonces, err := h.signerSession.GetNonces()
	if err != nil {
		return false, err
	}
	return false, h.svc.ark.SubmitTreeNonces(ctx, event.Id, h.signerSession.GetPublicKey(), nonces)
}

func (h *batchHandler) OnTreeNoncesAggregated(ctx context.Context, event clientlib.TreeNoncesAggregatedEvent) (bool, error) {
	h.signerSession.SetAggregatedNonces(event.Nonces)
	sigs, err := h.signerSession.Sign()
	if err != nil {
		return false, err
	}
	err = h.svc.ark.SubmitTreeSignatures(ctx, event.Id, h.signerSession.GetPublicKey(), sigs)
	return err == nil, err
}

// forfeiting hands the old vtxos to arkd: only once the batch holds the new ones and every forfeit is built
func (h *batchHandler) OnBatchFinalization(
	ctx context.Context, event clientlib.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree,
) ([]string, error) {
	var outputs []*wire.TxOut
	var assets [][]clientlib.Asset
	vtxosByIntent := make([][]renewalInput, len(h.inBatch))
	forfeits := false
	for i, p := range h.inBatch {
		outputs = append(outputs, p.outputs...)
		assets = append(assets, p.assets...)
		for _, in := range p.inputs {
			if !in.onchain {
				vtxosByIntent[i] = append(vtxosByIntent[i], in)
				forfeits = true
			}
		}
	}
	if err := validateBatch(event.Tx, vtxoTree, connectorTree, h.svc.forfeitPubKey, h.batchExpiry, outputs, assets, forfeits); err != nil {
		return nil, fmt.Errorf("refusing to forfeit: %w", err)
	}
	if err := h.mapSettlements(event.Tx, vtxoTree); err != nil {
		return nil, err
	}
	// the forfeits may reach arkd whatever becomes of this session
	for _, p := range h.inBatch {
		if err := h.svc.keep(ctx, p.settlement()); err != nil {
			return nil, err
		}
	}
	var flatConnectorTree tree.FlatTxTree
	var connectors []*psbt.Packet
	if connectorTree != nil {
		var err error
		if flatConnectorTree, err = connectorTree.Serialize(); err != nil {
			return nil, err
		}
		connectors = connectorTree.Leaves()
	}
	forfeitsByIntent := make([][]string, len(h.inBatch))
	for i, vtxos := range vtxosByIntent {
		if len(connectors) < len(vtxos) {
			return nil, fmt.Errorf("got %d connectors for %d vtxos", len(connectors), len(vtxos))
		}
		var err error
		if forfeitsByIntent[i], err = h.buildForfeits(vtxos, connectors[:len(vtxos)]); err != nil {
			return nil, err
		}
		connectors = connectors[len(vtxos):]
	}
	signedByIntent := make([][]string, len(h.inBatch))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for i, p := range h.inBatch {
		g.Go(func() error {
			signed, err := h.submitForfeits(ctx, p, forfeitsByIntent[i], flatConnectorTree, event.Tx)
			if err != nil {
				h.blame(p, err)
				return err
			}
			signedByIntent[i] = signed
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return slices.Concat(signedByIntent...), nil
}

func (h *batchHandler) submitForfeits(
	ctx context.Context, p *pendingIntent, forfeits []string, connectorTree tree.FlatTxTree, commitmentTx string,
) ([]string, error) {
	signedForfeits, signedCommitmentTx := forfeits, commitmentTx
	if p.hasEmulator {
		// the emulator signs a boarding input only against the leaf of the intent proof
		commitment, err := psbt.NewFromRawBytes(strings.NewReader(commitmentTx), true)
		if err != nil {
			return nil, err
		}
		if _, err = p.withBoardingLeaves(commitment); err != nil {
			return nil, err
		}
		raw, err := commitment.B64Encode()
		if err != nil {
			return nil, err
		}
		signedForfeits, signedCommitmentTx, err = h.svc.emulator.SubmitFinalization(ctx, p.intent, forfeits, connectorTree, raw)
		if err != nil {
			return nil, fmt.Errorf("emulator finalization: %w", err)
		}
	}
	if len(signedForfeits) != len(forfeits) {
		return nil, errors.New("emulator changed forfeit count")
	}
	c := p.inputs[0].watched.cosigner
	id := p.inputs[0].watched.delegation.TemplateID
	for j, raw := range signedForfeits {
		tx, err := mergeRemoteSignatures(forfeits[j], raw, c)
		if err != nil {
			return nil, err
		}
		if err = h.svc.signForTemplate(ctx, id, c, tx); err != nil {
			return nil, err
		}
		if signedForfeits[j], err = tx.B64Encode(); err != nil {
			return nil, err
		}
	}
	signedCommitmentTx, err := h.signCommitment(ctx, p, c, signedCommitmentTx, commitmentTx)
	if err != nil {
		return nil, err
	}
	p.forfeitSent = true
	if err = h.svc.ark.SubmitSignedForfeitTxs(ctx, signedForfeits, signedCommitmentTx); err != nil {
		return nil, err
	}
	return signedForfeits, nil
}

// the sweep path of every vtxo tree output: arkd alone, once the batch expired
func sweepTapTreeRoot(forfeitPubKey *btcec.PublicKey, batchExpiry arklib.RelativeLocktime) ([]byte, error) {
	sweepScript, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{forfeitPubKey}},
		Locktime:        batchExpiry,
	}).Script()
	if err != nil {
		return nil, err
	}
	root := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(sweepScript)).RootNode.TapHash()
	return root.CloneBytes(), nil
}

// runs before any forfeit is signed
// forfeits is false when no input is a vtxo: the batch then owes no connector
func validateBatch(
	commitmentTx string, vtxoTree, connectorTree *tree.TxTree,
	forfeitPubKey *btcec.PublicKey, batchExpiry arklib.RelativeLocktime, outputs []*wire.TxOut,
	assets [][]clientlib.Asset, forfeits bool,
) (err error) {
	// remote trees can be malformed: a validator panic is an error
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("malformed batch: %v", recovered)
		}
	}()
	commitment, err := psbt.NewFromRawBytes(strings.NewReader(commitmentTx), true)
	if err != nil {
		return fmt.Errorf("commitment tx: %w", err)
	}
	if commitment.UnsignedTx == nil {
		return fmt.Errorf("commitment tx is empty")
	}
	commitmentTxid := commitment.UnsignedTx.TxHash()
	if len(outputs) > 0 {
		if vtxoTree == nil || vtxoTree.Root == nil {
			return fmt.Errorf("vtxo tree is missing")
		}
		if err := validateTreePackets(vtxoTree, "vtxo"); err != nil {
			return err
		}
		if err := tree.ValidateVtxoTree(vtxoTree, commitment, forfeitPubKey, batchExpiry); err != nil {
			return fmt.Errorf("vtxo tree: %w", err)
		}
		if root := vtxoTree.Root.UnsignedTx.TxIn[0].PreviousOutPoint; root.Hash != commitmentTxid || root.Index != 0 {
			return fmt.Errorf("vtxo tree spends %s, not the batch output of commitment tx %s", root, commitmentTxid)
		}
		if err := leavesPay(vtxoTree.Leaves(), outputs, assets); err != nil {
			return err
		}
	}
	if !forfeits {
		return nil
	}
	if connectorTree == nil || connectorTree.Root == nil {
		return fmt.Errorf("connector tree is missing")
	}
	if err := validateTreePackets(connectorTree, "connector"); err != nil {
		return err
	}
	if len(commitment.UnsignedTx.TxOut) < 2 {
		return fmt.Errorf("commitment tx has no connector output")
	}
	if root := connectorTree.Root.UnsignedTx.TxIn[0].PreviousOutPoint; root.Hash != commitmentTxid || root.Index != 1 {
		return fmt.Errorf("connectors spend %s, not connector output 1 of commitment tx %s", root, commitmentTxid)
	}
	if err := connectorTree.Validate(); err != nil {
		return fmt.Errorf("connector tree: %w", err)
	}
	return nil
}

func validateTreePackets(t *tree.TxTree, name string) error {
	seen := make(map[*tree.TxTree]struct{})
	var visit func(*tree.TxTree) error
	visit = func(node *tree.TxTree) error {
		if node == nil || node.Root == nil || node.Root.UnsignedTx == nil {
			return fmt.Errorf("%s tree has a missing transaction", name)
		}
		if _, ok := seen[node]; ok {
			return fmt.Errorf("%s tree contains a cycle or duplicate node", name)
		}
		seen[node] = struct{}{}
		if len(node.Root.UnsignedTx.TxIn) == 0 {
			return fmt.Errorf("%s tree transaction has no input", name)
		}
		for index, child := range node.Children {
			if index >= uint32(len(node.Root.UnsignedTx.TxOut)) {
				return fmt.Errorf("%s tree child output %d is out of bounds", name, index)
			}
			if err := visit(child); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(t)
}

// one leaf pays one output
func leavesPay(leaves []*psbt.Packet, outputs []*wire.TxOut, expectedAssets [][]clientlib.Asset) error {
	if expectedAssets != nil && len(expectedAssets) != len(outputs) {
		return fmt.Errorf("expected asset count %d does not match output count %d", len(expectedAssets), len(outputs))
	}
	type output struct {
		script string
		value  int64
	}
	type leafCandidate struct {
		packet asset.Packet
		index  int
	}
	available := make(map[output][]leafCandidate)
	for _, leafPacket := range leaves {
		if leafPacket == nil || leafPacket.UnsignedTx == nil {
			return fmt.Errorf("vtxo tree has a missing leaf transaction")
		}
		ext, err := extension.NewExtensionFromTx(leafPacket.UnsignedTx)
		if err != nil && !errors.Is(err, extension.ErrExtensionNotFound) {
			return fmt.Errorf("vtxo tree leaf extension: %w", err)
		}
		var packet asset.Packet
		if err == nil {
			packet = ext.GetAssetPacket()
		}
		for index, out := range leafPacket.UnsignedTx.TxOut {
			if out == nil {
				return fmt.Errorf("vtxo tree has a missing leaf output")
			}
			key := output{string(out.PkScript), out.Value}
			available[key] = append(available[key], leafCandidate{packet: packet, index: index})
		}
	}
	for i, out := range outputs {
		if out == nil {
			return fmt.Errorf("expected renewal output is missing")
		}
		k := output{string(out.PkScript), out.Value}
		candidates := available[k]
		matched := slices.IndexFunc(candidates, func(c leafCandidate) bool {
			return expectedAssets == nil || assetsAt(c.packet, c.index, expectedAssets[i])
		})
		if matched < 0 {
			return fmt.Errorf("no leaf pays %d sats to %x", out.Value, out.PkScript)
		}
		candidates[matched] = candidates[len(candidates)-1]
		available[k] = candidates[:len(candidates)-1]
	}
	return nil
}

// assetsAt reports whether packet puts exactly expected on index, issuing nothing there.
func assetsAt(packet asset.Packet, index int, expected []clientlib.Asset) bool {
	actual := make(map[string]uint64)
	for _, group := range packet {
		for _, assetOut := range group.Outputs {
			if int(assetOut.Vout) != index {
				continue
			}
			if group.IsIssuance() {
				return false
			}
			id := group.AssetId.String()
			if _, exists := actual[id]; exists {
				return false
			}
			actual[id] = assetOut.Amount
		}
	}
	if len(actual) != len(expected) {
		return false
	}
	for _, a := range expected {
		if actual[a.AssetId] != a.Amount {
			return false
		}
	}
	return true
}

func (h *batchHandler) buildForfeits(inputs []renewalInput, connectors []*psbt.Packet) ([]string, error) {
	forfeits := make([]string, 0, len(inputs))
	for i, in := range inputs {
		if connectors[i] == nil || connectors[i].UnsignedTx == nil {
			return nil, fmt.Errorf("connector %d is missing", i)
		}
		connectorTx := connectors[i].UnsignedTx
		vout := slices.IndexFunc(connectorTx.TxOut, func(out *wire.TxOut) bool {
			return !bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT)
		})
		if vout < 0 {
			return nil, fmt.Errorf("connector not found for vtxo %s", in.coin.Outpoint)
		}
		vtxo := in.coin.Outpoint
		forfeit, err := tree.BuildForfeitTx(
			[]*wire.OutPoint{&vtxo, {Hash: connectorTx.TxHash(), Index: uint32(vout)}},
			[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
			[]*wire.TxOut{in.prevOut, connectorTx.TxOut[vout]},
			h.svc.forfeitPkScript,
			0,
		)
		if err != nil {
			return nil, err
		}
		forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{in.leaf}
		b64, err := forfeit.B64Encode()
		if err != nil {
			return nil, err
		}
		forfeits = append(forfeits, b64)
	}
	return forfeits, nil
}
