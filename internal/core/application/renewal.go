package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
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
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/emulator/pkg/arkade"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// renewalResult is the outcome for one group of inputs: the batch that
// renewed them, or why they were not renewed.
type renewalResult struct {
	inputs         []renewalInput
	commitmentTxid string
	err            error
}

// renew splits inputs into intents small enough for arkd, has each one
// cosigned by the emulator and registered, then follows batch sessions until
// every registered intent has been included.
func (s *service) renew(ctx context.Context, inputs []renewalInput) []renewalResult {
	groups := make([][]renewalInput, len(s.cosigners))
	indices := make(map[*cosigner]int, len(s.cosigners))
	for i, cosigner := range s.cosigners {
		indices[cosigner] = i
	}
	for _, in := range inputs {
		cosigner := in.cosigner
		if cosigner == nil {
			cosigner = s.cosigners[0]
		}
		groups[indices[cosigner]] = append(groups[indices[cosigner]], in)
	}
	var results []renewalResult
	for i, inputs := range groups {
		if len(inputs) > 0 {
			results = append(results, s.renewForCosigner(ctx, s.cosigners[i], inputs)...)
		}
	}
	return results
}

func (s *service) renewForCosigner(ctx context.Context, cosigner *cosigner, inputs []renewalInput) []renewalResult {
	var results []renewalResult
	// arkd's fee programs can change at any time: read them every cycle, and
	// settle first which inputs can pay so they don't sink a whole intent
	fees, err := s.feeEstimator(ctx)
	if err != nil {
		return []renewalResult{{inputs: inputs, err: err}}
	}
	payable := make([]renewalInput, 0, len(inputs))
	for _, in := range inputs {
		fee, err := fees.of(in)
		if err == nil {
			in.output, err = renewalOutput(in.vtxo, in.pkScript, in.delegation.Params, fee)
		}
		if err != nil {
			results = append(results, renewalResult{inputs: []renewalInput{in}, err: err})
			continue
		}
		payable = append(payable, in)
	}
	inputs = payable

	// intents are independent: build a few at a time, keep them in order
	type built struct {
		pending []*pendingIntent
		failed  []renewalResult
	}
	chunks := slices.Collect(slices.Chunk(inputs, s.maxVtxosPerIntent))
	builds := make([]built, len(chunks))
	var g errgroup.Group
	g.SetLimit(concurrency)
	for i, chunk := range chunks {
		g.Go(func() error {
			b := &builds[i]
			p, err := s.buildIntent(ctx, cosigner, chunk)
			if err == nil {
				b.pending = append(b.pending, p)
				return nil
			}
			if len(chunk) == 1 {
				b.failed = append(b.failed, renewalResult{inputs: chunk, err: err})
				return nil
			}
			// one bad vtxo must not block its neighbours: retry them one by one
			log.WithError(err).WithField("count", len(chunk)).Warn("intent rejected, retrying per vtxo")
			for _, in := range chunk {
				single := []renewalInput{in}
				if p, err := s.buildIntent(ctx, cosigner, single); err != nil {
					b.failed = append(b.failed, renewalResult{inputs: single, err: err})
				} else {
					b.pending = append(b.pending, p)
				}
			}
			return nil
		})
	}
	_ = g.Wait()
	var pending []*pendingIntent
	for _, b := range builds {
		pending = append(pending, b.pending...)
		results = append(results, b.failed...)
	}
	if len(pending) == 0 {
		return results
	}

	var outpoints []types.Outpoint
	for _, p := range pending {
		for _, in := range p.inputs {
			outpoints = append(outpoints, in.vtxo.Outpoint)
		}
	}
	signerSession := tree.NewTreeSignerSession(cosigner.key)
	eventsCh, stop, err := s.ark.GetEventStream(ctx, clientlib.GetEventStreamTopics(
		outpoints, []tree.SignerSession{signerSession},
	))
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
		p.id, err = s.ark.RegisterIntent(ctx, p.intent.Proof, p.intent.Message)
		if err != nil {
			results = append(results, renewalResult{inputs: p.inputs, err: fmt.Errorf("register intent: %w", err)})
			continue
		}
		log.WithField("intent_id", p.id).Info("intent registered")
		registered = append(registered, p)
	}

	h := &batchHandler{svc: s, pending: registered}
	for len(h.pending) > 0 {
		h.signerSession = tree.NewTreeSignerSession(cosigner.key)
		commitmentTxid, _, _, _, _, err := clientlib.JoinBatchSession(ctx, eventsCh, h)
		if err != nil {
			for _, p := range append(h.inBatch, h.pending...) {
				results = append(results, renewalResult{inputs: p.inputs, err: fmt.Errorf("batch session: %w", err)})
			}
			return results
		}
		for _, p := range h.inBatch {
			results = append(results, renewalResult{inputs: p.inputs, commitmentTxid: commitmentTxid})
		}
		h.inBatch = nil
	}
	return results
}

type pendingIntent struct {
	id     string
	intent emulatorclient.Intent
	inputs []renewalInput
}

// buildIntent creates the self-send register intent for inputs and has the
// emulator cosign it.
func (s *service) buildIntent(ctx context.Context, cosigner *cosigner, inputs []renewalInput) (*pendingIntent, error) {
	message, err := intent.RegisterMessage{
		BaseMessage:          intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		OnchainOutputIndexes: []int{}, // must encode as "[]"
		CosignersPublicKeys:  []string{cosigner.pubKey},
	}.Encode()
	if err != nil {
		return nil, err
	}

	proofInputs := make([]intent.Input, len(inputs))
	outputs := make([]*wire.TxOut, len(inputs))
	vtxos := make([]types.Vtxo, len(inputs))
	for i, in := range inputs {
		hash, err := chainhash.NewHashFromStr(in.vtxo.Txid)
		if err != nil {
			return nil, err
		}
		proofInputs[i] = intent.Input{
			OutPoint:    &wire.OutPoint{Hash: *hash, Index: in.vtxo.VOut},
			Sequence:    wire.MaxTxInSequenceNum,
			WitnessUtxo: &wire.TxOut{Value: int64(in.vtxo.Amount), PkScript: in.pkScript},
		}
		outputs[i] = in.output
		vtxos[i] = in.vtxo
	}
	proof, err := intent.New(message, proofInputs, outputs)
	if err != nil {
		return nil, fmt.Errorf("build intent proof: %w", err)
	}
	ptx := &proof.Packet

	prevTxs, err := s.virtualTxs(ctx, inputs)
	if err != nil {
		return nil, err
	}
	entries := make([]arkade.EmulatorEntry, 0, len(inputs))
	for i := range ptx.Inputs {
		in := inputs[max(i-1, 0)] // input 0 is the bip322 message, it shares input 1's script
		ptx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{in.leaf}
		if err := txutils.SetArkPsbtField(
			ptx, i, txutils.VtxoTaprootTreeField, txutils.TapTree(in.delegation.Tapscripts),
		); err != nil {
			return nil, err
		}
		if i == 0 {
			continue
		}
		if err := txutils.SetArkPsbtField(ptx, i, arkade.PrevArkTxField, *prevTxs[in.vtxo.Txid]); err != nil {
			return nil, err
		}
		entries = append(entries, arkade.EmulatorEntry{Vin: uint16(i), Script: in.arkadeScript})
	}
	emulatorPacket, err := arkade.NewPacket(entries...)
	if err != nil {
		return nil, err
	}
	ext := extension.Extension{}
	if assetPacket, err := assetPacketFor(vtxos); err != nil {
		return nil, err
	} else if assetPacket != nil {
		ext = append(ext, assetPacket)
	}
	ext = append(ext, emulatorPacket)
	extOut, err := ext.TxOut()
	if err != nil {
		return nil, err
	}
	ptx.UnsignedTx.AddTxOut(extOut)
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})

	encoded, err := ptx.B64Encode()
	if err != nil {
		return nil, err
	}
	signedProof, err := s.emulator.SubmitIntent(ctx, emulatorclient.Intent{Proof: encoded, Message: message})
	if err != nil {
		return nil, fmt.Errorf("emulator rejected intent: %w", err)
	}
	return &pendingIntent{
		intent: emulatorclient.Intent{Proof: signedProof, Message: message},
		inputs: inputs,
	}, nil
}

// feeEstimator prices one input and the output it pays, the way arkd will.
type feeEstimator struct{ *arkfee.Estimator }

func (s *service) feeEstimator(ctx context.Context) (*feeEstimator, error) {
	config, err := s.IntentFees(ctx)
	if err != nil {
		return nil, err
	}
	estimator, err := arkfee.New(config)
	if err != nil {
		return nil, fmt.Errorf("arkd intent fees: %w", err)
	}
	return &feeEstimator{estimator}, nil
}

func (f *feeEstimator) of(in renewalInput) (int64, error) {
	inFee, err := f.EvalOffchainInput(types.VtxoWithTapTree{Vtxo: in.vtxo}.ToArkFeeInput())
	if err != nil {
		return 0, fmt.Errorf("intent input fee: %w", err)
	}
	inputSats, err := feeSatoshis(inFee)
	if err != nil {
		return 0, fmt.Errorf("intent input fee: %w", err)
	}

	// Solve the output-fee dependency at the actual output amount.
	fee := inputSats
	seen := make(map[int64]struct{}, 8)
	for range 32 {
		if fee >= int64(in.vtxo.Amount) {
			return fee, nil
		}
		if _, ok := seen[fee]; ok {
			return 0, fmt.Errorf("intent fee did not converge")
		}
		seen[fee] = struct{}{}
		outFee, err := f.EvalOffchainOutput(arkfee.Output{
			Amount: in.vtxo.Amount - uint64(fee), Script: hex.EncodeToString(in.pkScript),
		})
		if err != nil {
			return 0, fmt.Errorf("intent output fee: %w", err)
		}
		outputSats, err := feeSatoshis(outFee)
		if err != nil {
			return 0, fmt.Errorf("intent output fee: %w", err)
		}
		if outputSats > math.MaxInt64-inputSats {
			return 0, fmt.Errorf("intent fee overflows int64")
		}
		next := inputSats + outputSats
		if next == fee {
			return next, nil
		}
		fee = next
	}
	return 0, fmt.Errorf("intent fee did not converge")
}

func feeSatoshis(fee arkfee.FeeAmount) (int64, error) {
	value := float64(fee)
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0, fmt.Errorf("invalid fee amount %v", value)
	}
	sats := fee.ToSatoshis()
	if sats < 0 {
		return 0, fmt.Errorf("invalid fee amount %v", value)
	}
	return sats, nil
}

// assetPacketFor moves the assets of proof input i to output i-1.
func assetPacketFor(vtxos []types.Vtxo) (asset.Packet, error) {
	type transfer struct {
		inputs  []asset.AssetInput
		outputs []asset.AssetOutput
	}
	transfers := map[string]*transfer{}
	var order []string
	for i, v := range vtxos {
		for _, a := range v.Assets {
			tr, ok := transfers[a.AssetId]
			if !ok {
				tr = &transfer{}
				transfers[a.AssetId] = tr
				order = append(order, a.AssetId)
			}
			in, err := asset.NewAssetInput(uint16(i+1), a.Amount)
			if err != nil {
				return nil, err
			}
			out, err := asset.NewAssetOutput(uint16(i), a.Amount)
			if err != nil {
				return nil, err
			}
			tr.inputs = append(tr.inputs, *in)
			tr.outputs = append(tr.outputs, *out)
		}
	}
	if len(order) == 0 {
		return nil, nil
	}
	groups := make([]asset.AssetGroup, 0, len(order))
	for _, id := range order {
		assetID, err := asset.NewAssetIdFromString(id)
		if err != nil {
			return nil, err
		}
		g, err := asset.NewAssetGroup(assetID, nil, transfers[id].inputs, transfers[id].outputs, nil)
		if err != nil {
			return nil, err
		}
		groups = append(groups, *g)
	}
	return asset.NewPacket(groups)
}

// virtualTxs fetches the txs that created the inputs, in one request. The
// indexer owes no order, so they are matched by their own txid.
func (s *service) virtualTxs(ctx context.Context, inputs []renewalInput) (map[string]*wire.MsgTx, error) {
	txids := make([]string, 0, len(inputs))
	for _, in := range inputs {
		if !slices.Contains(txids, in.vtxo.Txid) {
			txids = append(txids, in.vtxo.Txid)
		}
	}
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

// batchHandler is the tree cosigner for one batch session. pending holds
// the intents not yet included; inBatch the ones the current batch took.
type batchHandler struct {
	svc           *service
	signerSession tree.SignerSession
	pending       []*pendingIntent
	inBatch       []*pendingIntent

	batchID     string
	batchExpiry arklib.RelativeLocktime
}

func (h *batchHandler) OnStreamStarted(context.Context, client.StreamStartedEvent) error { return nil }
func (h *batchHandler) OnBatchFinalized(context.Context, client.BatchFinalizedEvent) error {
	return nil
}
func (h *batchHandler) OnTreeTxEvent(context.Context, client.TreeTxEvent) error { return nil }
func (h *batchHandler) OnTreeSignatureEvent(context.Context, client.TreeSignatureEvent) error {
	return nil
}
func (h *batchHandler) OnTreeNonces(context.Context, client.TreeNoncesEvent) (bool, error) {
	return false, nil
}

func (h *batchHandler) OnBatchStarted(ctx context.Context, event client.BatchStartedEvent) (bool, time.Duration, error) {
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

func (h *batchHandler) OnBatchFailed(_ context.Context, event client.BatchFailedEvent) error {
	if event.Id == h.batchID {
		return fmt.Errorf("batch %s failed: %s", event.Id, event.Reason)
	}
	return nil
}

func (h *batchHandler) OnTreeSigningStarted(
	ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree,
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

func (h *batchHandler) OnTreeNoncesAggregated(ctx context.Context, event client.TreeNoncesAggregatedEvent) (bool, error) {
	h.signerSession.SetAggregatedNonces(event.Nonces)
	sigs, err := h.signerSession.Sign()
	if err != nil {
		return false, err
	}
	err = h.svc.ark.SubmitTreeSignatures(ctx, event.Id, h.signerSession.GetPublicKey(), sigs)
	return err == nil, err
}

func (h *batchHandler) OnBatchFinalization(
	ctx context.Context, event client.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree,
) ([]string, error) {
	// the point of no return: a forfeit hands the old vtxo to arkd, so the
	// batch must verifiably contain the new one. The users are not here to check.
	var outputs []*wire.TxOut
	var assets [][]types.Asset
	for _, p := range h.inBatch {
		for _, in := range p.inputs {
			outputs = append(outputs, in.output)
			assets = append(assets, in.vtxo.Assets)
		}
	}
	if err := validateBatchWithAssets(event.Tx, vtxoTree, connectorTree, h.svc.forfeitPubKey, h.batchExpiry, outputs, assets); err != nil {
		return nil, fmt.Errorf("refusing to forfeit: %w", err)
	}
	flatConnectorTree, err := connectorTree.Serialize()
	if err != nil {
		return nil, err
	}
	// arkd only streams the connector leaves assigned to our vtxos; any
	// unused one is valid for any of them, so hand them out in order. Then
	// finalize the intents side by side: arkd waits for forfeits only so long.
	connectors := connectorTree.Leaves()
	forfeitsByIntent := make([][]string, len(h.inBatch))
	for i, p := range h.inBatch {
		if len(connectors) < len(p.inputs) {
			return nil, fmt.Errorf("got %d connectors for %d vtxos", len(connectors), len(p.inputs))
		}
		if forfeitsByIntent[i], err = h.buildForfeits(p.inputs, connectors[:len(p.inputs)]); err != nil {
			return nil, err
		}
		connectors = connectors[len(p.inputs):]
	}
	// nothing is sent before every forfeit could be built
	signedByIntent := make([][]string, len(h.inBatch))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for i, p := range h.inBatch {
		g.Go(func() error {
			signedForfeits, signedCommitmentTx, err := h.svc.emulator.SubmitFinalization(
				ctx, p.intent, forfeitsByIntent[i], flatConnectorTree, event.Tx,
			)
			if err != nil {
				return fmt.Errorf("emulator finalization: %w", err)
			}
			signedByIntent[i] = signedForfeits
			return h.svc.ark.SubmitSignedForfeitTxs(ctx, signedForfeits, signedCommitmentTx)
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	signed := slices.Concat(signedByIntent...)
	return signed, nil
}

// sweepTapTreeRoot is the script path of every vtxo tree output: arkd alone,
// once the batch has expired.
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

// validateBatch checks what arkd proposes before any forfeit is signed: a
// well-formed vtxo tree hanging off the commitment tx, one distinct leaf
// output per expected output, and connectors created by that same tx, so the
// forfeits are only ever valid together with the new vtxos.
func validateBatch(
	commitmentTx string, vtxoTree, connectorTree *tree.TxTree,
	forfeitPubKey *btcec.PublicKey, batchExpiry arklib.RelativeLocktime, outputs []*wire.TxOut,
) (err error) {
	return validateBatchWithAssets(commitmentTx, vtxoTree, connectorTree, forfeitPubKey, batchExpiry, outputs, nil)
}

func validateBatchWithAssets(
	commitmentTx string, vtxoTree, connectorTree *tree.TxTree,
	forfeitPubKey *btcec.PublicKey, batchExpiry arklib.RelativeLocktime, outputs []*wire.TxOut,
	assets [][]types.Asset,
) (err error) {
	// Remote trees can be malformed; turn validator panics into errors.
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("malformed batch: %v", recovered)
		}
	}()
	if vtxoTree == nil || vtxoTree.Root == nil {
		return fmt.Errorf("vtxo tree is missing")
	}
	if connectorTree == nil || connectorTree.Root == nil {
		return fmt.Errorf("connector tree is missing")
	}
	if err := validateTreePackets(vtxoTree, "vtxo"); err != nil {
		return err
	}
	if err := validateTreePackets(connectorTree, "connector"); err != nil {
		return err
	}
	commitment, err := psbt.NewFromRawBytes(strings.NewReader(commitmentTx), true)
	if err != nil {
		return fmt.Errorf("commitment tx: %w", err)
	}
	if commitment.UnsignedTx == nil || len(commitment.UnsignedTx.TxOut) < 2 {
		return fmt.Errorf("commitment tx has no connector output")
	}
	commitmentTxid := commitment.UnsignedTx.TxHash()

	if err := tree.ValidateVtxoTree(vtxoTree, commitment, forfeitPubKey, batchExpiry); err != nil {
		return fmt.Errorf("vtxo tree: %w", err)
	}
	if root := vtxoTree.Root.UnsignedTx.TxIn[0].PreviousOutPoint; root.Hash != commitmentTxid || root.Index != 0 {
		return fmt.Errorf("vtxo tree spends %s, not the batch output of commitment tx %s", root, commitmentTxid)
	}
	if root := connectorTree.Root.UnsignedTx.TxIn[0].PreviousOutPoint; root.Hash != commitmentTxid || root.Index != 1 {
		return fmt.Errorf("connectors spend %s, not connector output 1 of commitment tx %s", root, commitmentTxid)
	}
	if err := connectorTree.Validate(); err != nil {
		return fmt.Errorf("connector tree: %w", err)
	}

	return leavesPayWithAssets(vtxoTree.Leaves(), outputs, assets)
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

// leavesPay reports the first expected output no leaf pays. Finalization also
// checks assets.
func leavesPay(leaves []*psbt.Packet, outputs []*wire.TxOut) error {
	return leavesPayWithAssets(leaves, outputs, nil)
}

func leavesPayWithAssets(leaves []*psbt.Packet, outputs []*wire.TxOut, expectedAssets [][]types.Asset) error {
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
		matched := -1
		for j, candidate := range candidates {
			if expectedAssets == nil || assetsAt(candidate.packet, candidate.index, expectedAssets[i]) {
				matched = j
				break
			}
		}
		if matched < 0 {
			return fmt.Errorf("no leaf pays %d sats to %x", out.Value, out.PkScript)
		}
		candidates[matched] = candidates[len(candidates)-1]
		available[k] = candidates[:len(candidates)-1]
	}
	return nil
}

func assetsAt(packet asset.Packet, index int, expected []types.Asset) bool {
	actual := make(map[string]uint64)
	for _, group := range packet {
		if group.IsIssuance() {
			for _, assetOut := range group.Outputs {
				if int(assetOut.Vout) == index {
					return false
				}
			}
			continue
		}
		for _, assetOut := range group.Outputs {
			if int(assetOut.Vout) == index {
				id := group.AssetId.String()
				if _, exists := actual[id]; exists {
					return false
				}
				actual[id] = assetOut.Amount
			}
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
		v := in.vtxo
		if connectors[i] == nil || connectors[i].UnsignedTx == nil {
			return nil, fmt.Errorf("connector %d is missing", i)
		}
		connectorTx := connectors[i].UnsignedTx
		var connector *wire.TxOut
		var connectorOutpoint *wire.OutPoint
		for vout, out := range connectorTx.TxOut {
			if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
				continue
			}
			connector, connectorOutpoint = out, &wire.OutPoint{Hash: connectorTx.TxHash(), Index: uint32(vout)}
			break
		}
		if connector == nil {
			return nil, fmt.Errorf("connector not found for vtxo %s", v.Outpoint.String())
		}
		hash, err := chainhash.NewHashFromStr(v.Txid)
		if err != nil {
			return nil, err
		}
		forfeit, err := tree.BuildForfeitTx(
			[]*wire.OutPoint{{Hash: *hash, Index: v.VOut}, connectorOutpoint},
			[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
			[]*wire.TxOut{{Value: int64(v.Amount), PkScript: in.pkScript}, connector},
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
