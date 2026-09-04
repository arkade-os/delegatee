package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
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
	var results []renewalResult
	var pending []*pendingIntent
	for start := 0; start < len(inputs); start += s.maxVtxosPerIntent {
		chunk := inputs[start:min(start+s.maxVtxosPerIntent, len(inputs))]
		p, err := s.buildIntent(ctx, chunk)
		if err == nil {
			pending = append(pending, p)
			continue
		}
		if len(chunk) == 1 {
			results = append(results, renewalResult{inputs: chunk, err: err})
			continue
		}
		// one bad vtxo must not block its neighbours: retry them one by one
		log.WithError(err).WithField("count", len(chunk)).Warn("intent rejected, retrying per vtxo")
		for _, in := range chunk {
			single := []renewalInput{in}
			if p, err := s.buildIntent(ctx, single); err != nil {
				results = append(results, renewalResult{inputs: single, err: err})
			} else {
				pending = append(pending, p)
			}
		}
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
	signerSession := tree.NewTreeSignerSession(s.key)
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
		h.signerSession = tree.NewTreeSignerSession(s.key)
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
func (s *service) buildIntent(ctx context.Context, inputs []renewalInput) (*pendingIntent, error) {
	message, err := intent.RegisterMessage{
		BaseMessage:          intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		OnchainOutputIndexes: []int{}, // must encode as "[]"
		CosignersPublicKeys:  []string{s.delegatePubKeyHex},
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
		outputs[i] = &wire.TxOut{Value: int64(in.vtxo.Amount), PkScript: in.pkScript}
		vtxos[i] = in.vtxo
	}
	proof, err := intent.New(message, proofInputs, outputs)
	if err != nil {
		return nil, fmt.Errorf("build intent proof: %w", err)
	}
	ptx := &proof.Packet

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
		prevTx, err := s.virtualTx(ctx, in.vtxo.Txid)
		if err != nil {
			return nil, err
		}
		if err := txutils.SetArkPsbtField(ptx, i, arkade.PrevArkTxField, *prevTx); err != nil {
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

func (s *service) virtualTx(ctx context.Context, txid string) (*wire.MsgTx, error) {
	resp, err := s.indexer.GetVirtualTxs(ctx, []string{txid})
	if err != nil {
		return nil, fmt.Errorf("get virtual tx %s: %w", txid, err)
	}
	if resp == nil || len(resp.Txs) == 0 {
		return nil, fmt.Errorf("virtual tx %s not found", txid)
	}
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(resp.Txs[0]), true)
	if err != nil {
		return nil, err
	}
	return ptx.UnsignedTx, nil
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
	sweepScript, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{h.svc.forfeitPubKey}},
		Locktime:        h.batchExpiry,
	}).Script()
	if err != nil {
		return false, err
	}
	root := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(sweepScript)).RootNode.TapHash()

	commitmentTx, err := psbt.NewFromRawBytes(strings.NewReader(event.UnsignedCommitmentTx), true)
	if err != nil {
		return false, err
	}
	if err := h.signerSession.Init(root.CloneBytes(), commitmentTx.UnsignedTx.TxOut[0].Value, vtxoTree); err != nil {
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
	ctx context.Context, event client.BatchFinalizationEvent, _, connectorTree *tree.TxTree,
) ([]string, error) {
	if connectorTree == nil {
		return nil, fmt.Errorf("connector tree is nil")
	}
	flatConnectorTree, err := connectorTree.Serialize()
	if err != nil {
		return nil, err
	}
	// arkd only streams the connector leaves assigned to our vtxos; any
	// unused one is valid for any of them, so hand them out in order
	connectors := connectorTree.Leaves()
	var signed []string
	for _, p := range h.inBatch {
		if len(connectors) < len(p.inputs) {
			return nil, fmt.Errorf("got %d connectors for %d vtxos", len(connectors), len(p.inputs))
		}
		forfeits, err := h.buildForfeits(p.inputs, connectors[:len(p.inputs)])
		if err != nil {
			return nil, err
		}
		connectors = connectors[len(p.inputs):]
		signedForfeits, signedCommitmentTx, err := h.svc.emulator.SubmitFinalization(
			ctx, p.intent, forfeits, flatConnectorTree, event.Tx,
		)
		if err != nil {
			return nil, fmt.Errorf("emulator finalization: %w", err)
		}
		if err := h.svc.ark.SubmitSignedForfeitTxs(ctx, signedForfeits, signedCommitmentTx); err != nil {
			return nil, err
		}
		signed = append(signed, signedForfeits...)
	}
	return signed, nil
}

func (h *batchHandler) buildForfeits(inputs []renewalInput, connectors []*psbt.Packet) ([]string, error) {
	forfeits := make([]string, 0, len(inputs))
	for i, in := range inputs {
		v := in.vtxo
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
