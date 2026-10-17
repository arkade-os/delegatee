package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	offchaintx "github.com/arkade-os/arkd/pkg/client-lib/offchain-tx"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	log "github.com/sirupsen/logrus"
)

// settlement is a transaction that spent a delegation's coins, with the outpoints it advertises.
type settlement struct {
	delegation domain.Delegation
	tx         *wire.MsgTx
	outpoints  map[int]wire.OutPoint
	sources    map[string]*wire.MsgTx
	// the daemon built tx: it is recorded until its successors exist
	own         bool
	spentBy     string
	coins       []string
	checkpoints []string // unsigned, when the daemon submits the offchain tx itself
	finals      []string // while arkd holds an offchain tx it did not finalize
	landed      bool
	created     time.Time
}

// offchainTx keeps the encodings from before any remote signature.
type offchainTx struct {
	ark                 *psbt.Packet
	checkpoints         []*psbt.Packet
	original            string
	originalCheckpoints []string
}

func (s *service) runDirect(ctx context.Context, c *cosigner, inputs []renewalInput, fees arkfee.Config) renewalResult {
	r := renewalResult{inputs: inputs}
	var st settlement
	if inputs[0].watched.tmpl.Type() == template.Offchain {
		r.commitmentTxid, st, r.registered, r.err = s.runOffchain(ctx, c, inputs, fees)
	} else {
		r.commitmentTxid, st, r.err = s.runOnchain(ctx, c, inputs, fees)
	}
	if r.err != nil {
		return r
	}
	s.settle(ctx, st)
	return r
}

func spentBy(d domain.Delegation, tx *wire.MsgTx) settlement {
	outpoints := map[int]wire.OutPoint{}
	for i := range tx.TxOut {
		outpoints[i] = wire.OutPoint{Hash: tx.TxHash(), Index: uint32(i)}
	}
	return settlement{delegation: d, tx: tx, outpoints: outpoints, sources: map[string]*wire.MsgTx{tx.TxHash().String(): tx}}
}

// settle runs once st.tx spent the coins; successors of the daemon's own transactions are retried every scan until the failure is permanent.
func (s *service) settle(ctx context.Context, st settlement) {
	// the coins moved: the deadline of the cycle must not lose their successors
	ctx = context.WithoutCancel(ctx)
	d := &st.delegation
	done := true
	if !d.IsWatch() {
		if err := s.repo.SetStatus(ctx, d.ID, domain.DelegationStatusDone); err != nil {
			log.WithError(err).WithField("delegation", d.ID).Error("complete delegation")
			done = false
		}
	}
	txid := st.tx.TxHash().String()
	err := s.successors(ctx, d, st.tx, st.outpoints, st.sources, st.own)
	if err != nil && st.own && (!done || !permanent(err)) {
		log.WithError(err).WithFields(log.Fields{"delegation": d.ID, "txid": txid}).Error("successors not created: tried again at the next scan")
		st.landed = true
		if err := s.keep(ctx, st); err != nil {
			log.WithError(err).WithField("txid", txid).Error("successors lost")
		}
		return
	}
	if err != nil {
		log.WithError(err).WithFields(log.Fields{"delegation": d.ID, "txid": txid}).Error("successors not created")
	}
	if st.own {
		s.forget(ctx, st)
	}
}

// permanent: every failure in err comes from the advertisement itself.
func permanent(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		return !slices.ContainsFunc(joined.Unwrap(), func(e error) bool { return !permanent(e) })
	}
	for _, target := range []error{
		errUnusableAdvertisement, errOtherKey, domain.ErrTemplateNotFound, domain.ErrTemplateDisabled,
		domain.ErrDelegationAlreadyExists, domain.ErrBlocked, ErrInvalidArgs, ErrIneligible, ErrUnsupported,
		ErrDelegateKeyLeaf, ErrSecretsRequired,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func (s *service) runOffchain(ctx context.Context, c *cosigner, inputs []renewalInput, fees arkfee.Config) (string, settlement, bool, error) {
	spend, coins, hasEmulator, err := s.buildOffchain(ctx, c, inputs, fees)
	if err != nil {
		return "", settlement{}, false, err
	}
	txid := spend.ark.UnsignedTx.TxHash().String()
	st := owned(inputs, spend.ark.UnsignedTx, txid)
	if !hasEmulator {
		st.checkpoints = spend.originalCheckpoints
	}
	// the emulator may submit and finalize it by itself; arkd may accept it and lose the reply
	if err := s.keep(ctx, st); err != nil {
		return "", settlement{}, false, err
	}
	raw, checkpoints := spend.original, slices.Clone(spend.originalCheckpoints)
	if hasEmulator {
		if raw, checkpoints, err = s.emulatorSignsOffchain(ctx, spend.ark, coins, checkpoints); err != nil {
			s.forgetRefused(ctx, st, err)
			return "", settlement{}, false, err
		}
	}
	if err := spend.merge(raw, checkpoints, c); err != nil {
		return "", settlement{}, false, err
	}
	// an emulator signing last submits and finalizes by itself
	if offchaintx.VerifySignedTx(spend.original, raw, s.serverSigners()) == nil {
		return txid, st, true, nil
	}
	finals, accepted, err := s.submitOffchain(ctx, c, inputs[0].watched.delegation.TemplateID, spend)
	if err != nil {
		s.forgetRefused(ctx, st, err)
		return "", settlement{}, accepted, err
	}
	// arkd holds the transaction: the deadline of the cycle must not strand it
	ctx = context.WithoutCancel(ctx)
	st.finals = finals
	if err := s.keep(ctx, st); err != nil {
		log.WithError(err).WithField("txid", txid).Error("pending offchain tx kept in memory until recorded")
		s.keepUnsaved(st)
	}
	if err = s.ark.FinalizeTx(ctx, txid, finals); err != nil {
		if isRejection(ctx, err) {
			s.forget(ctx, st)
		} else {
			// submitting it again would be a duplicate: the next scan finishes it
			for _, in := range inputs {
				s.consume(in.coin.Outpoint.String())
			}
		}
		return "", settlement{}, true, fmt.Errorf("finalize offchain tx: %w", err)
	}
	s.dropUnsaved(txid)
	st.finals = nil
	return txid, st, true, nil
}

// forgetRefused drops st when a refusal proves its tx went nowhere.
func (s *service) forgetRefused(ctx context.Context, st settlement, err error) {
	if errors.Is(err, errIntentRejected) {
		s.forget(context.WithoutCancel(ctx), st)
	}
}

// buildOffchain also reports whether the emulator must cosign.
func (s *service) buildOffchain(ctx context.Context, c *cosigner, inputs []renewalInput, fees arkfee.Config) (*offchainTx, []coin, bool, error) {
	logical, coins, err := s.logicalTx(ctx, inputs, fees)
	if err != nil {
		return nil, nil, false, err
	}
	info, err := s.ark.GetInfo(ctx)
	if err != nil {
		return nil, nil, false, err
	}
	unroll, err := hex.DecodeString(info.CheckpointTapscript)
	if err != nil {
		return nil, nil, false, err
	}
	ins := make([]offchain.VtxoInput, len(inputs))
	for i, in := range inputs {
		if in.onchain {
			return nil, nil, false, errors.New("offchain executor received onchain input")
		}
		leaf := logical.Inputs[i].TaprootLeafScript[0]
		ctrl, err := txscript.ParseControlBlock(leaf.ControlBlock)
		if err != nil {
			return nil, nil, false, err
		}
		ins[i] = offchain.VtxoInput{
			Outpoint: &coins[i].Outpoint, Amount: int64(coins[i].Amount),
			Tapscript:          &waddrmgr.Tapscript{ControlBlock: ctrl, RevealedScript: leaf.Script},
			RevealedTapscripts: in.watched.delegation.Slots[in.coin.Slot].Tapscripts,
		}
	}
	ark, checkpoints, err := offchain.BuildTxs(ins, logical.UnsignedTx.TxOut, unroll)
	if err != nil {
		return nil, nil, false, err
	}
	for i := range inputs {
		witness, err := txutils.GetArkPsbtConditionWitness(logical, i)
		if err != nil {
			return nil, nil, false, err
		}
		if witness == nil {
			continue
		}
		if err = txutils.SetArkPsbtField(ark, i, txutils.ConditionWitnessField, witness); err != nil {
			return nil, nil, false, err
		}
		if err = txutils.SetArkPsbtField(checkpoints[i], 0, txutils.ConditionWitnessField, witness); err != nil {
			return nil, nil, false, err
		}
	}
	if err = s.signForTemplate(ctx, inputs[0].watched.delegation.TemplateID, c, ark); err != nil {
		return nil, nil, false, err
	}
	spend := &offchainTx{ark: ark, checkpoints: checkpoints}
	if spend.original, err = ark.B64Encode(); err != nil {
		return nil, nil, false, err
	}
	if spend.originalCheckpoints, err = encodeAll(checkpoints); err != nil {
		return nil, nil, false, err
	}
	ext, err := extension.NewExtensionFromTx(logical.UnsignedTx)
	hasEmulator := err == nil && ext.GetPacketByType(arkade.PacketType) != nil
	return spend, coins, hasEmulator, nil
}

func (s *service) emulatorSignsOffchain(ctx context.Context, ark *psbt.Packet, coins []coin, checkpoints []string) (string, []string, error) {
	// the emulator reads the transaction funding each checkpoint from the ark input
	for i, coin := range coins {
		if err := txutils.SetArkPsbtField(ark, i, arkade.PrevArkTxField, *coin.Source); err != nil {
			return "", nil, err
		}
	}
	withSources, err := ark.B64Encode()
	if err != nil {
		return "", nil, err
	}
	raw, signed, err := s.emulator.SubmitTx(ctx, withSources, checkpoints)
	if err != nil {
		return "", nil, refusal(ctx, "emulator", err)
	}
	if len(signed) != len(checkpoints) {
		return "", nil, errors.New("emulator changed checkpoint count")
	}
	return raw, signed, nil
}

func (o *offchainTx) merge(raw string, checkpoints []string, c *cosigner) error {
	ark, err := mergeRemoteSignatures(o.original, raw, c)
	if err != nil {
		return err
	}
	o.ark = ark
	for i := range o.checkpoints {
		if o.checkpoints[i], err = mergeRemoteSignatures(o.originalCheckpoints[i], checkpoints[i], c); err != nil {
			return err
		}
	}
	return nil
}

func (s *service) submitOffchain(ctx context.Context, c *cosigner, templateID string, spend *offchainTx) ([]string, bool, error) {
	raw, err := spend.ark.B64Encode()
	if err != nil {
		return nil, false, err
	}
	checkpoints, err := encodeAll(spend.checkpoints)
	if err != nil {
		return nil, false, err
	}
	txid, signedArk, signedCheckpoints, err := s.ark.SubmitTx(ctx, raw, checkpoints)
	if err != nil {
		return nil, false, refusal(ctx, "arkd", err)
	}
	if err = offchaintx.VerifySignedTx(spend.original, signedArk, s.serverSigners()); err != nil {
		return nil, true, err
	}
	if spend.ark.UnsignedTx.TxHash().String() != txid {
		return nil, true, errors.New("ark txid mismatch")
	}
	finals, err := s.signCheckpoints(ctx, c, templateID, spend, signedCheckpoints)
	return finals, true, err
}

// signCheckpoints validates the server's signatures first: checkpoint signatures release the old coins.
func (s *service) signCheckpoints(ctx context.Context, c *cosigner, templateID string, spend *offchainTx, signedCheckpoints []string) ([]string, error) {
	if len(signedCheckpoints) != len(spend.checkpoints) {
		return nil, errors.New("checkpoint count changed")
	}
	if err := offchaintx.VerifySignedCheckpointTxs(spend.originalCheckpoints, signedCheckpoints, s.serverSigners()); err != nil {
		return nil, err
	}
	finals := make([]string, len(signedCheckpoints))
	for i, signed := range signedCheckpoints {
		remote, err := psbt.NewFromRawBytes(strings.NewReader(signed), true)
		if err != nil {
			return nil, err
		}
		j := slices.IndexFunc(spend.checkpoints, func(cp *psbt.Packet) bool { return cp.UnsignedTx.TxHash() == remote.UnsignedTx.TxHash() })
		if j < 0 {
			return nil, errors.New("unknown returned checkpoint")
		}
		addSignatures(spend.checkpoints[j], remote, c)
		if err = s.signForTemplate(ctx, templateID, c, spend.checkpoints[j]); err != nil {
			return nil, err
		}
		if finals[i], err = spend.checkpoints[j].B64Encode(); err != nil {
			return nil, err
		}
	}
	return finals, nil
}

func (s *service) serverSigners() map[string]*btcec.PublicKey {
	return map[string]*btcec.PublicKey{hex.EncodeToString(schnorr.SerializePubKey(s.serverPubKey)): s.serverPubKey}
}

func encodeAll(txs []*psbt.Packet) ([]string, error) {
	out := make([]string, len(txs))
	for i, tx := range txs {
		var err error
		if out[i], err = tx.B64Encode(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// a remote signer changes nothing but signatures
func mergeRemoteSignatures(original, signed string, c *cosigner) (*psbt.Packet, error) {
	local, err := psbt.NewFromRawBytes(strings.NewReader(original), true)
	if err != nil {
		return nil, err
	}
	remote, err := psbt.NewFromRawBytes(strings.NewReader(signed), true)
	if err != nil {
		return nil, err
	}
	if local.UnsignedTx.TxHash() != remote.UnsignedTx.TxHash() || len(local.Inputs) != len(remote.Inputs) {
		return nil, errors.New("remote signer changed transaction")
	}
	addSignatures(local, remote, c)
	return local, nil
}

// addSignatures skips remote signatures under c's key: the daemon makes its own.
func addSignatures(local, remote *psbt.Packet, c *cosigner) {
	own := schnorr.SerializePubKey(c.key.PubKey())
	for i := range local.Inputs {
		for _, sig := range remote.Inputs[i].TaprootScriptSpendSig {
			if !bytes.Equal(sig.XOnlyPubKey, own) && !hasTapscriptSig(local.Inputs[i].TaprootScriptSpendSig, sig.XOnlyPubKey, sig.LeafHash) {
				local.Inputs[i].TaprootScriptSpendSig = append(local.Inputs[i].TaprootScriptSpendSig, sig)
			}
		}
	}
}
