package application

import (
	"bytes"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestOffchainClaim(t *testing.T) {
	e, server, inputs := claimEnv(t)
	e.emulator.submitTx = func(tx string, cps []string) (string, []string, error) {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		require.NoError(t, err)
		prev, err := txutils.GetArkPsbtFields(ptx, 0, arkade.PrevArkTxField)
		require.NoError(t, err)
		require.Len(t, prev, 1, "the ark input carries the transaction funding its checkpoint")
		require.Equal(t, inputs[0].coin.Outpoint.Hash.String(), prev[0].TxHash().String())
		return tx, cps, nil // without the server's signature: arkd comes next
	}
	e.ark.submitTx = func(ark string, cps []string) (string, string, []string, error) {
		ptx, signed := signAs(t, server, ark)
		prev, err := txutils.GetArkPsbtFields(ptx, 0, arkade.PrevArkTxField)
		require.NoError(t, err)
		require.Empty(t, prev, "the source transactions are for the emulator")
		require.Len(t, cps, 1)
		_, cp := signAs(t, server, cps[0])
		return ptx.UnsignedTx.TxHash().String(), signed, []string{cp}, nil
	}
	txid, st, accepted, err := e.svc.runOffchain(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.NoError(t, err)
	require.True(t, accepted)
	require.Equal(t, st.tx.TxHash().String(), txid)
	require.Equal(t, "5120"+inputs[0].watched.delegation.Variables["receiver_program"], hex.EncodeToString(st.tx.TxOut[0].PkScript))
	require.EqualValues(t, inputs[0].coin.Amount, st.tx.TxOut[0].Value)
	require.Len(t, e.ark.finalized, 1)
	final, err := psbt.NewFromRawBytes(strings.NewReader(e.ark.finalized[0]), true)
	require.NoError(t, err)
	require.Len(t, final.Inputs[0].TaprootScriptSpendSig, 1)
	require.Equal(t, schnorr.SerializePubKey(server.PubKey()), final.Inputs[0].TaprootScriptSpendSig[0].XOnlyPubKey)
}

func TestOffchainRefusalAndOutage(t *testing.T) {
	e, _, inputs := claimEnv(t)
	e.emulator.submitTx = func(tx string, cps []string) (string, []string, error) { return tx, cps, nil }
	for code, rejected := range map[codes.Code]bool{codes.InvalidArgument: true, codes.Unavailable: false} {
		e.ark.submitTx = func(string, []string) (string, string, []string, error) {
			return "", "", nil, status.Error(code, "no")
		}
		_, _, accepted, err := e.svc.runOffchain(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
		require.Error(t, err)
		require.False(t, accepted)
		require.Equal(t, rejected, errors.Is(err, errIntentRejected), code.String())
		require.Empty(t, e.ark.finalized)
	}
}

// A template holding secrets is watched only while trusted.
func TestOffchainUntrustedNeverSubmits(t *testing.T) {
	e := newTestEnv(t)
	secrets, _ := hexKey(t)
	e.svc.encryptionKeys = []*btcec.PrivateKey{secrets}
	vars := claimVars(t, secrets.PubKey())
	vars["receiver"] = cosignerHex // the delegate claims for itself
	d, err := e.svc.RegisterDelegation(t.Context(), e.trust(t, e.fixture(t, "vhtlc_claim.json")), vars, nil)
	require.NoError(t, err)
	require.NoError(t, e.svc.SetTemplateTrusted(t.Context(), d.TemplateID, false))
	script, err := hex.DecodeString(d.Slots[0].Script)
	require.NoError(t, err)
	e.indexer.serve(e.vtxoAt(t, script, 10_000, time.Hour))
	// submitTx is nil: a submission would panic
	e.scan(t)
	require.Equal(t, ErrSecretsRequired.Error(), e.svc.Status().Unwatched[d.ID])
	require.Empty(t, e.repo.recorded())
}

// no emulator involved
func TestOffchainDelegateSigns(t *testing.T) {
	e, server := serverEnv(t)
	tmpl, err := e.svc.RegisterTemplate(t.Context(), []byte(delegatedTransfer))
	require.NoError(t, err)
	d, err := e.svc.RegisterDelegation(t.Context(), e.trust(t, tmpl.ID), nil, nil)
	require.NoError(t, err)
	inputs := dueAt(t, e, d)
	delegate := schnorr.SerializePubKey(e.svc.cosigners[0].key.PubKey())
	e.ark.submitTx = func(ark string, cps []string) (string, string, []string, error) {
		ptx, signed := signAs(t, server, ark)
		require.True(t, signedBy(ptx, delegate), "the ark tx comes signed by the delegate key")
		require.Len(t, cps, 1)
		cp, _ := signAs(t, server, cps[0])
		// a bogus signature labelled with the delegate key must not replace the daemon's
		leaf := cp.Inputs[0].TaprootLeafScript[0]
		hash := txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script).TapHash()
		cp.Inputs[0].TaprootScriptSpendSig = append(cp.Inputs[0].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: delegate, LeafHash: hash[:], Signature: make([]byte, 64),
		})
		planted, err := cp.B64Encode()
		require.NoError(t, err)
		return ptx.UnsignedTx.TxHash().String(), signed, []string{planted}, nil
	}
	_, _, accepted, err := e.svc.runOffchain(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.NoError(t, err)
	require.True(t, accepted)
	require.Empty(t, e.emulator.submitted)
	require.Len(t, e.ark.finalized, 1)
	final, err := psbt.NewFromRawBytes(strings.NewReader(e.ark.finalized[0]), true)
	require.NoError(t, err)
	require.True(t, signedBy(final, delegate))
	require.True(t, signedBy(final, schnorr.SerializePubKey(server.PubKey())))
	for _, sig := range final.Inputs[0].TaprootScriptSpendSig {
		require.NotEqual(t, make([]byte, 64), sig.Signature, "the daemon's own signature")
	}

	e.ark.submitTx, e.ark.finalized = nil, nil // a submission would panic
	require.NoError(t, e.svc.SetTemplateTrusted(t.Context(), d.TemplateID, false))
	_, _, _, err = e.svc.runOffchain(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.ErrorIs(t, err, ErrDelegateKeyLeaf)
}

func TestOffchainEmulatorFinalizes(t *testing.T) {
	e, server, inputs := claimEnv(t)
	e.emulator.submitTx = func(tx string, cps []string) (string, []string, error) {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		require.NoError(t, err)
		prev, err := txutils.GetArkPsbtFields(ptx, 0, arkade.PrevArkTxField)
		require.NoError(t, err)
		require.Len(t, prev, 1, "the ark input carries the transaction funding its checkpoint")
		require.Equal(t, inputs[0].coin.Outpoint.Hash.String(), prev[0].TxHash().String())
		_, tx = signAs(t, server, tx)
		for i := range cps {
			_, cps[i] = signAs(t, server, cps[i])
		}
		return tx, cps, nil
	}
	// ark.submitTx is nil: a second submission would panic
	txid, st, accepted, err := e.svc.runOffchain(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.NoError(t, err)
	require.True(t, accepted)
	require.Equal(t, st.tx.TxHash().String(), txid)
	require.Empty(t, e.ark.finalized)
}

func TestOffchainKeepsEmulatorSignatures(t *testing.T) {
	e, server, inputs := claimEnv(t)
	emulator := bytes.Repeat([]byte{0xee}, 32)
	sign := func(raw string) string {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
		require.NoError(t, err)
		for i := range ptx.Inputs {
			ptx.Inputs[i].TaprootScriptSpendSig = append(ptx.Inputs[i].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
				XOnlyPubKey: emulator, LeafHash: make([]byte, 32), Signature: make([]byte, 64),
			})
		}
		out, err := ptx.B64Encode()
		require.NoError(t, err)
		return out
	}
	e.emulator.submitTx = func(tx string, cps []string) (string, []string, error) {
		for i := range cps {
			cps[i] = sign(cps[i])
		}
		return sign(tx), cps, nil
	}
	e.ark.submitTx = func(ark string, cps []string) (string, string, []string, error) {
		ptx, signed := signAs(t, server, ark)
		// arkd signs checkpoints it rebuilt: nobody else's signature comes back
		for i := range cps {
			cp, err := psbt.NewFromRawBytes(strings.NewReader(cps[i]), true)
			require.NoError(t, err)
			for j := range cp.Inputs {
				cp.Inputs[j].TaprootScriptSpendSig = nil
			}
			bare, err := cp.B64Encode()
			require.NoError(t, err)
			_, cps[i] = signAs(t, server, bare)
		}
		return ptx.UnsignedTx.TxHash().String(), signed, cps, nil
	}
	_, _, accepted, err := e.svc.runOffchain(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.NoError(t, err)
	require.True(t, accepted)
	require.Len(t, e.ark.finalized, 1)
	final, err := psbt.NewFromRawBytes(strings.NewReader(e.ark.finalized[0]), true)
	require.NoError(t, err)
	var signers [][]byte
	for _, sig := range final.Inputs[0].TaprootScriptSpendSig {
		signers = append(signers, sig.XOnlyPubKey)
	}
	require.ElementsMatch(t, [][]byte{emulator, schnorr.SerializePubKey(server.PubKey())}, signers)
}

// a duplicate submission is not the template's fault
func TestOffchainFinishesAPendingTx(t *testing.T) {
	e, server, inputs := claimEnv(t)
	e.emulator.submitTx = func(tx string, cps []string) (string, []string, error) { return tx, cps, nil }
	submitted := 0
	e.ark.submitTx = func(ark string, cps []string) (string, string, []string, error) {
		submitted++
		ptx, signed := signAs(t, server, ark)
		_, cp := signAs(t, server, cps[0])
		return ptx.UnsignedTx.TxHash().String(), signed, []string{cp}, nil
	}
	e.ark.finalizeErrs = []error{status.Error(codes.Unavailable, "later")}
	e.svc.renewAndRecord(t.Context(), inputs)
	require.Empty(t, e.ark.finalized)
	require.False(t, e.repo.recorded()[0].Success)

	e.indexer.serve(asVtxo(inputs[0].coin)) // the indexer still lists the coin
	e.scan(t)
	require.Equal(t, 1, submitted, "finished, not submitted again")
	require.Len(t, e.ark.finalized, 1)
	recorded := e.repo.recorded()
	require.True(t, recorded[len(recorded)-1].Success)
	require.Empty(t, e.repo.settled())

	require.False(t, isRejection(t.Context(), status.Error(codes.InvalidArgument, "duplicated offchain tx abc")))
}

// finished, not dropped, when the indexer already shows the coin spent
func TestOffchainPendingTxOfASpentCoin(t *testing.T) {
	e, server, inputs := claimEnv(t)
	ctx := t.Context()
	watch := inputs[0].watched.delegation
	require.NoError(t, e.svc.CancelDelegationByID(ctx, watch.ID))
	bound := watch
	bound.Address, bound.ParentID, bound.Fingerprint = "", watch.ID, "bound"
	bound.Slots = []domain.SlotBinding{watch.Slots[0]}
	bound.Slots[0].Outpoint = inputs[0].coin.Outpoint.String()
	d, err := e.repo.Create(ctx, bound, 0)
	require.NoError(t, err)
	in := inputs[0]
	in.watched, err = e.svc.watch(ctx, d)
	require.NoError(t, err)
	e.emulator.submitTx = func(tx string, cps []string) (string, []string, error) { return tx, cps, nil }
	e.ark.submitTx = func(ark string, cps []string) (string, string, []string, error) {
		ptx, signed := signAs(t, server, ark)
		_, cp := signAs(t, server, cps[0])
		return ptx.UnsignedTx.TxHash().String(), signed, []string{cp}, nil
	}
	e.ark.finalizeErrs = []error{status.Error(codes.Unavailable, "later"), status.Error(codes.Unavailable, "later")}
	e.svc.renewAndRecord(ctx, []renewalInput{in})
	require.Len(t, e.repo.settled(), 1)
	for _, row := range e.repo.settled() {
		e.indexer.known = []clientlib.Vtxo{arkSpent(in.coin, row.Txid)}
		tx := wire.NewMsgTx(2)
		require.NoError(t, tx.Deserialize(bytes.NewReader(row.Tx)))
		ptx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)
		e.indexer.txs[row.Txid], err = ptx.B64Encode()
		require.NoError(t, err)
	}

	e.indexer.serve()
	e.scan(t) // arkd is still out
	require.Len(t, e.repo.settled(), 1, "still to finish")
	require.Len(t, e.active(t), 1, "the delegation waits for its own tx")
	e.indexer.serve()
	e.scan(t)
	require.Len(t, e.ark.finalized, 1)
	require.Empty(t, e.repo.settled())
}

func TestDiscoverWaitsForHeightLocktime(t *testing.T) {
	e, _, d := refundEnv(t, 200)
	pkScript, err := hex.DecodeString(d.Slots[0].Script)
	require.NoError(t, err)
	coin := e.vtxoAt(t, pkScript, 10_000, time.Hour)
	active := map[string]struct{}{d.TemplateID: {}}

	e.explorer.tip.Height = 199
	e.indexer.serve(coin) // the fake serves a coin once
	held, _, inputs, err := e.svc.discover(t.Context(), []domain.Delegation{*d}, active, time.Now())
	require.NoError(t, err)
	require.Empty(t, inputs, "arkd would refuse it below height 200")
	require.WithinDuration(t, time.Now().Add(10*time.Minute), held[d.ID].NextDue, time.Minute, "due in about a block")

	e.explorer.tip, e.explorer.tipErr = ports.ChainTip{}, errors.New("explorer down")
	e.indexer.serve(coin) // the fake serves a coin once
	_, _, inputs, err = e.svc.discover(t.Context(), []domain.Delegation{*d}, active, time.Now())
	require.NoError(t, err)
	require.Empty(t, inputs, "an unknown tip waits")

	e.explorer.tip, e.explorer.tipErr = ports.ChainTip{Height: 200}, nil
	e.indexer.serve(coin) // the fake serves a coin once
	_, _, inputs, err = e.svc.discover(t.Context(), []domain.Delegation{*d}, active, time.Now())
	require.NoError(t, err)
	require.Len(t, inputs, 1)
}

func TestDiscoverWaitsForMedianTime(t *testing.T) {
	now := time.Now()
	e, _, d := refundEnv(t, now.Add(-time.Hour).Unix())
	pkScript, err := hex.DecodeString(d.Slots[0].Script)
	require.NoError(t, err)
	coin := e.vtxoAt(t, pkScript, 10_000, time.Hour)
	active := map[string]struct{}{d.TemplateID: {}}

	e.explorer.tip.MedianTime = now.Add(-2 * time.Hour).Unix()
	e.indexer.serve(coin) // the fake serves a coin once
	_, _, inputs, err := e.svc.discover(t.Context(), []domain.Delegation{*d}, active, now)
	require.NoError(t, err)
	require.Empty(t, inputs, "arkd compares a timestamp with the median time past, which lags the clock")

	e.explorer.tip.MedianTime = now.Add(-time.Hour).Unix()
	e.indexer.serve(coin)
	_, _, inputs, err = e.svc.discover(t.Context(), []domain.Delegation{*d}, active, now)
	require.NoError(t, err)
	require.Len(t, inputs, 1)
}

func TestOffchainRefundSetsLocktime(t *testing.T) {
	e, server, d := refundEnv(t, 200)
	e.explorer.tip.Height = 200
	inputs := dueAt(t, e, d)
	e.emulator.submitTx = func(tx string, cps []string) (string, []string, error) { return tx, cps, nil }
	e.ark.submitTx = func(ark string, cps []string) (string, string, []string, error) {
		ptx, signed := signAs(t, server, ark)
		require.EqualValues(t, 200, ptx.UnsignedTx.LockTime)
		require.Equal(t, uint32(wire.MaxTxInSequenceNum-1), ptx.UnsignedTx.TxIn[0].Sequence)
		cp, cpSigned := signAs(t, server, cps[0])
		require.EqualValues(t, 200, cp.UnsignedTx.LockTime, "the checkpoint spends the CLTV leaf")
		return ptx.UnsignedTx.TxHash().String(), signed, []string{cpSigned}, nil
	}
	_, st, accepted, err := e.svc.runOffchain(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.NoError(t, err)
	require.True(t, accepted)
	require.Equal(t, "5120"+d.Variables["sender_program"], hex.EncodeToString(st.tx.TxOut[0].PkScript))
}

func TestOffchainLockedRefusalRetries(t *testing.T) {
	e, _, d := refundEnv(t, 200)
	e.explorer.tip.Height = 200
	inputs := dueAt(t, e, d)
	e.emulator.submitTx = func(tx string, cps []string) (string, []string, error) { return tx, cps, nil }
	e.ark.submitTx = func(string, []string) (string, string, []string, error) {
		return "", "", nil, status.Error(codes.FailedPrecondition, "FORFEIT_CLOSURE_LOCKED: 200 > 199 (blockheight)")
	}
	_, _, _, err := e.svc.runOffchain(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.Error(t, err)
	require.False(t, permanent(err), "the next scan retries")
	require.NotErrorIs(t, err, errIntentRejected, "an early spend says nothing against the template")
}

func claimEnv(t *testing.T) (*testEnv, *btcec.PrivateKey, []renewalInput) {
	e, server := serverEnv(t)
	secrets, _ := hexKey(t)
	e.svc.encryptionKeys = []*btcec.PrivateKey{secrets}
	d, err := e.svc.RegisterDelegation(t.Context(), e.trust(t, e.fixture(t, "vhtlc_claim.json")), claimVars(t, secrets.PubKey()), nil)
	require.NoError(t, err)
	return e, server, dueAt(t, e, d)
}

// refundEnv watches the VHTLC refund path, which needs no preimage after locktime.
func refundEnv(t *testing.T, locktime int64) (*testEnv, *btcec.PrivateKey, *domain.Delegation) {
	t.Helper()
	e, server := serverEnv(t)
	secrets, _ := hexKey(t)
	e.svc.encryptionKeys = []*btcec.PrivateKey{secrets}
	tmpl, err := e.svc.RegisterTemplate(t.Context(), document(t, "vhtlc_refund.json"))
	require.NoError(t, err)
	vars := claimVars(t, secrets.PubKey())
	lock, err := arkade.BigNumFromInt64(locktime).Bytes()
	require.NoError(t, err)
	vars["refund_locktime"] = hex.EncodeToString(lock)
	d, err := e.svc.RegisterDelegation(t.Context(), e.trust(t, tmpl.ID), vars, nil)
	require.NoError(t, err)
	return e, server, d
}

func serverEnv(t *testing.T) (*testEnv, *btcec.PrivateKey) {
	server, serverHex := hexKey(t)
	e := newTestEnv(t, func(e *testEnv) {
		unroll, err := (&script.CSVMultisigClosure{
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{server.PubKey()}},
			Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
		}).Script()
		require.NoError(t, err)
		e.ark.info.SignerPubKey = serverHex
		e.ark.info.CheckpointTapscript = hex.EncodeToString(unroll)
	})
	return e, server
}

// dueAt is a 10,000-satoshi vtxo at watch d.
func dueAt(t *testing.T, e *testEnv, d *domain.Delegation) []renewalInput {
	t.Helper()
	pkScript, err := hex.DecodeString(d.Slots[0].Script)
	require.NoError(t, err)
	e.indexer.serve(e.vtxoAt(t, pkScript, 10_000, time.Hour))
	_, _, inputs, err := e.svc.discover(t.Context(), []domain.Delegation{*d}, map[string]struct{}{d.TemplateID: {}}, time.Now())
	require.NoError(t, err)
	require.Len(t, inputs, 1)
	return inputs
}

func signAs(t *testing.T, key *btcec.PrivateKey, raw string) (*psbt.Packet, string) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
	require.NoError(t, err)
	n, err := signDelegateInputs(ptx, key, witnessPrevouts(ptx))
	require.NoError(t, err)
	require.Equal(t, len(ptx.Inputs), n)
	out, err := ptx.B64Encode()
	require.NoError(t, err)
	return ptx, out
}

func signedBy(ptx *psbt.Packet, key []byte) bool {
	return !slices.ContainsFunc(ptx.Inputs, func(in psbt.PInput) bool {
		return !slices.ContainsFunc(in.TaprootScriptSpendSig, func(sig *psbt.TaprootScriptSpendSig) bool { return bytes.Equal(sig.XOnlyPubKey, key) })
	})
}

// delegatedTransfer pays a vtxo on under the server and delegate keys.
const delegatedTransfer = `{
  "format": "delegateed-template/v1",
  "type": "offchain",
  "inputs": [{
    "name": "funds",
    "contract": {
      "definition": {
        "contractName": "Delegated",
        "constructorInputs": [{"name": "delegate", "type": "pubkey"}],
        "structs": [],
        "functions": [{"name": "spend", "leaves": [{
          "name": "spend",
          "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<delegate>", "OP_CHECKSIG"],
          "witness": [
            {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true},
            {"name": "delegateSig", "type": "signature", "encoding": "schnorr-64", "injected": true}
          ]
        }]}]
      },
      "arguments": {"delegate": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}
    },
    "spend": {"function": "spend", "leaf": "spend"}
  }],
  "outputs": [{"name": "payment", "index": 0, "value": {"from": "funds"}, "locking": "5120f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"}]
}`
