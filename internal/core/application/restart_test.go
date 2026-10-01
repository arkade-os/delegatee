package application

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/delegatee/internal/core/domain"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// the stream ends once the intent is registered: nothing moved, the restarted daemon renews the coin
func TestRestartAfterRegister(t *testing.T) {
	e := newTestEnv(t)
	in := dueInput(t, e, 0, 10_000)
	e.indexer.serve(asVtxo(in.coin))
	e.scan(t)
	require.Len(t, e.ark.registered, 1)
	require.Empty(t, e.ark.forfeits)
	require.Empty(t, e.repo.settled())

	r := e.restart(t)
	r.ark.registered = nil // arkd dropped the stale intent
	batch := r.playBatch(t)
	r.indexer.serve(asVtxo(in.coin))
	r.scan(t)
	r.requireSettledOnce(t, in, batch)
}

// the stream ends once the forfeits reached arkd: the restarted daemon follows the batch
func TestRestartAfterForfeits(t *testing.T) {
	e := newTestEnv(t)
	in := dueInput(t, e, 0, 10_000)
	batch := e.playBatch(t)
	batch.closeAfterForfeits = true
	e.indexer.serve(asVtxo(in.coin))
	e.scan(t)
	require.Len(t, e.ark.forfeits, 1)
	require.Len(t, e.active(t), 1, "the predecessor alone")
	require.Len(t, e.repo.settled(), 1)

	r := e.restart(t)
	r.indexer.known = []clientlib.Vtxo{settledBy(in.coin, batch.txid)}
	r.indexer.serve()
	r.scan(t)
	r.requireSettledOnce(t, in, batch)
}

// arkd never reports the batch finalized: the renewal times out, the restarted daemon follows the batch
func TestRestartWithoutFinalizationEvent(t *testing.T) {
	e := newTestEnv(t)
	e.svc.renewalTimeout = 200 * time.Millisecond
	in := dueInput(t, e, 0, 10_000)
	batch := e.playBatch(t)
	batch.hangAfterForfeits = true
	e.indexer.serve(asVtxo(in.coin))
	e.scan(t)
	require.Len(t, e.ark.forfeits, 1)
	require.Len(t, e.active(t), 1, "the predecessor alone")

	r := e.restart(t)
	// the commitment is not listed yet: the settlement waits and holds the coin
	r.indexer.known = []clientlib.Vtxo{asVtxo(in.coin)}
	r.indexer.serve(asVtxo(in.coin))
	r.scan(t)
	require.Len(t, r.active(t), 1)
	require.Len(t, r.repo.settled(), 1)
	require.Len(t, r.ark.registered, 1, "not registered again")

	r.indexer.known = []clientlib.Vtxo{settledBy(in.coin, batch.txid)}
	r.indexer.serve()
	r.scan(t)
	r.requireSettledOnce(t, in, batch)
}

// the coin of a stale settlement was renewed by another batch: the settlement is dropped, never followed
func TestRestartDropsARowSpentByAnotherBatch(t *testing.T) {
	e := newTestEnv(t)
	in := dueInput(t, e, 0, 10_000)
	failed := e.playBatch(t)
	failed.closeAfterForfeits = true
	e.indexer.serve(asVtxo(in.coin))
	e.scan(t)
	require.Len(t, e.repo.settled(), 1)

	r := e.restart(t)
	r.indexer.known = []clientlib.Vtxo{settledBy(in.coin, "another commitment")}
	r.indexer.serve()
	r.scan(t)
	require.Empty(t, r.repo.settled())
	require.Len(t, r.active(t), 1, "the watch alone, no successor from the stale batch")
}

// arkd reports the batch failed after the forfeits: they are void and the coin is renewed at the next scan
func TestBatchFailedFreesTheCoin(t *testing.T) {
	e := newTestEnv(t)
	in := dueInput(t, e, 0, 10_000)
	failed := e.playBatch(t)
	failed.failAfterForfeits = true
	e.indexer.serve(asVtxo(in.coin))
	e.scan(t)
	require.Empty(t, e.repo.settled())

	e.ark.forfeits, e.ark.confirmed, e.ark.registered = nil, nil, nil // a new batch
	batch := e.playBatch(t)
	e.indexer.known = []clientlib.Vtxo{asVtxo(in.coin)}
	e.indexer.serve(asVtxo(in.coin))
	e.scan(t)
	e.requireSettledOnce(t, in, batch)
}

// the session fails before any forfeit is sent: nothing can land and the coin is free
func TestUnsentForfeitsFreeTheCoin(t *testing.T) {
	e := newTestEnv(t)
	in := dueInput(t, e, 0, 10_000)
	e.emulator.forfeits = func(emulatorclient.Intent, []string) []string { return nil }
	e.playBatch(t)
	results := e.svc.renew(t.Context(), []renewalInput{in})
	require.Error(t, results[0].err)
	require.Empty(t, e.ark.forfeits)
	require.Empty(t, e.repo.settled())
}

// the daemon dies between recording the batch and its forfeits: the coin waits for the batch, then is renewed
func TestRestartBetweenRecordAndForfeits(t *testing.T) {
	e := newTestEnv(t)
	in := dueInput(t, e, 0, 10_000)
	crashed := e.playBatch(t)
	crashed.crashAtForfeits = true
	e.indexer.serve(asVtxo(in.coin))
	e.scan(t)
	require.Empty(t, e.ark.forfeits)
	require.Len(t, e.repo.settled(), 1, "the forfeits may have reached arkd")

	r := e.restart(t)
	r.ark.forfeits, r.ark.confirmed, r.ark.registered = nil, nil, nil
	r.indexer.known = []clientlib.Vtxo{asVtxo(in.coin)}
	r.indexer.serve(asVtxo(in.coin))
	r.scan(t)
	require.Empty(t, r.ark.registered, "held while the batch may land")

	r.repo.age(landingWindow)
	batch := r.playBatch(t)
	r.indexer.serve(asVtxo(in.coin))
	r.scan(t)
	r.requireSettledOnce(t, in, batch)
}

// an emulator outage is not a spend: the coin is retried at the next scan
func TestEmulatorOutageRetriesAtTheNextScan(t *testing.T) {
	e, server, inputs := claimEnv(t)
	submitted := acceptOffchain(t, e, server)
	calls := 0
	e.emulator.submitTx = func(tx string, cps []string) (string, []string, error) {
		if calls++; calls == 1 {
			return "", nil, status.Error(codes.Unavailable, "emulator down")
		}
		return tx, cps, nil
	}
	e.svc.renewAndRecord(t.Context(), inputs)
	e.indexer.known = []clientlib.Vtxo{asVtxo(inputs[0].coin)}
	e.indexer.serve(asVtxo(inputs[0].coin))
	e.scan(t)
	require.Equal(t, 2, calls)
	require.Equal(t, 1, *submitted)
	require.Len(t, e.ark.finalized, 1)
}

// a refused submission spends nothing: no settlement is left
func TestRefusedSubmitLeavesNoRow(t *testing.T) {
	e, _, inputs := claimEnv(t)
	e.emulator.submitTx = func(tx string, cps []string) (string, []string, error) { return tx, cps, nil }
	e.ark.submitTx = func(string, []string) (string, string, []string, error) {
		return "", "", nil, status.Error(codes.InvalidArgument, "invalid tx")
	}
	e.svc.renewAndRecord(t.Context(), inputs)
	require.Empty(t, e.repo.settled())
}

// the final checkpoints could not be recorded and FinalizeTx failed: the next scan records and finalizes them
func TestUnsavedFinalsAreRetried(t *testing.T) {
	e, server, inputs := claimEnv(t)
	submitted := acceptOffchain(t, e, server)
	e.repo.finalsSaveErr = errBoom
	e.ark.finalizeErrs = []error{status.Error(codes.Unavailable, "later")}
	e.svc.renewAndRecord(t.Context(), inputs)
	require.Empty(t, e.ark.finalized)
	e.repo.finalsSaveErr = nil

	e.indexer.known = []clientlib.Vtxo{arkSpent(inputs[0].coin, e.repo.settled()[0].Txid)}
	e.indexer.serve()
	e.scan(t)
	require.Len(t, e.ark.finalized, 1)
	require.Equal(t, 1, *submitted)
	require.Empty(t, e.repo.settled())
}

// arkd failed the pending tx: FinalizeTx answers Internal for good, the bound delegation ends
func TestArkdFailedPendingTx(t *testing.T) {
	e, server, in := boundClaim(t)
	acceptOffchain(t, e, server)
	internal := status.Error(codes.Internal, "not in a valid stage to finalize offchain tx")
	e.ark.finalizeErrs = []error{status.Error(codes.Unavailable, "later"), internal, internal, internal}
	e.svc.renewAndRecord(t.Context(), []renewalInput{in})
	txid := e.repo.settled()[0].Txid
	e.indexer.known = []clientlib.Vtxo{arkSpent(in.coin, txid)}

	e.indexer.serve()
	e.scan(t)
	require.Len(t, e.repo.settled(), 1, "a young row is retried")
	require.Len(t, e.active(t), 1)

	backdateFailures(e.svc, 2*e.svc.renewalTimeout)
	e.indexer.serve()
	e.scan(t)
	require.Empty(t, e.repo.settled())
	got, err := e.repo.GetByID(t.Context(), in.watched.delegation.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusDone, got.Status)
	calls := e.ark.finalizes
	e.indexer.serve()
	e.scan(t)
	require.Equal(t, calls, e.ark.finalizes, "FinalizeTx is not called again")
}

// an old row is not abandoned on transient errors, however long they last: only arkd refusing ends it
func TestOldRowSurvivesTransientErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault func(e *testEnv)
	}{
		{"arkd unavailable", func(e *testEnv) {
			down := status.Error(codes.Unavailable, "down")
			e.ark.finalizeErrs = []error{down, down}
		}},
		{"indexer internal", func(e *testEnv) {
			e.indexer.err = status.Error(codes.Internal, "database is locked")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, server, in := boundClaim(t)
			acceptOffchain(t, e, server)
			e.ark.finalizeErrs = []error{status.Error(codes.Unavailable, "later")}
			e.svc.renewAndRecord(t.Context(), []renewalInput{in})
			e.indexer.known = []clientlib.Vtxo{arkSpent(in.coin, e.repo.settled()[0].Txid)}

			r := e.restart(t) // down for hours
			r.repo.age(24 * time.Hour)
			tc.fault(r)
			r.indexer.serve()
			r.scan(t)
			backdateFailures(r.svc, 2*r.svc.renewalTimeout)
			r.indexer.serve()
			r.scan(t)
			require.Len(t, r.repo.settled(), 1)
			got, err := r.repo.GetByID(t.Context(), in.watched.delegation.ID)
			require.NoError(t, err)
			require.Equal(t, domain.DelegationStatusActive, got.Status)
		})
	}
	t.Run("GetPendingTx unavailable", func(t *testing.T) {
		e, pending := lostReply(t)
		r := e.restart(t)
		r.repo.age(24 * time.Hour)
		r.svc.ark = &pendingOutage{r.ark}
		r.indexer.known = []clientlib.Vtxo{arkSpent(pending.coin, pending.txid)}
		r.indexer.serve()
		r.scan(t)
		backdateFailures(r.svc, 2*r.svc.renewalTimeout)
		r.indexer.serve()
		r.scan(t)
		require.Len(t, r.repo.settled(), 1)
	})
}

// arkd lists no such tx for a renewal timeout: the row is abandoned
func TestUnlistedPendingTxIsAbandoned(t *testing.T) {
	e, pending := lostReply(t)
	r := e.restart(t)
	r.ark.pending = nil
	r.indexer.known = []clientlib.Vtxo{arkSpent(pending.coin, pending.txid)}
	r.indexer.serve()
	r.scan(t)
	require.Len(t, r.repo.settled(), 1, "a first miss")

	backdateFailures(r.svc, 2*r.svc.renewalTimeout)
	r.indexer.serve()
	r.scan(t)
	require.Empty(t, r.repo.settled())
}

// arkd lists another pending tx first and ours unsigned by the server: only ours, only once signed
func TestRecoveryChecksWhatArkdReturns(t *testing.T) {
	t.Run("another tx first", func(t *testing.T) {
		e, pending := lostReply(t)
		r := e.restart(t)
		ours := r.ark.pending[0]
		r.ark.pending = []clientlib.AcceptedOffchainTx{{Txid: "other", FinalArkTx: ours.FinalArkTx, SignedCheckpointTxs: []string{ours.FinalArkTx}}, ours}
		r.indexer.known = []clientlib.Vtxo{arkSpent(pending.coin, pending.txid)}
		r.indexer.serve()
		r.scan(t)
		require.Len(t, r.ark.finalized, 1)
	})
	t.Run("no server signature", func(t *testing.T) {
		e, pending := lostReply(t)
		r := e.restart(t)
		r.ark.pending[0].SignedCheckpointTxs = []string{pending.checkpoint}
		r.indexer.known = []clientlib.Vtxo{arkSpent(pending.coin, pending.txid)}
		r.indexer.serve()
		r.scan(t)
		require.Zero(t, r.ark.finalizes)
		require.Len(t, r.repo.settled(), 1)
	})
}

// the finals were recorded late: a tx finalized meanwhile is not recorded twice
func TestUnsavedFinalsOfAFinalizedTx(t *testing.T) {
	e, server, inputs := claimEnv(t)
	acceptOffchain(t, e, server)
	e.repo.finalsSaveErr = errBoom
	e.svc.renewAndRecord(t.Context(), inputs)
	require.Len(t, e.ark.finalized, 1)
	e.repo.finalsSaveErr = nil

	e.indexer.serve()
	e.scan(t)
	successes := 0
	for _, ren := range e.repo.recorded() {
		if ren.Success {
			successes++
		}
	}
	require.Equal(t, 1, successes)
	require.EqualValues(t, 1, e.svc.Status().Renewed)
}

// arkd accepted the tx and its reply was lost: the restarted daemon reads the checkpoints back and finalizes once
func TestLostSubmitReplyIsRecovered(t *testing.T) {
	e, server := serverEnv(t)
	tmpl, err := e.svc.RegisterTemplate(t.Context(), []byte(delegatedTransfer))
	require.NoError(t, err)
	d, err := e.svc.RegisterDelegation(t.Context(), e.trust(t, tmpl.ID), nil, nil)
	require.NoError(t, err)
	inputs := dueAt(t, e, d)
	e.ark.submitTx = func(ark string, cps []string) (string, string, []string, error) {
		ptx, signed := signAs(t, server, ark)
		_, cp := signAs(t, server, cps[0])
		e.ark.pending = []clientlib.AcceptedOffchainTx{{Txid: ptx.UnsignedTx.TxHash().String(), FinalArkTx: signed, SignedCheckpointTxs: []string{cp}}}
		return "", "", nil, status.Error(codes.Unavailable, "reply lost")
	}
	e.svc.renewAndRecord(t.Context(), inputs)
	require.Len(t, e.repo.settled(), 1)
	require.Empty(t, e.ark.finalized)

	r := e.restart(t)
	txid := r.ark.pending[0].Txid
	r.indexer.known = []clientlib.Vtxo{arkSpent(inputs[0].coin, txid)}
	r.indexer.serve()
	r.scan(t)
	require.Positive(t, r.ark.pendingProofs)
	require.Len(t, r.ark.finalized, 1)
	final, err := psbt.NewFromRawBytes(strings.NewReader(r.ark.finalized[0]), true)
	require.NoError(t, err)
	require.True(t, signedBy(final, schnorr.SerializePubKey(r.svc.cosigners[0].key.PubKey())))
	require.True(t, signedBy(final, schnorr.SerializePubKey(server.PubKey())))
	recorded := r.repo.recorded()
	require.True(t, recorded[len(recorded)-1].Success)
	require.Empty(t, r.repo.settled())
}

// arkd lists the coin spent by the daemon's tx but not its outputs: the settlement waits
func TestAcceptedTxWaitsForItsOutputs(t *testing.T) {
	e, server, inputs := claimEnv(t)
	acceptOffchain(t, e, server)
	e.ark.submitTx = func(string, []string) (string, string, []string, error) {
		return "", "", nil, status.Error(codes.Unavailable, "reply lost")
	}
	e.svc.renewAndRecord(t.Context(), inputs)
	require.Len(t, e.repo.settled(), 1)

	r := e.restart(t)
	r.indexer.known = []clientlib.Vtxo{arkSpent(inputs[0].coin, r.repo.settled()[0].Txid)}
	r.indexer.serve()
	r.scan(t)
	require.Len(t, r.repo.settled(), 1, "neither settled nor dropped")
}

// the onchain tx was broadcast and the daemon died before settling it
func TestRestartAfterBroadcast(t *testing.T) {
	e, inputs := releaseEnv(t)
	txid, _, err := e.svc.runOnchain(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.NoError(t, err)
	require.Len(t, e.repo.settled(), 1)

	r := e.restart(t)
	r.explorer.spent, r.explorer.spentBy, r.explorer.utxos = true, txid, nil
	r.indexer.serve()
	r.scan(t)
	require.Empty(t, r.repo.settled())
}

// the emulator submitted and finalized the tx and the daemon died before settling it
func TestRestartAfterEmulatorFinalized(t *testing.T) {
	e, server, inputs := claimEnv(t)
	e.emulator.submitTx = func(tx string, cps []string) (string, []string, error) {
		_, tx = signAs(t, server, tx)
		for i := range cps {
			_, cps[i] = signAs(t, server, cps[i])
		}
		return tx, cps, nil
	}
	txid, _, _, err := e.svc.runOffchain(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.NoError(t, err)
	require.Len(t, e.repo.settled(), 1)

	r := e.restart(t)
	r.indexer.known = []clientlib.Vtxo{arkSpent(inputs[0].coin, txid), {Outpoint: clientlib.Outpoint{Txid: txid}}}
	r.indexer.serve()
	r.scan(t)
	require.Empty(t, r.repo.settled())
	require.Zero(t, r.ark.finalizes)
}

// a restart within the indexer's lag does not register a coin renewed before it
func TestRestartSeesPastRenewals(t *testing.T) {
	e := newTestEnv(t)
	e.fixture(t, "renewal.json")
	watch := e.boarding(t, e.userKey.PubKey())
	e.deposit(t, watch, 10_000)
	e.playBatch(t)
	e.scan(t)
	require.Len(t, e.ark.registered, 1)

	r := e.restart(t)
	r.indexer.serve()
	r.scan(t) // the explorer still lists the deposit
	require.Len(t, r.ark.registered, 1)
}

func TestScanWithoutSettlements(t *testing.T) {
	t.Run("list fails", func(t *testing.T) {
		e := newTestEnv(t)
		in := dueInput(t, e, 0, 10_000)
		e.repo.listSettlementErr = errBoom
		e.indexer.serve(asVtxo(in.coin))
		e.scan(t)
		require.Empty(t, e.ark.registered)
	})
	t.Run("a row cannot be read", func(t *testing.T) {
		e := newTestEnv(t)
		in := dueInput(t, e, 0, 10_000)
		batch := e.playBatch(t)
		batch.closeAfterForfeits = true
		e.indexer.serve(asVtxo(in.coin))
		e.scan(t)

		r := e.restart(t)
		r.repo.age(landingWindow)
		r.repo.getErr = errBoom
		r.indexer.serve(asVtxo(in.coin))
		r.scan(t)
		require.Len(t, r.ark.registered, 1, "its coins stay held")
	})
}

// a boarding watch's deposit forfeited in a batch whose end the daemon missed
func TestRestartAfterBoardingForfeits(t *testing.T) {
	e := newTestEnv(t)
	renewal := e.renewal(t, e.userKey.PubKey(), 0)
	watch := e.boarding(t, e.userKey.PubKey())
	e.deposit(t, watch, 10_000)
	batch := e.playBatch(t)
	batch.closeAfterForfeits = true
	e.scan(t)
	require.NotEmpty(t, e.emulator.finalized, "the commitment was signed")
	require.Len(t, e.active(t), 2)

	r := e.restart(t)
	r.explorer.spent, r.explorer.spentBy = true, batch.txid
	r.explorer.utxos = nil
	r.indexer.serve()
	r.scan(t)
	require.Len(t, r.active(t), 2, "the boarded coin is at the renewal watch's address")
	leaf := batch.batch.vtxoTree.Leaves()[0].UnsignedTx
	require.Equal(t, renewal.Slots[0].Script, hex.EncodeToString(leaf.TxOut[0].PkScript))
	require.Empty(t, r.repo.settled())

	r.indexer.serve()
	r.scan(t)
	require.Len(t, r.active(t), 2)
}

// arkd accepted the offchain tx and FinalizeTx failed: the restarted daemon finalizes it once
func TestRestartBeforeFinalize(t *testing.T) {
	e, server, inputs := claimEnv(t)
	submitted := acceptOffchain(t, e, server)
	e.ark.finalizeErrs = []error{status.Error(codes.Unavailable, "later")}
	e.svc.renewAndRecord(t.Context(), inputs)
	require.Empty(t, e.ark.finalized)
	require.Len(t, e.repo.settled(), 1)

	r := e.restart(t)
	r.indexer.known = []clientlib.Vtxo{arkSpent(inputs[0].coin, e.repo.settled()[0].Txid)}
	r.indexer.serve(asVtxo(inputs[0].coin)) // listed by a lagging indexer
	r.scan(t)
	require.Equal(t, 1, *submitted)
	require.Len(t, r.ark.finalized, 1)
	require.Equal(t, 2, r.ark.finalizes)
	recorded := r.repo.recorded()
	require.True(t, recorded[len(recorded)-1].Success)
	require.Empty(t, r.repo.settled())

	r.indexer.serve()
	r.scan(t)
	require.Equal(t, 2, r.ark.finalizes)
	require.Equal(t, 1, *submitted)
}

// arkd finalized the offchain tx but its reply was lost: the restarted daemon does not finalize it again
func TestRestartAfterFinalize(t *testing.T) {
	e, server, inputs := claimEnv(t)
	acceptOffchain(t, e, server)
	e.ark.finalizeErrs = []error{status.Error(codes.Unavailable, "reply lost")}
	e.svc.renewAndRecord(t.Context(), inputs)
	require.Len(t, e.repo.settled(), 1)
	txid := e.repo.settled()[0].Txid

	r := e.restart(t)
	r.indexer.known = []clientlib.Vtxo{arkSpent(inputs[0].coin, txid), {Outpoint: clientlib.Outpoint{Txid: txid}}}
	r.indexer.serve()
	r.scan(t)
	require.Equal(t, 1, r.ark.finalizes, "not finalized twice")
	require.Empty(t, r.repo.settled())
	recorded := r.repo.recorded()
	require.True(t, recorded[len(recorded)-1].Success)
}

// forfeits never reach arkd before their settlement is recorded
func TestNoForfeitsWithoutARecord(t *testing.T) {
	e := newTestEnv(t)
	in := dueInput(t, e, 0, 10_000)
	e.playBatch(t)
	e.repo.saveErr = errBoom
	results := e.svc.renew(t.Context(), []renewalInput{in})
	require.Len(t, results, 1)
	require.ErrorContains(t, results[0].err, "record settlement")
	require.NotErrorIs(t, results[0].err, errIntentRejected)
	require.Empty(t, e.ark.forfeits)
}

// arkd dropped the pending offchain tx while the daemon was down: the coin is renewed again
func TestRestartAfterArkdDroppedTheTx(t *testing.T) {
	e, server, inputs := claimEnv(t)
	submitted := acceptOffchain(t, e, server)
	e.ark.finalizeErrs = []error{status.Error(codes.Unavailable, "later"), status.Error(codes.NotFound, "offchain tx not found")}
	e.svc.renewAndRecord(t.Context(), inputs)
	require.Len(t, e.repo.settled(), 1)

	r := e.restart(t)
	r.indexer.serve(asVtxo(inputs[0].coin))
	r.scan(t)
	require.Equal(t, 2, *submitted)
	require.Len(t, r.ark.finalized, 1)
	require.Empty(t, r.repo.settled())
}

// a boarding deposit forfeited in a batch that never landed
func TestRestartDropsUnlandedSettlements(t *testing.T) {
	for _, tc := range []struct {
		name    string
		spentBy string // "": the deposit is unspent
		cancel  bool
		old     bool // older than a landing window
		kept    bool
	}{
		{name: "unspent", kept: true},
		{name: "unspent for a landing window", old: true},
		{name: "unspent, watch cancelled", cancel: true},
		{name: "spent by another tx", spentBy: "another"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			e.fixture(t, "renewal.json")
			watch := e.boarding(t, e.userKey.PubKey())
			e.deposit(t, watch, 10_000)
			batch := e.playBatch(t)
			batch.closeAfterForfeits = true
			e.scan(t)
			require.Len(t, e.repo.settled(), 1)

			r := e.restart(t)
			r.explorer.spent, r.explorer.spentBy = tc.spentBy != "", tc.spentBy
			if tc.cancel {
				require.NoError(t, r.svc.CancelDelegationByID(t.Context(), watch.ID))
			}
			if tc.old {
				r.repo.age(landingWindow)
			}
			r.ark.batch = nil
			r.indexer.serve()
			r.scan(t)
			require.Equal(t, tc.kept, len(r.repo.settled()) == 1)
			all, err := r.repo.List(t.Context(), "")
			require.NoError(t, err)
			require.Len(t, all, 1, "no successor")
		})
	}
}

// lostPending is a transfer arkd accepted without the daemon hearing.
type lostPending struct {
	coin       coin
	txid       string
	checkpoint string // as submitted, without the server's signature
}

func lostReply(t *testing.T) (*testEnv, lostPending) {
	t.Helper()
	e, server := serverEnv(t)
	tmpl, err := e.svc.RegisterTemplate(t.Context(), []byte(delegatedTransfer))
	require.NoError(t, err)
	d, err := e.svc.RegisterDelegation(t.Context(), e.trust(t, tmpl.ID), nil, nil)
	require.NoError(t, err)
	inputs := dueAt(t, e, d)
	var lost lostPending
	e.ark.submitTx = func(ark string, cps []string) (string, string, []string, error) {
		ptx, signed := signAs(t, server, ark)
		_, cp := signAs(t, server, cps[0])
		lost = lostPending{coin: inputs[0].coin, txid: ptx.UnsignedTx.TxHash().String(), checkpoint: cps[0]}
		e.ark.pending = []clientlib.AcceptedOffchainTx{{Txid: lost.txid, FinalArkTx: signed, SignedCheckpointTxs: []string{cp}}}
		return "", "", nil, status.Error(codes.Unavailable, "reply lost")
	}
	e.svc.renewAndRecord(t.Context(), inputs)
	require.Len(t, e.repo.settled(), 1)
	return e, lost
}

// pendingOutage is arkd timing out on GetPendingTx.
type pendingOutage struct{ *fakeArk }

func (pendingOutage) GetPendingTx(context.Context, string, string) ([]clientlib.AcceptedOffchainTx, error) {
	return nil, status.Error(codes.Unavailable, "timeout")
}

func backdateFailures(s *service, d time.Duration) {
	for txid, at := range s.refusedSince {
		s.refusedSince[txid] = at.Add(-d)
	}
}

// boundClaim is a claim bound to its coin, as a successor is.
func boundClaim(t *testing.T) (*testEnv, *btcec.PrivateKey, renewalInput) {
	t.Helper()
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
	return e, server, in
}

func (e *testEnv) requireSettledOnce(t *testing.T, in renewalInput, batch *fakeBatch) {
	t.Helper()
	require.Len(t, e.ark.forfeits, 1, "the coin was forfeited once")
	rows := e.active(t)
	require.Len(t, rows, 1, "the watch alone: the renewed coin is back at its address")
	require.Equal(t, in.watched.delegation.ID, rows[0].ID)
	leaf := batch.batch.vtxoTree.Leaves()[0].UnsignedTx
	require.Equal(t, in.coin.Script, leaf.TxOut[0].PkScript)
	require.Empty(t, e.repo.settled())

	e.indexer.serve()
	e.scan(t)
	require.Len(t, e.ark.forfeits, 1)
	require.Len(t, e.active(t), 1)
}

// acceptOffchain has the emulator and arkd sign every offchain tx; it counts SubmitTx calls
func acceptOffchain(t *testing.T, e *testEnv, server *btcec.PrivateKey) *int {
	t.Helper()
	submitted := 0
	e.emulator.submitTx = func(tx string, cps []string) (string, []string, error) { return tx, cps, nil }
	e.ark.submitTx = func(ark string, cps []string) (string, string, []string, error) {
		submitted++
		ptx, signed := signAs(t, server, ark)
		_, cp := signAs(t, server, cps[0])
		return ptx.UnsignedTx.TxHash().String(), signed, []string{cp}, nil
	}
	return &submitted
}

func settledBy(c coin, commitment string) clientlib.Vtxo {
	v := asVtxo(c)
	v.Spent, v.SettledBy = true, commitment
	return v
}

func arkSpent(c coin, arkTxid string) clientlib.Vtxo {
	v := asVtxo(c)
	v.Spent, v.ArkTxid = true, arkTxid
	return v
}
