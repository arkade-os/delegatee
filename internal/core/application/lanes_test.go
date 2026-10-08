package application

import (
	"sync/atomic"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDirectInputsSkipThePlan(t *testing.T) {
	e, coin := claimable(t)
	e.svc.renewalReserve = 5 * time.Minute
	coin.CreatedAt = time.Now() // due now: a batch input would wait for its deadline
	e.indexer.serve(coin)
	e.scan(t)
	require.True(t, e.svc.collectUntil.IsZero())
	require.Empty(t, e.svc.Status().Batches, "a transaction of its own is not planned")
	require.NotEmpty(t, e.ark.finalized, "claimed by the scan that found it")
}

func TestBatchInputsWaitForTheBatchInFlight(t *testing.T) {
	env := newTestEnv(t)
	v := env.coin(t, env.userKey.PubKey(), 1000, time.Minute)
	env.advertised(t, v)
	env.svc.batch.busy.Store(1)
	env.indexer.serve(v)
	env.svc.scan(t.Context())
	require.Empty(t, env.emulator.submitted, "one batch session at a time")
	require.True(t, env.svc.batch.waiting.Load(), "the batch wakes the scan when it ends")
	require.Empty(t, env.svc.wake)
}

func TestClaimBesideABatch(t *testing.T) {
	e, coin := claimable(t)
	e.svc.batch.busy.Store(1)
	e.indexer.serve(coin)
	e.scan(t)
	require.NotEmpty(t, e.ark.finalized)
	require.Equal(t, 1, e.svc.Status().RenewingVtxos, "the batch is still counted")
}

// the scans and the lane share the consumed coins
func TestScansBesideALaneInFlight(t *testing.T) {
	e, coin := claimable(t)
	sign := e.ark.submitTx
	submitting, release := make(chan struct{}), make(chan struct{})
	var submits atomic.Int32
	e.ark.submitTx = func(ark string, cps []string) (string, string, []string, error) {
		if submits.Add(1) == 1 {
			close(submitting)
		}
		<-release
		return sign(ark, cps)
	}
	e.indexer.serve(coin)
	e.svc.scan(t.Context())
	<-submitting
	for range 5 {
		e.indexer.serve(coin)
		e.svc.scan(t.Context())
	}

	// a scan between the lane forgetting its row and consuming its coin
	forgotten, resume := make(chan struct{}), make(chan struct{})
	e.repo.afterDeleteSettlement = func() {
		close(forgotten)
		<-resume
	}
	close(release)
	<-forgotten
	e.indexer.serve(coin)
	e.svc.scan(t.Context())

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 20 {
			e.indexer.serve(coin)
			e.svc.scan(t.Context())
		}
	}()
	close(resume)
	<-done
	e.svc.wg.Wait()
	e.indexer.serve(coin)
	e.scan(t)
	require.EqualValues(t, 1, submits.Load(), "a coin in flight is not claimed twice")
}

// a lane that ends during a scan leaves its row and its lane to the next scan
func TestScanSamplesTheLanes(t *testing.T) {
	e := newTestEnv(t)
	in := dueInput(t, e, 0, 10_000)
	batch := e.playBatch(t)
	batch.closeAfterForfeits = true
	e.indexer.serve(asVtxo(in.coin))
	e.scan(t)
	rows := e.repo.settled()
	require.Len(t, rows, 1)
	registered := len(e.ark.registered)

	// the lane writes its row once the scan listed none
	e.repo.mu.Lock()
	saved := e.repo.settlements
	e.repo.settlements = nil
	e.repo.mu.Unlock()
	e.laneEndsDuringScan(in, func() {
		e.repo.mu.Lock()
		e.repo.settlements = saved
		e.repo.mu.Unlock()
	})
	e.indexer.serve(asVtxo(in.coin))
	e.scan(t)
	require.Equal(t, registered, len(e.ark.registered), "not registered again")
	require.Equal(t, rows, e.repo.settled())

	// the lane ends once the scan listed its row
	e.laneEndsDuringScan(in, func() {})
	e.indexer.known = []clientlib.Vtxo{settledBy(in.coin, batch.txid)}
	e.indexer.serve()
	e.scan(t)
	require.Equal(t, rows, e.repo.settled(), "its lane settles it")
	require.Len(t, e.active(t), 1)

	e.indexer.serve()
	e.scan(t)
	e.requireSettledOnce(t, in, batch)
}

func TestDiscoverLeavesADelegationInFlight(t *testing.T) {
	e := newTestEnv(t)
	v := e.ownedCoin(t, e.userKey.PubKey(), 5000, time.Hour)
	d := e.advertised(t, v)
	next := e.ownedCoin(t, e.userKey.PubKey(), 5000, time.Hour)
	v.Spent, v.ArkTxid = true, next.Txid
	e.indexer.known = []clientlib.Vtxo{v}
	in := renewalInput{watched: &watched{delegation: *d}}

	e.laneEndsDuringScan(in, func() {})
	e.indexer.serve()
	e.scan(t)
	got, err := e.repo.GetByID(t.Context(), d.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusActive, got.Status, "its lane settles it")

	e.indexer.serve()
	e.scan(t)
	got, err = e.repo.GetByID(t.Context(), d.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusDone, got.Status)
}

func TestScanLeavesUnsavedInFlight(t *testing.T) {
	e, server, inputs := claimEnv(t)
	acceptOffchain(t, e, server)
	e.repo.finalsSaveErr = errBoom
	e.ark.finalizeErrs = []error{status.Error(codes.Unavailable, "later")}
	e.svc.renewAndRecord(t.Context(), inputs)
	require.Len(t, e.svc.unsaved, 1)
	rows := e.repo.settled()
	require.Len(t, rows, 1)
	require.Empty(t, rows[0].Finals)
	e.repo.finalsSaveErr = nil

	e.svc.direct.busy.Store(1)
	e.svc.setInFlight(inputs, true)
	e.indexer.serve()
	e.scan(t)
	require.Len(t, e.svc.unsaved, 1, "its lane records it")
	require.Equal(t, rows, e.repo.settled())

	e.svc.direct.busy.Store(0)
	e.svc.setInFlight(inputs, false)
	e.indexer.serve()
	e.scan(t)
	require.Empty(t, e.svc.unsaved)
	require.Len(t, e.ark.finalized, 1)
}

func TestScanLeavesSettlementsInFlight(t *testing.T) {
	e := newTestEnv(t)
	in := dueInput(t, e, 0, 10_000)
	batch := e.playBatch(t)
	batch.closeAfterForfeits = true
	e.indexer.serve(asVtxo(in.coin))
	e.scan(t)
	require.Len(t, e.repo.settled(), 1)

	// as if the lane that owns the settlement were still running
	e.svc.setInFlight([]renewalInput{in}, true)
	e.indexer.known = []clientlib.Vtxo{settledBy(in.coin, batch.txid)}
	e.indexer.serve()
	e.scan(t)
	require.Len(t, e.repo.settled(), 1, "its lane settles it")

	e.svc.setInFlight([]renewalInput{in}, false)
	e.indexer.serve()
	e.scan(t)
	e.requireSettledOnce(t, in, batch)
}
