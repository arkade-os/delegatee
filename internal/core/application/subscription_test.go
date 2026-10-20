package application

import (
	"testing"
	"testing/synctest"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/stretchr/testify/require"
)

func TestWakeScansAtOnceThenKeepsItsDistance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := newTestEnv(t)
		env.svc.Start()
		synctest.Wait()
		first := env.svc.Status().LastScan

		time.Sleep(5 * time.Second)
		env.svc.wakeScan()
		synctest.Wait()
		second := env.svc.Status().LastScan
		require.Equal(t, 5*time.Second, second.Sub(first), "an idle scanner wakes at once")

		env.svc.wakeScan()
		synctest.Wait()
		require.Equal(t, second, env.svc.Status().LastScan, "woken scans keep their distance")
		time.Sleep(minScanGap)
		synctest.Wait()
		require.Equal(t, minScanGap, env.svc.Status().LastScan.Sub(second))
		env.svc.Stop()
	})
}

func TestRegistrationWakesTheScan(t *testing.T) {
	e := newTestEnv(t)
	e.renewal(t, e.userKey.PubKey(), 0)
	require.Len(t, e.svc.wake, 1, "the scan subscribes to the new script")
}

func TestBusyLaneWakesTheScanWhenFree(t *testing.T) {
	e, coin := claimable(t)
	e.openSubscription(t)
	sign := e.ark.submitTx
	release := make(chan struct{})
	e.ark.submitTx = func(ark string, cps []string) (string, string, []string, error) {
		<-release
		return sign(ark, cps)
	}
	e.indexer.serve(coin)
	_ = e.svc.scan(t.Context())
	// this scan finds work the busy lane cannot take
	e.indexer.serve(coin)
	_ = e.svc.scan(t.Context())
	require.Empty(t, e.svc.wake)

	close(release)
	e.svc.wg.Wait()
	require.Len(t, e.svc.wake, 1)
}

func TestSubscriptionFollowsEveryWatch(t *testing.T) {
	e, _, _ := claimEnv(t)
	claim := e.active(t)[0]
	renewal := e.renewal(t, e.userKey.PubKey(), 0)
	e.indexer.serve()
	e.scan(t)
	require.ElementsMatch(t, []string{claim.Slots[0].Script, renewal.Slots[0].Script}, e.indexer.subscribedScripts())
	require.NoError(t, e.svc.CancelDelegationByID(t.Context(), renewal.ID))
	e.indexer.serve()
	e.scan(t)
	require.Equal(t, []string{claim.Slots[0].Script}, e.indexer.subscribedScripts())

	vars := claimVars(t, e.svc.encryptionKeys[0].PubKey())
	vars["unilateral_claim_delay"] = "030040"
	second, err := e.svc.RegisterDelegation(t.Context(), claim.TemplateID, vars, nil)
	require.NoError(t, err)
	e.indexer.serve()
	e.scan(t)
	require.ElementsMatch(t, []string{claim.Slots[0].Script, second.Slots[0].Script}, e.indexer.subscribedScripts())
	require.Equal(t, 1, e.indexer.subscriptions, "one subscription, updated")

	require.NoError(t, e.svc.CancelDelegationByID(t.Context(), claim.ID))
	require.NoError(t, e.svc.CancelDelegationByID(t.Context(), second.ID))
	e.indexer.serve()
	e.scan(t)
	require.Empty(t, e.indexer.subscribedScripts())
	require.Nil(t, e.svc.sub, "no watch, no subscription")
}

func TestScriptEventWakesTheScan(t *testing.T) {
	require.True(t, wakes(clientlib.ScriptEvent{Data: &clientlib.ScriptEventData{NewVtxos: []clientlib.Vtxo{{}}}}))
	require.True(t, wakes(clientlib.ScriptEvent{Connection: &clientlib.StreamConnectionEvent{}}), "events may have been missed")
	require.True(t, wakes(clientlib.ScriptEvent{Data: &clientlib.ScriptEventData{SpentVtxos: []clientlib.Vtxo{{}}}}), "an owner's spend ends a delegation")
	require.False(t, wakes(clientlib.ScriptEvent{Err: errBoom}))

	e, _, _ := claimEnv(t)
	e.openSubscription(t)
	e.indexer.events <- clientlib.ScriptEvent{Data: &clientlib.ScriptEventData{NewVtxos: []clientlib.Vtxo{{}}}}
	require.Eventually(t, func() bool { return len(e.svc.wake) == 1 }, time.Second, time.Millisecond)
}

func TestSubscriptionReopensAfterItsStreamEnds(t *testing.T) {
	e, _, _ := claimEnv(t)
	e.openSubscription(t)
	sub := e.svc.sub
	e.indexer.closeSubscription()
	require.Eventually(t, sub.dead.Load, time.Second, time.Millisecond)

	e.indexer.serve()
	e.scan(t)
	require.Equal(t, 2, e.indexer.subscriptions)
	require.NotSame(t, sub, e.svc.sub)
	require.Empty(t, e.svc.wake, "a stream that keeps ending must not scan in a loop")
}

func TestSubscribeFailureKeepsScanning(t *testing.T) {
	e, _, _ := claimEnv(t)
	e.indexer.subErr = errBoom
	e.indexer.serve()
	e.scan(t)
	require.False(t, e.svc.Status().LastScan.IsZero())
	require.Nil(t, e.svc.sub)

	e.indexer.subErr = nil
	e.indexer.serve()
	e.scan(t)
	require.NotNil(t, e.svc.sub)
}

func TestOpeningASubscriptionWakesTheScan(t *testing.T) {
	e, _, _ := claimEnv(t)
	<-e.svc.wake // the registration's
	e.indexer.serve()
	e.scan(t)
	require.NotNil(t, e.svc.sub)
	require.Len(t, e.svc.wake, 1, "a coin may have arrived before the stream opened")
}

func TestGrowingASubscriptionWakesTheScan(t *testing.T) {
	e := newTestEnv(t)
	e.svc.syncSubscription(t.Context(), []string{"a", "b"})
	require.Len(t, e.svc.wake, 1)
	<-e.svc.wake // the opening's

	e.svc.syncSubscription(t.Context(), []string{"a", "b", "c"})
	require.Len(t, e.svc.wake, 1, "a coin may have reached the added script")
	<-e.svc.wake

	e.svc.syncSubscription(t.Context(), []string{"a", "b"})
	require.Empty(t, e.svc.wake, "a removal loses nothing")
	require.Equal(t, 1, e.indexer.subscriptions)
}

func TestFailedUpdateReopensInTheSameScan(t *testing.T) {
	e := newTestEnv(t)
	e.svc.syncSubscription(t.Context(), []string{"a"})
	old := e.svc.sub
	e.indexer.updateErr = errBoom

	e.svc.syncSubscription(t.Context(), []string{"a", "b"})
	require.Equal(t, 2, e.indexer.subscriptions)
	require.NotNil(t, e.svc.sub)
	require.NotSame(t, old, e.svc.sub)
	require.Equal(t, []string{"a", "b"}, e.indexer.subscribedScripts())
	require.Len(t, e.svc.sub.scripts, 2)
}

func TestSubscriptionOpensEachScriptOnce(t *testing.T) {
	e := newTestEnv(t)
	e.svc.syncSubscription(t.Context(), []string{"a", "b", "a"})
	require.Len(t, e.indexer.opened, 1)
	require.ElementsMatch(t, []string{"a", "b"}, e.indexer.opened[0])
}
