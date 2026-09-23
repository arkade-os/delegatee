package application

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/delegatee/internal/core/domain"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestNewService(t *testing.T) {
	for name, tweak := range map[string]func(*testEnv){
		"arkd down":        func(e *testEnv) { e.ark.infoErr = errBoom },
		"emulator down":    func(e *testEnv) { e.emulator.infoErr = errBoom },
		"bad signer key":   func(e *testEnv) { e.ark.info.SignerPubKey = "zz" },
		"bad forfeit key":  func(e *testEnv) { e.ark.info.ForfeitPubKey = "02" },
		"bad emulator key": func(e *testEnv) { e.emulator.info.SignerPublicKey = "" },
		"unknown network":  func(e *testEnv) { e.ark.info.Network = "moon" },
		"bad forfeit addr": func(e *testEnv) { e.ark.info.ForfeitAddress = "nope" },
	} {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t)
			tweak(env)
			_, err := NewService(t.Context(), env.repo, env.ark, env.indexer, env.emulator,
				env.userKey, time.Hour, time.Minute, 0, 16, 100)
			require.Error(t, err)
		})
	}
	env := newTestEnv(t)
	_, err := NewService(t.Context(), env.repo, env.ark, env.indexer, env.emulator, env.userKey, time.Hour, time.Minute, 0, 0, 100)
	require.Error(t, err, "zero vtxos per intent")
	_, err = NewService(t.Context(), env.repo, env.ark, env.indexer, env.emulator, env.userKey, time.Hour, time.Minute, 0, 16, 0)
	require.Error(t, err, "zero max delegations")
}

func TestInfo(t *testing.T) {
	env := newTestEnv(t)
	def, err := env.svc.Info(domain.Params{})
	require.NoError(t, err)
	require.Equal(t, int64(DefaultRenewalWindow), def.Params.RenewalWindow)
	require.Equal(t, "regtest", def.Network)
	require.Equal(t, env.svc.delegatePubKeyHex, def.DelegatePubKey)

	// every param is part of the covenant, hence of the leaf
	other, err := env.svc.Info(domain.Params{RenewalWindow: 600})
	require.NoError(t, err)
	withFee, err := env.svc.Info(domain.Params{RenewalWindow: 600, MaxFee: 100})
	require.NoError(t, err)
	require.NotEqual(t, def.DelegateTapscript, other.DelegateTapscript)
	require.NotEqual(t, other.DelegateTapscript, withFee.DelegateTapscript)
	require.NotEqual(t, other.EmulatorTweakedPubKey, withFee.EmulatorTweakedPubKey)
	require.Equal(t, other.EmulatorPubKey, withFee.EmulatorPubKey)

	_, err = env.svc.Info(domain.Params{RenewalWindow: -1})
	require.ErrorIs(t, err, ErrInvalidScript)
}

func TestRegisterDelegation(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	p := domain.Params{RenewalWindow: 600, MaxFee: 50}
	ts := env.tapscripts(t, p)

	d, err := env.svc.RegisterDelegation(ctx, ts, p)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(d.Address, "tark1"), d.Address)
	require.Equal(t, p, d.Params)

	_, err = env.svc.RegisterDelegation(ctx, ts, p)
	require.ErrorIs(t, err, domain.ErrDelegationAlreadyExists)

	// cancel, then registering again resumes
	require.NoError(t, env.svc.CancelDelegation(ctx, d.Address))
	got, err := env.svc.GetDelegation(ctx, d.Address)
	require.NoError(t, err)
	require.Equal(t, "cancelled", got.Status)
	_, err = env.svc.RegisterDelegation(ctx, ts, p)
	require.NoError(t, err)
	require.ErrorIs(t, env.svc.CancelDelegation(ctx, "tark1unknown"), domain.ErrDelegationNotFound)

	for name, tc := range map[string]struct {
		tapscripts []string
		params     domain.Params
	}{
		"params the leaf was not built for": {ts, domain.Params{RenewalWindow: 600, MaxFee: 51}},
		"default window instead of 600":     {ts, domain.Params{MaxFee: 50}},
		"no exit leaf":                      {ts[:1], p},
		"no delegate leaf":                  {ts[1:], p},
		"not hex":                           {[]string{"zz"}, p},
		"too many tapscripts":               {make([]string, maxTapscripts+1), p},
		"oversized tapscript":               {[]string{strings.Repeat("00", maxTapscriptLen)}, p},
		"window out of bounds":              {ts, domain.Params{RenewalWindow: maxRenewalWindow + 1}},
		"negative fee":                      {ts, domain.Params{RenewalWindow: 600, MaxFee: -1}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := env.svc.RegisterDelegation(ctx, tc.tapscripts, tc.params)
			require.ErrorIs(t, err, ErrInvalidScript)
		})
	}

	list, err := env.svc.ListDelegations(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
}

func TestKeyRotationWatchesPreviousDelegations(t *testing.T) {
	env := newTestEnv(t)
	oldKey := env.svc.key
	d := env.register(t, domain.Params{RenewalWindow: 600})
	newKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	rotated, err := NewServiceWithKeys(
		t.Context(), env.repo, env.ark, env.indexer, env.emulator,
		[]*btcec.PrivateKey{newKey, oldKey}, time.Hour, time.Minute, 0, 16, 100,
	)
	require.NoError(t, err)
	rotatedSvc := rotated.(*service)
	w, err := rotatedSvc.watch(d)
	require.NoError(t, err)
	require.NotNil(t, w)
	require.Same(t, rotatedSvc.cosigners[1], w.cosigner)
}

func TestRegisterDelegationCap(t *testing.T) {
	env := newTestEnv(t)
	env.svc.maxDelegations = 2
	env.register(t, domain.Params{RenewalWindow: 100})
	second := env.register(t, domain.Params{RenewalWindow: 200})
	p := domain.Params{RenewalWindow: 300}
	_, err := env.svc.RegisterDelegation(t.Context(), env.tapscripts(t, p), p)
	require.ErrorIs(t, err, ErrFull)

	// only active delegations count
	require.NoError(t, env.svc.CancelDelegation(t.Context(), second.Address))
	env.register(t, p)

	env.repo.err = errBoom
	_, err = env.svc.RegisterDelegation(t.Context(), env.tapscripts(t, domain.Params{RenewalWindow: 400}), domain.Params{RenewalWindow: 400})
	require.ErrorIs(t, err, errBoom)
}

func TestScanHoldingsAndStatus(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	require.True(t, env.svc.Status().LastScan.IsZero())

	busy := env.register(t, domain.Params{RenewalWindow: 600})
	empty := env.register(t, domain.Params{RenewalWindow: 700})
	// registered by an instance with another key: same table, not ours to renew
	stranger := newTestEnv(t)
	foreign, err := env.repo.Create(ctx, "tark1foreign", stranger.tapscripts(t, domain.Params{RenewalWindow: 600}), domain.Params{RenewalWindow: 600})
	require.NoError(t, err)
	stopped := env.register(t, domain.Params{RenewalWindow: 800})
	require.NoError(t, env.svc.CancelDelegation(ctx, stopped.Address))

	soon := env.vtxo(t, busy, 1, 3000, 2*time.Hour)
	later := env.vtxo(t, busy, 2, 7000, 5*time.Hour)
	env.indexer.serve(later, soon)

	env.svc.scan(ctx)
	env.svc.wg.Wait()

	st := env.svc.Status()
	require.WithinDuration(t, time.Now(), st.LastScan, time.Minute)
	require.Equal(t, time.Hour, st.PollInterval)
	require.Zero(t, st.RenewingVtxos)
	require.Equal(t, Holdings{
		Vtxos: 2, Amount: 10000, NextExpiry: soon.ExpiresAt, NextDue: soon.ExpiresAt.Add(-600 * time.Second),
	}, st.Holdings[busy.ID])
	require.Equal(t, Holdings{}, st.Holdings[empty.ID])
	require.NotContains(t, st.Holdings, foreign.ID)
	require.NotContains(t, st.Holdings, stopped.ID)
	require.Empty(t, env.repo.recorded(), "nothing is due")
	require.WithinDuration(t, time.Now().Add(-renewalsRetention), env.repo.prunedTo, time.Minute)

	vtxos, err := env.svc.Vtxos(ctx, busy)
	require.NoError(t, err)
	require.Empty(t, vtxos, "the fake serves them once")
	require.Equal(t, soon.ExpiresAt.Add(-600*time.Second), env.svc.DueAt(busy, soon))
}

func TestScanFailures(t *testing.T) {
	env := newTestEnv(t)
	d := env.register(t, domain.Params{RenewalWindow: 600})
	env.indexer.serve(env.vtxo(t, d, 1, 1000, time.Hour))

	env.repo.err = errBoom
	env.svc.scan(t.Context())
	require.True(t, env.svc.Status().LastScan.IsZero(), "a failed scan reports nothing")
	env.repo.err = nil

	env.indexer.err = errBoom
	env.svc.scan(t.Context())
	require.True(t, env.svc.Status().LastScan.IsZero())

	// a batch in flight pauses scanning
	env.indexer.err = nil
	env.svc.renewing.Store(1)
	calls := env.indexer.calls
	env.svc.scan(t.Context())
	require.Equal(t, calls, env.indexer.calls)
	require.Equal(t, 1, env.svc.Status().RenewingVtxos)
}

func TestSpendableVtxosChunks(t *testing.T) {
	env := newTestEnv(t)
	scripts := make([]string, 250)
	_, err := env.svc.spendableVtxos(t.Context(), scripts)
	require.NoError(t, err)
	require.Equal(t, 3, env.indexer.calls)
}

// A due vtxo goes all the way to the emulator; whatever stops it is recorded
// once per distinct error, not once per scan.
func TestRenewalFailuresAreRecordedOnce(t *testing.T) {
	env := newTestEnv(t)
	d := env.register(t, domain.Params{RenewalWindow: 600})
	due := env.vtxo(t, d, 1, 1000, time.Minute)
	env.emulator.reject = func(emulatorclient.Intent) error { return errBoom }

	scan := func() {
		env.indexer.serve(due)
		env.svc.scan(t.Context())
		env.svc.wg.Wait()
	}
	scan()
	recorded := env.repo.recorded()
	require.Len(t, recorded, 1)
	require.False(t, recorded[0].Success)
	require.Equal(t, d.ID, recorded[0].DelegationID)
	require.Equal(t, []string{due.Outpoint.String()}, recorded[0].Outpoints)
	require.Contains(t, recorded[0].Error, "emulator rejected intent: boom")
	require.Len(t, env.emulator.submitted, 1)

	scan()
	require.Len(t, env.repo.recorded(), 1, "same failure, no new row")
	require.Len(t, env.emulator.submitted, 2, "but it was retried")

	// a different reason is news
	env.emulator.reject = nil
	env.ark.registerErr = errBoom
	scan()
	recorded = env.repo.recorded()
	require.Len(t, recorded, 2)
	require.Contains(t, recorded[1].Error, "register intent: boom")

	// the vtxo is gone: its failure is forgotten
	env.indexer.serve(env.vtxo(t, d, 2, 1000, time.Minute))
	env.svc.scan(t.Context())
	env.svc.wg.Wait()
	require.NotContains(t, env.svc.lastFailure, due.Outpoint.String())

	renewals, err := env.svc.ListRenewals(t.Context(), d)
	require.NoError(t, err)
	require.Len(t, renewals, 3)
	last, err := env.svc.LastRenewals(t.Context())
	require.NoError(t, err)
	require.Contains(t, last, d.ID)
}

func TestHealth(t *testing.T) {
	env := newTestEnv(t)
	for _, err := range env.svc.Health(t.Context()) {
		require.NoError(t, err)
	}
	env.repo.err, env.ark.infoErr, env.emulator.infoErr = errBoom, errBoom, errBoom
	health := env.svc.Health(t.Context())
	require.Len(t, health, 4)
	for _, name := range []string{"database", "ark", "emulator"} {
		require.ErrorIs(t, health[name], errBoom, name)
	}
	require.NoError(t, health["scanner"])
	_, err := env.svc.IntentFees(t.Context())
	require.ErrorIs(t, err, errBoom)
}

func TestStartStop(t *testing.T) {
	env := newTestEnv(t)
	env.svc.pollInterval = time.Millisecond
	env.svc.Start()
	require.Eventually(t, func() bool { return !env.svc.Status().LastScan.IsZero() }, 5*time.Second, time.Millisecond)
	env.svc.Stop()
	require.True(t, env.repo.closed)

	idle := newTestEnv(t)
	idle.svc.Stop() // never started
	require.True(t, idle.repo.closed)
}

func TestHelpers(t *testing.T) {
	_, err := PubKeyFromHex("zz")
	require.Error(t, err)
	_, err = PubKeyFromHex("00")
	require.Error(t, err)
	for _, name := range []string{"bitcoin", "testnet", "testnet4", "signet", "mutinynet", "regtest"} {
		n, err := networkFromName(name)
		require.NoError(t, err, name)
		require.Equal(t, name, n.Name)
	}
	require.False(t, hasLeaf([]string{"zz", "00"}, []byte{1}))
	require.True(t, hasLeaf([]string{"zz", "01"}, []byte{1}))

	_, _, err = (&service{}).scriptOf(&domain.Delegation{Tapscripts: []string{"zz"}})
	require.Error(t, err)
	_ = context.Background
}

func TestLateAndScannerHealth(t *testing.T) {
	env := newTestEnv(t)
	now := time.Now()
	due := now.Add(-time.Hour)
	require.False(t, late(types.Vtxo{ExpiresAt: now.Add(time.Hour)}, due, now), "half the room left")
	require.True(t, late(types.Vtxo{ExpiresAt: now.Add(10 * time.Minute)}, due, now), "last quarter")
	require.False(t, late(types.Vtxo{ExpiresAt: due}, due, now), "no room at all is not late, it is a zero window")

	d := env.register(t, domain.Params{RenewalWindow: 3600})
	stuck := env.vtxo(t, d, 1, 5000, 5*time.Minute) // renewable since 55 min, expires in 5
	fresh := env.vtxo(t, d, 2, 1000, 50*time.Minute)
	env.emulator.reject = func(emulatorclient.Intent) error { return errBoom }
	env.indexer.serve(stuck, fresh)
	env.svc.scan(t.Context())
	env.svc.wg.Wait()
	h := env.svc.Status().Holdings[d.ID]
	require.Equal(t, 1, h.Late)
	require.Equal(t, uint64(5000), h.LateAmount)
	require.Equal(t, uint64(2), env.svc.Status().Failed)
	require.Zero(t, env.svc.Status().Renewed)

	// the scanner is healthy right after start, then stale
	require.NoError(t, env.svc.scannerHealth(now))
	require.Error(t, env.svc.scannerHealth(now.Add(4*time.Hour)))
	env.svc.renewing.Store(1)
	require.NoError(t, env.svc.scannerHealth(now.Add(4*time.Hour)), "a batch in flight pauses scans")
	env.svc.renewing.Store(0)
	require.NoError(t, env.svc.Health(t.Context())["scanner"], "just scanned")
	n, err := env.svc.CountActive(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
}
