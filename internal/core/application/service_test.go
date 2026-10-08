package application

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/delegatee/pkg/template/ecies"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
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
			_, err := NewServiceWithKeys(t.Context(), env.repo, env.ark, env.indexer, env.emulator, nil, 30*time.Second, 50, nil,
				[]*btcec.PrivateKey{env.userKey}, time.Hour, time.Minute, 2*time.Hour, 0,
				Limits{MaxDelegations: 100, MaxTemplates: 100, MaxArtifacts: 100, MaxDocumentBytes: 4096, TemplateMaxFailures: 3})
			require.Error(t, err)
		})
	}
	env := newTestEnv(t)
	_, err := NewServiceWithKeys(t.Context(), env.repo, env.ark, env.indexer, env.emulator, nil, 30*time.Second, 50, nil,
		[]*btcec.PrivateKey{env.userKey}, time.Hour, time.Minute, 2*time.Hour, 0, Limits{})
	require.Error(t, err, "zero max delegations")
}

func TestInfo(t *testing.T) {
	env := newTestEnv(t)
	info := env.svc.Info()
	require.Equal(t, "regtest", info.Network)
	require.Equal(t, cosignerHex, info.DelegatePubKey)
	require.Equal(t, hex.EncodeToString(env.svc.serverPubKey.SerializeCompressed()), info.ServerPubKey)
	require.Equal(t, hex.EncodeToString(env.svc.emulatorPubKey.SerializeCompressed()), info.EmulatorPubKey)
	require.Empty(t, info.EncryptionPubKey, "no encryption key yet")
}

func TestRegisterDelegation(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	id := env.fixture(t, "boarding.json")
	d := env.boarding(t, env.userKey.PubKey())
	args := d.Variables

	require.True(t, strings.HasPrefix(d.Address, "bcrt1p"), d.Address)
	require.Equal(t, id, d.TemplateID)
	require.Equal(t, hex.EncodeToString(env.userKey.PubKey().SerializeCompressed()), args["owner"])
	require.Len(t, args, 5)
	require.True(t, d.IsWatch())
	require.Zero(t, d.ParentID)
	require.Nil(t, d.ExpiresAt)
	require.Equal(t, domain.Fingerprint(id, args, nil), d.Fingerprint)
	require.Equal(t, cosignerHex, d.DelegatePubKey)
	require.Len(t, d.Slots, 1)
	slot := d.Slots[0]
	require.Equal(t, "deposit", slot.Name)
	require.True(t, slot.Onchain)
	require.Empty(t, slot.Outpoint)
	require.Len(t, slot.Tapscripts, 3)

	// the address is the one the engine's tree gives, under arkd's signer key
	tmpl, err := env.svc.parseTemplate(ctx, id)
	require.NoError(t, err)
	inst, err := env.svc.newInstance(ctx, tmpl, env.svc.cosigners[0], args, nil, nil)
	require.NoError(t, err)
	require.Equal(t, inst.Tapscripts(0), slot.Tapscripts)
	pkScript, _, err := pkScriptOf(slot.Tapscripts)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(pkScript), slot.Script)
	addr, err := address.DecodeAddress(d.Address, &chaincfg.RegressionNetParams)
	require.NoError(t, err)
	paid, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	require.Equal(t, pkScript, paid)

	// an active watch registered again is returned unchanged, whatever the expiry
	later := time.Now().Add(time.Hour)
	same, err := env.svc.RegisterDelegation(ctx, id, args, &later)
	require.NoError(t, err)
	require.Equal(t, d.ID, same.ID)
	require.Nil(t, same.ExpiresAt, "the stored expiry is kept")

	require.NoError(t, env.svc.CancelDelegation(ctx, d.Address))
	got, err := env.svc.GetDelegation(ctx, d.Address)
	require.NoError(t, err)
	require.Equal(t, "cancelled", got.Status)
	// an operator cancel holds until the operator resumes the row
	expiresAt := time.Now().Add(time.Hour)
	_, err = env.svc.RegisterDelegation(ctx, id, args, &expiresAt)
	require.ErrorIs(t, err, domain.ErrBlocked)
	require.NoError(t, env.svc.ResumeDelegation(ctx, d.ID))
	require.ErrorIs(t, env.svc.ResumeDelegation(ctx, d.ID), domain.ErrNotCancelled)
	require.ErrorIs(t, env.svc.ResumeDelegation(ctx, 999), domain.ErrDelegationNotFound)
	again, err := env.svc.RegisterDelegation(ctx, id, args, &expiresAt)
	require.NoError(t, err)
	require.Equal(t, d.ID, again.ID, "the same row renews again")
	require.Nil(t, again.ExpiresAt)
	require.ErrorIs(t, env.svc.CancelDelegation(ctx, "tark1unknown"), domain.ErrDelegationNotFound)

	other := func(edit func(map[string]string)) map[string]string {
		a := maps.Clone(args)
		_, key := hexKey(t)
		a["owner"] = key
		edit(a)
		return a
	}
	past := time.Now().Add(-time.Second)
	for name, tc := range map[string]struct {
		id        string
		args      map[string]string
		expiresAt *time.Time
		want      error
	}{
		"unknown template": {"nope", args, nil, domain.ErrTemplateNotFound},
		"missing arg":      {id, map[string]string{"owner": args["owner"]}, nil, ErrInvalidArgs},
		"extra arg":        {id, other(func(a map[string]string) { a["x"] = "01" }), nil, ErrInvalidArgs},
		"owner not hex":    {id, other(func(a map[string]string) { a["owner"] = "zz" }), nil, ErrInvalidArgs},
		"owner not a key":  {id, other(func(a map[string]string) { a["owner"] = "00" }), nil, ErrInvalidArgs},
		"expired already":  {id, other(func(map[string]string) {}), &past, ErrInvalidArgs},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := env.svc.RegisterDelegation(ctx, tc.id, tc.args, tc.expiresAt)
			require.ErrorIs(t, err, tc.want)
		})
	}

	require.NoError(t, env.svc.CancelDelegationByID(ctx, d.ID))
	newer, err := env.svc.RegisterDelegation(ctx, id, other(func(map[string]string) {}), nil)
	require.NoError(t, err)
	require.NoError(t, env.svc.SetTemplateStatus(ctx, id, domain.TemplateStatusDisabled))
	_, err = env.svc.RegisterDelegation(ctx, id, other(func(map[string]string) {}), nil)
	require.ErrorIs(t, err, domain.ErrTemplateDisabled)

	list, err := env.svc.ListDelegations(ctx, "", 0, 10)
	require.NoError(t, err)
	require.Len(t, list, 2)
	require.Equal(t, newer.ID, list[0].ID, "newest first")
	list, err = env.svc.ListDelegations(ctx, domain.DelegationStatusCancelled, 0, 10)
	require.NoError(t, err)
	require.Equal(t, d.ID, list[0].ID)
	list, err = env.svc.ListDelegations(ctx, "", newer.ID, 1)
	require.NoError(t, err)
	require.Equal(t, []int64{d.ID}, []int64{list[0].ID}, "below the cursor")
}

func TestRegisterDelegationRefusals(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, err := env.svc.RegisterDelegation(ctx, env.fixture(t, "counter.json"), nil, nil)
	require.ErrorIs(t, err, ErrInvalidArgs, "a watch on two inputs")
	require.ErrorContains(t, err, "one input")

	board := env.boarding(t, env.userKey.PubKey())
	upper := maps.Clone(board.Variables)
	upper["owner"] = strings.ToUpper(upper["owner"])
	_, err = env.svc.RegisterDelegation(ctx, board.TemplateID, upper, nil)
	require.ErrorIs(t, err, ErrInvalidArgs, "variables are canonical: lower-case hex")

	secrets, _ := hexKey(t)
	claim := env.trust(t, env.fixture(t, "vhtlc_claim.json"))
	_, err = env.svc.RegisterDelegation(ctx, claim, claimVars(t, secrets.PubKey()), nil)
	require.ErrorIs(t, err, ErrSecretsRequired)
	env.svc.encryptionKeys = []*btcec.PrivateKey{secrets}
	d, err := env.svc.RegisterDelegation(ctx, claim, claimVars(t, secrets.PubKey()), nil)
	require.NoError(t, err)
	require.Equal(t, "htlc", d.Slots[0].Name)
	require.False(t, d.Slots[0].Onchain)
	require.True(t, strings.HasPrefix(d.Address, "tark1"), d.Address)
}

func TestCancelDelegationByID(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	d := env.boarding(t, env.userKey.PubKey())
	require.NoError(t, env.svc.CancelDelegationByID(ctx, d.ID))
	got, err := env.svc.GetDelegation(ctx, d.Address)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusCancelled, got.Status)
	_, err = env.svc.RegisterDelegation(ctx, d.TemplateID, d.Variables, nil)
	require.ErrorIs(t, err, domain.ErrBlocked)
	require.ErrorIs(t, env.svc.CancelDelegationByID(ctx, 999), domain.ErrDelegationNotFound)

	other, _ := hexKey(t)
	active := env.boarding(t, other.PubKey())
	env.repo.err = errBoom
	require.ErrorIs(t, env.svc.CancelDelegationByID(ctx, active.ID), errBoom)
	_, err = env.svc.RegisterDelegation(ctx, d.TemplateID, active.Variables, nil)
	require.ErrorIs(t, err, errBoom)
	env.repo.err = nil
	got, err = env.repo.GetByID(ctx, active.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusActive, got.Status, "left active when the cancel fails")
}

// only an operator cancel blocks: an expired watch may be registered again
func TestExpiryDoesNotBlock(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	board := env.boarding(t, env.userKey.PubKey())
	soon := time.Now().Add(time.Hour)
	owner, _ := hexKey(t)
	d, err := env.svc.RegisterDelegation(ctx, board.TemplateID, env.boardingVars(t, owner.PubKey()), &soon)
	require.NoError(t, err)
	_, err = env.repo.Expire(ctx, soon)
	require.NoError(t, err)
	require.NoError(t, env.svc.CancelDelegationByID(ctx, d.ID), "stopped already: nothing to block")

	later := soon.Add(time.Hour)
	again, err := env.svc.RegisterDelegation(ctx, d.TemplateID, d.Variables, &later)
	require.NoError(t, err)
	require.NotEqual(t, d.ID, again.ID)
}

// an expired watch stops renewing; a cancelled one keeps refusing its fingerprint
func TestScanExpiresWatches(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	kept := env.boarding(t, env.userKey.PubKey())
	soon := time.Now().Add(time.Hour)
	watch := func() *domain.Delegation {
		owner, _ := hexKey(t)
		d, err := env.svc.RegisterDelegation(ctx, kept.TemplateID, env.boardingVars(t, owner.PubKey()), &soon)
		require.NoError(t, err)
		return d
	}
	expired, cancelled := watch(), watch()
	require.NoError(t, env.svc.CancelDelegationByID(ctx, cancelled.ID))
	env.repo.mu.Lock()
	past := time.Now().Add(-time.Second)
	for i, d := range env.repo.delegations {
		if d.ID != kept.ID {
			env.repo.delegations[i].ExpiresAt = &past
		}
	}
	env.repo.mu.Unlock()

	env.scan(t)
	for id, want := range map[int64]string{expired.ID: domain.DelegationStatusExpired, cancelled.ID: domain.DelegationStatusCancelled} {
		got, err := env.repo.GetByID(ctx, id)
		require.NoError(t, err)
		require.Equal(t, want, got.Status)
	}
	_, err := env.svc.RegisterDelegation(ctx, cancelled.TemplateID, cancelled.Variables, nil)
	require.ErrorIs(t, err, domain.ErrBlocked)
	st := env.svc.Status()
	require.NotContains(t, st.Holdings, expired.ID)
	require.Contains(t, st.Holdings, kept.ID)
}

// expires_at is at least MinWatchExpiry ahead; no expiry is always allowed
func TestMinWatchExpiry(t *testing.T) {
	env := newTestEnv(t)
	board := env.boarding(t, env.userKey.PubKey())
	register := func(expiresAt *time.Time) error {
		owner, _ := hexKey(t)
		_, err := env.svc.RegisterDelegation(t.Context(), board.TemplateID, env.boardingVars(t, owner.PubKey()), expiresAt)
		return err
	}
	in := func(d time.Duration) *time.Time { at := time.Now().Add(d); return &at }

	require.NoError(t, register(in(time.Minute)), "no minimum")
	env.svc.limits.MinWatchExpiry = 24 * time.Hour
	require.ErrorIs(t, register(in(23*time.Hour)), ErrInvalidArgs)
	require.NoError(t, register(in(24*time.Hour+time.Minute)))
	require.NoError(t, register(nil))
}

func TestInstantiateChecksEverySlot(t *testing.T) {
	env := newTestEnv(t)
	d := env.advertised(t, env.coin(t, env.userKey.PubKey(), 1000, time.Hour))
	_, _, err := env.svc.instantiate(t.Context(), d)
	require.NoError(t, err)

	moved := *d
	moved.Slots = []domain.SlotBinding{d.Slots[0]}
	moved.Slots[0].Tapscripts = []string{"51"}
	_, _, err = env.svc.instantiate(t.Context(), &moved)
	require.ErrorContains(t, err, "tree changed since registration")

	extra := *d
	extra.Slots = []domain.SlotBinding{d.Slots[0], d.Slots[0]}
	_, _, err = env.svc.instantiate(t.Context(), &extra)
	require.ErrorContains(t, err, "slots")
}

func TestOnchainAddress(t *testing.T) {
	key, _ := hexKey(t)
	tapKey := key.PubKey()
	for net, prefix := range map[arklib.Network]string{
		arklib.Bitcoin: "bc1p", arklib.BitcoinTestNet: "tb1p", arklib.BitcoinTestNet4: "tb1p",
		arklib.BitcoinSigNet: "tb1p", arklib.BitcoinMutinyNet: "tb1p", arklib.BitcoinRegTest: "bcrt1p",
	} {
		addr, err := onchainAddress(tapKey, net)
		require.NoError(t, err, net.Name)
		require.True(t, strings.HasPrefix(addr, prefix), addr)
		decoded, err := address.DecodeAddress(addr, nil)
		require.NoError(t, err)
		require.Equal(t, schnorr.SerializePubKey(tapKey), decoded.ScriptAddress())
	}
	_, err := onchainAddress(tapKey, arklib.Network{Name: "moon"})
	require.Error(t, err)
}

func TestWatchSkipsATreeThatMoved(t *testing.T) {
	env := newTestEnv(t)
	d := env.boarding(t, env.userKey.PubKey())
	// arkd and the emulator rotated their keys since registration
	other := newTestEnv(t)
	rotated, err := NewServiceWithKeys(t.Context(), env.repo, other.ark, other.indexer, other.emulator, nil, 30*time.Second, 50, nil,
		[]*btcec.PrivateKey{env.svc.cosigners[0].key}, time.Hour, time.Minute, 2*time.Hour, 0, env.svc.limits)
	require.NoError(t, err)
	w, err := rotated.(*service).watch(t.Context(), d)
	require.Nil(t, w)
	require.ErrorContains(t, err, "tree changed since registration")
}

// only another key's delegation is cached as nil
func TestWatchErrsOnADisabledTemplate(t *testing.T) {
	env := newTestEnv(t)
	d := env.boarding(t, env.userKey.PubKey())
	require.NoError(t, env.svc.SetTemplateStatus(t.Context(), d.TemplateID, domain.TemplateStatusDisabled))
	w, err := env.svc.watch(t.Context(), d)
	require.Nil(t, w)
	require.ErrorIs(t, err, domain.ErrTemplateDisabled)
}

func TestScanDropsDisabledTemplates(t *testing.T) {
	env := newTestEnv(t)
	v := env.coin(t, env.userKey.PubKey(), 10_000, time.Minute)
	d := env.advertised(t, v)
	env.ark.streamErr = errBoom
	scan := func() {
		env.indexer.serve(v)
		env.scan(t)
	}
	scan()
	require.NotNil(t, env.svc.watched[d.ID], "cached by the first scan")
	require.Len(t, env.emulator.submitted, 1)

	// disabling the template evicts the cached delegation: nothing more is submitted
	require.NoError(t, env.svc.SetTemplateStatus(t.Context(), d.TemplateID, domain.TemplateStatusDisabled))
	scan()
	require.Nil(t, env.svc.watched[d.ID])
	require.Len(t, env.emulator.submitted, 1, "nothing renewed under a disabled template")
	require.Equal(t, "template disabled", env.svc.Status().Unwatched[d.ID], "the operator sees why")
	require.NotContains(t, env.svc.Status().Holdings, d.ID)

	// re-enabling resumes without a restart
	require.NoError(t, env.svc.SetTemplateStatus(t.Context(), d.TemplateID, domain.TemplateStatusActive))
	scan()
	require.NotNil(t, env.svc.watched[d.ID])
	require.Len(t, env.emulator.submitted, 2)
}

func TestKeyRotationWatchesPreviousDelegations(t *testing.T) {
	env := newTestEnv(t)
	oldKey := env.svc.cosigners[0].key
	d := env.boarding(t, env.userKey.PubKey())
	newKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	rotated, err := NewServiceWithKeys(
		t.Context(), env.repo, env.ark, env.indexer, env.emulator, env.explorer, 30*time.Second, 50, nil,
		[]*btcec.PrivateKey{newKey, oldKey}, time.Hour, time.Minute, 2*time.Hour, 0, env.svc.limits,
	)
	require.NoError(t, err)
	rotatedSvc := rotated.(*service)
	w, err := rotatedSvc.watch(t.Context(), d)
	require.NoError(t, err)
	require.NotNil(t, w)
	require.Same(t, rotatedSvc.cosigners[1], w.cosigner)
}

func TestRegisterDelegationCap(t *testing.T) {
	env := newTestEnv(t)
	env.svc.limits.MaxDelegations = 2
	env.boarding(t, env.userKey.PubKey())
	secondKey, _ := hexKey(t)
	second := env.boarding(t, secondKey.PubKey())
	third, _ := hexKey(t)
	_, err := env.svc.RegisterDelegation(t.Context(), second.TemplateID, env.boardingVars(t, third.PubKey()), nil)
	require.ErrorIs(t, err, ErrFull)

	// only active delegations count
	require.NoError(t, env.svc.CancelDelegation(t.Context(), second.Address))
	env.boarding(t, third.PubKey())

	env.repo.err = errBoom
	_, err = env.svc.RegisterDelegation(t.Context(), second.TemplateID, second.Variables, nil)
	require.ErrorIs(t, err, errBoom)
}

func TestScanHoldingsAndStatus(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	require.True(t, env.svc.Status().LastScan.IsZero())

	soon := env.coin(t, env.userKey.PubKey(), 3000, 2*time.Hour)
	busy := env.advertised(t, soon)
	board := env.boarding(t, env.userKey.PubKey())
	first, second := env.deposit(t, board, 3000), env.deposit(t, board, 4000)
	env.explorer.depth = 0 // seen, not yet renewable
	emptyKey, _ := hexKey(t)
	empty := env.boarding(t, emptyKey.PubKey())
	// registered by an instance with another key: same table, not ours to renew
	stranger := newTestEnv(t)
	strange := stranger.boarding(t, stranger.userKey.PubKey())
	_, otherKey := hexKey(t)
	foreign, err := env.repo.Create(ctx, domain.Delegation{
		Fingerprint: strange.Fingerprint, Address: strange.Address, TemplateID: board.TemplateID,
		Variables: strange.Variables, Slots: strange.Slots, DelegatePubKey: otherKey,
	}, 0)
	require.NoError(t, err)
	stoppedKey, _ := hexKey(t)
	stopped := env.boarding(t, stoppedKey.PubKey())
	require.NoError(t, env.svc.CancelDelegation(ctx, stopped.Address))

	secrets, _ := hexKey(t)
	env.svc.encryptionKeys = []*btcec.PrivateKey{secrets}
	claim, err := env.svc.RegisterDelegation(ctx, env.trust(t, env.fixture(t, "vhtlc_claim.json")), claimVars(t, secrets.PubKey()), nil)
	require.NoError(t, err)
	claimScript, err := hex.DecodeString(claim.Slots[0].Script)
	require.NoError(t, err)
	sooner, later := env.vtxoAt(t, claimScript, 1000, 3*time.Hour), env.vtxoAt(t, claimScript, 2000, 5*time.Hour)
	for _, v := range []*clientlib.Vtxo{&sooner, &later} {
		v.CreatedAt = time.Now().Add(time.Hour) // renewable once created: not yet
	}

	env.indexer.serve(soon, later, sooner)
	env.scan(t)

	st := env.svc.Status()
	require.WithinDuration(t, time.Now(), st.LastScan, time.Minute)
	require.Equal(t, time.Hour, st.PollInterval)
	require.Zero(t, st.RenewingVtxos)
	due := soon.ExpiresAt.Add(-1024 * time.Second)
	require.Equal(t, Holdings{
		Vtxos: 1, Amount: 3000, NextExpiry: soon.ExpiresAt, NextDue: due, NextDeadline: due, NextBatchAt: due,
	}, st.Holdings[busy.ID], "the window is shorter than the reserve: due, deadline and batch coincide")
	boarded := st.Holdings[board.ID]
	require.WithinDuration(t, time.Now().Add(time.Hour), boarded.NextDue, time.Minute, "unconfirmed: looked at again later")
	boarded.NextDue = time.Time{}
	require.Equal(t, Holdings{Vtxos: 2, Amount: 7000}, boarded)
	require.Equal(t, Holdings{Vtxos: 2, Amount: 3000, NextExpiry: sooner.ExpiresAt, NextDue: sooner.CreatedAt, NextDeadline: sooner.CreatedAt}, st.Holdings[claim.ID], "the sooner coin, whatever the order served; a transaction of its own goes at due")
	require.Equal(t, Holdings{}, st.Holdings[empty.ID])
	require.NotContains(t, st.Holdings, foreign.ID)
	require.Equal(t, errOtherKey.Error(), st.Unwatched[foreign.ID])
	require.NotContains(t, st.Holdings, stopped.ID)
	require.Empty(t, env.repo.recorded(), "nothing is due")
	require.WithinDuration(t, time.Now().Add(-renewalsRetention), env.repo.prunedTo, time.Minute)

	vtxos, err := env.svc.Vtxos(ctx, busy)
	require.NoError(t, err)
	require.Empty(t, vtxos, "the fake serves them once")
	coins, err := env.svc.Vtxos(ctx, board)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{first.Txid, second.Txid}, []string{coins[0].Txid, coins[1].Txid})
	w, err := env.svc.watch(ctx, busy)
	require.NoError(t, err)
	require.Equal(t, soon.ExpiresAt.Add(-1024*time.Second), dueTime(w.instance, vtxoCoin(0, soon), noTip))
}

func TestScanFailures(t *testing.T) {
	env := newTestEnv(t)
	v := env.coin(t, env.userKey.PubKey(), 1000, time.Hour)
	env.advertised(t, v)
	env.indexer.serve(v)

	env.repo.err = errBoom
	env.svc.scan(t.Context())
	require.True(t, env.svc.Status().LastScan.IsZero(), "a failed scan reports nothing")
	env.repo.err = nil

	env.indexer.err = errBoom
	env.svc.scan(t.Context())
	require.True(t, env.svc.Status().LastScan.IsZero())

	// scans run beside a batch in flight
	env.indexer.err = nil
	env.svc.batch.busy.Store(1)
	calls := env.indexer.calls
	env.svc.scan(t.Context())
	require.Greater(t, env.indexer.calls, calls)
	require.Equal(t, 1, env.svc.Status().RenewingVtxos)
}

func TestSpendableVtxosChunks(t *testing.T) {
	env := newTestEnv(t)
	scripts := make([]string, 250)
	_, err := env.svc.spendableVtxos(t.Context(), scripts)
	require.NoError(t, err)
	require.Equal(t, 3, env.indexer.calls)
}

func TestRenewalFailuresAreRecordedOnce(t *testing.T) {
	env := newTestEnv(t)
	due := env.coin(t, env.userKey.PubKey(), 1000, time.Minute)
	d := env.advertised(t, due)
	env.emulator.reject = func(emulatorclient.Intent) error { return errBoom } // an outage, not a refusal

	scan := func(v clientlib.Vtxo) {
		env.indexer.serve(v)
		env.scan(t)
	}
	scan(due)
	recorded := env.repo.recorded()
	require.Len(t, recorded, 1)
	require.False(t, recorded[0].Success)
	require.Equal(t, d.ID, recorded[0].DelegationID)
	require.Equal(t, []string{due.Outpoint.String()}, recorded[0].Outpoints)
	require.Equal(t, "emulator: boom", recorded[0].Error)
	require.Len(t, env.emulator.submitted, 1)

	scan(due)
	require.Len(t, env.repo.recorded(), 1, "same failure, no new row")
	require.Len(t, env.emulator.submitted, 2, "but it was retried")

	// a different reason is news
	env.emulator.reject = nil
	env.ark.registerErr = errBoom
	scan(due)
	recorded = env.repo.recorded()
	require.Len(t, recorded, 2)
	require.Equal(t, "arkd: boom", recorded[1].Error)
	tmpl, err := env.svc.GetTemplate(t.Context(), d.TemplateID)
	require.NoError(t, err)
	require.Zero(t, tmpl.Failures, "failures to answer never count against the template")

	// the vtxo is gone: its failure is forgotten
	next := env.coin(t, env.userKey.PubKey(), 1000, time.Minute)
	env.advertised(t, next)
	scan(next)
	require.NotContains(t, env.svc.batch.lastFailure, due.Outpoint.String())
	require.Contains(t, env.svc.batch.lastFailure, next.Outpoint.String())

	renewals, err := env.svc.ListRenewals(t.Context(), d)
	require.NoError(t, err)
	require.Len(t, renewals, 3, "both coins are the watch's")
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

func TestDecoders(t *testing.T) {
	_, err := PubKeyFromHex("zz")
	require.Error(t, err)
	_, err = PubKeyFromHex("00")
	require.Error(t, err)
	for _, name := range []string{"bitcoin", "testnet", "testnet4", "signet", "mutinynet", "regtest"} {
		n, err := networkFromName(name)
		require.NoError(t, err, name)
		require.Equal(t, name, n.Name)
	}
	_, _, err = pkScriptOf([]string{"zz"})
	require.Error(t, err)
	_, _, err = pkScriptOf(nil)
	require.Error(t, err)
}

func TestLateAndScannerHealth(t *testing.T) {
	env := newTestEnv(t)
	now := time.Now()
	// renewable 1024s before expiry, a window shorter than the reserve: due at once, late once its batch time passed untaken
	stuck := env.coin(t, env.userKey.PubKey(), 5000, 3*time.Minute)
	other, _ := hexKey(t)
	fresh := env.coin(t, other.PubKey(), 1000, 50*time.Minute)
	stuckD, freshD := env.advertised(t, stuck), env.advertised(t, fresh)
	env.emulator.reject = func(emulatorclient.Intent) error { return errBoom }
	env.indexer.serve(stuck, fresh)
	env.scan(t)
	h := env.svc.Status().Holdings
	require.Equal(t, 1, h[stuckD.ID].Late, "a session past its batch time, whether in one or not")
	require.Equal(t, uint64(5000), h[stuckD.ID].LateAmount)
	require.True(t, h[stuckD.ID].Renewing, "taken by the lane at this scan")
	require.Zero(t, h[freshD.ID].Late)
	require.Equal(t, fresh.ExpiresAt.Add(-1024*time.Second), h[freshD.ID].NextDue)
	require.Equal(t, h[freshD.ID].NextDue, h[freshD.ID].NextDeadline, "the window is shorter than the reserve")
	require.Equal(t, h[freshD.ID].NextDeadline, h[freshD.ID].NextBatchAt)
	require.Equal(t, uint64(1), env.svc.Status().Failed, "only the due coin was tried")
	require.Zero(t, env.svc.Status().Renewed)

	// the scanner is healthy right after start, then stale
	require.NoError(t, env.svc.scannerHealth(now))
	require.Error(t, env.svc.scannerHealth(now.Add(4*time.Hour)))
	require.NoError(t, env.svc.Health(t.Context())["scanner"], "just scanned")
	n, err := env.svc.CountActive(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 2, n)
}

// the older watch keeps the script and the coin reaches the intent once
func TestScanGivesAScriptToOneDelegation(t *testing.T) {
	env := newTestEnv(t)
	env.ark.streamErr = errBoom
	first := env.boarding(t, env.userKey.PubKey())
	slow := env.variant(t, "boarding.json", `"min_confirmations": 1`, `"min_confirmations": 2`)
	other, err := env.svc.RegisterDelegation(t.Context(), slow, first.Variables, nil)
	require.NoError(t, err)
	require.Equal(t, first.Address, other.Address, "same tree, another template")
	env.deposit(t, first, 10_000)

	env.scan(t)
	require.Len(t, env.emulator.submitted, 1)
	proof, err := psbt.NewFromRawBytes(strings.NewReader(env.emulator.submitted[0].Proof), true)
	require.NoError(t, err)
	require.Len(t, proof.UnsignedTx.TxIn, 2, "bip322 message input plus the deposit, once")
	st := env.svc.Status()
	require.Equal(t, 1, st.Holdings[first.ID].Vtxos)
	require.NotContains(t, st.Holdings, other.ID)
	require.Equal(t, fmt.Sprintf("shares a script with delegation %d", first.ID), st.Unwatched[other.ID])

	require.NoError(t, env.svc.CancelDelegation(t.Context(), first.Address))
	require.Empty(t, env.active(t), "both watches of the address")
}

func TestUniqueInputs(t *testing.T) {
	env := newTestEnv(t)
	w := &watched{delegation: domain.Delegation{ID: 1}}
	a := vtxoCoin(0, env.coin(t, env.userKey.PubKey(), 1000, time.Minute))
	b := vtxoCoin(0, env.coin(t, env.userKey.PubKey(), 1000, time.Minute))
	got := uniqueInputs([]renewalInput{{coin: a, watched: w}, {coin: b, watched: w}, {coin: a, watched: w}})
	require.Len(t, got, 2)
	require.Equal(t, a.Outpoint, got[0].coin.Outpoint)
	require.Equal(t, b.Outpoint, got[1].coin.Outpoint)
}

func TestCancelLeavesStoppedDelegations(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	done := env.boarding(t, env.userKey.PubKey())
	soon := time.Now().Add(time.Hour)
	owner, _ := hexKey(t)
	expired, err := env.svc.RegisterDelegation(ctx, done.TemplateID, env.boardingVars(t, owner.PubKey()), &soon)
	require.NoError(t, err)
	require.NoError(t, env.repo.SetStatus(ctx, done.ID, domain.DelegationStatusDone))
	n, err := env.repo.Expire(ctx, soon)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)

	require.NoError(t, env.svc.CancelDelegationByID(ctx, expired.ID))
	require.NoError(t, env.svc.CancelDelegationByID(ctx, done.ID))
	require.NoError(t, env.svc.CancelDelegation(ctx, expired.Address))
	for id, want := range map[int64]string{expired.ID: domain.DelegationStatusExpired, done.ID: domain.DelegationStatusDone} {
		got, err := env.repo.GetByID(ctx, id)
		require.NoError(t, err)
		require.Equal(t, want, got.Status)
	}
}

// a repeat is answered before time or chain checks
func TestRepeatsReturnTheActiveDelegation(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	soon := time.Now().Add(time.Hour)
	board := env.boarding(t, env.userKey.PubKey())
	owner, _ := hexKey(t)
	args := env.boardingVars(t, owner.PubKey())
	watch, err := env.svc.RegisterDelegation(ctx, board.TemplateID, args, &soon)
	require.NoError(t, err)
	past := time.Now().Add(-time.Hour)
	again, err := env.svc.RegisterDelegation(ctx, board.TemplateID, args, &past)
	require.NoError(t, err)
	require.Equal(t, watch.ID, again.ID)

	// another replica inserted it between our lookups: the insert's conflict returns its row
	env.repo.fingerprintMisses = 1
	raced, err := env.svc.RegisterDelegation(ctx, board.TemplateID, args, nil)
	require.NoError(t, err)
	require.Equal(t, watch.ID, raced.ID)
}

func TestEncryptionKeyRotation(t *testing.T) {
	env := newTestEnv(t)
	active, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	old, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	keys := []*btcec.PrivateKey{active, old}
	svc, err := NewServiceWithKeys(t.Context(), env.repo, env.ark, env.indexer, env.emulator, nil,
		30*time.Second, 50, keys, []*btcec.PrivateKey{env.svc.cosigners[0].key}, time.Hour, time.Minute, 2*time.Hour, 0, env.svc.limits)
	require.NoError(t, err)
	s := svc.(*service)
	keys[0] = old // constructor owns its keyring slice
	require.Equal(t, hex.EncodeToString(active.PubKey().SerializeCompressed()), s.Info().EncryptionPubKey)
	decrypt := s.decrypter()
	for _, key := range []*btcec.PrivateKey{active, old} {
		ciphertext, err := ecies.Encrypt(key.PubKey(), []byte("retained secret"))
		require.NoError(t, err)
		plaintext, err := decrypt(ciphertext)
		require.NoError(t, err)
		require.Equal(t, []byte("retained secret"), plaintext)
	}
	_, err = decrypt([]byte("invalid"))
	require.Error(t, err)
	// a secret sealed to the retired key still opens
	claim := env.trust(t, env.fixture(t, "vhtlc_claim.json"))
	_, err = s.RegisterDelegation(t.Context(), claim, claimVars(t, old.PubKey()), nil)
	require.NoError(t, err)
	_, err = s.RegisterDelegation(t.Context(), claim, claimVars(t, env.userKey.PubKey()), nil)
	require.Error(t, err, "sealed to a key it does not hold")
	require.Nil(t, env.svc.decrypter())
}

func TestGetDelegationIsByAddressOnly(t *testing.T) {
	env := newTestEnv(t)
	d := env.boarding(t, env.userKey.PubKey())
	_, err := env.svc.GetDelegation(t.Context(), strconv.FormatInt(d.ID, 10))
	require.ErrorIs(t, err, domain.ErrDelegationNotFound, "an id is not an address")
	got, err := env.svc.GetDelegationByID(t.Context(), d.ID)
	require.NoError(t, err)
	require.Equal(t, d.Address, got.Address)
}

func TestSecretsNeedATrustedTemplate(t *testing.T) {
	e := newTestEnv(t)
	secrets, _ := hexKey(t)
	e.svc.encryptionKeys = []*btcec.PrivateKey{secrets}
	sealed, err := ecies.Encrypt(secrets.PubKey(), e.userKey.PubKey().SerializeCompressed())
	require.NoError(t, err)
	vars := map[string]string{"ct": hex.EncodeToString(sealed)}
	tmpl, err := e.svc.RegisterTemplate(t.Context(), []byte(leakTemplate))
	require.NoError(t, err)
	_, err = e.svc.RegisterDelegation(t.Context(), tmpl.ID, vars, nil)
	require.ErrorIs(t, err, ErrSecretsRequired)

	d, err := e.svc.RegisterDelegation(t.Context(), e.trust(t, tmpl.ID), vars, nil)
	require.NoError(t, err)
	require.NoError(t, e.svc.SetTemplateTrusted(t.Context(), tmpl.ID, false))
	_, _, err = e.svc.instantiate(t.Context(), d)
	require.ErrorIs(t, err, ErrSecretsRequired, "nor renews once distrusted")
}

func TestSecretTemplateRegistersWithoutAKey(t *testing.T) {
	e := newTestEnv(t)
	id := e.trust(t, e.fixture(t, "vhtlc_claim.json"))
	secrets, _ := hexKey(t)
	_, err := e.svc.RegisterDelegation(t.Context(), id, claimVars(t, secrets.PubKey()), nil)
	require.ErrorIs(t, err, ErrSecretsRequired)
}

func TestNewInstance(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	renewal, err := env.svc.parseTemplate(ctx, env.fixture(t, "renewal.json"))
	require.NoError(t, err)
	v := env.coin(t, env.userKey.PubKey(), 1000, time.Hour)
	src, err := env.svc.virtualTx(ctx, v.Txid)
	require.NoError(t, err)
	op := wire.OutPoint{Hash: src.TxHash()}
	vars := renewalVars(env.userKey.PubKey(), 0)
	inst, err := env.svc.newInstance(ctx, renewal, env.svc.cosigners[0], vars, []*wire.OutPoint{&op}, nil)
	require.NoError(t, err)
	raw := map[string][]byte{}
	for n, v := range vars {
		raw[n], _ = hex.DecodeString(v)
	}
	want, err := renewal.Instantiate(ctx, template.Context{
		Keys: env.keys(), Variables: raw, Sources: []*template.Source{{Outpoint: op, Tx: src, Amount: v.Amount}},
	})
	require.NoError(t, err)
	require.Equal(t, want.Tapscripts(0), inst.Tapscripts(0))

	unknown := wire.OutPoint{Index: 1}
	_, err = env.svc.newInstance(ctx, renewal, env.svc.cosigners[0], vars, []*wire.OutPoint{&unknown}, nil)
	require.ErrorContains(t, err, "not found")
	require.NotErrorIs(t, err, ErrIneligible, "a failed fetch is not ineligibility")
	far := wire.OutPoint{Hash: src.TxHash(), Index: 9}
	_, err = env.svc.newInstance(ctx, renewal, env.svc.cosigners[0], vars, []*wire.OutPoint{&far}, nil)
	require.ErrorIs(t, err, ErrIneligible, "an output out of range")

	// each source is fetched once
	counter, reserve := env.pair(t, time.Hour)
	pair, err := env.svc.parseTemplate(ctx, env.fixture(t, "counter.json"))
	require.NoError(t, err)
	a, err := wire.NewOutPointFromString(counter.Outpoint.String())
	require.NoError(t, err)
	b, err := wire.NewOutPointFromString(reserve.Outpoint.String())
	require.NoError(t, err)
	lookups := env.indexer.txLookups
	_, err = env.svc.newInstance(ctx, pair, env.svc.cosigners[0], nil, []*wire.OutPoint{a, b}, nil)
	require.NoError(t, err)
	require.Equal(t, lookups+1, env.indexer.txLookups)
	_, err = env.svc.newInstance(ctx, pair, env.svc.cosigners[0], nil, nil, nil)
	require.ErrorIs(t, err, ErrUnsupported, "a watch on two slots")
}

func TestNewInstanceMapsModuleErrors(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	tmpl, err := template.Parse(ctx, twoKeys(t), nil)
	require.NoError(t, err)
	k := hex.EncodeToString(env.userKey.PubKey().SerializeCompressed())
	other, _ := hexKey(t)
	same := map[string]string{"a": k, "b": k}
	_, err = env.svc.newInstance(ctx, tmpl, env.svc.cosigners[0], same, nil, nil)
	require.ErrorIs(t, err, ErrInvalidArgs, "a watch: two leaves from equal variables")

	src := env.source(t, []*wire.TxOut{wire.NewTxOut(1000, []byte{0x51})})
	op := wire.OutPoint{Hash: src.TxHash()}
	_, err = env.svc.newInstance(ctx, tmpl, env.svc.cosigners[0], same, []*wire.OutPoint{&op}, nil)
	require.ErrorIs(t, err, ErrIneligible, "a bound instance")

	upper := map[string]string{"a": strings.ToUpper(k), "b": hex.EncodeToString(other.PubKey().SerializeCompressed())}
	_, err = env.svc.newInstance(ctx, tmpl, env.svc.cosigners[0], upper, nil, nil)
	require.ErrorIs(t, err, ErrInvalidArgs, "upper-case hex")

	distinct := map[string]string{"a": k, "b": upper["b"]}
	env.indexer.txs[op.Hash.String()] = "garbage"
	_, err = env.svc.newInstance(ctx, tmpl, env.svc.cosigners[0], distinct, []*wire.OutPoint{&op}, nil)
	require.ErrorContains(t, err, "virtual tx")
	for _, sentinel := range []error{ErrInvalidArgs, ErrIneligible, ErrUnsupported} {
		require.NotErrorIs(t, err, sentinel, "an outage is not the client's")
	}
}

// variant is fixture file with old replaced by new: another id, the same contract.
func (e *testEnv) variant(t *testing.T, file, old, new string) string {
	t.Helper()
	e.fixture(t, file)
	doc := strings.Replace(string(document(t, file)), old, new, 1)
	require.NotEqual(t, string(document(t, file)), doc)
	tmpl, err := e.svc.RegisterTemplate(t.Context(), []byte(doc))
	require.NoError(t, err)
	return tmpl.ID
}

// leakTemplate pushes the hash of its secret, a pubkey sealed in variable ct, in its only leaf.
const leakTemplate = `{"format":"delegateed-template/v1","type":"intent","variables":{"ct":"bytes"},` +
	`"secrets":{"s":{"type":"pubkey","from":"funds","ciphertext":"<ct>"}},` +
	`"inputs":[{"name":"funds","contract":{"definition":{"contractName":"Leak","constructorInputs":[{"name":"k","type":"bytes20"}],"structs":[],` +
	`"functions":[{"name":"f","leaves":[{"name":"l","asm":["<k>","OP_DROP","<SERVER_KEY>","OP_CHECKSIG"],` +
	`"witness":[{"name":"serverSig","type":"signature","encoding":"schnorr-64","injected":true}]}]}]},` +
	`"arguments":{"k":"$(<s> OP_HASH160)"}},"spend":{"function":"f","leaf":"l"}}],` +
	`"outputs":[{"name":"o","index":0,"value":{"from":"funds"},"locking":{"from":"funds"}}],` +
	`"packets":{"output_index":1}}`

// twoKeys is minimal.json with variables a and b, each in a leaf of its own.
func twoKeys(t *testing.T) []byte {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(document(t, "minimal.json"), &m))
	m["variables"] = map[string]any{"a": "pubkey", "b": "pubkey"}
	in := m["inputs"].([]any)[0].(map[string]any)
	c := in["contract"].(map[string]any)
	c["arguments"] = map[string]any{"a": "<a>", "b": "<b>"}
	def := c["definition"].(map[string]any)
	def["constructorInputs"] = []any{map[string]any{"name": "a", "type": "pubkey"}, map[string]any{"name": "b", "type": "pubkey"}}
	leaf := func(k string) map[string]any {
		return map[string]any{"name": k, "leaves": []any{map[string]any{"name": k, "asm": []any{"<" + k + ">", "OP_CHECKSIG"},
			"witness": []any{map[string]any{"name": "sig", "type": "signature", "encoding": "schnorr-64", "injected": true}}}}}
	}
	def["functions"] = []any{leaf("a"), leaf("b")}
	in["spend"] = map[string]any{"function": "a", "leaf": "a"}
	doc, err := json.Marshal(m)
	require.NoError(t, err)
	return doc
}
