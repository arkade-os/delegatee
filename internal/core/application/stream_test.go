package application

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/pkg/template/ecies"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestRegisterStreamDelegation(t *testing.T) {
	e, _, d := streamEnv(t)
	require.True(t, d.IsStream())
	require.Empty(t, d.Address)
	require.Nil(t, d.ExpiresAt)

	again, err := e.svc.RegisterStreamDelegation(t.Context(), d.TemplateID, map[string]string{})
	require.NoError(t, err)
	require.Equal(t, d.ID, again.ID, "registered once")

	_, err = e.svc.RegisterStreamDelegation(t.Context(), d.TemplateID, map[string]string{"taptree": "00"})
	require.ErrorIs(t, err, ErrInvalidArgs, "the trigger binds taptree")
	_, err = e.svc.RegisterStreamDelegation(t.Context(), d.TemplateID, map[string]string{"nope": "00"})
	require.ErrorIs(t, err, ErrInvalidArgs, "an undeclared variable")
	_, err = e.svc.RegisterStreamDelegation(t.Context(), e.trust(t, e.fixture(t, "vhtlc_claim.json")), nil)
	require.ErrorIs(t, err, ErrNotStream)

	plain := newTestEnv(t)
	_, err = plain.svc.RegisterStreamDelegation(t.Context(), plain.trust(t, plain.fixture(t, "noninteractiveclaim.json")), nil)
	require.ErrorIs(t, err, ErrSecretsRequired, "no encryption key")
}

func TestPublicRegistrationRefusesTriggers(t *testing.T) {
	e, secrets, d := streamEnv(t)
	ptx, vars := funding(t, e, secrets)
	childVars := map[string]string{
		"taptree": hex.EncodeToString(ptx.Outputs[0].TaprootTapTree), "receiver_program": vars["receiver_program"], "ciphertext": vars["ciphertext"],
	}
	_, err := e.svc.RegisterDelegation(t.Context(), d.TemplateID, childVars, nil)
	require.ErrorIs(t, err, ErrInvalidArgs)
	require.ErrorContains(t, err, "stream delegation", "refused for the trigger, not the variables")

	_, err = e.svc.RegisterDelegation(t.Context(), d.TemplateID, map[string]string{}, nil)
	require.ErrorIs(t, err, ErrInvalidArgs, "the operator's stream delegation is not returned")

	e.scan(t)
	e.svc.react(t.Context(), b64(t, ptx))
	require.Len(t, children(t, e, d.ID), 1)
	_, err = e.svc.RegisterDelegation(t.Context(), d.TemplateID, childVars, nil)
	require.ErrorIs(t, err, ErrInvalidArgs, "nor a watch it spawned")
}

func TestScanHandsStreamsToTheWatcher(t *testing.T) {
	e, _, d := streamEnv(t)
	e.scan(t)
	require.Len(t, e.svc.streamSet(), 1)
	require.Equal(t, d.ID, e.svc.streamSet()[0].delegation.ID)
	require.NotContains(t, e.svc.watched, d.ID, "the scan does not watch a stream delegation")
	require.NotContains(t, e.svc.unwatched, d.ID)
	select {
	case <-e.svc.streamsChanged:
	default:
		t.Fatal("the watcher was not told")
	}

	require.NoError(t, e.svc.SetTemplateTrusted(t.Context(), d.TemplateID, false))
	e.scan(t)
	require.Empty(t, e.svc.streamSet())
	require.Equal(t, ErrSecretsRequired.Error(), e.svc.unwatched[d.ID], "an unusable stream delegation is reported, not watched")
	require.NoError(t, e.svc.SetTemplateTrusted(t.Context(), d.TemplateID, true))

	require.NoError(t, e.svc.CancelDelegationByID(t.Context(), d.ID))
	e.scan(t)
	require.Empty(t, e.svc.streamSet(), "a cancelled stream delegation stops")
}

func TestReactSpawnsAWatch(t *testing.T) {
	e, secrets, d := streamEnv(t)
	e.scan(t)
	ptx, vars := funding(t, e, secrets)
	for len(e.svc.wake) > 0 {
		<-e.svc.wake
	}

	e.svc.react(t.Context(), b64(t, ptx))
	got := children(t, e, d.ID)
	require.Len(t, got, 1)
	child := got[0]
	require.False(t, child.IsStream())
	require.Equal(t, hex.EncodeToString(ptx.UnsignedTx.TxOut[0].PkScript), child.Slots[0].Script)
	require.Equal(t, vars["receiver_program"], child.Variables["receiver_program"])
	require.Equal(t, vars["ciphertext"], child.Variables["ciphertext"])
	require.WithinDuration(t, time.Now().Add(24*time.Hour), *child.ExpiresAt, time.Minute)
	require.Len(t, e.svc.wake, 1, "the scan is woken for the coin")

	e.svc.react(t.Context(), b64(t, ptx))
	require.Len(t, children(t, e, d.ID), 1, "a replay spawns nothing more")
}

func TestReactIgnores(t *testing.T) {
	e, secrets, d := streamEnv(t)
	e.scan(t)
	other, _ := hexKey(t)
	key := secrets.SerializeCompressed()
	elsewhere, err := ecies.Encrypt(other.PubKey(), make([]byte, 32))
	require.NoError(t, err)

	undecryptable, _ := fundingWith(t, e, secrets, func(_, s []byte) []byte { return claimPacket(elsewhere, s, key) })
	wrongKey, _ := fundingWith(t, e, secrets, func(c, s []byte) []byte { return claimPacket(c, s, other.PubKey().SerializeCompressed()) })
	nonCanonical, _ := fundingWith(t, e, secrets, func(c, s []byte) []byte {
		return claimPacket(c, append(s, txscript.OP_NOP), key)
	})
	noKey, _ := fundingWith(t, e, secrets, func(c, s []byte) []byte { return claimPacket(c, s, nil) })
	moved, _ := funding(t, e, secrets)
	moved.UnsignedTx.TxOut[0].PkScript = append([]byte{0x51, 0x20}, make([]byte, 32)...)
	noTree, _ := funding(t, e, secrets)
	noTree.Outputs[0].TaprootTapTree = nil
	for name, raw := range map[string]string{
		"undecryptable ciphertext": b64(t, undecryptable),
		"packet for another key":   b64(t, wrongKey),
		"non-canonical script":     b64(t, nonCanonical),
		"no key":                   b64(t, noKey),
		"tree of another output":   b64(t, moved),
		"no tree":                  b64(t, noTree),
		"not a psbt":               "bm90IGEgcHNidA==",
	} {
		e.svc.react(t.Context(), raw)
		require.Empty(t, children(t, e, d.ID), name)
	}

	ptx, _ := funding(t, e, secrets)
	require.NoError(t, e.svc.CancelDelegationByID(t.Context(), d.ID))
	e.scan(t)
	e.svc.react(t.Context(), b64(t, ptx))
	require.Empty(t, children(t, e, d.ID), "a cancelled stream delegation spawns nothing")
}

func TestWatchStreamsReopens(t *testing.T) {
	e, secrets, d := streamEnv(t)
	e.scan(t)
	first := make(chan clientlib.TransactionEvent)
	e.indexer.setTxs(first)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.svc.watchStreams(ctx)
	}()
	ptx, _ := funding(t, e, secrets)
	first <- clientlib.TransactionEvent{ArkTx: &clientlib.TxNotification{TxData: clientlib.TxData{Tx: b64(t, ptx)}}}
	require.Eventually(t, func() bool { return len(children(t, e, d.ID)) == 1 }, 5*time.Second, 10*time.Millisecond)

	e.indexer.setTxs(make(chan clientlib.TransactionEvent))
	close(first)
	require.Eventually(t, e.indexer.transactionsOpened(2), 5*time.Second, 10*time.Millisecond, "reopened after the stream ended")

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher outlived its context")
	}
}

func TestStopEndsTheWatcher(t *testing.T) {
	e, _, _ := streamEnv(t)
	e.indexer.setTxs(make(chan clientlib.TransactionEvent))
	e.svc.Start()
	require.Eventually(t, e.indexer.transactionsOpened(1), 5*time.Second, 10*time.Millisecond, "the first scan opens the stream")
	stopped := make(chan struct{})
	go func() {
		e.svc.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not end the watcher")
	}
}

func TestStreamSurvivesRestart(t *testing.T) {
	e, secrets, d := streamEnv(t)
	r := e.restart(t)
	r.scan(t)
	ptx, _ := funding(t, r, secrets)
	r.svc.react(t.Context(), b64(t, ptx))
	require.Len(t, children(t, r, d.ID), 1)
}

func TestSpawnedWatchIsWatched(t *testing.T) {
	e, secrets, d := streamEnv(t)
	e.scan(t)
	ptx, _ := funding(t, e, secrets)
	e.svc.react(t.Context(), b64(t, ptx))
	child := children(t, e, d.ID)[0]
	e.scan(t)
	require.NotNil(t, e.svc.watched[child.ID], "the scan instantiates the child like any watch")
	require.NotContains(t, e.svc.unwatched, child.ID)
}

func TestStreamChildrenHaveTheirOwnCap(t *testing.T) {
	e, secrets, d := streamEnv(t)
	e.svc.limits.MaxDelegations, e.svc.limits.MaxStreamChildren = 2, 2
	e.scan(t)
	first, _ := funding(t, e, secrets)
	e.svc.react(t.Context(), b64(t, first))
	public := e.boarding(t, e.userKey.PubKey()) // with the stream delegation, the public cap is full

	second, _ := funding(t, e, secrets)
	e.svc.react(t.Context(), b64(t, second))
	require.Len(t, children(t, e, d.ID), 2, "a full public cap does not block children")
	other, _ := hexKey(t)
	_, err := e.svc.RegisterDelegation(t.Context(), public.TemplateID, e.boardingVars(t, other.PubKey()), nil)
	require.ErrorIs(t, err, ErrFull, "children do not free the public cap")

	third, vars := funding(t, e, secrets)
	childVars := map[string]string{
		"taptree": hex.EncodeToString(third.Outputs[0].TaprootTapTree), "receiver_program": vars["receiver_program"], "ciphertext": vars["ciphertext"],
	}
	expires := time.Now().Add(24 * time.Hour)
	_, err = e.svc.registerWatch(t.Context(), d.TemplateID, childVars, &expires, &spawn{parent: d.ID, script: third.UnsignedTx.TxOut[0].PkScript})
	require.ErrorIs(t, err, ErrFull)
	require.Len(t, children(t, e, d.ID), 2)
}

func TestSpawnedWatchOwnsASharedScript(t *testing.T) {
	e, secrets, d := streamEnv(t)
	e.scan(t)
	ptx, vars := funding(t, e, secrets)
	public, err := e.svc.RegisterDelegation(t.Context(), e.trust(t, e.fixture(t, "vhtlc_claim.json")), vars, nil)
	require.NoError(t, err)
	e.svc.react(t.Context(), b64(t, ptx))
	child := children(t, e, d.ID)[0]
	require.Equal(t, public.Slots[0].Script, child.Slots[0].Script)
	require.Less(t, public.ID, child.ID)

	e.scan(t)
	require.NotNil(t, e.svc.watched[child.ID])
	require.NotContains(t, e.svc.unwatched, child.ID)
	require.Equal(t, fmt.Sprintf("shares a script with delegation %d", child.ID), e.svc.unwatched[public.ID])
}

// streamEnv has an encryption key and the noninteractiveclaim stream delegation registered.
func streamEnv(t *testing.T) (*testEnv, *btcec.PublicKey, *domain.Delegation) {
	t.Helper()
	e := newTestEnv(t)
	secrets, _ := hexKey(t)
	e.svc.encryptionKeys = []*btcec.PrivateKey{secrets}
	d, err := e.svc.RegisterStreamDelegation(t.Context(), e.trust(t, e.fixture(t, "noninteractiveclaim.json")), nil)
	require.NoError(t, err)
	return e, secrets.PubKey(), d
}

// funding pays a VHTLC whose preimage is sealed to secrets, the daemon's key, and stamps it as intent-solver does.
func funding(t *testing.T, e *testEnv, secrets *btcec.PublicKey) (*psbt.Packet, map[string]string) {
	t.Helper()
	key := secrets.SerializeCompressed()
	return fundingWith(t, e, secrets, func(ciphertext, script []byte) []byte { return claimPacket(ciphertext, script, key) })
}

// fundingWith stamps the packet body stamp builds from the sealed preimage and the covenant.
func fundingWith(t *testing.T, e *testEnv, secrets *btcec.PublicKey, stamp func(ciphertext, script []byte) []byte) (*psbt.Packet, map[string]string) {
	t.Helper()
	vars := claimVars(t, secrets)
	tmpl, err := e.svc.parseTemplate(t.Context(), e.trust(t, e.fixture(t, "vhtlc_claim.json")))
	require.NoError(t, err)
	inst, err := e.svc.newInstance(t.Context(), tmpl, e.svc.cosigners[0], vars, nil, nil)
	require.NoError(t, err)
	tree, err := txutils.TapTree(inst.Tapscripts(0)).Encode()
	require.NoError(t, err)
	program, err := hex.DecodeString(vars["receiver_program"])
	require.NoError(t, err)
	ciphertext, err := hex.DecodeString(vars["ciphertext"])
	require.NoError(t, err)
	ext, err := extension.Extension{packets.Raw(4, stamp(ciphertext, enforcePayTo(t, program)))}.TxOut()
	require.NoError(t, err)
	e.txs++
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: e.txs}})
	tx.AddTxOut(wire.NewTxOut(10_000, inst.PkScript(0)))
	tx.AddTxOut(ext)
	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	ptx.Outputs[0].TaprootTapTree = tree
	return ptx, vars
}

// claimPacket is covclaimd's ClaimPacket body: ciphertext, arkade script, key; a nil value is left out.
func claimPacket(ciphertext, script, key []byte) []byte {
	var b []byte
	for i, v := range [][]byte{ciphertext, script, key} {
		if v == nil {
			continue
		}
		b = append(b, byte(i+1))
		b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
		b = append(b, v...)
	}
	return b
}

func enforcePayTo(t *testing.T, program []byte) []byte {
	t.Helper()
	s, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddOp(arkade.OP_DUP).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).AddData(program).AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddOp(arkade.OP_GREATERTHANOREQUAL).Script()
	require.NoError(t, err)
	return s
}

func b64(t *testing.T, ptx *psbt.Packet) string {
	t.Helper()
	s, err := ptx.B64Encode()
	require.NoError(t, err)
	return s
}

func children(t *testing.T, e *testEnv, parent int64) []domain.Delegation {
	t.Helper()
	var out []domain.Delegation
	for _, d := range e.active(t) {
		if d.ParentID == parent {
			out = append(out, d)
		}
	}
	return out
}

func TestStreamSubscriptionUsesRecipientFilter(t *testing.T) {
	e, key, d := offlineStream(t)
	events := make(chan clientlib.TransactionEvent)
	e.indexer.setTxs(events)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); e.svc.watchStreams(ctx) }()
	require.Eventually(t, e.indexer.transactionsOpened(1), 5*time.Second, time.Millisecond)
	e.indexer.mu.Lock()
	filters := slices.Clone(e.indexer.filters[0])
	e.indexer.mu.Unlock()
	require.Len(t, filters, 1)
	require.Contains(t, filters[0], "hasPacket(tx.extension, 4)")
	require.Contains(t, filters[0], hex.EncodeToString(key.PubKey().SerializeCompressed()))
	require.Contains(t, filters[0], hex.EncodeToString([]byte("delegatee-secrets/v1")))
	require.NoError(t, e.svc.CancelDelegationByID(t.Context(), d.ID))
	e.scan(t)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("filtered stream did not stop")
	}
}

func TestStreamFilterUpdateKeepsReceiving(t *testing.T) {
	e, key, d := offlineStream(t)
	events := make(chan clientlib.TransactionEvent)
	e.indexer.setTxs(events)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.indexer.updateTransactions = func() error { once.Do(func() { close(entered); <-release }); return nil }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); e.svc.watchStreams(ctx) }()
	require.Eventually(t, e.indexer.transactionsOpened(1), time.Second, time.Millisecond)
	_, err := e.svc.RegisterStreamDelegation(t.Context(), e.trust(t, e.fixture(t, "noninteractiveclaim.json")), nil)
	require.NoError(t, err)
	e.scan(t)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("filter update did not start")
	}
	ptx, _ := offlineFunding(t, e, key, d.TemplateID, nil)
	events <- clientlib.TransactionEvent{ArkTx: &clientlib.TxNotification{TxData: clientlib.TxData{Tx: b64(t, ptx)}}}
	require.Eventually(t, func() bool { return len(children(t, e, d.ID)) == 1 }, time.Second, time.Millisecond)
	close(release)
	require.Eventually(t, func() bool { e.indexer.mu.Lock(); defer e.indexer.mu.Unlock(); return len(e.indexer.filters) == 2 }, time.Second, time.Millisecond)
	require.True(t, e.indexer.transactionsOpened(1)(), "filter updates keep the original subscription")
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watcher did not stop")
	}
}

func TestStreamFilterReconcilesAmbiguousUpdate(t *testing.T) {
	e, key, d := offlineStream(t)
	events := make(chan clientlib.TransactionEvent)
	e.indexer.setTxs(events)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	attempt := 0
	e.indexer.updateTransactions = func() error {
		attempt++
		once.Do(func() { close(entered); <-release })
		if attempt == 1 {
			return errBoom
		}
		return nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); e.svc.watchStreams(ctx) }()
	require.Eventually(t, e.indexer.transactionsOpened(1), time.Second, time.Millisecond)
	other, err := e.svc.RegisterStreamDelegation(t.Context(), e.trust(t, e.fixture(t, "noninteractiveclaim.json")), nil)
	require.NoError(t, err)
	e.scan(t)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("filter update did not start")
	}
	ptx, _ := offlineFunding(t, e, key, d.TemplateID, nil)
	events <- clientlib.TransactionEvent{ArkTx: &clientlib.TxNotification{TxData: clientlib.TxData{Tx: b64(t, ptx)}}}
	require.Eventually(t, func() bool { return len(children(t, e, d.ID)) == 1 }, time.Second, time.Millisecond)
	require.NoError(t, e.svc.CancelDelegationByID(t.Context(), other.ID))
	e.scan(t)
	require.Eventually(t, func() bool { return len(e.svc.streamsChanged) == 0 }, time.Second, time.Millisecond)
	close(release)
	require.Eventually(t, func() bool { e.indexer.mu.Lock(); defer e.indexer.mu.Unlock(); return len(e.indexer.filters) == 2 }, time.Second, time.Millisecond)
	e.indexer.mu.Lock()
	updates := e.indexer.txUpdates
	e.indexer.mu.Unlock()
	require.Equal(t, 2, updates)
	require.True(t, e.indexer.transactionsOpened(1)(), "filter updates keep the original subscription")
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watcher did not stop")
	}
}
