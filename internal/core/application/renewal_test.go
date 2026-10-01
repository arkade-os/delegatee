package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/emulator/pkg/arkade"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLeavesPay(t *testing.T) {
	leaf := func(outs ...*wire.TxOut) *psbt.Packet {
		return &psbt.Packet{UnsignedTx: &wire.MsgTx{TxOut: outs}}
	}
	alice, bob := []byte{0x51, 0x01}, []byte{0x51, 0x02}
	leaves := []*psbt.Packet{
		leaf(wire.NewTxOut(1000, alice), wire.NewTxOut(0, []byte{0x51})),
		leaf(wire.NewTxOut(1000, alice)),
		leaf(wire.NewTxOut(500, bob)),
	}

	require.NoError(t, leavesPay(leaves, []*wire.TxOut{
		wire.NewTxOut(1000, alice), wire.NewTxOut(500, bob), wire.NewTxOut(1000, alice),
	}, nil))
	// the same leaf cannot pay two vtxos
	require.ErrorContains(t, leavesPay(leaves, []*wire.TxOut{
		wire.NewTxOut(1000, alice), wire.NewTxOut(1000, alice), wire.NewTxOut(1000, alice),
	}, nil), "no leaf pays 1000")
	// right script, short amount
	require.ErrorContains(t, leavesPay(leaves, []*wire.TxOut{wire.NewTxOut(501, bob)}, nil), "no leaf pays 501")
	require.ErrorContains(t, leavesPay(nil, []*wire.TxOut{wire.NewTxOut(500, bob)}, nil), "no leaf pays")
}

func TestLeavesPayChecksAssets(t *testing.T) {
	script := []byte{0x51, 0x02}
	packet := assetPacket(t)
	ext, err := (extension.Extension{packet}).TxOut()
	require.NoError(t, err)
	leaf := &psbt.Packet{UnsignedTx: &wire.MsgTx{TxOut: []*wire.TxOut{
		wire.NewTxOut(1_000, script), ext,
	}}}

	require.NoError(t, leavesPay(
		[]*psbt.Packet{leaf},
		[]*wire.TxOut{wire.NewTxOut(1_000, script)},
		[][]clientlib.Asset{{{AssetId: assetID, Amount: 5}}},
	))
	require.Error(t, leavesPay(
		[]*psbt.Packet{leaf},
		[]*wire.TxOut{wire.NewTxOut(1_000, script)},
		[][]clientlib.Asset{{{AssetId: assetID, Amount: 6}}},
	))
}

func TestRenewPaysTheFeeOrRefuses(t *testing.T) {
	env := newTestEnv(t)
	env.setFees("200.0")
	env.ark.streamErr = errBoom // stop right after the intents are built
	pays := dueInput(t, env, 1000, 10_000)
	refuses := dueInput(t, env, 0, 10_000)

	results := env.svc.renew(t.Context(), []renewalInput{pays, refuses})
	require.Len(t, results, 2)
	byOutpoint := map[string]error{}
	for _, r := range results {
		require.Len(t, r.inputs, 1)
		byOutpoint[r.inputs[0].coin.Outpoint.String()] = r.err
	}
	require.ErrorIs(t, byOutpoint[refuses.coin.Outpoint.String()], ErrIneligible, "a template without fees pays none")
	require.ErrorContains(t, byOutpoint[pays.coin.Outpoint.String()], "event stream: boom")

	// only the payer reached the emulator, with its output short of exactly the fee
	require.Len(t, env.emulator.submitted, 1)
	proof, err := psbt.NewFromRawBytes(strings.NewReader(env.emulator.submitted[0].Proof), true)
	require.NoError(t, err)
	require.Equal(t, int64(9_800), proof.UnsignedTx.TxOut[0].Value)
	require.Equal(t, pays.coin.Script, proof.UnsignedTx.TxOut[0].PkScript)
	require.Len(t, proof.UnsignedTx.TxIn, 2, "bip322 message input plus the vtxo")
	require.Contains(t, env.emulator.submitted[0].Message, env.svc.cosigners[0].pubKey)

	// over the template's cap
	env.setFees("1001.0")
	results = env.svc.renew(t.Context(), []renewalInput{pays})
	require.ErrorIs(t, results[0].err, ErrIneligible)
	require.ErrorContains(t, results[0].err, "exceeds the cap")
	require.Len(t, env.emulator.submitted, 1)
}

func TestRenewPricesOutputFeeAtTheActualOutputAmount(t *testing.T) {
	env := newTestEnv(t)
	env.ark.info.Fees = clientlib.FeeInfo{IntentFees: arkfee.Config{
		IntentOffchainOutputProgram: "amount < 10000.0 ? 200.0 : 100.0",
	}}
	env.ark.streamErr = errBoom
	in := dueInput(t, env, 1000, 10_000)

	results := env.svc.renew(t.Context(), []renewalInput{in})
	require.Len(t, results, 1)
	require.ErrorContains(t, results[0].err, "event stream: boom")
	require.Len(t, env.emulator.submitted, 1)
	proof, err := psbt.NewFromRawBytes(strings.NewReader(env.emulator.submitted[0].Proof), true)
	require.NoError(t, err)
	require.Equal(t, int64(9_800), proof.UnsignedTx.TxOut[0].Value)
}

func TestRenewFeeErrors(t *testing.T) {
	env := newTestEnv(t)
	in := dueInput(t, env, 0, 1000)

	env.ark.infoErr = errBoom
	results := env.svc.renew(t.Context(), []renewalInput{in})
	require.Len(t, results, 1)
	require.ErrorIs(t, results[0].err, errBoom)

	env.ark.infoErr = nil
	env.setFees("not a program(")
	results = env.svc.renew(t.Context(), []renewalInput{in})
	require.ErrorContains(t, results[0].err, "template tx")
	require.NotErrorIs(t, results[0].err, errIntentRejected, "a template tx error is not a rejection")
	require.Empty(t, env.emulator.submitted)
}

// the renewed coin is back at the watched address: no successor, the watch finds it
func TestRenewalKeepsTheWatch(t *testing.T) {
	env := newTestEnv(t)
	in := dueInput(t, env, 0, 10_000)
	batch := env.playBatch(t)

	env.svc.renewAndRecord(t.Context(), []renewalInput{in})

	recorded := env.repo.recorded()
	require.Len(t, recorded, 1)
	require.True(t, recorded[0].Success, recorded[0].Error)
	require.Contains(t, env.svc.consumed, in.coin.Outpoint.String())
	active := env.active(t)
	require.Len(t, active, 1)
	require.Equal(t, in.watched.delegation.ID, active[0].ID)
	leaf := batch.batch.vtxoTree.Leaves()[0].UnsignedTx
	require.Equal(t, in.coin.Script, leaf.TxOut[0].PkScript)
	require.EqualValues(t, 10_000, leaf.TxOut[0].Value)
}

// the successor takes over even at the delegation cap; the coin is not offered again
func TestRenewalSettlesIntoItsSuccessor(t *testing.T) {
	env := newTestEnv(t)
	env.svc.limits.MaxDelegations = 1
	in := ownedInput(t, env, 10_000)
	batch := env.playBatch(t)

	env.svc.renewAndRecord(t.Context(), []renewalInput{in})

	recorded := env.repo.recorded()
	require.Len(t, recorded, 1)
	require.True(t, recorded[0].Success, recorded[0].Error)
	require.Equal(t, batch.txid, recorded[0].CommitmentTxid)
	require.Contains(t, env.svc.consumed, in.coin.Outpoint.String())
	require.Len(t, env.ark.forfeits, 1)
	require.EqualValues(t, 1, env.svc.Status().Renewed)
	prev, err := env.repo.GetByID(t.Context(), in.watched.delegation.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusDone, prev.Status)
	active := env.active(t)
	require.Len(t, active, 1, "the successor, above the cap")
	require.Equal(t, in.watched.delegation.ID, active[0].ParentID)
	leaf := batch.batch.vtxoTree.Leaves()[0].UnsignedTx
	require.Equal(t, wire.OutPoint{Hash: leaf.TxHash()}.String(), active[0].Slots[0].Outpoint)
}

func TestFailedSuccessorIsRetried(t *testing.T) {
	env := newTestEnv(t)
	in := ownedInput(t, env, 10_000)
	env.playBatch(t)
	env.repo.createErr = errBoom
	env.svc.renewAndRecord(t.Context(), []renewalInput{in})
	env.repo.createErr = nil
	active := env.active(t)
	require.Empty(t, active)

	env.scan(t)
	active = env.active(t)
	require.Len(t, active, 1)
	require.Equal(t, in.watched.delegation.ID, active[0].ParentID)
	require.Empty(t, env.repo.settled())
}

// the sunk batch is not charged to the other intents' templates
func TestFinalizationFailureBlamesItsIntent(t *testing.T) {
	env := newTestEnv(t)
	good := ownedInput(t, env, 10_000)
	bad := dueInput(t, env, 1000, 20_000)
	env.emulator.forfeits = func(in emulatorclient.Intent, forfeits []string) []string {
		if proofSpends(t, in.Proof, bad.coin.Outpoint.Hash.String()) {
			return nil // the emulator signs none of them
		}
		return forfeits
	}
	env.playBatch(t)

	results := env.svc.renew(t.Context(), []renewalInput{good, bad})
	require.Len(t, results, 2)
	byOutpoint := map[string]renewalResult{}
	for _, r := range results {
		byOutpoint[r.inputs[0].coin.Outpoint.String()] = r
	}
	failed := byOutpoint[bad.coin.Outpoint.String()]
	require.ErrorIs(t, failed.err, errIntentRejected)
	require.ErrorContains(t, failed.err, "forfeit count")
	require.False(t, failed.registered)
	sunk := byOutpoint[good.coin.Outpoint.String()]
	require.ErrorContains(t, sunk.err, "batch session")
	require.NotErrorIs(t, sunk.err, errIntentRejected)
	outcomes := templateOutcomes(results)
	require.Equal(t, tally{rejected: 1}, outcomes[bad.watched.delegation.TemplateID])
	require.Equal(t, tally{accepted: true}, outcomes[good.watched.delegation.TemplateID])
}

// one renewal row for all of a watch's coins
func TestRenewOneCoinPerIntent(t *testing.T) {
	env := newTestEnv(t)
	env.ark.streamErr = errBoom
	d := env.boarding(t, env.userKey.PubKey())
	var outpoints []string
	for range 3 {
		outpoints = append(outpoints, env.deposit(t, d, 1000).Txid+":0")
	}
	env.scan(t)
	require.Len(t, env.emulator.submitted, 3, "one intent per coin")
	for _, in := range env.emulator.submitted {
		proof, err := psbt.NewFromRawBytes(strings.NewReader(in.Proof), true)
		require.NoError(t, err)
		require.Len(t, proof.Inputs, 2, "the message and one coin")
	}
	recorded := env.repo.recorded()
	require.Len(t, recorded, 1, "one row per delegation and outcome")
	require.Equal(t, d.ID, recorded[0].DelegationID)
	require.ElementsMatch(t, outpoints, recorded[0].Outpoints)
}

func TestBuildIntentNeedsThePreviousTx(t *testing.T) {
	env := newTestEnv(t)
	in := dueInput(t, env, 0, 1000)
	env.indexer.prevMiss = true
	results := env.svc.renew(t.Context(), []renewalInput{in})
	require.ErrorContains(t, results[0].err, "virtual tx "+in.coin.Outpoint.Hash.String()+" not found")

	env.indexer.prevMiss, env.indexer.txs[in.coin.Outpoint.Hash.String()] = false, "garbage"
	results = env.svc.renew(t.Context(), []renewalInput{in})
	require.ErrorContains(t, results[0].err, "virtual tx")
}

// proof input 1 is the vtxo
func TestBuildIntentShiftsAssets(t *testing.T) {
	env := newTestEnv(t)
	in := dueInput(t, env, 0, 1000)
	in.coin.Assets = []clientlib.Asset{{AssetId: assetID, Amount: 5}}

	p, err := env.svc.buildIntent(t.Context(), env.svc.cosigners[0], []renewalInput{in}, arkfee.Config{})
	require.NoError(t, err)
	require.Len(t, p.outputs, 1)
	require.Equal(t, [][]clientlib.Asset{{{AssetId: assetID, Amount: 5}}}, p.assets)
	require.NotNil(t, p.inputs[0].leaf, "set from the template tx, for the forfeits")
	require.Equal(t, in.coin.Script, p.inputs[0].prevOut.PkScript)
	proof, err := psbt.NewFromRawBytes(strings.NewReader(p.intent.Proof), true)
	require.NoError(t, err)
	require.Len(t, proof.UnsignedTx.TxIn, 2)
	ext, err := extension.NewExtensionFromTx(proof.UnsignedTx)
	require.NoError(t, err)
	assets := ext.GetAssetPacket()
	require.Len(t, assets, 1)
	require.Equal(t, uint16(1), assets[0].Inputs[0].Vin, "proof input 1 is vtxo 0")
	require.Equal(t, uint16(0), assets[0].Outputs[0].Vout)
	emu, err := arkade.FindEmulatorPacket(proof.UnsignedTx)
	require.NoError(t, err)
	require.Equal(t, uint16(1), emu[0].Vin)
	require.Len(t, proof.Inputs[1].TaprootLeafScript, 1)
}

func TestShiftInputs(t *testing.T) {
	packet := assetPacket(t)
	emu, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 0, Script: []byte{0x51}}, arkade.EmulatorEntry{Vin: 1, Script: []byte{0x52}})
	require.NoError(t, err)
	shifted, err := shiftInputs(extension.Extension{packet, emu}, 1)
	require.NoError(t, err)
	require.Equal(t, uint16(1), shifted.GetAssetPacket()[0].Inputs[0].Vin)
	require.Equal(t, uint16(0), shifted.GetAssetPacket()[0].Outputs[0].Vout, "outputs do not move")
	emuOut, err := arkade.DeserializeEmulatorPacket(mustSerialize(t, shifted.GetPacketByType(arkade.PacketType)))
	require.NoError(t, err)
	require.Equal(t, uint16(1), emuOut[0].Vin)
	require.Equal(t, uint16(2), emuOut[1].Vin)

	// packets 2 and 5 reference outputs, not inputs: they pass through as they are
	unknown := extension.UnknownPacket{PacketType: 2, Data: []byte{0xde, 0xad}}
	shifted, err = shiftInputs(extension.Extension{packet, unknown, emu}, 1)
	require.NoError(t, err)
	require.Len(t, shifted, 3)
	require.Equal(t, unknown, shifted[1])
}

func TestAssetsByOutput(t *testing.T) {
	got := assetsByOutput(assetPacket(t), 2)
	require.Len(t, got, 2)
	require.Equal(t, []clientlib.Asset{{AssetId: assetID, Amount: 5}}, got[0])
	require.Empty(t, got[1])
	require.Equal(t, [][]clientlib.Asset{{}, {}}, assetsByOutput(nil, 2))
}

func TestOneBadVtxoDoesNotSinkItsNeighbours(t *testing.T) {
	env := newTestEnv(t)
	env.setFees("200.0")
	good := dueInput(t, env, 1000, 10_000)
	broke := dueInput(t, env, 1000, 150) // cannot pay the 200 sat fee
	refused := dueInput(t, env, 1000, 10_000)
	env.emulator.reject = func(in emulatorclient.Intent) error {
		proof, err := psbt.NewFromRawBytes(strings.NewReader(in.Proof), true)
		require.NoError(t, err)
		if proof.UnsignedTx.TxIn[1].PreviousOutPoint.Hash.String() == refused.coin.Outpoint.Hash.String() {
			return status.Error(codes.InvalidArgument, "boom")
		}
		return nil
	}
	results := env.svc.renew(t.Context(), []renewalInput{good, broke, refused})
	byOutpoint := map[string]error{}
	for _, r := range results {
		for _, in := range r.inputs {
			byOutpoint[in.coin.Outpoint.String()] = r.err
		}
	}
	require.ErrorIs(t, byOutpoint[broke.coin.Outpoint.String()], ErrIneligible)
	require.ErrorIs(t, byOutpoint[refused.coin.Outpoint.String()], errIntentRejected)
	require.ErrorContains(t, byOutpoint[good.coin.Outpoint.String()], "batch session", "the fake stream closes before any batch")
	require.Len(t, env.emulator.submitted, 2)
	require.Len(t, env.ark.registered, 1, "the good one alone reached arkd")
}

// a Tx error does not count; a trusted template is never disabled
func TestFailureValve(t *testing.T) {
	ctx := t.Context()
	env := newTestEnv(t)
	env.svc.limits.TemplateMaxFailures = 2
	env.emulator.reject = func(emulatorclient.Intent) error { return status.Error(codes.InvalidArgument, "boom") }
	env.trust(t, env.fixture(t, "renewal.json"))
	trustedCoin := env.feeCoin(t, env.userKey.PubKey(), 10_000, 1000)
	trustedOne := env.advertised(t, trustedCoin)
	otherCoin := env.ownedCoin(t, env.userKey.PubKey(), 10_000, time.Minute)
	d := env.advertised(t, otherCoin)
	require.NotEqual(t, trustedOne.TemplateID, d.TemplateID)
	cycle := func(vtxos ...clientlib.Vtxo) {
		env.indexer.serve(vtxos...)
		env.scan(t)
	}
	get := func(id string) *domain.Template {
		tmpl, err := env.svc.GetTemplate(ctx, id)
		require.NoError(t, err)
		return tmpl
	}

	cycle(trustedCoin, otherCoin)
	require.Equal(t, 1, get(d.TemplateID).Failures)
	require.Equal(t, domain.TemplateStatusActive, get(d.TemplateID).Status)

	// a Tx error never reaches arkd and does not count
	env.setFees("20000.0") // no coin can pay: Tx fails before any submission
	cycle(otherCoin)
	require.Equal(t, 1, get(d.TemplateID).Failures, "unchanged")

	env.setFees("0.0")
	cycle(trustedCoin, otherCoin)
	require.Equal(t, domain.TemplateStatusDisabled, get(d.TemplateID).Status, "two rejected cycles at threshold two")
	require.Len(t, env.emulator.submitted, 4)

	// a trusted template keeps renewing; a disabled one's delegation submits nothing more
	for range 6 {
		cycle(trustedCoin, otherCoin)
	}
	require.Equal(t, domain.TemplateStatusActive, get(trustedOne.TemplateID).Status, "trusted: never disabled")
	require.Zero(t, get(trustedOne.TemplateID).Failures, "trusted: not counted")
	require.Nil(t, env.svc.watched[d.ID], "evicted from the scan")
	require.Len(t, env.emulator.submitted, 10, "one per cycle for the trusted template, nothing for the disabled one")
}

func TestIsRejection(t *testing.T) {
	for _, code := range []codes.Code{
		codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound, codes.AlreadyExists, codes.OutOfRange,
	} {
		err := fmt.Errorf("wrapped: %w", status.Error(code, "no"))
		require.True(t, isRejection(t.Context(), err), code.String())
	}
	for name, err := range map[string]error{
		"unavailable": status.Error(codes.Unavailable, "down"),
		"deadline":    status.Error(codes.DeadlineExceeded, "slow"),
		"internal":    status.Error(codes.Internal, "emulator bug"),
		// the daemon's own misconfiguration, not the template's
		"unauthenticated":   status.Error(codes.Unauthenticated, "no"),
		"permission denied": status.Error(codes.PermissionDenied, "no"),
		"unimplemented":     status.Error(codes.Unimplemented, "no"),
		"plain":             errors.New("boom"),
	} {
		require.False(t, isRejection(t.Context(), err), name)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.False(t, isRejection(ctx, status.Error(codes.InvalidArgument, "no")), "our own shutdown")
}

// a template tx not spending exactly the coin would register an intent whose forfeits never verify
func TestBuildIntentChecksTheTemplateTx(t *testing.T) {
	for name, tc := range map[string]struct {
		tamper func(*psbt.Packet)
		want   string
	}{
		"another coin": {func(p *psbt.Packet) {
			p.UnsignedTx.TxIn[0].PreviousOutPoint.Index++
		}, "template tx input 0 spends"},
		"wrong amount": {func(p *psbt.Packet) {
			p.Inputs[0].WitnessUtxo = wire.NewTxOut(p.Inputs[0].WitnessUtxo.Value+1, p.Inputs[0].WitnessUtxo.PkScript)
		}, "template tx input 0 witness utxo does not match"},
		"wrong script": {func(p *psbt.Packet) {
			p.Inputs[0].WitnessUtxo = wire.NewTxOut(p.Inputs[0].WitnessUtxo.Value, []byte{0x51})
		}, "template tx input 0 witness utxo does not match"},
		"input count": {func(p *psbt.Packet) {
			p.UnsignedTx.TxIn, p.Inputs = append(p.UnsignedTx.TxIn, p.UnsignedTx.TxIn[0]), append(p.Inputs, p.Inputs[0])
		}, "template tx has 2 inputs for 1 vtxos"},
		"no extension": {func(p *psbt.Packet) {
			n := len(p.UnsignedTx.TxOut) - 1
			p.UnsignedTx.TxOut, p.Outputs = p.UnsignedTx.TxOut[:n], p.Outputs[:n]
		}, "template tx has no extension output"},
		"no tap leaf": {func(p *psbt.Packet) {
			p.Inputs[0].TaprootLeafScript = nil
		}, "template tx input 0 lacks its witness utxo or tap leaf"},
	} {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t)
			in := dueInput(t, env, 0, 1000)
			tx, coins, err := env.svc.templateTx(t.Context(), []renewalInput{in}, arkfee.Config{})
			require.NoError(t, err)
			tc.tamper(tx)
			_, err = env.svc.intentOf(t.Context(), env.svc.cosigners[0], []renewalInput{in}, tx, coins)
			require.ErrorContains(t, err, tc.want)
			require.Empty(t, env.emulator.submitted)
		})
	}
	env := newTestEnv(t)
	in := dueInput(t, env, 0, 1000)
	_, coins, err := env.svc.templateTx(t.Context(), []renewalInput{in}, arkfee.Config{})
	require.NoError(t, err)
	_, err = env.svc.intentOf(t.Context(), env.svc.cosigners[0], []renewalInput{in}, nil, coins)
	require.ErrorContains(t, err, "template tx is empty")

	// a coin is spent only at the script of its slot
	w := *dueInput(t, env, 0, 1000).watched
	w.delegation.Slots = []domain.SlotBinding{w.delegation.Slots[0]}
	w.delegation.Slots[0].Script = "5120" + strings.Repeat("00", 32)
	in.watched = &w
	_, err = env.svc.buildIntent(t.Context(), env.svc.cosigners[0], []renewalInput{in}, arkfee.Config{})
	require.ErrorContains(t, err, "not at the script of its slot")
}

func TestTemplateOutcomes(t *testing.T) {
	in := func(templateID string) renewalInput {
		return renewalInput{watched: &watched{delegation: domain.Delegation{TemplateID: templateID}}}
	}
	got := templateOutcomes([]renewalResult{
		{inputs: []renewalInput{in("a")}, err: fmt.Errorf("%w: emulator: boom", errIntentRejected)},
		{inputs: []renewalInput{in("a")}, commitmentTxid: "c1"},
		{inputs: []renewalInput{in("b")}, err: fmt.Errorf("%w: arkd: boom", errIntentRejected)},
		{inputs: []renewalInput{in("c")}, err: errors.New("template tx: not covered")},
		{inputs: []renewalInput{in("b"), in("b")}, err: fmt.Errorf("%w: arkd: boom", errIntentRejected)},
		{inputs: []renewalInput{in("d")}, err: errors.New("event stream: boom")},
		{inputs: []renewalInput{in("e")}, err: errors.New("batch session: boom"), registered: true},
	})
	require.Equal(t, tally{accepted: true, rejected: 1}, got["a"], "one accepted intent makes the cycle a success")
	require.Equal(t, tally{rejected: 3}, got["b"], "counted per vtxo")
	require.Equal(t, tally{}, got["c"], "never reached arkd")
	require.Equal(t, tally{}, got["d"], "accepted by the emulator, lost before arkd: not the template's doing")
	require.Equal(t, tally{accepted: true}, got["e"], "registered by arkd: accepted, whatever the batch did")
}

func TestBatchHandlerSelection(t *testing.T) {
	env := newTestEnv(t)
	hashed := func(id string) string {
		sum := sha256.Sum256([]byte(id))
		return hex.EncodeToString(sum[:])
	}
	mine, other := &pendingIntent{id: "mine"}, &pendingIntent{id: "later"}
	h := &batchHandler{svc: env.svc, pending: []*pendingIntent{mine, other}}

	skip, _, err := h.OnBatchStarted(t.Context(), clientlib.BatchStartedEvent{Id: "b0", HashedIntentIds: []string{hashed("someone")}})
	require.NoError(t, err)
	require.True(t, skip, "not our batch")
	require.Empty(t, env.ark.confirmed)

	skip, timeout, err := h.OnBatchStarted(t.Context(), clientlib.BatchStartedEvent{
		Id: "b1", HashedIntentIds: []string{hashed("mine")}, BatchExpiry: 1024,
	})
	require.NoError(t, err)
	require.False(t, skip)
	require.Equal(t, 1024*time.Second, timeout)
	require.Equal(t, []string{"mine"}, env.ark.confirmed)
	require.Equal(t, []*pendingIntent{mine}, h.inBatch)
	require.Equal(t, []*pendingIntent{other}, h.pending)
	require.Equal(t, arklib.LocktimeTypeSecond, h.batchExpiry.Type)

	_, _, err = h.OnBatchStarted(t.Context(), clientlib.BatchStartedEvent{Id: "b2", HashedIntentIds: []string{hashed("later")}, BatchExpiry: 144})
	require.NoError(t, err)
	require.Equal(t, arklib.LocktimeTypeBlock, h.batchExpiry.Type)

	require.NoError(t, h.OnBatchFailed(t.Context(), clientlib.BatchFailedEvent{Id: "another", Reason: "x"}))
	require.ErrorContains(t, h.OnBatchFailed(t.Context(), clientlib.BatchFailedEvent{Id: "b2", Reason: "timeout"}), "batch b2 failed: timeout")

	require.NoError(t, h.OnStreamStarted(t.Context(), clientlib.StreamStartedEvent{}))
	require.NoError(t, h.OnBatchFinalized(t.Context(), clientlib.BatchFinalizedEvent{}))
	require.NoError(t, h.OnTreeTxEvent(t.Context(), clientlib.TreeTxEvent{}))
	require.NoError(t, h.OnTreeSignatureEvent(t.Context(), clientlib.TreeSignatureEvent{}))
	done, err := h.OnTreeNonces(t.Context(), clientlib.TreeNoncesEvent{})
	require.NoError(t, err)
	require.False(t, done)
}

func TestForfeits(t *testing.T) {
	env := newTestEnv(t)
	p := builtIntent(t, env, dueInput(t, env, 0, 1000))
	in := p.inputs[0]
	h := &batchHandler{svc: env.svc, inBatch: []*pendingIntent{p}}

	connectorTx := wire.NewMsgTx(3)
	connectorTx.AddTxOut(wire.NewTxOut(0, txutils.ANCHOR_PKSCRIPT))
	connectorTx.AddTxOut(wire.NewTxOut(330, []byte{0x51, 0x20}))
	connector := &psbt.Packet{UnsignedTx: connectorTx}

	forfeits, err := h.buildForfeits([]renewalInput{in}, []*psbt.Packet{connector})
	require.NoError(t, err)
	require.Len(t, forfeits, 1)
	forfeit, err := psbt.NewFromRawBytes(strings.NewReader(forfeits[0]), true)
	require.NoError(t, err)
	require.Len(t, forfeit.UnsignedTx.TxIn, 2)
	require.Equal(t, in.coin.Outpoint.Hash.String(), forfeit.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String())
	require.Equal(t, wire.OutPoint{Hash: connectorTx.TxHash(), Index: 1}, forfeit.UnsignedTx.TxIn[1].PreviousOutPoint)
	require.Equal(t, env.svc.forfeitPkScript, forfeit.UnsignedTx.TxOut[0].PkScript)
	require.Equal(t, int64(1330), forfeit.UnsignedTx.TxOut[0].Value, "vtxo plus connector go to arkd")
	require.Equal(t, in.leaf.Script, forfeit.Inputs[0].TaprootLeafScript[0].Script)

	onlyAnchor := wire.NewMsgTx(3)
	onlyAnchor.AddTxOut(wire.NewTxOut(0, txutils.ANCHOR_PKSCRIPT))
	_, err = h.buildForfeits([]renewalInput{in}, []*psbt.Packet{{UnsignedTx: onlyAnchor}})
	require.ErrorContains(t, err, "connector not found")

	// nothing is forfeited for a batch that cannot be verified
	_, err = h.OnBatchFinalization(t.Context(), clientlib.BatchFinalizationEvent{}, nil, nil)
	require.ErrorContains(t, err, "refusing to forfeit")
}

// no emulator involved
func TestIntentDelegateSigns(t *testing.T) {
	env := newTestEnv(t)
	tmpl, err := env.svc.RegisterTemplate(t.Context(), []byte(delegatedRenewal))
	require.NoError(t, err)
	d, err := env.svc.RegisterDelegation(t.Context(), env.trust(t, tmpl.ID), nil, nil)
	require.NoError(t, err)
	inputs := dueAt(t, env, d)
	delegate := schnorr.SerializePubKey(env.svc.cosigners[0].key.PubKey())

	p := builtIntent(t, env, inputs[0])
	require.False(t, p.hasEmulator)
	require.Empty(t, env.emulator.submitted)
	proof, err := psbt.NewFromRawBytes(strings.NewReader(p.intent.Proof), true)
	require.NoError(t, err)
	require.True(t, signedBy(proof, delegate), "the message input and the coin")
	prev, err := txutils.GetArkPsbtFields(proof, 1, arkade.PrevArkTxField)
	require.NoError(t, err)
	require.Empty(t, prev, "funding txs are for the emulator")

	batch := buildBatch(t, env, p.outputs, 1)
	carry(batch.vtxoTree, p)
	h := &batchHandler{svc: env.svc, batchExpiry: testExpiry, inBatch: []*pendingIntent{p}}
	forfeits, err := h.OnBatchFinalization(t.Context(), clientlib.BatchFinalizationEvent{Tx: batch.commitment}, batch.vtxoTree, batch.connectors)
	require.NoError(t, err)
	require.Len(t, forfeits, 1)
	forfeit, err := psbt.NewFromRawBytes(strings.NewReader(forfeits[0]), true)
	require.NoError(t, err)
	require.True(t, signedBy(&psbt.Packet{UnsignedTx: forfeit.UnsignedTx, Inputs: forfeit.Inputs[:1]}, delegate), "the vtxo input")
	require.Empty(t, env.emulator.finalized)

	require.NoError(t, env.svc.SetTemplateTrusted(t.Context(), d.TemplateID, false))
	_, err = env.svc.buildIntent(t.Context(), env.svc.cosigners[0], inputs, arkfee.Config{})
	require.ErrorIs(t, err, ErrDelegateKeyLeaf)
	require.Empty(t, env.emulator.submitted)
}

// assetPacket moves 5 units of assetID from input 0 to output 0.
func assetPacket(t *testing.T) asset.Packet {
	t.Helper()
	id, err := asset.NewAssetIdFromString(assetID)
	require.NoError(t, err)
	in, err := asset.NewAssetInput(0, 5)
	require.NoError(t, err)
	out, err := asset.NewAssetOutput(0, 5)
	require.NoError(t, err)
	g, err := asset.NewAssetGroup(id, nil, []asset.AssetInput{*in}, []asset.AssetOutput{*out}, nil)
	require.NoError(t, err)
	packet, err := asset.NewPacket([]asset.AssetGroup{*g})
	require.NoError(t, err)
	return packet
}

func mustSerialize(t *testing.T, p extension.Packet) []byte {
	t.Helper()
	b, err := p.Serialize()
	require.NoError(t, err)
	return b
}

func proofSpends(t *testing.T, proof, txid string) bool {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(proof), true)
	require.NoError(t, err)
	return slices.ContainsFunc(ptx.UnsignedTx.TxIn, func(in *wire.TxIn) bool { return in.PreviousOutPoint.Hash.String() == txid })
}

// ownedInput is a due coin of an ownedRenewal chain.
func ownedInput(t *testing.T, env *testEnv, amount uint64) renewalInput {
	t.Helper()
	v := env.ownedCoin(t, env.userKey.PubKey(), amount, time.Minute)
	w, err := env.svc.watch(t.Context(), env.advertised(t, v))
	require.NoError(t, err)
	coin := vtxoCoin(0, v)
	return renewalInput{coin: coin, watched: w, due: dueTime(w.instance, coin)}
}

// dueInput is a coin of the user's renewal watch paying up to maxFee.
func dueInput(t *testing.T, env *testEnv, maxFee int64, amount uint64) renewalInput {
	t.Helper()
	v := env.feeCoin(t, env.userKey.PubKey(), amount, maxFee)
	w, err := env.svc.watch(t.Context(), env.renewal(t, env.userKey.PubKey(), maxFee))
	require.NoError(t, err)
	require.NotNil(t, w)
	coin := vtxoCoin(0, v)
	return renewalInput{coin: coin, watched: w, due: dueTime(w.instance, coin)}
}

func builtIntent(t *testing.T, env *testEnv, in renewalInput) *pendingIntent {
	t.Helper()
	p, err := env.svc.buildIntent(t.Context(), env.svc.cosigners[0], []renewalInput{in}, arkfee.Config{})
	require.NoError(t, err)
	return p
}

const assetID = "abababababababababababababababababababababababababababababababab0000"

// delegatedRenewal pays a vtxo back to itself under the server and delegate keys.
const delegatedRenewal = `{
  "format": "delegateed-template/v1",
  "type": "intent",
  "inputs": [{
    "name": "funds",
    "contract": {
      "definition": {
        "contractName": "Delegated",
        "constructorInputs": [],
        "structs": [],
        "functions": [{"name": "spend", "leaves": [{
          "name": "spend",
          "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<DELEGATE_KEY>", "OP_CHECKSIG"],
          "witness": [
            {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true},
            {"name": "delegateSig", "type": "signature", "encoding": "schnorr-64", "injected": true}
          ]
        }]}]
      }
    },
    "spend": {"function": "spend", "leaf": "spend"}
  }],
  "outputs": [{"name": "renewed", "index": 0, "value": {"from": "funds"}, "locking": {"from": "funds"}}],
  "packets": {"output_index": 1, "rules": [{"type": 2, "action": "emit", "from": "funds", "data": "01"}]}
}`
