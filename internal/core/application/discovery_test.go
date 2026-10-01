package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestOnchainDiscovery(t *testing.T) {
	e := newTestEnv(t)
	d := e.boarding(t, e.userKey.PubKey())
	u := e.deposit(t, d, 10_000)
	e.explorer.depth = 0
	active := map[string]struct{}{d.TemplateID: {}}
	now := time.Now()
	h, _, inputs, err := e.svc.discover(t.Context(), []domain.Delegation{*d}, active, now)
	require.NoError(t, err)
	require.Empty(t, inputs)
	require.Equal(t, 1, h[d.ID].Vtxos)
	e.explorer.depth = 1
	_, _, inputs, err = e.svc.discover(t.Context(), []domain.Delegation{*d}, active, now.Add(time.Minute))
	require.NoError(t, err)
	require.Len(t, inputs, 1)
	require.True(t, inputs[0].onchain)
	p, err := e.svc.buildIntent(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.NoError(t, err)
	require.True(t, p.hasEmulator, "the boarding covenant")
	require.Len(t, e.emulator.submitted, 1)
	proof, err := psbt.NewFromRawBytes(strings.NewReader(p.intent.Proof), true)
	require.NoError(t, err)
	prev, err := txutils.GetArkPsbtFields(proof, 1, arkade.PrevArkTxField)
	require.NoError(t, err)
	require.Len(t, prev, 1, "a boarding input carries its funding tx")
	require.Equal(t, u.Txid, prev[0].TxHash().String())

	// the emulator signs a boarding input against the leaf of the proof
	op, err := wire.NewOutPointFromString(u.Txid + ":0")
	require.NoError(t, err)
	batch := buildBatch(t, e, p.outputs, 1, *op)
	carry(batch.vtxoTree, p)
	handler := &batchHandler{svc: e.svc, batchExpiry: testExpiry, inBatch: []*pendingIntent{p}}
	_, err = handler.OnBatchFinalization(t.Context(), clientlib.BatchFinalizationEvent{Tx: batch.commitment}, batch.vtxoTree, batch.connectors)
	require.NoError(t, err)
	require.Len(t, e.emulator.finalized, 1)
	sent, err := psbt.NewFromRawBytes(strings.NewReader(e.emulator.finalized[0]), true)
	require.NoError(t, err)
	require.Empty(t, sent.Inputs[0].TaprootLeafScript, "arkd's input")
	require.Equal(t, []*psbt.TaprootTapLeafScript{inputs[0].leaf}, sent.Inputs[1].TaprootLeafScript)
	require.Equal(t, inputs[0].prevOut, sent.Inputs[1].WitnessUtxo)

}

func TestSuccessorValidatesBoundScripts(t *testing.T) {
	e := newTestEnv(t)
	renewal := e.fixture(t, ownedRenewal)
	v := e.ownedCoin(t, e.userKey.PubKey(), 5000, time.Hour)
	tx, err := e.svc.virtualTx(t.Context(), v.Txid)
	require.NoError(t, err)
	op := wire.OutPoint{Hash: tx.TxHash()}
	parent := &domain.Delegation{ID: 7, DelegatePubKey: e.svc.cosigners[0].pubKey}
	mapped := map[int]wire.OutPoint{0: op}
	sources := map[string]*wire.MsgTx{op.Hash.String(): tx}
	require.NoError(t, e.svc.successor(t.Context(), parent, renewal, []uint16{0}, mapped, sources, false))
	rows := e.active(t)
	require.Len(t, rows, 1)
	require.Empty(t, rows[0].Variables)
	require.Equal(t, parent.ID, rows[0].ParentID)
	require.Equal(t, op.String(), rows[0].Slots[0].Outpoint)
	_, _, err = e.svc.instantiate(t.Context(), &rows[0])
	require.NoError(t, err)

	bad := tx.Copy()
	bad.TxOut[0].PkScript = []byte{0x51}
	badop := wire.OutPoint{Hash: bad.TxHash()}
	err = e.svc.successor(t.Context(), parent, renewal, []uint16{0}, map[int]wire.OutPoint{0: badop}, map[string]*wire.MsgTx{badop.Hash.String(): bad}, false)
	require.ErrorIs(t, err, ErrIneligible)
	require.ErrorContains(t, err, "script differs")
}

func TestSpentCoinFollowsItsArkTx(t *testing.T) {
	e := newTestEnv(t)
	v := e.ownedCoin(t, e.userKey.PubKey(), 5000, time.Hour)
	d := e.advertised(t, v)
	next := e.ownedCoin(t, e.userKey.PubKey(), 5000, time.Hour) // a tx advertising ownedRenewal for output 0
	v.Spent, v.ArkTxid = true, next.Txid
	e.indexer.known = []clientlib.Vtxo{v}

	e.indexer.serve()
	e.scan(t)
	got, err := e.repo.GetByID(t.Context(), d.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusDone, got.Status)
	rows := e.active(t)
	require.Len(t, rows, 1)
	require.Equal(t, d.ID, rows[0].ParentID)
	require.Equal(t, next.Outpoint.String(), rows[0].Slots[0].Outpoint)
}

// the batch closed its stream before reporting the end
func TestSpentCoinFollowsAnUnreportedBatch(t *testing.T) {
	e := newTestEnv(t)
	in := ownedInput(t, e, 10_000)
	batch := e.playBatch(t)
	batch.closeAfterForfeits = true
	results := e.svc.renew(t.Context(), []renewalInput{in})
	require.Len(t, results, 1)
	require.ErrorContains(t, results[0].err, "event stream closed")

	spent := asVtxo(in.coin)
	spent.Spent, spent.SettledBy = true, batch.txid
	e.indexer.known = []clientlib.Vtxo{spent}
	e.indexer.serve()
	e.scan(t)
	got, err := e.repo.GetByID(t.Context(), in.watched.delegation.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusDone, got.Status)
	rows := e.active(t)
	require.Len(t, rows, 1)
	require.Equal(t, got.ID, rows[0].ParentID)
	leaf := batch.batch.vtxoTree.Leaves()[0].UnsignedTx
	require.Equal(t, wire.OutPoint{Hash: leaf.TxHash()}.String(), rows[0].Slots[0].Outpoint)
}

func TestForeignSuccessorsFollowTheCap(t *testing.T) {
	e := newTestEnv(t)
	v := e.ownedCoin(t, e.userKey.PubKey(), 5000, time.Hour)
	d := e.advertised(t, v)
	e.svc.limits.MaxDelegations = 1
	var id [32]byte
	_, err := hex.Decode(id[:], []byte(e.fixture(t, ownedRenewal)))
	require.NoError(t, err)
	key := e.userKey.PubKey().SerializeCompressed()
	script := e.contract(t, ownedRenewal, 0, map[string]string{"owner": hex.EncodeToString(key)})
	var outs []*wire.TxOut
	var records []packets.Record
	for i := range 5 {
		outs = append(outs, wire.NewTxOut(330, script))
		records = append(records, packets.Record{Template: id, Outputs: []uint16{uint16(i)}})
	}
	ad, err := packets.EncodeAdvertisement(records)
	require.NoError(t, err)
	tx := e.source(t, outs, packets.Raw(packets.TypeState, key), packets.Raw(packets.TypeAdvertisement, ad))
	v.Spent, v.ArkTxid = true, tx.TxHash().String()
	e.indexer.known = []clientlib.Vtxo{v}

	e.indexer.serve()
	e.scan(t)
	got, err := e.repo.GetByID(t.Context(), d.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusDone, got.Status)
	rows := e.active(t)
	require.Len(t, rows, 1, "the predecessor's place only")
}

func TestForeignSettlementIsNotRetried(t *testing.T) {
	e := newTestEnv(t)
	v := e.ownedCoin(t, e.userKey.PubKey(), 5000, time.Hour)
	e.advertised(t, v)
	var bogus [32]byte
	copy(bogus[:], bytes.Repeat([]byte{0xab}, 32))
	ad, err := packets.EncodeAdvertisement([]packets.Record{{Template: bogus, Outputs: []uint16{0}}})
	require.NoError(t, err)
	tx := e.source(t, []*wire.TxOut{wire.NewTxOut(330, []byte{0x51})}, packets.Raw(packets.TypeAdvertisement, ad))
	v.Spent, v.ArkTxid = true, tx.TxHash().String()
	e.indexer.known = []clientlib.Vtxo{v}

	e.indexer.serve()
	e.scan(t)
	require.Empty(t, e.repo.settled())
}

func TestOwnSettlementDroppedWhenUnusable(t *testing.T) {
	e := newTestEnv(t)
	v := e.ownedCoin(t, e.userKey.PubKey(), 5000, time.Hour)
	d := e.advertised(t, v)
	var bogus [32]byte
	copy(bogus[:], bytes.Repeat([]byte{0xab}, 32))
	ad, err := packets.EncodeAdvertisement([]packets.Record{{Template: bogus, Outputs: []uint16{0}}})
	require.NoError(t, err)
	st := spentBy(*d, e.source(t, []*wire.TxOut{wire.NewTxOut(330, []byte{0x51})}, packets.Raw(packets.TypeAdvertisement, ad)))
	st.own = true

	e.svc.settle(t.Context(), st)
	require.Empty(t, e.repo.settled())
	got, err := e.repo.GetByID(t.Context(), d.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusDone, got.Status)
}

func TestArkTxOutranksAFailedBatch(t *testing.T) {
	e := newTestEnv(t)
	v := e.ownedCoin(t, e.userKey.PubKey(), 5000, time.Hour)
	d := e.advertised(t, v)
	stale := e.ownedCoin(t, e.userKey.PubKey(), 5000, time.Hour)
	staleTx, err := e.svc.virtualTx(t.Context(), stale.Txid)
	require.NoError(t, err)
	failed := spentBy(*d, staleTx)
	failed.own, failed.spentBy, failed.coins = true, "a failed batch", []string{v.Outpoint.String()}
	require.NoError(t, e.svc.keep(t.Context(), failed))
	next := e.ownedCoin(t, e.userKey.PubKey(), 5000, time.Hour)
	v.Spent, v.ArkTxid = true, next.Txid
	e.indexer.known = []clientlib.Vtxo{v}

	e.indexer.serve()
	e.scan(t)
	rows := e.active(t)
	require.Len(t, rows, 1)
	require.Equal(t, next.Outpoint.String(), rows[0].Slots[0].Outpoint)
	require.Empty(t, e.repo.settled())
}

func TestUntrustedDelegateKeyRegistration(t *testing.T) {
	e := newTestEnv(t)
	// the release leaf is the delegate key alone
	_, err := e.svc.RegisterDelegation(t.Context(), e.fixture(t, "onchain_release.json"), nil, nil)
	require.ErrorIs(t, err, ErrDelegateKeyLeaf)
}

func TestOnchainRelease(t *testing.T) {
	e, inputs := releaseEnv(t)
	id, st, err := e.svc.runOnchain(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.NoError(t, err)
	paid := st.tx
	require.Equal(t, paid.TxHash().String(), id)
	require.NotNil(t, e.explorer.broadcast)
	var doc struct{ Outputs []struct{ Locking string } }
	require.NoError(t, json.Unmarshal(document(t, "onchain_release.json"), &doc))
	require.Equal(t, doc.Outputs[0].Locking, hex.EncodeToString(paid.TxOut[0].PkScript))
	vsize := (paid.SerializeSizeStripped()*3 + paid.SerializeSize() + 3) / 4
	require.EqualValues(t, 10_000-2*vsize, paid.TxOut[0].Value, "the explorer's 2 sat/vB")
	require.NoError(t, e.repo.SetTemplateTrusted(t.Context(), inputs[0].watched.delegation.TemplateID, false))
	e.explorer.broadcast = nil
	_, _, err = e.svc.runOnchain(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.ErrorIs(t, err, ErrDelegateKeyLeaf)
	require.Nil(t, e.explorer.broadcast)
}

func TestSuccessorSkipsUnusableTargets(t *testing.T) {
	e := newTestEnv(t)
	renewal, boarding := e.fixture(t, ownedRenewal), e.fixture(t, "boarding.json")
	parent := &domain.Delegation{DelegatePubKey: e.svc.cosigners[0].pubKey}
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{})
	tx.AddTxOut(&wire.TxOut{Value: 5000, PkScript: []byte{0x51}})
	tx.AddTxOut(&wire.TxOut{Value: 5000, PkScript: []byte{0x51}})
	op := func(i uint32) wire.OutPoint { return wire.OutPoint{Hash: tx.TxHash(), Index: i} }
	mapped := map[int]wire.OutPoint{0: op(0), 1: op(1)}
	sources := map[string]*wire.MsgTx{tx.TxHash().String(): tx}

	unknown := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	require.ErrorIs(t, e.svc.successor(t.Context(), parent, unknown, []uint16{0}, mapped, sources, false), domain.ErrTemplateNotFound)
	require.ErrorContains(t, e.svc.successor(t.Context(), parent, boarding, []uint16{0}, mapped, sources, false), "requires variables")
	require.ErrorContains(t, e.svc.successor(t.Context(), parent, renewal, []uint16{0, 1}, mapped, sources, false), "wrong slot count")
	require.ErrorContains(t, e.svc.successor(t.Context(), parent, renewal, []uint16{7}, mapped, sources, false), "unavailable")
	require.NoError(t, e.repo.SetTemplateStatus(t.Context(), renewal, domain.TemplateStatusDisabled))
	require.ErrorIs(t, e.svc.successor(t.Context(), parent, renewal, []uint16{0}, mapped, sources, false), domain.ErrTemplateDisabled)

	// a transaction advertising an unusable target reports it and creates no row
	var id [32]byte
	copy(id[:], bytes.Repeat([]byte{0xab}, 32))
	body, err := packets.EncodeAdvertisement([]packets.Record{{Template: id, Outputs: []uint16{0}}})
	require.NoError(t, err)
	out, err := extension.Extension{packets.Raw(packets.TypeAdvertisement, body)}.TxOut()
	require.NoError(t, err)
	tx.AddTxOut(out)
	require.ErrorIs(t, e.svc.successors(t.Context(), parent, tx, mapped, sources, false), domain.ErrTemplateNotFound)
	rows := e.active(t)
	require.Empty(t, rows)
}

func TestPairWaitsForBothCoinsThenIsDone(t *testing.T) {
	e := newTestEnv(t)
	pair := e.fixture(t, "counter.json")
	counter, reserve := e.pair(t, time.Second)
	tx, err := e.svc.virtualTx(t.Context(), counter.Txid)
	require.NoError(t, err)
	id := tx.TxHash()
	parent := &domain.Delegation{DelegatePubKey: e.svc.cosigners[0].pubKey}
	mapped := map[int]wire.OutPoint{0: {Hash: id}, 1: {Hash: id, Index: 1}}
	require.NoError(t, e.svc.successor(t.Context(), parent, pair, []uint16{0, 1}, mapped, map[string]*wire.MsgTx{id.String(): tx}, false))
	rows := e.active(t)
	require.Len(t, rows, 1)

	// a coin of someone else at the same script is never paired in
	stranger := reserve
	stranger.Txid = hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 32))
	active := map[string]struct{}{pair: {}}

	e.indexer.serve(counter, stranger)
	_, _, inputs, err := e.svc.discover(t.Context(), rows, active, time.Now())
	require.NoError(t, err)
	require.Empty(t, inputs, "one coin missing: the pair waits")

	e.indexer.serve(counter, reserve, stranger)
	_, _, inputs, err = e.svc.discover(t.Context(), rows, active, time.Now())
	require.NoError(t, err)
	require.Len(t, inputs, 2)
	for slot, in := range inputs {
		require.Equal(t, slot, in.coin.Slot)
		require.Equal(t, id.String(), in.coin.Outpoint.Hash.String())
	}

	status := func() string {
		e.indexer.serve(stranger)
		_, _, inputs, err = e.svc.discover(t.Context(), rows, active, time.Now())
		require.NoError(t, err)
		require.Empty(t, inputs)
		got, err := e.repo.GetByID(t.Context(), rows[0].ID)
		require.NoError(t, err)
		return got.Status
	}
	require.Equal(t, domain.DelegationStatusActive, status(), "coins the indexer does not list are not spent")
	counter.Spent = true
	e.indexer.known = []clientlib.Vtxo{counter, reserve}
	require.Equal(t, domain.DelegationStatusActive, status(), "one coin is left")
	reserve.Spent = true
	e.indexer.known = []clientlib.Vtxo{counter, reserve}
	require.Equal(t, domain.DelegationStatusDone, status())
}

func TestOnchainRefusals(t *testing.T) {
	e, inputs := releaseEnv(t)
	e.explorer.feeRate = 5 // more than the cap below allows

	e.svc.maxOnchainFeeRate = 10
	tight, err := template.Parse(t.Context(), bytes.Replace(document(t, "onchain_release.json"), []byte(`"max": 1000`), []byte(`"max": 499`), 1), nil)
	require.NoError(t, err)
	w := *inputs[0].watched
	w.tmpl = tight
	w.instance, err = tight.Instantiate(t.Context(), template.Context{Keys: e.keys()})
	require.NoError(t, err)
	capped := []renewalInput{inputs[0]}
	capped[0].watched = &w
	_, _, err = e.svc.runOnchain(t.Context(), e.svc.cosigners[0], capped, e.ark.info.Fees.IntentFees)
	require.ErrorContains(t, err, "exceeds the cap")
	require.Nil(t, e.explorer.broadcast)
}

func TestOnchainBroadcastLostReply(t *testing.T) {
	e, inputs := releaseEnv(t)
	e.explorer.lostReply = true
	id, st, err := e.svc.runOnchain(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.NoError(t, err, "the explorer knows the transaction")
	require.Equal(t, st.tx.TxHash().String(), id)
}

func TestCoinConversions(t *testing.T) {
	txid := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	created, expiry := time.Unix(1_000, 0), time.Unix(2_000, 0)
	v := clientlib.Vtxo{
		Outpoint: clientlib.Outpoint{Txid: txid, VOut: 3}, Script: "5120ab", Amount: 42,
		Assets: []clientlib.Asset{{AssetId: "x", Amount: 1}}, CreatedAt: created, ExpiresAt: expiry, Swept: true,
	}
	c := vtxoCoin(1, v)
	require.Equal(t, txid, c.Outpoint.Hash.String(), "txids are displayed reversed, parsed back")
	require.Equal(t, uint32(3), c.Outpoint.Index)
	require.Equal(t, []byte{0x51, 0x20, 0xab}, c.Script)
	require.Equal(t, coin{
		Slot: 1, Outpoint: c.Outpoint, Amount: 42, Script: c.Script, Assets: v.Assets,
		CreatedAt: created, Expiry: expiry, Swept: true,
	}, c)

	u := clientlib.ExplorerUtxo{Txid: txid, Vout: 1, Amount: 7, Script: "0014aa", Status: clientlib.ConfirmedStatus{Confirmed: true, BlockTime: 1_000}}
	uc := utxoCoin(0, u, 6)
	require.Equal(t, c.Outpoint.Hash, uc.Outpoint.Hash)
	require.Equal(t, coin{Outpoint: uc.Outpoint, Amount: 7, Script: []byte{0x00, 0x14, 0xaa}, CreatedAt: created, Confirms: 6}, uc)
	u.Status = clientlib.ConfirmedStatus{}
	require.True(t, utxoCoin(0, u, 0).CreatedAt.IsZero(), "unconfirmed")
}

// releaseEnv has a confirmed deposit due at a watch on the trusted onchain_release.json.
func releaseEnv(t *testing.T) (*testEnv, []renewalInput) {
	t.Helper()
	e := newTestEnv(t)
	id := e.trust(t, e.fixture(t, "onchain_release.json"))
	d, err := e.svc.RegisterDelegation(t.Context(), id, nil, nil)
	require.NoError(t, err)
	e.deposit(t, d, 10_000)
	_, _, inputs, err := e.svc.discover(t.Context(), []domain.Delegation{*d}, map[string]struct{}{id: {}}, time.Now())
	require.NoError(t, err)
	require.Len(t, inputs, 1)
	return e, inputs
}
