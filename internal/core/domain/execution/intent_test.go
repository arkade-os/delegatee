package execution

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/pkg/template"
	"github.com/arkade-os/executor/templates"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

var now = time.Unix(1_800_000_000, 0)

func TestBuildIntentRenewsTheCoinInFullWithProofAndMessage(t *testing.T) {
	r := newRenewal(t, 1000)
	in, err := BuildIntent(
		r.inst, r.inputs, []delegation.Coin{r.coin}, r.txs, template.Fee{Dust: 330},
		r.cosigner.PubKey(),
	)
	require.NoError(t, err)
	require.True(t, in.HasArkadePacket)
	require.Len(t, in.Outputs, 1)
	require.Equal(t, int64(10_000), in.Outputs[0].Value, "the coin renews in full")
	require.Equal(t, r.coin.Script, hex.EncodeToString(in.Outputs[0].PkScript), "at its own script")
	require.Empty(t, in.Onchain)

	var msg intent.RegisterMessage
	require.NoError(t, msg.Decode(in.Message))
	require.Equal(t, []int{}, msg.OnchainOutputIndexes)
	require.Equal(
		t, []string{hex.EncodeToString(r.cosigner.PubKey().SerializeCompressed())},
		msg.CosignersPublicKeys,
	)
	require.Contains(t, in.Message, `"onchain_output_indexes":[]`)

	proof, err := psbt.NewFromRawBytes(strings.NewReader(in.Proof), true)
	require.NoError(t, err)
	require.Len(t, proof.Inputs, 2, "the message, then the coin")
	require.Equal(t, r.coin.Outpoint, proof.UnsignedTx.TxIn[1].PreviousOutPoint.String())
	require.Equal(t, in.Tx.Inputs[0].TaprootLeafScript, proof.Inputs[1].TaprootLeafScript)
	require.Equal(
		t, in.Tx.Inputs[0].TaprootLeafScript, proof.Inputs[0].TaprootLeafScript,
		"the message shares input 1's script",
	)

	own, err := arkade.FindEmulatorPacket(in.Tx.UnsignedTx)
	require.NoError(t, err)
	shifted, err := arkade.FindEmulatorPacket(proof.UnsignedTx)
	require.NoError(t, err)
	require.Equal(t, own[0].Vin+1, shifted[0].Vin, "every input reference moves for the message")
	require.Equal(t, own[0].Script, shifted[0].Script)
}

func TestBuildIntentDeductsTheIntentFeeAndRefusesAboveMaxFee(t *testing.T) {
	r := newRenewal(t, 1000)
	fee := template.Fee{Dust: 330, Intent: arkfee.Config{IntentOffchainInputProgram: "500.0"}}
	in, err := BuildIntent(
		r.inst, r.inputs, []delegation.Coin{r.coin}, r.txs, fee, r.cosigner.PubKey(),
	)
	require.NoError(t, err)
	require.Equal(t, int64(9_500), in.Outputs[0].Value)

	capped := newRenewal(t, 100)
	_, err = BuildIntent(
		capped.inst, capped.inputs, []delegation.Coin{capped.coin}, capped.txs, fee,
		capped.cosigner.PubKey(),
	)
	require.ErrorIs(t, err, template.ErrIneligible)
	require.ErrorContains(t, err, "exceeds the cap 100")
	free := newRenewal(t, 0)
	_, err = BuildIntent(
		free.inst, free.inputs, []delegation.Coin{free.coin}, free.txs, fee, free.cosigner.PubKey(),
	)
	require.ErrorContains(t, err, "exceeds the cap 0")
	_, err = BuildIntent(
		free.inst, free.inputs, []delegation.Coin{free.coin}, free.txs, template.Fee{Dust: 330},
		free.cosigner.PubKey(),
	)
	require.NoError(t, err, "no fee, no cap to exceed")
}

func TestBuildIntentRefusesCoinNotMatchingItsFundingTxOrTree(t *testing.T) {
	r := newRenewal(t, 1000)
	_, err := BuildIntent(
		r.inst, r.inputs, []delegation.Coin{r.coin}, nil, template.Fee{Dust: 330},
		r.cosigner.PubKey(),
	)
	require.ErrorContains(t, err, "missing source output")
	moved := r.coin
	moved.Script = "5120" + strings.Repeat("00", 32)
	_, err = BuildIntent(
		r.inst, r.inputs, []delegation.Coin{moved}, r.txs, template.Fee{Dust: 330},
		r.cosigner.PubKey(),
	)
	require.ErrorContains(t, err, "differs from its source output")
	wrong := r.inputs[0]
	wrong.Tapscripts = nil
	_, err = BuildIntent(
		r.inst, []delegation.Input{wrong}, []delegation.Coin{r.coin}, r.txs,
		template.Fee{Dust: 330}, r.cosigner.PubKey(),
	)
	require.ErrorContains(t, err, "not in the registered tree")
}

func TestIntentForfeitSpendsTheVtxoIntoItsBatchConnector(t *testing.T) {
	r := newRenewal(t, 1000)
	in, err := BuildIntent(
		r.inst, r.inputs, []delegation.Coin{r.coin}, r.txs, template.Fee{Dust: 330},
		r.cosigner.PubKey(),
	)
	require.NoError(t, err)
	b := newBatch(t, []*wire.TxOut{in.Outputs[0]}, 1)

	forfeits, err := in.Forfeits(b.ConnectorTree.Leaves(), b.forfeitScript)
	require.NoError(t, err)
	require.Len(t, forfeits, 1)
	forfeit, err := psbt.NewFromRawBytes(strings.NewReader(forfeits[0]), true)
	require.NoError(t, err)
	require.Equal(t, r.coin.Outpoint, forfeit.UnsignedTx.TxIn[0].PreviousOutPoint.String())
	connector := b.ConnectorTree.Leaves()[0].UnsignedTx
	require.Equal(t, connector.TxHash(), forfeit.UnsignedTx.TxIn[1].PreviousOutPoint.Hash)
	require.Equal(t, b.forfeitScript, forfeit.UnsignedTx.TxOut[0].PkScript)
	require.Equal(t, in.Tx.Inputs[0].TaprootLeafScript, forfeit.Inputs[0].TaprootLeafScript)
	require.Empty(t, forfeit.Inputs[1].TaprootLeafScript)

	_, err = in.Forfeits(nil, b.forfeitScript)
	require.ErrorContains(t, err, "got 0 connectors for 1 vtxos")
	_, err = in.Forfeits([]*psbt.Packet{nil}, b.forfeitScript)
	require.ErrorContains(t, err, "connector 0 is missing")
	anchorOnly := &psbt.Packet{UnsignedTx: wire.NewMsgTx(3)}
	_, err = in.Forfeits([]*psbt.Packet{anchorOnly}, b.forfeitScript)
	require.ErrorContains(t, err, "connector not found")
}

func TestBoardingIntentSpendsOnchainInputAndNeedsNoForfeit(t *testing.T) {
	b := newBoarding(t)
	in, err := BuildIntent(
		b.inst, b.inputs, []delegation.Coin{b.coin}, b.txs, template.Fee{Dust: 330},
		b.cosigner.PubKey(),
	)
	require.NoError(t, err)
	require.Equal(t, []bool{true}, in.Boarding)
	require.Zero(t, in.Vtxos())
	require.Equal(t, int64(20_000), in.Outputs[0].Value)

	forfeits, err := in.Forfeits(nil, nil)
	require.NoError(t, err)
	require.Empty(t, forfeits, "a boarding input has no forfeit")
}

func TestForfeitsSkipTheBoardingInputs(t *testing.T) {
	r := newRenewal(t, 1000)
	in, err := BuildIntent(
		r.inst, r.inputs, []delegation.Coin{r.coin}, r.txs, template.Fee{Dust: 330},
		r.cosigner.PubKey(),
	)
	require.NoError(t, err)
	b := newBatch(t, []*wire.TxOut{in.Outputs[0]}, 1)

	mixed := *in
	unsigned := wire.NewMsgTx(3)
	unsigned.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 9}})
	unsigned.AddTxIn(in.Tx.UnsignedTx.TxIn[0])
	tx, err := psbt.NewFromUnsignedTx(unsigned)
	require.NoError(t, err)
	tx.Inputs[1] = in.Tx.Inputs[0]
	mixed.Tx, mixed.Boarding = tx, []bool{true, false}
	require.Equal(t, 1, mixed.Vtxos())

	forfeits, err := mixed.Forfeits(b.ConnectorTree.Leaves(), b.forfeitScript)
	require.NoError(t, err)
	require.Len(t, forfeits, 1)
	forfeit, err := psbt.NewFromRawBytes(strings.NewReader(forfeits[0]), true)
	require.NoError(t, err)
	require.Equal(
		t, r.coin.Outpoint, forfeit.UnsignedTx.TxIn[0].PreviousOutPoint.String(),
		"the vtxo, not the boarding input",
	)
	_, err = mixed.Forfeits(nil, b.forfeitScript)
	require.ErrorContains(t, err, "got 0 connectors for 1 vtxos")
}

func TestForfeitsSkipTheSweptInputs(t *testing.T) {
	r := newRenewal(t, 1000)
	in, err := BuildIntent(
		r.inst, r.inputs, []delegation.Coin{r.coin}, r.txs, template.Fee{Dust: 330},
		r.cosigner.PubKey(),
	)
	require.NoError(t, err)
	require.Equal(t, 1, in.Forfeited())

	in.Swept = []bool{true}
	require.Equal(t, 1, in.Vtxos(), "a swept vtxo is still a vtxo")
	require.Zero(t, in.Forfeited())
	forfeits, err := in.Forfeits(nil, nil)
	require.NoError(t, err)
	require.Empty(t, forfeits, "arkd recovers a swept vtxo without a forfeit")
}

func TestAssetPacketInputsShiftWithTheIntentMessageInput(t *testing.T) {
	id := asset.AssetId{}
	id.Txid[0] = 7
	group, err := asset.NewAssetGroup(
		&id, nil, []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 5}},
		[]asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 5}}, nil,
	)
	require.NoError(t, err)
	packet, err := asset.NewPacket([]asset.AssetGroup{*group})
	require.NoError(t, err)
	shifted, err := shiftInputs(extension.Extension{packet}, 1)
	require.NoError(t, err)
	require.Equal(t, uint16(1), shifted.GetAssetPacket()[0].Inputs[0].Vin)
	require.Equal(t, uint16(0), shifted.GetAssetPacket()[0].Outputs[0].Vout, "outputs stay")
}

// renewal is a renewal watch with a coin funded by a real transaction.
type renewal struct {
	inst                       *template.Instance
	inputs                     []delegation.Input
	coin                       delegation.Coin
	txs                        map[string]*wire.MsgTx
	server, emulator, cosigner *btcec.PrivateKey
}

func newRenewal(t *testing.T, maxFee int64) renewal {
	t.Helper()
	server, emulator, cosigner, owner := testKey(1), testKey(2), testKey(3), testKey(4)
	inst := instantiateWith(t, templates.Templates["renew.json"], map[string][]byte{
		"owner": owner.PubKey().SerializeCompressed(), "exit_delay": scriptNum(1<<22 | 1),
		"renewal_window": scriptNum(1024), "max_fee": scriptNum(maxFee),
	}, template.Keys{Server: server.PubKey(), Emulator: emulator.PubKey(), Cosigner: cosigner.PubKey()})
	source := wire.NewMsgTx(3)
	source.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})
	source.AddTxOut(wire.NewTxOut(10_000, inst.PkScript(0)))
	pkScript := hex.EncodeToString(inst.PkScript(0))
	return renewal{
		inst: inst,
		inputs: []delegation.Input{
			{Name: "funds", Script: pkScript, Tapscripts: inst.Tapscripts(0)},
		},
		coin: delegation.Coin{
			Outpoint: source.TxHash().
				String() +
				":0",
			DelegationID: 1,
			Script:       pkScript,
			Amount:       10_000,
			ExpiresAt: now.Add(
				500e9,
			),
			CreatedAt: now.Add(-3600e9),
			Due:       now,
			Status:    delegation.Present,
		},
		txs:      map[string]*wire.MsgTx{source.TxHash().String(): source},
		server:   server,
		emulator: emulator,
		cosigner: cosigner,
	}
}

// boarding is a boarding watch with a boarding input funded by a real transaction.
type boarding struct {
	inst                       *template.Instance
	inputs                     []delegation.Input
	coin                       delegation.Coin
	txs                        map[string]*wire.MsgTx
	server, emulator, cosigner *btcec.PrivateKey
}

func newBoarding(t *testing.T) boarding {
	t.Helper()
	server, emulator, cosigner, owner := testKey(1), testKey(2), testKey(3), testKey(4)
	inst := instantiateWith(t, templates.Templates["board.json"], map[string][]byte{
		"owner": owner.PubKey().
			SerializeCompressed(),
		"boarding_exit_delay": scriptNum(1<<22 | 2),
		"exit_delay":          scriptNum(1<<22 | 1),
		"renewal_window":      scriptNum(1024),
		"max_fee":             scriptNum(1000),
	}, template.Keys{Server: server.PubKey(), Emulator: emulator.PubKey(), Cosigner: cosigner.PubKey()})
	boardingTx := wire.NewMsgTx(3)
	boardingTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})
	boardingTx.AddTxOut(wire.NewTxOut(20_000, inst.PkScript(0)))
	pkScript := hex.EncodeToString(inst.PkScript(0))
	return boarding{
		inst: inst,
		inputs: []delegation.Input{
			{Name: "deposit", Onchain: true, Script: pkScript, Tapscripts: inst.Tapscripts(0)},
		},
		coin: delegation.Coin{
			Outpoint: boardingTx.TxHash().
				String() +
				":0",
			DelegationID:  1,
			Script:        pkScript,
			Amount:        20_000,
			Onchain:       true,
			Height:        100,
			Confirmations: 1,
			Due:           now,
			Status:        delegation.Present,
		},
		txs:      map[string]*wire.MsgTx{boardingTx.TxHash().String(): boardingTx},
		server:   server,
		emulator: emulator,
		cosigner: cosigner,
	}
}

// testBatch is a commitment tx and the connector tree of a batch.
type testBatch struct {
	CommitmentTx  string
	ConnectorTree *tree.TxTree
	forfeitScript []byte
}

func newBatch(t *testing.T, outputs []*wire.TxOut, connectors int) testBatch {
	t.Helper()
	forfeit := testKey(5).PubKey()
	forfeitScript, err := txscript.PayToTaprootScript(forfeit)
	require.NoError(t, err)
	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1024}
	sweepRoot := sweepTapTreeRoot(t, forfeit, expiry)
	cosigner := hex.EncodeToString(testKey(3).PubKey().SerializeCompressed())

	leaves := make([]tree.Leaf, len(outputs))
	for i, out := range outputs {
		leaves[i] = tree.Leaf{
			Outputs: []tree.LeafOutput{
				{Amount: uint64(out.Value), Script: hex.EncodeToString(out.PkScript)},
			},
			CosignersPublicKeys: []string{cosigner},
		}
	}
	connectorLeaves := make([]tree.Leaf, connectors)
	for i := range connectorLeaves {
		connectorLeaves[i] = tree.Leaf{
			Outputs: []tree.LeafOutput{
				{Amount: 330, Script: hex.EncodeToString(forfeitScript)},
			},
			CosignersPublicKeys: []string{hex.EncodeToString(forfeit.SerializeCompressed())},
		}
	}
	batchScript, batchAmount, err := tree.BuildBatchOutput(leaves, sweepRoot)
	require.NoError(t, err)
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 7}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(batchAmount, batchScript))
	connectorAmount := int64(0)
	if connectors > 0 {
		var connectorScript []byte
		connectorScript, connectorAmount, err = tree.BuildConnectorOutput(connectorLeaves)
		require.NoError(t, err)
		tx.AddTxOut(wire.NewTxOut(connectorAmount, connectorScript))
	}
	commitment, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	for i := range commitment.Inputs {
		commitment.Inputs[i].WitnessUtxo = wire.NewTxOut(batchAmount+connectorAmount, forfeitScript)
	}

	txid := tx.TxHash()
	b := testBatch{CommitmentTx: mustEncode(t, commitment), forfeitScript: forfeitScript}
	if connectors > 0 {
		b.ConnectorTree, err = tree.BuildConnectorTree(
			&wire.OutPoint{Hash: txid, Index: 1}, connectorLeaves,
		)
		require.NoError(t, err)
	}
	return b
}

func mustEncode(t *testing.T, p *psbt.Packet) string {
	t.Helper()
	out, err := p.B64Encode()
	require.NoError(t, err)
	return out
}

func sweepTapTreeRoot(
	t *testing.T, forfeitKey *btcec.PublicKey, expiry arklib.RelativeLocktime,
) []byte {
	t.Helper()
	sweep, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{forfeitKey}},
		Locktime:        expiry,
	}).Script()
	require.NoError(t, err)
	root := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(sweep)).RootNode.TapHash()
	return root.CloneBytes()
}

func instantiateWith(
	t *testing.T, doc []byte, variables map[string][]byte, keys template.Keys,
) *template.Instance {
	t.Helper()
	tmpl, err := template.Parse(doc, artifactDocs())
	require.NoError(t, err)
	inst, err := tmpl.Instantiate(template.Context{Keys: keys, Variables: variables})
	require.NoError(t, err)
	return inst
}

func artifactDocs() map[string][]byte {
	docs := map[string][]byte{}
	for _, a := range templates.Artifacts {
		if parsed, err := template.ParseArtifact(a); err == nil {
			docs[parsed.ID] = a
		}
	}
	return docs
}

func scriptNum(n int64) []byte {
	b, _ := arkade.BigNumFromInt64(n).Bytes()
	return b
}

func testKey(scalar uint32) *btcec.PrivateKey {
	var s btcec.ModNScalar
	s.SetInt(scalar)
	return btcec.PrivKeyFromScalar(&s)
}
