package application

import (
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestSignDelegateIntentProofVerifies(t *testing.T) {
	server, delegate, owner := signingKeys(t)
	coin := newSigningCoin(t, &script.MultisigClosure{PubKeys: []*btcec.PublicKey{server.PubKey(), delegate.PubKey()}}, owner.PubKey())
	const message = "delegate signing test"
	skip := []*btcec.PublicKey{server.PubKey()}

	unsigned := newSigningProof(t, coin, message)
	b64, err := unsigned.B64Encode()
	require.NoError(t, err)
	require.Error(t, intent.Verify(b64, message, skip), "an unsigned proof must not verify")

	ptx := newSigningProof(t, coin, message)
	n, err := signDelegateInputs(ptx, delegate, witnessPrevouts(ptx))
	require.NoError(t, err)
	require.Equal(t, 2, n, "the message input and the coin share the delegate leaf")
	b64, err = ptx.B64Encode()
	require.NoError(t, err)
	require.NoError(t, intent.Verify(b64, message, skip))
}

func TestSignDelegateSkipsCovenantLeaf(t *testing.T) {
	server, delegate, owner := signingKeys(t)
	emulator, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	// the arkade script names the delegate key, the leaf itself does not
	arkadeScript, err := txscript.NewScriptBuilder().AddData(delegate.PubKey().SerializeCompressed()).AddOp(txscript.OP_DROP).Script()
	require.NoError(t, err)
	tweaked := arkade.ComputeArkadeScriptPublicKey(emulator.PubKey(), arkade.ArkadeScriptHash(arkadeScript))
	coin := newSigningCoin(t, &script.MultisigClosure{PubKeys: []*btcec.PublicKey{server.PubKey(), tweaked}}, owner.PubKey())

	ptx := newSigningProof(t, coin, "covenant")
	n, err := signDelegateInputs(ptx, delegate, witnessPrevouts(ptx))
	require.NoError(t, err)
	require.Zero(t, n)
	for _, in := range ptx.Inputs {
		require.Empty(t, in.TaprootScriptSpendSig)
	}
}

func TestSignDelegateForfeit(t *testing.T) {
	forfeit, prevouts, delegate := newSigningForfeit(t)
	n, err := signDelegateInputs(forfeit, delegate, prevouts)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Empty(t, forfeit.Inputs[1].TaprootScriptSpendSig, "the connector has no tap leaf")
	require.Len(t, forfeit.Inputs[0].TaprootScriptSpendSig, 1)

	got := forfeit.Inputs[0].TaprootScriptSpendSig[0]
	leaf := forfeit.Inputs[0].TaprootLeafScript[0]
	tapLeaf := txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script)
	leafHash := tapLeaf.TapHash()
	require.Equal(t, schnorr.SerializePubKey(delegate.PubKey()), got.XOnlyPubKey)
	require.Equal(t, leafHash[:], got.LeafHash)
	require.Equal(t, txscript.SigHashDefault, got.SigHash)

	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for i, in := range forfeit.UnsignedTx.TxIn {
		fetcher.AddPrevOut(in.PreviousOutPoint, prevouts[i])
	}
	sighash, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(forfeit.UnsignedTx, fetcher), txscript.SigHashDefault,
		forfeit.UnsignedTx, 0, fetcher, tapLeaf,
	)
	require.NoError(t, err)
	sig, err := schnorr.ParseSignature(got.Signature)
	require.NoError(t, err)
	require.True(t, sig.Verify(sighash, delegate.PubKey()))
}

func TestSignDelegateIsIdempotent(t *testing.T) {
	forfeit, prevouts, delegate := newSigningForfeit(t)
	_, err := signDelegateInputs(forfeit, delegate, prevouts)
	require.NoError(t, err)
	n, err := signDelegateInputs(forfeit, delegate, prevouts)
	require.NoError(t, err)
	require.Zero(t, n)
	require.Len(t, forfeit.Inputs[0].TaprootScriptSpendSig, 1)
}

func TestSignDelegateRejectsBadPrevouts(t *testing.T) {
	forfeit, prevouts, delegate := newSigningForfeit(t)
	_, err := signDelegateInputs(forfeit, delegate, prevouts[:1])
	require.Error(t, err)
	_, err = signDelegateInputs(forfeit, delegate, []*wire.TxOut{prevouts[0], nil})
	require.Error(t, err)
	require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
}

func TestSignDelegateReportsPartialSigning(t *testing.T) {
	forfeit, prevouts, delegate := newSigningForfeit(t)
	leaf := forfeit.Inputs[0].TaprootLeafScript[0]
	forfeit.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{leaf, leaf}
	n, err := signDelegateInputs(forfeit, delegate, prevouts)
	require.Error(t, err)
	require.Equal(t, 1, n)
	require.Len(t, forfeit.Inputs[0].TaprootScriptSpendSig, 1)
}

// signingCoin spends the first leaf of a real two-leaf tree.
type signingCoin struct {
	outpoint   wire.OutPoint
	prevout    *wire.TxOut
	leaf       *psbt.TaprootTapLeafScript
	tapscripts []string
}

func newSigningCoin(t *testing.T, spend script.Closure, owner *btcec.PublicKey) signingCoin {
	t.Helper()
	vtxoScript := &script.TapscriptsVtxoScript{Closures: []script.Closure{
		spend,
		&script.CSVMultisigClosure{
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{owner}},
			Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
		},
	}}
	tapscripts, err := vtxoScript.Encode()
	require.NoError(t, err)
	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)
	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)
	leafScript, err := spend.Script()
	require.NoError(t, err)
	proof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(leafScript).TapHash())
	require.NoError(t, err)
	return signingCoin{
		outpoint:   wire.OutPoint{Hash: chainhash.DoubleHashH([]byte("vtxo")), Index: 1},
		prevout:    &wire.TxOut{Value: 10_000, PkScript: pkScript},
		leaf:       &psbt.TaprootTapLeafScript{ControlBlock: proof.ControlBlock, Script: proof.Script, LeafVersion: txscript.BaseLeafVersion},
		tapscripts: tapscripts,
	}
}

func signingKeys(t *testing.T) (server, delegate, owner *btcec.PrivateKey) {
	t.Helper()
	var err error
	server, err = btcec.NewPrivateKey()
	require.NoError(t, err)
	delegate, err = btcec.NewPrivateKey()
	require.NoError(t, err)
	owner, err = btcec.NewPrivateKey()
	require.NoError(t, err)
	return
}

// newSigningProof builds a bip322 proof the way buildIntent does.
func newSigningProof(t *testing.T, coin signingCoin, message string) *psbt.Packet {
	t.Helper()
	proof, err := intent.New(message, []intent.Input{{OutPoint: &coin.outpoint, WitnessUtxo: coin.prevout}},
		[]*wire.TxOut{{Value: coin.prevout.Value, PkScript: coin.prevout.PkScript}})
	require.NoError(t, err)
	ptx := &proof.Packet
	for i := range ptx.Inputs {
		ptx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{coin.leaf}
		require.NoError(t, txutils.SetArkPsbtField(ptx, i, txutils.VtxoTaprootTreeField, txutils.TapTree(coin.tapscripts)))
	}
	return ptx
}

func newSigningForfeit(t *testing.T) (*psbt.Packet, []*wire.TxOut, *btcec.PrivateKey) {
	t.Helper()
	server, delegate, owner := signingKeys(t)
	coin := newSigningCoin(t, &script.MultisigClosure{PubKeys: []*btcec.PublicKey{server.PubKey(), delegate.PubKey()}}, owner.PubKey())
	connectorScript, err := script.P2TRScript(server.PubKey())
	require.NoError(t, err)
	connector := &wire.TxOut{Value: 330, PkScript: connectorScript}
	connectorOutpoint := &wire.OutPoint{Hash: chainhash.DoubleHashH([]byte("connector")), Index: 0}
	prevouts := []*wire.TxOut{coin.prevout, connector}
	forfeit, err := tree.BuildForfeitTx(
		[]*wire.OutPoint{&coin.outpoint, connectorOutpoint},
		[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
		prevouts, connectorScript, 0,
	)
	require.NoError(t, err)
	forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{coin.leaf}
	return forfeit, prevouts, delegate
}
