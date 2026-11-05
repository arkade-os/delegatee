package execution

import (
	"bytes"
	"strings"
	"testing"

	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/internal/core/domain/execution"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestForEmulator(t *testing.T) {
	source := wire.NewMsgTx(3)
	source.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))
	ark := leafTx(t, testKey(1).PubKey(), wire.OutPoint{Hash: source.TxHash()})
	checkpoint := leafTx(t, testKey(1).PubKey(), wire.OutPoint{Hash: [32]byte{2}})
	txs := []delegation.Tx{rawTx(t, ark), rawTx(t, checkpoint)}

	got, checkpoints, err := forEmulator(txs, []*wire.MsgTx{source})
	require.NoError(t, err)
	require.Len(t, checkpoints, 1)

	plain, err := ark.B64Encode()
	require.NoError(t, err)
	require.NotEqual(t, plain, got, "the ark tx carries the source")
	plainCheckpoint, err := checkpoint.B64Encode()
	require.NoError(t, err)
	require.Equal(t, plainCheckpoint, checkpoints[0])

	_, _, err = forEmulator(nil, nil)
	require.Error(t, err)
	_, _, err = forEmulator([]delegation.Tx{{Raw: []byte("nope")}}, nil)
	require.Error(t, err)
}

func TestSignForfeitsMergesTheEmulator(t *testing.T) {
	server := testKey(1)
	forfeit := leafTx(t, server.PubKey(), wire.OutPoint{Hash: [32]byte{1}})
	forfeits := []string{mustEncode(t, forfeit)}

	serverSigned := leafTx(t, server.PubKey(), wire.OutPoint{Hash: [32]byte{1}})
	signWith(t, serverSigned, server)
	signed, err := signForfeits(forfeits, []string{mustEncode(t, serverSigned)})
	require.NoError(t, err)
	out, err := psbt.NewFromRawBytes(strings.NewReader(signed[0]), true)
	require.NoError(t, err)
	require.Len(t, out.Inputs[0].TaprootScriptSpendSig, 1)

	unsigned, err := signForfeits(forfeits, forfeits)
	require.NoError(t, err)
	require.Equal(t, forfeits, unsigned, "unsigned forfeits pass through")
	_, err = signForfeits(forfeits, []string{"nope"})
	require.Error(t, err)
}

func TestSignCommitmentOfABoardingInput(t *testing.T) {
	server := testKey(1)
	boarding := leafTx(t, server.PubKey(), wire.OutPoint{Hash: [32]byte{1}})
	in := &execution.Intent{Tx: boarding, Boarding: []bool{true}}
	commitment := commitmentOf(t, boarding)

	got, err := boardingCommitment(in, commitment)
	require.NoError(t, err)
	tx, err := psbt.NewFromRawBytes(strings.NewReader(got), true)
	require.NoError(t, err)
	require.Empty(t, tx.Inputs[0].TaprootLeafScript, "arkd's input is not ours to sign")
	require.Equal(t, boarding.Inputs[0].TaprootLeafScript, tx.Inputs[1].TaprootLeafScript)
	require.Equal(t, boarding.Inputs[0].WitnessUtxo, tx.Inputs[1].WitnessUtxo)

	signWith(t, tx, server)
	remote := mustEncode(t, tx)
	for signed, sigs := range map[string]int{remote: 1, "": 0} {
		out, err := signCommitment(in, commitment, signed)
		require.NoError(t, err)
		merged, err := psbt.NewFromRawBytes(strings.NewReader(out), true)
		require.NoError(t, err)
		require.Empty(t, merged.Inputs[0].TaprootScriptSpendSig)
		require.Len(t, merged.Inputs[1].TaprootScriptSpendSig, sigs)
	}

	_, err = signCommitment(in, commitment, "nope")
	require.ErrorContains(t, err, "signed commitment tx")
	_, err = signCommitment(in, "nope", "")
	require.ErrorContains(t, err, "commitment tx")
	other := leafTx(t, server.PubKey(), wire.OutPoint{Hash: [32]byte{9}})
	_, err = boardingCommitment(in, mustEncode(t, other))
	require.ErrorContains(t, err, "omits boarding input")
}

func TestSignCommitmentWithoutBoardingInputs(t *testing.T) {
	vtxo := leafTx(t, testKey(1).PubKey(), wire.OutPoint{Hash: [32]byte{1}})
	in := &execution.Intent{Tx: vtxo, Boarding: []bool{false}}
	out, err := signCommitment(in, commitmentOf(t, vtxo), "")
	require.NoError(t, err)
	require.Empty(t, out, "nothing to sign")
}

func TestMergeAddsSignaturesOnce(t *testing.T) {
	key := testKey(1)
	local := leafTx(t, key.PubKey(), wire.OutPoint{Hash: [32]byte{1}})
	remote := leafTx(t, key.PubKey(), wire.OutPoint{Hash: [32]byte{1}})
	signWith(t, remote, key)
	mergeSignatures(local, remote)
	require.Len(t, local.Inputs[0].TaprootScriptSpendSig, 1)
	mergeSignatures(local, remote)
	require.Len(t, local.Inputs[0].TaprootScriptSpendSig, 1, "merging twice adds nothing")
}

// leafTx spends prev, a one-leaf taproot output whose leaf is <key> OP_CHECKSIG.
func leafTx(t *testing.T, key *btcec.PublicKey, prev wire.OutPoint) *psbt.Packet {
	t.Helper()
	leaf, err := txscript.NewScriptBuilder().AddData(schnorr.SerializePubKey(key)).AddOp(txscript.OP_CHECKSIG).Script()
	require.NoError(t, err)
	tree := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(leaf))
	internal := testKey(9).PubKey()
	root := tree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(internal, root[:])
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)
	control := tree.LeafMerkleProofs[0].ToControlBlock(internal)
	controlBytes, err := control.ToBytes()
	require.NoError(t, err)

	tx, err := psbt.New([]*wire.OutPoint{&prev}, []*wire.TxOut{wire.NewTxOut(900, pkScript)}, 2, 0, []uint32{wire.MaxTxInSequenceNum})
	require.NoError(t, err)
	tx.Inputs[0].WitnessUtxo = wire.NewTxOut(1000, pkScript)
	tx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{ControlBlock: controlBytes, Script: leaf, LeafVersion: txscript.BaseLeafVersion}}
	return tx
}

// commitmentOf is a commitment transaction of arkd's input and the first input of spender.
func commitmentOf(t *testing.T, spender *psbt.Packet) string {
	t.Helper()
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 7}})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: spender.UnsignedTx.TxIn[0].PreviousOutPoint})
	tx.AddTxOut(wire.NewTxOut(30_000, []byte{0x51}))
	commitment, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	commitment.Inputs[0].WitnessUtxo = wire.NewTxOut(10_000, []byte{0x51})
	commitment.Inputs[0].TaprootLeafScript = spender.Inputs[0].TaprootLeafScript
	return mustEncode(t, commitment)
}

func rawTx(t *testing.T, p *psbt.Packet) delegation.Tx {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, p.Serialize(&buf))
	return delegation.Tx{Raw: buf.Bytes(), Txid: p.UnsignedTx.TxHash().String()}
}

func mustEncode(t *testing.T, p *psbt.Packet) string {
	t.Helper()
	out, err := p.B64Encode()
	require.NoError(t, err)
	return out
}

func testKey(scalar uint32) *btcec.PrivateKey {
	var s btcec.ModNScalar
	s.SetInt(scalar)
	return btcec.PrivKeyFromScalar(&s)
}

// signWith adds key's signature to every input whose leaf pushes its x-only key.
func signWith(t *testing.T, tx *psbt.Packet, key *btcec.PrivateKey) {
	t.Helper()
	prevouts := map[wire.OutPoint]*wire.TxOut{}
	for i, in := range tx.Inputs {
		prevouts[tx.UnsignedTx.TxIn[i].PreviousOutPoint] = in.WitnessUtxo
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	hashes := txscript.NewTxSigHashes(tx.UnsignedTx, fetcher)
	xOnly := schnorr.SerializePubKey(key.PubKey())
	for i := range tx.Inputs {
		in := &tx.Inputs[i]
		if len(in.TaprootLeafScript) == 0 || !bytes.Contains(in.TaprootLeafScript[0].Script, xOnly) {
			continue
		}
		leaf := txscript.NewBaseTapLeaf(in.TaprootLeafScript[0].Script)
		sighash, err := txscript.CalcTapscriptSignaturehash(hashes, txscript.SigHashDefault, tx.UnsignedTx, i, fetcher, leaf)
		require.NoError(t, err)
		sig, err := schnorr.Sign(key, sighash)
		require.NoError(t, err)
		hash := leaf.TapHash()
		in.TaprootScriptSpendSig = append(in.TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: xOnly, LeafHash: hash[:], Signature: sig.Serialize(), SigHash: txscript.SigHashDefault,
		})
	}
}
