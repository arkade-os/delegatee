package application

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// signDelegateInputs does not judge the leaf: call it for operator-trusted templates only.
func signDelegateInputs(ptx *psbt.Packet, key *btcec.PrivateKey, prevouts []*wire.TxOut) (int, error) {
	if len(prevouts) != len(ptx.Inputs) || len(prevouts) != len(ptx.UnsignedTx.TxIn) {
		return 0, fmt.Errorf("got %d prevouts for %d inputs", len(prevouts), len(ptx.Inputs))
	}
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for i, prevout := range prevouts {
		if prevout == nil {
			return 0, fmt.Errorf("missing prevout for input %d", i)
		}
		fetcher.AddPrevOut(ptx.UnsignedTx.TxIn[i].PreviousOutPoint, prevout)
	}
	sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)
	xOnly := schnorr.SerializePubKey(key.PubKey())

	signed := 0
	for i := range ptx.Inputs {
		in := &ptx.Inputs[i]
		switch len(in.TaprootLeafScript) {
		case 0:
			continue
		case 1:
		default:
			return signed, fmt.Errorf("input %d has %d tap leaves, expected one", i, len(in.TaprootLeafScript))
		}
		leaf := in.TaprootLeafScript[0]
		holds, err := scriptPushes(leaf.Script, xOnly)
		if err != nil {
			return signed, fmt.Errorf("input %d leaf: %w", i, err)
		}
		if !holds {
			continue
		}
		tapLeaf := txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script)
		leafHash := tapLeaf.TapHash()
		if hasTapscriptSig(in.TaprootScriptSpendSig, xOnly, leafHash[:]) {
			continue
		}
		sighash, err := txscript.CalcTapscriptSignaturehash(
			sigHashes, txscript.SigHashDefault, ptx.UnsignedTx, i, fetcher, tapLeaf,
		)
		if err != nil {
			return signed, fmt.Errorf("input %d sighash: %w", i, err)
		}
		sig, err := schnorr.Sign(key, sighash)
		if err != nil {
			return signed, fmt.Errorf("input %d sign: %w", i, err)
		}
		in.TaprootScriptSpendSig = append(in.TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: xOnly,
			LeafHash:    leafHash[:],
			Signature:   sig.Serialize(),
			SigHash:     txscript.SigHashDefault,
		})
		signed++
	}
	return signed, nil
}

func witnessPrevouts(ptx *psbt.Packet) []*wire.TxOut {
	prevouts := make([]*wire.TxOut, len(ptx.Inputs))
	for i, in := range ptx.Inputs {
		prevouts[i] = in.WitnessUtxo
	}
	return prevouts
}

// scriptPushes reports whether script pushes data exactly.
func scriptPushes(script, data []byte) (bool, error) {
	tok := txscript.MakeScriptTokenizer(0, script)
	for tok.Next() {
		if bytes.Equal(tok.Data(), data) {
			return true, nil
		}
	}
	return false, tok.Err()
}

func hasTapscriptSig(sigs []*psbt.TaprootScriptSpendSig, xOnly, leafHash []byte) bool {
	for _, s := range sigs {
		if bytes.Equal(s.XOnlyPubKey, xOnly) && bytes.Equal(s.LeafHash, leafHash) {
			return true
		}
	}
	return false
}
