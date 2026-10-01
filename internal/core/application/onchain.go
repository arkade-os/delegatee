package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

func (s *service) runOnchain(ctx context.Context, c *cosigner, inputs []renewalInput, fees arkfee.Config) (string, settlement, error) {
	maxRate := s.maxOnchainFeeRate
	if math.IsNaN(maxRate) || math.IsInf(maxRate, 0) || maxRate <= 0 {
		return "", settlement{}, errors.New("onchain template requires a finite positive fee-rate cap")
	}
	for _, in := range inputs {
		if !in.onchain {
			return "", settlement{}, errors.New("onchain executor received offchain input")
		}
	}
	ptx, coins, err := s.logicalTx(ctx, inputs, fees)
	if err != nil {
		return "", settlement{}, err
	}
	var total uint64
	for _, coin := range coins {
		if coin.Amount > math.MaxInt64-total {
			return "", settlement{}, errors.New("input amount overflow")
		}
		total += coin.Amount
	}
	var outputs uint64
	for _, out := range ptx.UnsignedTx.TxOut {
		if uint64(out.Value) > total-outputs {
			return "", settlement{}, errors.New("outputs exceed inputs")
		}
		outputs += uint64(out.Value)
	}
	fee := total - outputs
	if feeCap, _ := inputs[0].watched.instance.FeeCap(); fee > feeCap {
		return "", settlement{}, errors.New("onchain fee exceeds template cap")
	}
	if err = s.signForTemplate(ctx, inputs[0].watched.delegation.TemplateID, c, ptx); err != nil {
		return "", settlement{}, err
	}
	original := ptx.UnsignedTx.TxHash()
	if ext, e := extension.NewExtensionFromTx(ptx.UnsignedTx); e == nil && ext.GetPacketByType(arkade.PacketType) != nil {
		raw, e := ptx.B64Encode()
		if e != nil {
			return "", settlement{}, e
		}
		signed, e := s.emulator.SubmitOnchainTx(ctx, raw)
		if e != nil {
			return "", settlement{}, refusal(ctx, "emulator", e)
		}
		ptx, e = psbt.NewFromRawBytes(strings.NewReader(signed), true)
		if e != nil {
			return "", settlement{}, e
		}
		if ptx.UnsignedTx.TxHash() != original {
			return "", settlement{}, errors.New("emulator changed transaction")
		}
	}
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for i, coin := range coins {
		fetcher.AddPrevOut(coin.Outpoint, &wire.TxOut{Value: int64(coin.Amount), PkScript: coin.Script})
		if len(ptx.Inputs[i].FinalScriptWitness) == 0 {
			if err = script.FinalizeVtxoScript(ptx, i); err != nil {
				return "", settlement{}, err
			}
		}
	}
	tx, err := psbt.Extract(ptx)
	if err != nil {
		return "", settlement{}, err
	}
	// every witness runs locally before the broadcast
	hashes := txscript.NewTxSigHashes(tx, fetcher)
	for i, coin := range coins {
		vm, e := txscript.NewEngine(coin.Script, tx, i, txscript.StandardVerifyFlags, nil, hashes, int64(coin.Amount), fetcher)
		if e != nil {
			return "", settlement{}, e
		}
		if e = vm.Execute(); e != nil {
			return "", settlement{}, e
		}
	}
	weight := tx.SerializeSizeStripped()*3 + tx.SerializeSize()
	vsize := (weight + 3) / 4
	if float64(fee)/float64(vsize) > maxRate {
		return "", settlement{}, errors.New("onchain fee rate exceeds template cap")
	}
	var buf bytes.Buffer
	if err = tx.Serialize(&buf); err != nil {
		return "", settlement{}, err
	}
	st := owned(inputs, tx, tx.TxHash().String())
	if err := s.keep(ctx, st); err != nil {
		return "", settlement{}, err
	}
	// a failed broadcast keeps st: the coins tell whether the tx was relayed
	txid, err := s.explorer.Broadcast(hex.EncodeToString(buf.Bytes()))
	if err != nil {
		// the reply may be lost after the transaction was relayed
		if _, known := s.explorer.GetTxHex(tx.TxHash().String()); known != nil {
			return "", settlement{}, fmt.Errorf("broadcast: %w", err)
		}
		txid = tx.TxHash().String()
	}
	if txid != tx.TxHash().String() {
		return "", settlement{}, errors.New("broadcast returned a different txid")
	}
	for _, in := range inputs {
		delete(s.onchainCache, in.watched.delegation.Slots[in.coin.Slot].Script)
	}
	return txid, st, nil
}
