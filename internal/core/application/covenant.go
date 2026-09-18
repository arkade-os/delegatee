package application

import (
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// DefaultRenewalWindow applies when a request leaves the window unset.
const DefaultRenewalWindow = 1024

// The renewal covenant and its rules are hardwired: the four functions below
// are everything specific to it, the batch plumbing in renewal.go is generic.
//
// TODO(templates): users will describe how their contract may be spent with a
// template passed at registration. These functions are what a template
// replaces: the covenant (buildArkadeScript), when to act (dueAt) and what the
// intent pays (renewalOutput, with input i paid by output i-1 today).

// bounds on what a request may bake into a covenant: beyond them the numbers
// stop meaning anything (and a huge window overflows time.Duration)
const (
	maxRenewalWindow = 366 * 24 * 60 * 60 // seconds
	maxMaxFee        = 1_000_000          // sats
)

func validateParams(p domain.Params) error {
	if p.RenewalWindow <= 0 || p.RenewalWindow > maxRenewalWindow {
		return fmt.Errorf("%w: renewal window must be between 1 and %d seconds", ErrInvalidScript, maxRenewalWindow)
	}
	if p.MaxFee < 0 || p.MaxFee > maxMaxFee {
		return fmt.Errorf("%w: max fee must be between 0 and %d sats", ErrInvalidScript, maxMaxFee)
	}
	return nil
}

// dueAt is when a vtxo must be renewed: the start of its renewal window. A delegation that may pay fees
// waits at least half the vtxo's life: a window longer than the life would
// otherwise renew, and pay, in every round.
func dueAt(v types.Vtxo, p domain.Params) time.Time {
	window := time.Duration(p.RenewalWindow) * time.Second
	if life := v.ExpiresAt.Sub(v.CreatedAt); p.MaxFee > 0 && life > 0 {
		window = min(window, life/2)
	}
	return v.ExpiresAt.Add(-window)
}

// renewalOutput is what the intent creates for the vtxo once arkd's fee for
// it is paid, or an error when the covenant would not allow it.
func renewalOutput(v types.Vtxo, pkScript []byte, p domain.Params, fee int64) (*wire.TxOut, error) {
	// the amount comes from the indexer: keep it a valid bitcoin amount
	if v.Amount > btcutil.MaxSatoshi {
		return nil, fmt.Errorf("vtxo amount %d is not a valid amount", v.Amount)
	}
	if fee < 0 {
		return nil, fmt.Errorf("negative intent fee %d", fee)
	}
	if fee > p.MaxFee {
		return nil, fmt.Errorf("intent fee %d exceeds the delegation max fee %d", fee, p.MaxFee)
	}
	if fee >= int64(v.Amount) {
		return nil, fmt.Errorf("intent fee %d is not covered by the vtxo amount %d", fee, v.Amount)
	}
	return &wire.TxOut{Value: int64(v.Amount) - fee, PkScript: pkScript}, nil
}

// buildArkadeScript is the renewal covenant: a register intent cosigned by this
// delegate only, within RenewalWindow seconds of expiry, output i-1
// preserving script and assets of input i and its value minus at most MaxFee.
//
//	OP_PUSHEXPIRY <window> OP_SUB OP_CHECKTIMEVERIFY
//	"type" OP_INSPECTINTENTMESSAGE OP_VERIFY "register" OP_EQUALVERIFY
//	"onchain_output_indexes" OP_INSPECTINTENTMESSAGE OP_VERIFY "[]" OP_EQUALVERIFY
//	"cosigners_public_keys.0" OP_INSPECTINTENTMESSAGE OP_VERIFY <delegate> OP_EQUALVERIFY
//	"cosigners_public_keys.1" OP_INSPECTINTENTMESSAGE OP_NOT OP_VERIFY OP_DROP
//
// then, when MaxFee is 0:
//
//	OP_PUSHCURRENTINPUTINDEX OP_1SUB <script|value|assets> 0 OP_TUNNEL
//
// otherwise:
//
//	OP_PUSHCURRENTINPUTINDEX OP_1SUB OP_INSPECTOUTPUTVALUE <max_fee> OP_ADD
//	OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTVALUE OP_GREATERTHANOREQUAL OP_VERIFY
//	OP_PUSHCURRENTINPUTINDEX OP_1SUB <script|assets> 0 OP_TUNNEL
func buildArkadeScript(delegatePubKeyHex string, p domain.Params) ([]byte, error) {
	b := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHEXPIRY).
		AddInt64(p.RenewalWindow).
		AddOp(arkade.OP_SUB).
		AddOp(arkade.OP_CHECKTIMEVERIFY).
		AddData([]byte("type")).
		AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddOp(txscript.OP_VERIFY).
		AddData([]byte(intent.IntentMessageTypeRegister)).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData([]byte("onchain_output_indexes")).
		AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddOp(txscript.OP_VERIFY).
		AddData([]byte("[]")).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData([]byte("cosigners_public_keys.0")).
		AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddOp(txscript.OP_VERIFY).
		AddData([]byte(delegatePubKeyHex)).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData([]byte("cosigners_public_keys.1")).
		AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddOp(txscript.OP_NOT).
		AddOp(txscript.OP_VERIFY).
		AddOp(txscript.OP_DROP)

	tunnel := int64(arkade.TunnelScriptPubKey | arkade.TunnelValue | arkade.TunnelAssets)
	if p.MaxFee > 0 {
		tunnel = arkade.TunnelScriptPubKey | arkade.TunnelAssets
		b.AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
			AddOp(arkade.OP_1SUB).
			AddOp(arkade.OP_INSPECTOUTPUTVALUE).
			AddInt64(p.MaxFee).
			AddOp(arkade.OP_ADD).
			AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
			AddOp(arkade.OP_INSPECTINPUTVALUE).
			AddOp(arkade.OP_GREATERTHANOREQUAL).
			AddOp(txscript.OP_VERIFY)
	}
	return b.
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_1SUB).
		AddInt64(tunnel).
		AddInt64(0).
		AddOp(arkade.OP_TUNNEL).
		Script()
}
