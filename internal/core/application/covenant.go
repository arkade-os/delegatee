package application

import (
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/txscript"
)

// DefaultRenewalWindow applies when a request leaves the window unset.
const DefaultRenewalWindow = 1024

// buildArkadeScript is the delegate covenant: a register intent cosigned by
// this delegate only, output i-1 preserving input i, within renewalWindow
// seconds of expiry.
//
//	OP_PUSHEXPIRY <window> OP_SUB OP_CHECKTIMEVERIFY
//	"type" OP_INSPECTINTENTMESSAGE OP_VERIFY "register" OP_EQUALVERIFY
//	"onchain_output_indexes" OP_INSPECTINTENTMESSAGE OP_VERIFY "[]" OP_EQUALVERIFY
//	"cosigners_public_keys.0" OP_INSPECTINTENTMESSAGE OP_VERIFY <delegate> OP_EQUALVERIFY
//	"cosigners_public_keys.1" OP_INSPECTINTENTMESSAGE OP_NOT OP_VERIFY OP_DROP
//	OP_PUSHCURRENTINPUTINDEX OP_1SUB 7 0 OP_TUNNEL
func buildArkadeScript(delegatePubKeyHex string, renewalWindow int64) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHEXPIRY).
		AddInt64(renewalWindow).
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
		AddOp(txscript.OP_DROP).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_1SUB).
		AddInt64(arkade.TunnelScriptPubKey | arkade.TunnelValue | arkade.TunnelAssets).
		AddInt64(0).
		AddOp(arkade.OP_TUNNEL).
		Script()
}
