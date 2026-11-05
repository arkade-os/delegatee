package execution

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/internal/core/domain/execution"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// forEmulator encodes the attempt's offchain txs, the ark tx first, for the emulator: the ark tx
// carries the transaction funding each input, which the emulator reads to check the checkpoints.
func forEmulator(txs []delegation.Tx, sources []*wire.MsgTx) (string, []string, error) {
	if len(txs) == 0 {
		return "", nil, errors.New("no offchain tx")
	}
	packets := make([]*psbt.Packet, len(txs))
	for i, tx := range txs {
		p, err := psbt.NewFromRawBytes(bytes.NewReader(tx.Raw), false)
		if err != nil {
			return "", nil, fmt.Errorf("tx %s: %w", tx.Txid, err)
		}
		packets[i] = p
	}
	for i, src := range sources {
		if err := txutils.SetArkPsbtField(packets[0], i, arkade.PrevArkTxField, *src); err != nil {
			return "", nil, err
		}
	}
	encoded := make([]string, len(packets))
	for i, p := range packets {
		var err error
		if encoded[i], err = p.B64Encode(); err != nil {
			return "", nil, err
		}
	}
	return encoded[0], encoded[1:], nil
}

// boardingCommitment is the commitment transaction with the leaf and prevout of each boarding input the
// intent spends, the only inputs the intent's signers sign.
func boardingCommitment(in *execution.Intent, commitment string) (string, error) {
	tx, err := withBoarding(in, commitment)
	if err != nil {
		return "", err
	}
	return tx.B64Encode()
}

// signCommitment merges what a remote signer signed of boardingCommitment, empty when it signed
// none, and returns the result; empty when the intent spends no boarding input.
func signCommitment(in *execution.Intent, commitment, remote string) (string, error) {
	if in.Vtxos() == len(in.Tx.UnsignedTx.TxIn) {
		return "", nil
	}
	tx, err := withBoarding(in, commitment)
	if err != nil {
		return "", err
	}
	if remote != "" {
		signed, err := psbt.NewFromRawBytes(strings.NewReader(remote), true)
		if err != nil {
			return "", fmt.Errorf("signed commitment tx: %w", err)
		}
		mergeSignatures(tx, signed)
	}
	return tx.B64Encode()
}

// signForfeits merges what the emulator signed into forfeits.
func signForfeits(forfeits, signed []string) ([]string, error) {
	out := make([]string, len(forfeits))
	for i := range forfeits {
		remote := forfeits[i]
		if i < len(signed) {
			remote = signed[i]
		}
		tx, err := merge(forfeits[i], remote)
		if err != nil {
			return nil, err
		}
		if out[i], err = tx.B64Encode(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func withBoarding(in *execution.Intent, commitment string) (*psbt.Packet, error) {
	tx, err := psbt.NewFromRawBytes(strings.NewReader(commitment), true)
	if err != nil {
		return nil, fmt.Errorf("commitment tx: %w", err)
	}
	for i := range tx.Inputs {
		tx.Inputs[i].TaprootLeafScript = nil
	}
	for i, txin := range in.Tx.UnsignedTx.TxIn {
		if i >= len(in.Boarding) || !in.Boarding[i] {
			continue
		}
		j := slices.IndexFunc(tx.UnsignedTx.TxIn, func(c *wire.TxIn) bool { return c.PreviousOutPoint == txin.PreviousOutPoint })
		if j < 0 {
			return nil, fmt.Errorf("commitment tx omits boarding input %s", txin.PreviousOutPoint)
		}
		tx.Inputs[j].TaprootLeafScript = in.Tx.Inputs[i].TaprootLeafScript
		tx.Inputs[j].WitnessUtxo = in.Tx.Inputs[i].WitnessUtxo
	}
	return tx, nil
}

func merge(original, signed string) (*psbt.Packet, error) {
	local, err := psbt.NewFromRawBytes(strings.NewReader(original), true)
	if err != nil {
		return nil, err
	}
	remote, err := psbt.NewFromRawBytes(strings.NewReader(signed), true)
	if err != nil {
		return nil, err
	}
	mergeSignatures(local, remote)
	return local, nil
}

// mergeSignatures adds the signatures a remote signer put on signed to original.
func mergeSignatures(original, signed *psbt.Packet) {
	for i := range min(len(original.Inputs), len(signed.Inputs)) {
		for _, sig := range signed.Inputs[i].TaprootScriptSpendSig {
			if !hasSig(original.Inputs[i].TaprootScriptSpendSig, sig.XOnlyPubKey, sig.LeafHash) {
				original.Inputs[i].TaprootScriptSpendSig = append(original.Inputs[i].TaprootScriptSpendSig, sig)
			}
		}
	}
}

func hasSig(sigs []*psbt.TaprootScriptSpendSig, xOnly, leafHash []byte) bool {
	for _, s := range sigs {
		if bytes.Equal(s.XOnlyPubKey, xOnly) && bytes.Equal(s.LeafHash, leafHash) {
			return true
		}
	}
	return false
}
