package e2e

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	offchaintx "github.com/arkade-os/arkd/pkg/client-lib/offchain-tx"
	"github.com/arkade-os/delegatee/pkg/template/ecies"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/stretchr/testify/require"
)

func TestOfflineReceivePacketClaim(t *testing.T) {
	d := startDelegatee(t)
	templateID := fixtureID(t, "offline_receive.json")
	streamActive(t, d, templateID)
	swap := newSwap(t, d)
	addr, pkScript, tree := swapOutput(t, d, swap)
	key := d.cfg.EncryptionKeys[0].PubKey()
	payload, err := json.Marshal(map[string]any{
		"format": "delegatee-secrets/v1", "template_id": templateID,
		"values": map[string]string{"preimage": hex.EncodeToString(swap.preimage), "minimum_value": scriptNum(10_000), "receiver_program": swap.variables["receiver_program"]},
	})
	require.NoError(t, err)
	ciphertext, err := ecies.Encrypt(key, payload)
	require.NoError(t, err)
	program, err := hex.DecodeString(swap.variables["receiver_program"])
	require.NoError(t, err)
	marker := []byte("delegatee-secrets/v1")
	body := binary.BigEndian.AppendUint16([]byte{127}, uint16(len(marker)))
	body = append(body, marker...)
	for _, record := range []struct {
		tag   byte
		value []byte
	}{{1, ciphertext}, {3, key.SerializeCompressed()}, {2, enforcePayTo(t, program)}} {
		body = append(body, record.tag)
		body = binary.BigEndian.AppendUint16(body, uint16(len(record.value)))
		body = append(body, record.value...)
	}
	alice := fundedWallet(t)
	funding, err := alice.SendOffChain(t.Context(), []clientlib.Receiver{{To: addr, Amount: 10_000}},
		offchaintx.WithExtraPacket(packets.Raw(4, body)),
		offchaintx.WithTxOutsTaprootTree(map[string][]byte{hex.EncodeToString(pkScript): tree}))
	require.NoError(t, err)
	paid := waitForVtxo(t, d, swap.receiverScript, funding)
	require.EqualValues(t, 10_000, paid.Amount)
	claim, err := d.indexer.GetVirtualTxs(t.Context(), []string{paid.Txid})
	require.NoError(t, err)
	require.Len(t, claim.Txs, 1)
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(claim.Txs[0]), true)
	require.NoError(t, err)
	found := false
	for i := range ptx.Inputs {
		witness, err := txutils.GetArkPsbtConditionWitness(ptx, i)
		require.NoError(t, err)
		for _, item := range witness {
			found = found || bytes.Equal(item, swap.preimage)
		}
	}
	require.True(t, found, "claim condition witness contains the exact preimage")
	require.Equal(t, swap.receiverScript, ptx.UnsignedTx.TxOut[0].PkScript)
	rows, err := delegationsOf(t, d, templateID)
	require.NoError(t, err)
	require.Len(t, rows, 1, "funding packet spawned one durable child without client registration")
	require.NotZero(t, rows[0].ParentId)
	t.Logf("funding=%s claim=%s child=%d receiver=%x", funding, paid.Txid, rows[0].Id, swap.receiverScript)
}
