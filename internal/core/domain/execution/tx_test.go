package execution

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/pkg/template"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestBuildOffchainClaimPaysTheReceiverThroughACheckpoint(t *testing.T) {
	c := newClaim(t)
	txs, err := BuildOffchain(c.inst, c.inputs, []delegation.Coin{c.coin}, c.txs, template.Fee{Dust: 330}, c.unroll)
	require.NoError(t, err)
	require.Len(t, txs, 2)
	require.True(t, txs[0].Spends)
	require.False(t, txs[1].Spends)
	ark := decode(t, txs[0])
	checkpoint := decode(t, txs[1])
	require.Len(t, ark.Inputs, 1)
	require.Equal(t, ark.UnsignedTx.TxHash().String(), txs[0].Txid)
	require.Equal(t, checkpoint.UnsignedTx.TxHash().String(), txs[1].Txid)
	require.Equal(t, "5120"+c.receiver, hex.EncodeToString(ark.UnsignedTx.TxOut[0].PkScript))
	require.Equal(t, int64(10_000), ark.UnsignedTx.TxOut[0].Value)
	require.Equal(t, c.coin.Outpoint, checkpoint.UnsignedTx.TxIn[0].PreviousOutPoint.String())
	require.Equal(t, checkpoint.UnsignedTx.TxHash(), ark.UnsignedTx.TxIn[0].PreviousOutPoint.Hash)
}

func TestBuildOffchainRefusesCoinNotMatchingItsFundingTx(t *testing.T) {
	c := newClaim(t)
	fee := template.Fee{Dust: 330}
	_, err := BuildOffchain(c.inst, c.inputs, []delegation.Coin{c.coin}, nil, fee, c.unroll)
	require.ErrorContains(t, err, "missing source output")

	less := c.coin
	less.Amount--
	_, err = BuildOffchain(c.inst, c.inputs, []delegation.Coin{less}, c.txs, fee, c.unroll)
	require.ErrorContains(t, err, "differs from its source output")

	elsewhere := c.coin
	elsewhere.Outpoint = c.source.TxHash().String() + ":1"
	_, err = BuildOffchain(c.inst, c.inputs, []delegation.Coin{elsewhere}, c.txs, fee, c.unroll)
	require.ErrorContains(t, err, "missing source output")

	_, err = BuildOffchain(c.inst, c.inputs, []delegation.Coin{c.coin}, c.txs, fee, []byte{0x51})
	require.Error(t, err, "arkd's checkpoint tapscript is not a csv multisig")
}

func TestCoinSourcesCarryTransferredAndIssuedAssets(t *testing.T) {
	id, err := asset.NewAssetId(strings.Repeat("ab", 32), 0)
	require.NoError(t, err)
	input, err := asset.NewAssetInput(0, 700)
	require.NoError(t, err)
	output, err := asset.NewAssetOutput(0, 700)
	require.NoError(t, err)
	transfer, err := asset.NewAssetGroup(id, nil, []asset.AssetInput{*input}, []asset.AssetOutput{*output}, nil)
	require.NoError(t, err)
	issuance, err := asset.NewAssetGroup(nil, nil, nil, []asset.AssetOutput{*output}, nil)
	require.NoError(t, err)

	for name, group := range map[string]*asset.AssetGroup{"transferred": transfer, "issued": issuance} {
		t.Run(name, func(t *testing.T) {
			c := newClaim(t)
			packet, err := asset.NewPacket([]asset.AssetGroup{*group})
			require.NoError(t, err)
			ext, err := extension.Extension{packet}.TxOut()
			require.NoError(t, err)
			c.source.AddTxOut(ext)
			c.coin.Outpoint = c.source.TxHash().String() + ":0"

			sources, err := sourcesOf([]delegation.Coin{c.coin}, map[string]*wire.MsgTx{c.source.TxHash().String(): c.source})
			require.NoError(t, err)
			want := group.AssetId
			if want == nil {
				want, err = asset.NewAssetId(c.source.TxHash().String(), 0)
				require.NoError(t, err)
			}
			raw, err := want.Serialize()
			require.NoError(t, err)
			require.Equal(t, []template.Asset{{ID: raw, Amount: 700}}, sources[0].Assets)
		})
	}
}

func TestCheckTxRefusesTxNotSpendingExactlyTheWatchedCoins(t *testing.T) {
	c := newClaim(t)
	sources, err := sourcesOf([]delegation.Coin{c.coin}, c.txs)
	require.NoError(t, err)
	act, err := c.inst.Build(sources, template.Fee{Dust: 330})
	require.NoError(t, err)
	require.NoError(t, checkTx(act.Tx, []delegation.Coin{c.coin}, c.inputs))

	require.Error(t, checkTx(nil, []delegation.Coin{c.coin}, c.inputs))
	require.ErrorContains(t, checkTx(act.Tx, nil, c.inputs), "inputs for 0 coins")
	other := c.coin
	other.Outpoint = strings.Repeat("00", 32) + ":0"
	require.ErrorContains(t, checkTx(act.Tx, []delegation.Coin{other}, c.inputs), "spends another coin")
	moved := c.coin
	moved.Script = "5120" + strings.Repeat("00", 32)
	require.ErrorContains(t, checkTx(act.Tx, []delegation.Coin{moved}, c.inputs), "witness utxo does not match")
	wrongInput := c.coin
	wrongInput.Input = 1
	require.ErrorContains(t, checkTx(act.Tx, []delegation.Coin{wrongInput}, c.inputs), "not at the script of its input")
	pruned := []delegation.Input{{Script: c.inputs[0].Script, Tapscripts: c.inputs[0].Tapscripts[:1]}}
	require.ErrorContains(t, checkTx(act.Tx, []delegation.Coin{c.coin}, pruned), "not in the registered tree")
}

// claim is a VHTLC claim watch with a coin funded by a real transaction.
type claim struct {
	inst                       *template.Instance
	inputs                     []delegation.Input
	coin                       delegation.Coin
	source                     *wire.MsgTx
	txs                        map[string]*wire.MsgTx
	unroll                     []byte
	receiver                   string
	server, emulator, cosigner *btcec.PrivateKey
}

func newClaim(t *testing.T) claim {
	t.Helper()
	keys := make([]*btcec.PrivateKey, 5)
	for i := range keys {
		var scalar btcec.ModNScalar
		scalar.SetInt(uint32(i + 1))
		keys[i] = btcec.PrivKeyFromScalar(&scalar)
	}
	server, emulator, cosigner, sender, receiver := keys[0], keys[1], keys[2], keys[3], keys[4]
	preimage := make([]byte, 32)
	_, err := rand.Read(preimage)
	require.NoError(t, err)
	program := schnorr.SerializePubKey(receiver.PubKey())
	variables := map[string][]byte{
		"sender":                  sender.PubKey().SerializeCompressed(),
		"receiver":                receiver.PubKey().SerializeCompressed(),
		"refund_locktime":         binary.LittleEndian.AppendUint32(nil, uint32(now.Add(24*time.Hour).Unix())),
		"unilateral_claim_delay":  scriptNum(1024),
		"unilateral_refund_delay": scriptNum(1536),
		"unilateral_refund_without_receiver_delay": scriptNum(2048),
		"receiver_program":                         program,
		"sender_program":                           schnorr.SerializePubKey(sender.PubKey()),
		"ciphertext":                               preimage,
	}
	tmpl, err := template.Parse(fixture(t, "vhtlc_claim.json"), nil)
	require.NoError(t, err)
	inst, err := tmpl.Instantiate(template.Context{
		Keys:      template.Keys{Server: server.PubKey(), Emulator: emulator.PubKey(), Cosigner: cosigner.PubKey()},
		Variables: variables,
		Decrypt:   func(ciphertext []byte) ([]byte, error) { return ciphertext, nil },
	})
	require.NoError(t, err)

	source := wire.NewMsgTx(3)
	source.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})
	source.AddTxOut(wire.NewTxOut(10_000, inst.PkScript(0)))
	pkScript := hex.EncodeToString(inst.PkScript(0))
	unroll, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{server.PubKey()}},
		Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
	}).Script()
	require.NoError(t, err)
	return claim{
		inst:   inst,
		inputs: []delegation.Input{{Name: "htlc", Script: pkScript, Tapscripts: inst.Tapscripts(0)}},
		coin: delegation.Coin{
			Outpoint: source.TxHash().String() + ":0", DelegationID: 1, Script: pkScript, Amount: 10_000,
			ExpiresAt: now.Add(time.Hour), CreatedAt: now, Due: now, Status: delegation.Present,
		},
		source: source, txs: map[string]*wire.MsgTx{source.TxHash().String(): source}, unroll: unroll,
		receiver: hex.EncodeToString(program), server: server, emulator: emulator, cosigner: cosigner,
	}
}

func decode(t *testing.T, tx delegation.Tx) *psbt.Packet {
	t.Helper()
	p, err := psbt.NewFromRawBytes(bytes.NewReader(tx.Raw), false)
	require.NoError(t, err)
	return p
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	doc, err := os.ReadFile("../../../../pkg/template/testdata/" + name)
	require.NoError(t, err)
	return doc
}
