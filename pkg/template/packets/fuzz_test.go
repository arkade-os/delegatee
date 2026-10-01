package packets_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func FuzzDecodeAdvertisement(f *testing.F) {
	for _, h := range []string{
		"01" + "2200" + strings.Repeat("11", 32) + "0000",
		"01" + "2400" + strings.Repeat("22", 32) + "00000100" + "2200" + strings.Repeat("11", 32) + "0200",
		"01" + "2200",
	} {
		f.Add(mustHex(f, h))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		records, err := packets.DecodeAdvertisement(body)
		if err != nil {
			require.ErrorIs(t, err, packets.ErrInvalidAdvertisement)
			return
		}
		again, err := packets.EncodeAdvertisement(records)
		require.NoError(t, err)
		require.Len(t, again, len(body))
		decoded, err := packets.DecodeAdvertisement(again)
		require.NoError(t, err)
		require.ElementsMatch(t, records, decoded)
	})
}

func FuzzFind(f *testing.F) {
	for _, tx := range []*wire.MsgTx{
		buildTxWithExtension(f, validAssetPacket(f), validEmulatorPacket(f), packets.Raw(packets.TypeState, []byte{1}), packets.Raw(packets.TypeAdvertisement, []byte{2})),
		wire.NewMsgTx(wire.TxVersion),
	} {
		var b bytes.Buffer
		require.NoError(f, tx.Serialize(&b))
		f.Add(b.Bytes(), packets.TypeAdvertisement)
	}
	f.Fuzz(func(t *testing.T, raw []byte, typ uint8) {
		tx := wire.NewMsgTx(wire.TxVersion)
		if tx.Deserialize(bytes.NewReader(raw)) != nil {
			return
		}
		body, ok := packets.Find(tx, typ)
		if ok && typ == packets.TypeAdvertisement {
			_, _ = packets.DecodeAdvertisement(body)
		}
	})
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
