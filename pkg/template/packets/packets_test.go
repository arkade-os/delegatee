package packets_test

import (
	"bytes"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// TestAdvertisementSpecExamples checks the specification's byte-for-byte examples.
func TestAdvertisementSpecExamples(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []packets.Record
		hex     string
	}{
		{
			name:    "one record, one output",
			records: []packets.Record{{Template: repeat(0x11), Outputs: []uint16{0}}},
			hex:     "01" + "2200" + strings.Repeat("11", 32) + "0000",
		},
		{
			name:    "one record, two outputs",
			records: []packets.Record{{Template: repeat(0x22), Outputs: []uint16{0, 1}}},
			hex:     "01" + "2400" + strings.Repeat("22", 32) + "0000" + "0100",
		},
		{
			name: "two records",
			records: []packets.Record{
				{Template: repeat(0xaa), Outputs: []uint16{0}},
				{Template: repeat(0xbb), Outputs: []uint16{1}},
			},
			hex: "01" + "2200" + strings.Repeat("aa", 32) + "0000" + "2200" + strings.Repeat("bb", 32) + "0100",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := packets.EncodeAdvertisement(tc.records)
			require.NoError(t, err)
			require.Equal(t, tc.hex, hex.EncodeToString(got))
			decoded, err := packets.DecodeAdvertisement(got)
			require.NoError(t, err)
			require.Equal(t, tc.records, decoded)
		})
	}
}

func TestAdvertisementRoundtrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []packets.Record
	}{
		{"single record, single output", []packets.Record{{Template: repeat(0x33), Outputs: []uint16{2}}}},
		{"multiple records, multiple outputs", []packets.Record{
			{Template: repeat(0xaa), Outputs: []uint16{0, 3}},
			{Template: repeat(0xbb), Outputs: []uint16{1, 5}},
		}},
		{"record's own index order is preserved, unsorted", []packets.Record{{Template: repeat(0xcc), Outputs: []uint16{5, 1, 3}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := packets.EncodeAdvertisement(tc.records)
			require.NoError(t, err)
			decoded, err := packets.DecodeAdvertisement(encoded)
			require.NoError(t, err)
			require.Equal(t, tc.records, decoded)
		})
	}
}

func TestEncodeAdvertisementSortsRecordsBySmallestIndex(t *testing.T) {
	records := []packets.Record{
		{Template: repeat(0xbb), Outputs: []uint16{9, 5}},
		{Template: repeat(0xaa), Outputs: []uint16{1}},
	}
	got, err := packets.EncodeAdvertisement(records)
	require.NoError(t, err)

	decoded, err := packets.DecodeAdvertisement(got)
	require.NoError(t, err)
	require.Equal(t, []packets.Record{
		{Template: repeat(0xaa), Outputs: []uint16{1}},
		{Template: repeat(0xbb), Outputs: []uint16{9, 5}},
	}, decoded)
}

func TestEncodeAdvertisementValidation(t *testing.T) {
	// 16 records of 16 outputs: 16*(2+32+32) = 1056 bytes
	tooLong := make([]packets.Record, 16)
	for i := range tooLong {
		tooLong[i] = packets.Record{Template: repeat(byte(i)), Outputs: make([]uint16, 16)}
	}
	for _, tc := range []struct {
		name    string
		records []packets.Record
	}{
		{"no records", nil},
		{"record with no outputs", []packets.Record{{Template: repeat(0x01)}}},
		{"result over 520 bytes", tooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := packets.EncodeAdvertisement(tc.records)
			require.Error(t, err)
		})
	}
}

func TestDecodeAdvertisementValidation(t *testing.T) {
	template := bytes.Repeat([]byte{0x11}, 32)
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"wrong version", slices.Concat([]byte{0x02, 0x22, 0x00}, template, []byte{0, 0})},
		{"empty body", nil},
		{"truncated record length", []byte{0x01, 0x22}},
		{"truncated record body", []byte{0x01, 0x22, 0x00, 0x11, 0x11}},
		{"record body shorter than 32 bytes", []byte{0x01, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05}},
		{"record with zero indexes", slices.Concat([]byte{0x01, 32, 0x00}, template)},
		{"odd number of index bytes", slices.Concat([]byte{0x01, 33, 0x00}, template, []byte{0})},
		{"trailing bytes after last record", slices.Concat([]byte{0x01, 0x22, 0x00}, template, []byte{0, 0, 0xff})},
		{"packet over 520 bytes", make([]byte, 521)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := packets.DecodeAdvertisement(tc.body)
			require.ErrorIs(t, err, packets.ErrInvalidAdvertisement)
		})
	}

	t.Run("does not panic on short input", func(t *testing.T) {
		for n := range 5 {
			require.NotPanics(t, func() {
				_, _ = packets.DecodeAdvertisement(make([]byte, n))
			})
		}
	})
}

func TestRaw(t *testing.T) {
	p := packets.Raw(packets.TypeState, []byte{0x01, 0x02, 0x03})
	require.Equal(t, packets.TypeState, p.Type())
	body, err := p.Serialize()
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x02, 0x03}, body)
}

func TestFind(t *testing.T) {
	statePacket := packets.Raw(packets.TypeState, []byte{0xde, 0xad})
	adPacket := packets.Raw(packets.TypeAdvertisement, []byte{0xbe, 0xef})

	tx := buildTxWithExtension(t, validAssetPacket(t), validEmulatorPacket(t), statePacket, adPacket)

	t.Run("finds state packet", func(t *testing.T) {
		body, ok := packets.Find(tx, packets.TypeState)
		require.True(t, ok)
		require.Equal(t, []byte{0xde, 0xad}, body)
	})

	t.Run("finds advertisement packet", func(t *testing.T) {
		body, ok := packets.Find(tx, packets.TypeAdvertisement)
		require.True(t, ok)
		require.Equal(t, []byte{0xbe, 0xef}, body)
	})

	t.Run("type not present", func(t *testing.T) {
		_, ok := packets.Find(tx, 0x09)
		require.False(t, ok)
	})

	t.Run("no extension output", func(t *testing.T) {
		bare := wire.NewMsgTx(wire.TxVersion)
		bare.AddTxOut(wire.NewTxOut(1000, []byte{0x51, 0x20}))
		_, ok := packets.Find(bare, packets.TypeState)
		require.False(t, ok)
	})

	t.Run("truncated extension does not panic", func(t *testing.T) {
		bad := wire.NewMsgTx(wire.TxVersion)
		bad.AddTxOut(wire.NewTxOut(0, append([]byte{0x6a, 0x02}, extension.ArkadeMagic[:2]...)))
		require.NotPanics(t, func() {
			_, _ = packets.Find(bad, packets.TypeState)
		})
	})
}

func repeat(b byte) [32]byte { return [32]byte(bytes.Repeat([]byte{b}, 32)) }

func buildTxWithExtension(t testing.TB, pkts ...extension.Packet) *wire.MsgTx {
	t.Helper()
	ext, err := extension.NewExtensionFromPackets(pkts...)
	require.NoError(t, err)
	txout, err := ext.TxOut()
	require.NoError(t, err)

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxOut(wire.NewTxOut(1000, []byte{0x51, 0x20}))
	tx.AddTxOut(txout)
	return tx
}

func validAssetPacket(t testing.TB) asset.Packet {
	t.Helper()
	out, err := asset.NewAssetOutput(0, 1)
	require.NoError(t, err)
	group, err := asset.NewAssetGroup(nil, nil, nil, []asset.AssetOutput{*out}, nil)
	require.NoError(t, err)
	pkt, err := asset.NewPacket([]asset.AssetGroup{*group})
	require.NoError(t, err)
	return pkt
}

func validEmulatorPacket(t testing.TB) arkade.EmulatorPacket {
	t.Helper()
	pkt, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 0, Script: []byte{0x51}})
	require.NoError(t, err)
	return pkt
}
