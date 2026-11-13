package asm

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalBytes(t *testing.T) {
	key, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	for _, tc := range []struct {
		name, typ string
		raw       []byte
		ok        bool
	}{
		{"pubkey", "pubkey", key, true},
		{"x-only is not a pubkey", "pubkey", key[1:], false},
		{"above the field", "pubkey", append([]byte{2}, bytes.Repeat([]byte{0xff}, 32)...), false},
		{"not on curve", "pubkey", append([]byte{2}, bytes.Repeat([]byte{0x05}, 32)...), false},
		{"bytes32", "bytes32", make([]byte, 32), true},
		{"bytes32 short", "bytes32", make([]byte, 31), false},
		{"bytes20", "bytes20", make([]byte, 20), true},
		{"bytes any", "bytes", []byte{1, 2, 3}, true},
		{"bytes of a push", "bytes", make([]byte, 520), true},
		{"bytes over a push", "bytes", make([]byte, 521), false},
		{"asset", "asset", make([]byte, 32), true},
		{"int zero is empty", "int", nil, true},
		{"int 1024", "int", []byte{0x00, 0x04}, true},
		{"int with a padding byte", "int", []byte{0x01, 0x00}, false},
		{"int negative zero", "int", []byte{0x80}, false},
		{"bool true", "bool", []byte{1}, true},
		{"bool false", "bool", nil, true},
		{"bool two", "bool", []byte{2}, false},
		{"signature", "signature", make([]byte, 64), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CanonicalBytes(tc.typ, tc.raw)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrBadValue)
				if len(tc.raw) > 2 {
					require.NotContains(
						t, err.Error(), hex.EncodeToString(tc.raw[1:4]), "no plaintext",
					)
				}
			}
		})
	}
}

func TestScriptNum(t *testing.T) {
	const max = 1<<53 - 1
	for n, want := range map[int64]string{
		0: "", 1: "01", -1: "81", 127: "7f", 128: "8000", 1024: "0004", 1791000000: "c07dc06a",
		max: "ffffffffffff1f", -max: "ffffffffffff9f",
	} {
		require.Equal(t, want, hex.EncodeToString(ScriptNum(n)))
		got, err := ParseScriptNum(ScriptNum(n))
		require.NoError(t, err)
		require.Equal(t, n, got)
	}

	for name, raw := range map[string][]byte{
		"padded":        {0x01, 0x00},
		"negative zero": {0x80},
		"zero byte":     {0x00},
		"padded sign":   {0x01, 0x80},
		"too large":     {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20},
		"too long":      {1, 2, 3, 4, 5, 6, 7, 8, 9},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseScriptNum(raw)
			require.ErrorIs(t, err, ErrBadValue)
		})
	}
}
