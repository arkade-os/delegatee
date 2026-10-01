package ecies_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/delegatee/pkg/template/ecies"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestVectorDecrypts checks a vector produced by another implementation.
func TestVectorDecrypts(t *testing.T) {
	v := loadVector(t)
	privBytes := mustDecode(t, v.Privkey)
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	ciphertext := mustDecode(t, v.Ciphertext)
	plaintext := mustDecode(t, v.Plaintext)

	got, err := ecies.Decrypt(priv, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	plaintext := []byte("a secret preimage, arbitrary length")

	ciphertext, err := ecies.Encrypt(priv.PubKey(), plaintext)
	require.NoError(t, err)

	got, err := ecies.Decrypt(priv, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestDecryptRejects(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ciphertext, err := ecies.Encrypt(priv.PubKey(), []byte("some 32 byte long secret preimg"))
	require.NoError(t, err)
	flipped := func(i int) []byte {
		out := bytes.Clone(ciphertext)
		out[i] ^= 0xff
		return out
	}
	offCurve := make([]byte, 33+12+16)
	offCurve[0] = 0x02
	copy(offCurve[1:33], bytes.Repeat([]byte{0xff}, 32))

	for _, tc := range []struct {
		name       string
		ciphertext []byte
		msg        string
	}{
		{name: "flipped ephemeral pubkey byte (aad)", ciphertext: flipped(0)},
		{name: "flipped nonce byte", ciphertext: flipped(33)},
		{name: "flipped ciphertext byte", ciphertext: flipped(len(ciphertext) - 1)},
		// 33 (pubkey) + 12 (nonce) + 16 (gcm tag) = 61 is the minimum
		{name: "short input", ciphertext: make([]byte, 60), msg: "short"},
		{name: "invalid compressed-key prefix", ciphertext: append([]byte{0x04}, make([]byte, 12+16+32)...)},
		{name: "ephemeral point not on curve", ciphertext: offCurve},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ecies.Decrypt(priv, tc.ciphertext)
			require.Error(t, err)
			require.ErrorContains(t, err, tc.msg)
		})
	}
}

func TestDecryptAny(t *testing.T) {
	oldKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	newKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	other, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	plaintext := []byte("a secret preimage, arbitrary length")

	// sealed to the current key, the superseded one retained
	ciphertext, err := ecies.Encrypt(newKey.PubKey(), plaintext)
	require.NoError(t, err)
	got, err := ecies.DecryptAny([]*btcec.PrivateKey{oldKey, newKey}, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)

	ciphertext, err = ecies.Encrypt(other.PubKey(), plaintext)
	require.NoError(t, err)
	_, err = ecies.DecryptAny([]*btcec.PrivateKey{oldKey, newKey}, ciphertext)
	require.ErrorContains(t, err, "no key")
}

type vector struct {
	Privkey    string `json:"privkey"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	b, err := os.ReadFile("testdata/vector.json")
	require.NoError(t, err)
	var v vector
	require.NoError(t, json.Unmarshal(b, &v))
	return v
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
