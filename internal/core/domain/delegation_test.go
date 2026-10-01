package domain

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFingerprint(t *testing.T) {
	a := map[string]string{}
	a["owner"], a["amount"], a["delay"] = "02aa", "07", "0200"
	b := map[string]string{}
	b["delay"], b["owner"], b["amount"] = "0200", "02aa", "07"
	require.Equal(t, Fingerprint("t", a, nil), Fingerprint("t", b, nil), "key order does not matter")
	require.Equal(t, Fingerprint("t", nil, nil), Fingerprint("t", map[string]string{}, nil))
	// every part counts, and the separators keep parts from sliding into each other
	require.NotEqual(t, Fingerprint("t", a, nil), Fingerprint("u", a, nil))
	require.NotEqual(t, Fingerprint("t", a, nil), Fingerprint("t", a, []string{"aa:0"}))
	require.NotEqual(t, Fingerprint("t", a, []string{"aa:0", "bb:1"}), Fingerprint("t", a, []string{"bb:1", "aa:0"}))
	require.NotEqual(t, Fingerprint("t", map[string]string{"x": "1"}, nil), Fingerprint("t", map[string]string{"x": "2"}, nil))
	require.Len(t, Fingerprint("t", a, nil), 64)
}
