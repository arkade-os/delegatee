//go:build e2e

package electrum

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestFulcrumAnswers needs the regtest stack: make regtest-up.
func TestFulcrumAnswers(t *testing.T) {
	url := os.Getenv("ELECTRUM_URL")
	if url == "" {
		url = "tcp://127.0.0.1:50001"
	}
	w, err := NewWatcher(url)
	require.NoError(t, err)
	t.Cleanup(w.Close)

	tip, err := w.Tip(t.Context())
	require.NoError(t, err)
	require.Positive(t, tip.Height)
	require.False(t, tip.MedianTime.After(tip.Time))

	sub, err := w.Subscribe(
		t.Context(),
		[]string{"5120" + "11111111111111111111111111111111111111111111111111111111111111aa"},
	)
	require.NoError(t, err)
	defer sub.Stop()
	select {
	case ev := <-sub.Events():
		require.NotNil(t, ev.Tip)
		require.Equal(t, tip.Height, ev.Tip.Height)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "no tip pushed")
	}
}
