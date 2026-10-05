package explorer

import (
	"net/http"
	"net/http/httptest"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/stretchr/testify/require"
)

func TestConfirmations(t *testing.T) {
	statuses := map[string]string{
		"unconfirmed": `{"confirmed":false}`,
		"tip":         `{"confirmed":true,"block_height":100}`,
		"deep":        `{"confirmed":true,"block_height":91}`,
		"future":      `{"confirmed":true,"block_height":101}`,
		"noheight":    `{"confirmed":true}`,
		"garbage":     `{`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blocks/tip/height" {
			_, _ = w.Write([]byte("100"))
			return
		}
		for txid, body := range statuses {
			if r.URL.Path == "/tx/"+txid+"/status" {
				_, _ = w.Write([]byte(body))
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	e, err := New(srv.URL, arklib.BitcoinRegTest)
	require.NoError(t, err)

	for txid, want := range map[string]int{"unconfirmed": 0, "tip": 1, "deep": 10} {
		n, err := e.Confirmations(txid)
		require.NoError(t, err, txid)
		require.Equal(t, want, n, txid)
	}
	for _, txid := range []string{"future", "noheight", "garbage", "missing"} {
		_, err := e.Confirmations(txid)
		require.Error(t, err, txid)
	}
}

func TestChainTip(t *testing.T) {
	block := `[{"height":812,"mediantime":1790864398},{"height":811,"mediantime":1790864000}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/blocks" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(block))
	}))
	defer srv.Close()
	e, err := New(srv.URL, arklib.BitcoinRegTest)
	require.NoError(t, err)

	tip, err := e.ChainTip()
	require.NoError(t, err)
	require.Equal(t, ports.ChainTip{Height: 812, MedianTime: 1790864398}, tip)

	for _, body := range []string{`[`, `[]`, `[{"height":812}]`, `[{"mediantime":1790864398}]`} {
		block = body
		_, err = e.ChainTip()
		require.Error(t, err, "an incomplete tip would stall every locktime silently: %s", body)
	}
}
