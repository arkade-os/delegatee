package explorer

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

func TestThrottled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("error code: 1015"))
	}))
	defer srv.Close()
	e, err := New(srv.URL, arklib.BitcoinRegTest, 1000)
	require.NoError(t, err)
	addr, err := address.NewAddressWitnessPubKeyHash(make([]byte, 20), &chaincfg.RegressionNetParams)
	require.NoError(t, err)
	for name, call := range map[string]func() error{
		"tip":       func() error { _, err := e.ChainTip(); return err },
		"confirms":  func() error { _, err := e.Confirmations("ab"); return err },
		"utxos":     func() error { _, err := e.GetUtxos([]string{addr.EncodeAddress()}); return err },
		"outspends": func() error { _, err := e.GetTxOutspends("ab"); return err },
	} {
		require.ErrorIs(t, call(), ports.ErrThrottled, name)
	}
}

func TestPacing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("100")) }))
	defer srv.Close()
	e, err := New(srv.URL, arklib.BitcoinRegTest, 20)
	require.NoError(t, err)
	start := time.Now()
	for range 5 {
		_, _ = e.Confirmations("ab")
	}
	require.GreaterOrEqual(t, time.Since(start), 200*time.Millisecond, "one request every 50ms")
	_, err = New(srv.URL, arklib.BitcoinRegTest, 0)
	require.Error(t, err)
}

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
	e, err := New(srv.URL, arklib.BitcoinRegTest, 1000)
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
	e, err := New(srv.URL, arklib.BitcoinRegTest, 1000)
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
