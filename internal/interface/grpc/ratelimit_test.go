package grpc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRateLimiterRefusesAClientOverItsRate(t *testing.T) {
	limited := newRateLimiter(
		1,
	).middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	for range 10 {
		require.Equal(t, http.StatusOK, serve(limited, "203.0.113.7:4000"))
	}
	require.Equal(
		t, http.StatusTooManyRequests, serve(limited, "203.0.113.7:4001"),
		"the port does not count",
	)
	require.Equal(
		t, http.StatusOK, serve(limited, "203.0.113.8:4000"), "another client has its own bucket",
	)
}

func TestRateLimiterExemptsLoopback(t *testing.T) {
	limited := newRateLimiter(
		1,
	).middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for range 50 {
		require.Equal(t, http.StatusOK, serve(limited, "127.0.0.1:4000"))
		require.Equal(t, http.StatusOK, serve(limited, "[::1]:4000"))
	}
}

func serve(h http.Handler, remote string) int {
	req := httptest.NewRequest(http.MethodGet, "/v1/info", nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}
