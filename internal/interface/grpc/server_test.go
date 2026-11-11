package grpc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arkade-os/executor/internal/interface/grpc/handlers"
	"github.com/stretchr/testify/require"
)

func TestOnlyThePublicPortIsRateLimited(t *testing.T) {
	s, err := Listen(t.Context(), Options{PublicRateLimit: 1, Status: statusStub{}, Health: &healthStub{}}, &handlers.Executor{}, &handlers.Admin{})
	require.NoError(t, err)
	t.Cleanup(s.Stop)

	preflight := func(h http.Handler, remote string) int {
		req := httptest.NewRequest(http.MethodOptions, "/v1/info", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	limited := 0
	for range 30 {
		if preflight(s.public.http.Handler, "203.0.113.7:4000") == http.StatusTooManyRequests {
			limited++
		}
		require.Equal(t, http.StatusOK, preflight(s.admin.http.Handler, "203.0.113.7:4000"))
		require.Equal(t, http.StatusOK, preflight(s.public.http.Handler, "127.0.0.1:4000"))
	}
	require.InDelta(t, 20, limited, 2, "ten requests pass, the rest of the thirty do not")
}
