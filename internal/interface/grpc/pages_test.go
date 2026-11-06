package grpc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	executionapp "github.com/arkade-os/delegatee/internal/core/application/execution"
	"github.com/arkade-os/delegatee/internal/core/application/health"
	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/stretchr/testify/require"
)

func TestHealthzAnswers503WhileADependencyIsDown(t *testing.T) {
	checks := &healthStub{entries: []health.Entry{{Name: "db"}, {Name: "arkd", Err: errors.New("refused")}}}
	pages := adminPages(statusStub{}, checks)

	rec := get(pages, "/healthz")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.JSONEq(t, `{"healthy":false,"checks":{"db":"ok","arkd":"refused"}}`, rec.Body.String())

	checks.entries[1].Err = nil
	rec = get(pages, "/healthz")
	require.Equal(t, http.StatusOK, rec.Code)
	require.JSONEq(t, `{"healthy":true,"checks":{"db":"ok","arkd":"ok"}}`, rec.Body.String())
}

func TestMetricsExposeTheStatusAndTheHealth(t *testing.T) {
	status := statusStub{executionapp.Status{
		Active: 4, Queued: 2, Registered: 1, Late: 3, Coins: 6, Amount: 60_000, Tip: delegation.Tip{Height: 812},
		Succeeded: 5, Failed: 2, TemplateFailures: 1,
	}}
	checks := &healthStub{entries: []health.Entry{{Name: "db"}, {Name: "arkd", Err: errors.New("refused")}}}

	body := get(adminPages(status, checks), "/metrics").Body.String()
	for _, line := range []string{
		"delegatee_delegations_active 4", "delegatee_entries_queued 2", "delegatee_entries_registered 1", "delegatee_coins_late 3",
		"delegatee_coins_watched 6", "delegatee_sats_watched 60000", "delegatee_chain_tip_height 812",
		`delegatee_attempts_total{status="succeeded"} 5`, `delegatee_attempts_total{status="failed"} 2`,
		"delegatee_template_failures_total 1", `delegatee_dependency_up{name="db"} 1`, `delegatee_dependency_up{name="arkd"} 0`,
	} {
		require.Contains(t, body, line+"\n")
	}
}

func TestIndexIsServedAtTheRoot(t *testing.T) {
	pages := adminPages(statusStub{}, &healthStub{})
	rec := get(pages, "/")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	require.Contains(t, rec.Body.String(), "<html")
	require.False(t, servesPage(httptest.NewRequest(http.MethodGet, "/v1/info", nil)))
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

type statusStub struct{ status executionapp.Status }

func (s statusStub) Status(context.Context, time.Duration) (executionapp.Status, error) {
	return s.status, nil
}

type healthStub struct{ entries []health.Entry }

func (s *healthStub) Check(context.Context) []health.Entry { return s.entries }
