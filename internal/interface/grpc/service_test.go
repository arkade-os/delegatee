package grpcservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/config"
	"github.com/arkade-os/delegatee/internal/core/application"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type fakeApp struct {
	application.Service
	started, stopped bool
	cancelled        string
	arkDown          bool
}

func (f *fakeApp) Start() { f.started = true }
func (f *fakeApp) Stop()  { f.stopped = true }
func (f *fakeApp) Info(p domain.Params) (application.Info, error) {
	return application.Info{Network: "regtest", Params: p}, nil
}
func (f *fakeApp) ListDelegations(context.Context) ([]domain.Delegation, error) {
	return []domain.Delegation{{ID: 1, Address: "tark1x", Status: "active"}}, nil
}
func (f *fakeApp) LastRenewals(context.Context) (map[int64]domain.Renewal, error) { return nil, nil }
func (f *fakeApp) Status() application.Status {
	return application.Status{LastScan: time.Unix(1_700_000_000, 0), RenewingVtxos: 1, Renewed: 7, Failed: 2,
		Holdings: map[int64]application.Holdings{1: {Vtxos: 3, Amount: 9000, Late: 1, LateAmount: 4000}}}
}
func (f *fakeApp) CountActive(context.Context) (int64, error)        { return 5, nil }
func (f *fakeApp) IntentFees(context.Context) (arkfee.Config, error) { return arkfee.Config{}, nil }
func (f *fakeApp) Health(context.Context) map[string]error {
	h := map[string]error{"database": nil, "ark": nil}
	if f.arkDown {
		h["ark"] = errors.New("down")
	}
	return h
}
func (f *fakeApp) CancelDelegation(_ context.Context, address string) error {
	f.cancelled = address
	return nil
}

func freePort(t *testing.T) uint32 {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()
	return uint32(lis.Addr().(*net.TCPAddr).Port)
}

// serveFake runs the real servers (grpc, gateway, UI) over a fake application.
func serveFake(t *testing.T, password string) (public, admin string, app *fakeApp) {
	t.Helper()
	cfg := &config.Config{Port: freePort(t), AdminPort: freePort(t), AdminPassword: password}
	svc, err := NewService("test", cfg)
	require.NoError(t, err)
	app = &fakeApp{}
	require.NoError(t, svc.(*service).serve(t.Context(), app))
	t.Cleanup(func() {
		svc.Stop()
		require.True(t, app.stopped)
	})
	require.True(t, app.started)
	public, admin = fmt.Sprintf("127.0.0.1:%d", cfg.Port), fmt.Sprintf("127.0.0.1:%d", cfg.AdminPort)
	require.Eventually(t, func() bool {
		for _, addr := range []string{public, admin} {
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				return false
			}
			_ = conn.Close()
		}
		return true
	}, 5*time.Second, 10*time.Millisecond)
	return public, admin, app
}

func do(t *testing.T, method, url string, tweak ...func(*http.Request)) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, nil)
	require.NoError(t, err)
	for _, f := range tweak {
		f(req)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, string(body)
}

func TestPortsAndRouting(t *testing.T) {
	public, admin, app := serveFake(t, "")

	// REST on the public port, with CORS for browser wallets
	resp, body := do(t, http.MethodGet, "http://"+public+"/v1/info?renewalWindow=42&maxFee=7")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	var info struct{ Version, Network, RenewalWindow, MaxFee string }
	require.NoError(t, json.Unmarshal([]byte(body), &info))
	require.Equal(t, "test", info.Version)
	require.Equal(t, "42", info.RenewalWindow)
	require.Equal(t, "7", info.MaxFee)
	resp, _ = do(t, http.MethodOptions, "http://"+public+"/v1/delegate")
	require.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))

	// no UI and no admin API there
	resp, _ = do(t, http.MethodGet, "http://"+public+"/")
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp, _ = do(t, http.MethodGet, "http://"+public+"/v1/admin/delegate")
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	// the admin port serves the UI, both APIs, and never CORS
	resp, body = do(t, http.MethodGet, "http://"+admin+"/")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, resp.Header.Get("Content-Type"), "text/html")
	require.Contains(t, resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'")
	require.Contains(t, body, "<title>delegateed operator</title>")
	for _, path := range []string{"/v1/info", "/v1/admin/delegate", "/v1/admin/status", "/healthz"} {
		resp, _ = do(t, http.MethodGet, "http://"+admin+path)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		require.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"), path)
	}
	// metrics, admin port only
	app.arkDown = true
	resp, body = do(t, http.MethodGet, "http://"+admin+"/metrics")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	for _, line := range []string{
		"delegatee_delegations_active 5", "delegatee_delegations_foreign 4", "delegatee_vtxos_watched 3",
		"delegatee_sats_watched 9000", "delegatee_vtxos_late 1", "delegatee_sats_late 4000", "delegatee_vtxos_renewing 1",
		"delegatee_last_scan_timestamp_seconds 1.7e+09", `delegatee_renewals_total{result="ok"} 7`,
		`delegatee_renewals_total{result="failed"} 2`, `delegatee_dependency_up{name="ark"} 0`, `delegatee_dependency_up{name="database"} 1`,
	} {
		require.Contains(t, body, line)
	}
	resp, _ = do(t, http.MethodGet, "http://"+public+"/metrics")
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	app.arkDown = false

	resp, _ = do(t, http.MethodOptions, "http://"+admin+"/v1/admin/delegate/tark1x")
	require.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"), "a foreign page must fail its preflight")
	resp, _ = do(t, http.MethodDelete, "http://"+admin+"/v1/admin/delegate/tark1x")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "tark1x", app.cancelled)

	// grpc on the same ports
	conn, err := grpc.NewClient(public, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	got, err := delegateev1.NewDelegateeServiceClient(conn).GetInfo(t.Context(), &delegateev1.GetInfoRequest{})
	require.NoError(t, err)
	require.Equal(t, "regtest", got.GetNetwork())
	_, err = delegateev1.NewAdminServiceClient(conn).ListDelegations(t.Context(), &delegateev1.ListDelegationsRequest{})
	require.Equal(t, codes.Unimplemented, status.Code(err), "admin service is not on the public port")

	// bodies are capped
	resp, _ = do(t, http.MethodPost, "http://"+public+"/v1/delegate", func(r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		r.Body = io.NopCloser(strings.NewReader(`{"tapscripts":["` + strings.Repeat("00", maxRequestBodySize) + `"]}`))
	})
	require.NotEqual(t, http.StatusOK, resp.StatusCode)
}

func TestAdminPassword(t *testing.T) {
	public, admin, _ := serveFake(t, "s3cret")
	auth := func(user, pass string) func(*http.Request) {
		return func(r *http.Request) { r.SetBasicAuth(user, pass) }
	}
	for _, path := range []string{"/", "/v1/info", "/v1/admin/delegate", "/healthz"} {
		resp, _ := do(t, http.MethodGet, "http://"+admin+path)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, path)
		require.Contains(t, resp.Header.Get("WWW-Authenticate"), "Basic")
		for _, bad := range [][2]string{{"admin", "wrong"}, {"root", "s3cret"}, {"admin", ""}} {
			resp, _ = do(t, http.MethodGet, "http://"+admin+path, auth(bad[0], bad[1]))
			require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "%s %v", path, bad)
		}
		resp, _ = do(t, http.MethodGet, "http://"+admin+path, auth("admin", "s3cret"))
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
	}
	resp, _ := do(t, http.MethodGet, "http://"+public+"/v1/info")
	require.Equal(t, http.StatusOK, resp.StatusCode, "the public port has no password")

	conn, err := grpc.NewClient(admin, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = delegateev1.NewAdminServiceClient(conn).ListDelegations(t.Context(), &delegateev1.ListDelegationsRequest{})
	require.Error(t, err)
	authed, err := grpc.NewClient(admin, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(loopbackAuth("s3cret")))
	require.NoError(t, err)
	t.Cleanup(func() { _ = authed.Close() })
	_, err = delegateev1.NewAdminServiceClient(authed).ListDelegations(t.Context(), &delegateev1.ListDelegationsRequest{})
	require.NoError(t, err)
}

func TestRateLimit(t *testing.T) {
	l := newRateLimiter(2) // 2/s, burst 20
	now := time.Now()
	for range 20 {
		require.True(t, l.allow("1.1.1.1", now))
	}
	require.False(t, l.allow("1.1.1.1", now), "burst spent")
	require.True(t, l.allow("2.2.2.2", now), "per client")
	require.True(t, l.allow("1.1.1.1", now.Add(time.Second)), "refilled")

	srv := httptest.NewServer(l.middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	defer srv.Close()
	var last int
	for range 30 {
		resp, err := http.Get(srv.URL)
		require.NoError(t, err)
		_ = resp.Body.Close()
		last = resp.StatusCode
	}
	require.Equal(t, http.StatusTooManyRequests, last)

	// the public port has it, the admin port does not
	cfg := &config.Config{Port: freePort(t), AdminPort: freePort(t), PublicRateLimit: 1}
	svc, err := NewService("test", cfg)
	require.NoError(t, err)
	require.NoError(t, svc.(*service).serve(t.Context(), &fakeApp{}))
	t.Cleanup(svc.Stop)
	public, admin := fmt.Sprintf("127.0.0.1:%d", cfg.Port), fmt.Sprintf("127.0.0.1:%d", cfg.AdminPort)
	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + public + "/v1/info")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond)
	for range 15 {
		resp, _ := do(t, http.MethodGet, "http://"+public+"/v1/info")
		last = resp.StatusCode
	}
	require.Equal(t, http.StatusTooManyRequests, last)
	for range 15 {
		resp, _ := do(t, http.MethodGet, "http://"+admin+"/v1/info")
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}
}

func TestConfigValidate(t *testing.T) {
	require.Error(t, Config{Port: 1234, AdminPort: 1234}.Validate(), "same port twice")
	busy, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer func() { _ = busy.Close() }()
	taken := uint32(busy.Addr().(*net.TCPAddr).Port)
	require.Error(t, Config{Port: taken, AdminPort: freePort(t)}.Validate(), "port in use")
	require.NoError(t, Config{Port: freePort(t), AdminPort: freePort(t)}.Validate())
	_, err = NewService("v", &config.Config{Port: 1, AdminPort: 1})
	require.Error(t, err)
}

func TestIsHttpRequest(t *testing.T) {
	for _, tc := range []struct {
		method, contentType string
		want                bool
	}{
		{http.MethodGet, "", true},
		{http.MethodDelete, "", true},
		{http.MethodPost, "application/json", true},
		{http.MethodPost, "application/grpc", false},
		{http.MethodPost, "text/plain", false}, // what a cross-site form can send
	} {
		r := httptest.NewRequest(tc.method, "/", nil)
		r.Header.Set("Content-Type", tc.contentType)
		require.Equal(t, tc.want, isHttpRequest(r), "%s %s", tc.method, tc.contentType)
	}
}
