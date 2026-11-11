package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	executorv1 "github.com/arkade-os/executor/api-spec/protobuf/gen/executor/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestStatusAnswersWhileArkdIsUnreachable(t *testing.T) {
	d := Start(t)
	_, templateID := registerRenewal(t, d)
	code, body := post(t, d.RestURL+"/v1/delegation", map[string]any{"templateId": templateID, "variables": renewalVariables(t)})
	require.Equal(t, http.StatusOK, code, string(body))

	health, err := d.Admin.GetHealth(t.Context(), &executorv1.GetHealthRequest{})
	require.NoError(t, err)
	require.True(t, health.GetHealthy())
	require.Equal(t, []string{"db", "arkd", "electrum", "emulator", "loop"}, healthNames(health))

	d.Arkd.Unreachable(true)
	st, err := d.Admin.GetStatus(t.Context(), &executorv1.GetStatusRequest{})
	require.NoError(t, err)
	require.Equal(t, int64(1), st.GetActive())
	health, err = d.Admin.GetHealth(t.Context(), &executorv1.GetHealthRequest{})
	require.NoError(t, err)
	require.False(t, health.GetHealthy())
	for _, e := range health.GetEntries() {
		if e.GetName() == "arkd" {
			require.False(t, e.GetHealthy())
			require.Contains(t, e.GetError(), "connection refused")
			continue
		}
		require.True(t, e.GetHealthy(), "%s: %s", e.GetName(), e.GetError())
	}
	code, body = get(t, d.AdminURL+"/v1/admin/health")
	require.Equal(t, http.StatusOK, code, string(body))
	require.Contains(t, string(body), "connection refused")

	d.Chain.Drop()
	health, err = d.Admin.GetHealth(t.Context(), &executorv1.GetHealthRequest{})
	require.NoError(t, err)
	require.Equal(t, "electrum", unhealthy(health)[1])
}

func TestHealthzFollowsArkd(t *testing.T) {
	d := Start(t)
	d.Arkd.Unreachable(true)

	code, body := get(t, d.AdminURL+"/healthz")
	require.Equal(t, http.StatusServiceUnavailable, code, string(body))
	var got struct {
		Healthy bool              `json:"healthy"`
		Checks  map[string]string `json:"checks"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	require.False(t, got.Healthy)
	require.Equal(t, "ok", got.Checks["db"])
	require.Equal(t, "ok", got.Checks["loop"])
	require.Contains(t, got.Checks["arkd"], "connection refused")

	d.Arkd.Unreachable(false)
	code, body = get(t, d.AdminURL+"/healthz")
	require.Equal(t, http.StatusOK, code, string(body))
	require.NoError(t, json.Unmarshal(body, &got))
	require.True(t, got.Healthy)
}

func TestListDelegationsByNextDueWithItsDetail(t *testing.T) {
	d := Start(t)
	_, templateID := registerRenewal(t, d)
	register := func() delegation {
		code, body := post(t, d.RestURL+"/v1/delegation", map[string]any{"templateId": templateID, "variables": renewalVariables(t)})
		require.Equal(t, http.StatusOK, code, string(body))
		return decodeDelegation(t, body)
	}
	idle, later, sooner := register(), register(), register()
	d.Arkd.Land(later.Inputs[0].Script, strings.Repeat("aa", 32)+":0", 10_000, time.Now().Add(3*time.Hour))
	d.Arkd.Land(sooner.Inputs[0].Script, strings.Repeat("bb", 32)+":0", 4_000, time.Now().Add(2*time.Hour))
	d.Arkd.Land(sooner.Inputs[0].Script, strings.Repeat("cc", 32)+":0", 6_000, time.Now().Add(4*time.Hour))
	require.Eventually(t, func() bool { return coinRows(t, d, "present") == 3 }, 5*time.Second, 50*time.Millisecond)

	code, body := get(t, d.AdminURL+"/v1/admin/delegations")
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, []string{sooner.ID, later.ID, idle.ID}, delegationIDs(decodeDelegations(t, body)))
	var list struct {
		Delegations []struct {
			Coins   string `json:"coins"`
			Amount  string `json:"amount"`
			NextDue string `json:"nextDue"`
		} `json:"delegations"`
	}
	require.NoError(t, json.Unmarshal(body, &list))
	require.Equal(t, "2", list.Delegations[0].Coins)
	require.Equal(t, "10000", list.Delegations[0].Amount)
	require.Equal(t, "1", list.Delegations[1].Coins)
	require.Less(t, list.Delegations[0].NextDue, list.Delegations[1].NextDue)
	require.Equal(t, "0", list.Delegations[2].NextDue)

	var paged []string
	cursor := ""
	for {
		code, body = get(t, d.AdminURL+"/v1/admin/delegations?limit=1&cursor="+cursor)
		require.Equal(t, http.StatusOK, code, string(body))
		paged = append(paged, delegationIDs(decodeDelegations(t, body))...)
		if cursor = decodeNextCursor(t, body); cursor == "" {
			break
		}
	}
	require.Equal(t, []string{sooner.ID, later.ID, idle.ID}, paged)
	code, _ = get(t, d.AdminURL+"/v1/admin/delegations?cursor=garbage")
	require.Equal(t, http.StatusBadRequest, code)

	code, body = get(t, d.AdminURL+"/v1/delegation?id="+sooner.ID)
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, sooner.ID, decodeDelegation(t, body).ID)
	require.Equal(t, []string{strings.Repeat("bb", 32) + ":0", strings.Repeat("cc", 32) + ":0"}, coinOutpoints(decodeCoins(t, body)))
	code, _ = get(t, d.AdminURL+"/v1/delegation?id=404")
	require.Equal(t, http.StatusNotFound, code)
}

func TestMetricsFollowACoin(t *testing.T) {
	d := Start(t)
	_, templateID := registerRenewal(t, d)
	w := registerDelegationWith(t, d, templateID, renewalVariables(t))

	require.Equal(t, "1", metric(t, d, "executor_delegations_active"))
	require.Equal(t, "0", metric(t, d, "executor_coins_watched"))
	require.Equal(t, "1", metric(t, d, `executor_dependency_up{name="arkd"}`))
	require.Equal(t, "1", metric(t, d, `executor_dependency_up{name="loop"}`))
	require.NotEmpty(t, metric(t, d, "executor_chain_tip_height"))
	require.Equal(t, "0", metric(t, d, `executor_entries_queued`))
	require.Equal(t, "0", metric(t, d, `executor_coins_late`))

	outpoint := strings.Repeat("aa", 32) + ":0"
	d.Arkd.Land(w.Inputs[0].Script, outpoint, 10_000, time.Now().Add(time.Hour))
	require.Eventually(t, func() bool {
		return metric(t, d, "executor_coins_watched") == "1" && metric(t, d, "executor_sats_watched") == "10000"
	}, 5*time.Second, 50*time.Millisecond)

	d.Arkd.Spend(outpoint, strings.Repeat("bb", 32))
	require.Eventually(t, func() bool {
		return metric(t, d, "executor_coins_watched") == "0" && metric(t, d, "executor_sats_watched") == "0"
	}, 5*time.Second, 50*time.Millisecond)

	d.Arkd.Unreachable(true)
	require.Equal(t, "0", metric(t, d, `executor_dependency_up{name="arkd"}`))
	require.Equal(t, "1", metric(t, d, `executor_dependency_up{name="db"}`))
	require.Equal(t, "1", metric(t, d, "executor_delegations_active"), "the gauges do not need arkd")
}

func TestMetricsCountAFailedAttempt(t *testing.T) {
	d := Start(t, WithEncryptionKey)
	w, _ := claimDelegation(t, d)

	d.Emu.Refuse(status.Error(codes.InvalidArgument, "no preimage"))
	d.Arkd.Fund(w.Inputs[0].Script, 10_000, time.Now().Add(time.Hour))
	require.Eventually(t, func() bool {
		return metric(t, d, `executor_attempts_total{status="failed"}`) == "1"
	}, 5*time.Second, 50*time.Millisecond)
	require.Equal(t, "1", metric(t, d, "executor_template_failures_total"))
	require.Equal(t, "0", metric(t, d, `executor_attempts_total{status="succeeded"}`))
	require.Equal(t, "1", metric(t, d, "executor_coins_watched"))
}

func TestMetricsCountASucceededAttempt(t *testing.T) {
	d := Start(t, WithEncryptionKey)
	w, _ := claimDelegation(t, d)

	outpoint := d.Arkd.Fund(w.Inputs[0].Script, 10_000, time.Now().Add(time.Hour))
	require.Eventually(t, func() bool { return len(listAttempts(t, d, w.ID)) == 1 }, 5*time.Second, 50*time.Millisecond)
	d.Arkd.Spend(outpoint, listAttempts(t, d, w.ID)[0].Txid)
	require.Eventually(t, func() bool {
		return metric(t, d, `executor_attempts_total{status="succeeded"}`) == "1"
	}, 5*time.Second, 50*time.Millisecond)
	require.Equal(t, "0", metric(t, d, `executor_attempts_total{status="failed"}`))
	require.Equal(t, "0", metric(t, d, "executor_coins_watched"))

	code, body := get(t, d.AdminURL+"/v1/admin/delegation/"+w.ID+"/attempts")
	require.Equal(t, http.StatusOK, code, string(body))
	var detail struct {
		Attempts []attempt `json:"attempts"`
	}
	require.NoError(t, json.Unmarshal(body, &detail))
	require.Len(t, detail.Attempts, 1)
	require.Equal(t, "succeeded", detail.Attempts[0].Status)
	code, body = get(t, d.AdminURL+"/v1/admin/delegations")
	require.Equal(t, http.StatusOK, code, string(body))
	require.Contains(t, string(body), `"lastAttempt":"succeeded"`)
}

func TestUIIsServedBehindAuth(t *testing.T) {
	d := Start(t, WithAdminUser(t, "alice", "secret"))
	for _, path := range []string{"/", "/metrics", "/healthz"} {
		resp := send(t, d.AdminURL+path, "", "")
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, path)
		require.Contains(t, resp.Header.Get("WWW-Authenticate"), "Basic")
		resp = send(t, d.AdminURL+path, "alice", "wrong")
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, path)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, d.AdminURL+"/", nil)
	require.NoError(t, err)
	req.SetBasicAuth("alice", "secret")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	page, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, resp.Header.Get("Content-Type"), "text/html")
	require.Contains(t, string(page), "<title>executord operator</title>")

	code, _ := get(t, d.RestURL+"/")
	require.Equal(t, http.StatusNotFound, code, "the public port has no UI")
	code, _ = get(t, d.RestURL+"/metrics")
	require.NotEqual(t, http.StatusOK, code, "nor metrics")
}

func TestPublicRateLimitRefusesAClientOverItsRate(t *testing.T) {
	ip := externalIP(t)
	d := Start(t, WithPublicRateLimit(1))
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://%s:%d/v1/info", ip, portOf(d.RestURL))
	if resp, err := client.Get(url); err != nil {
		t.Skipf("this host's own address %s is not reachable: %v", ip, err)
	} else {
		_ = resp.Body.Close()
	}

	limited := 0
	for range 30 {
		resp, err := client.Get(url)
		require.NoError(t, err)
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusTooManyRequests:
			limited++
			require.Equal(t, "1", resp.Header.Get("Retry-After"))
		default:
			t.Fatalf("unexpected status %d", resp.StatusCode)
		}
	}
	require.Positive(t, limited, "one address past its burst is refused")
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/v1/admin/status", ip, portOf(d.AdminURL)))
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "the admin port is not limited")
}

func TestPublicRateLimitSparesLoopbackAndTheAdminPort(t *testing.T) {
	d := Start(t, WithPublicRateLimit(1))
	for range 60 {
		require.Equal(t, http.StatusOK, send(t, d.RestURL+"/v1/info", "", "").StatusCode, "the gateway's own calls come from loopback")
		require.Equal(t, http.StatusOK, send(t, d.AdminURL+"/v1/admin/status", "", "").StatusCode)
	}
}

// metric reads the value of the sample whose name and labels are series, empty when it is not exposed.
func metric(t *testing.T, d *Daemon, series string) string {
	t.Helper()
	code, body := get(t, d.AdminURL+"/metrics")
	require.Equal(t, http.StatusOK, code, string(body))
	for _, line := range strings.Split(string(body), "\n") {
		if name, value, ok := strings.Cut(line, " "); ok && name == series {
			return value
		}
	}
	return ""
}

func healthNames(resp *executorv1.GetHealthResponse) []string {
	names := make([]string, 0, len(resp.GetEntries()))
	for _, e := range resp.GetEntries() {
		names = append(names, e.GetName())
	}
	return names
}

func unhealthy(resp *executorv1.GetHealthResponse) []string {
	var names []string
	for _, e := range resp.GetEntries() {
		if !e.GetHealthy() {
			names = append(names, e.GetName())
		}
	}
	return names
}

// externalIP is an address of this host that is not loopback, where the daemon sees a client that is not the gateway.
func externalIP(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for _, addr := range addrs {
		if n, ok := addr.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsGlobalUnicast() {
			return n.IP.String()
		}
	}
	t.Skip("no non-loopback address on this host")
	return ""
}

func portOf(url string) int {
	_, port, _ := strings.Cut(strings.TrimPrefix(url, "http://"), ":")
	var n int
	_, _ = fmt.Sscan(port, &n)
	return n
}
