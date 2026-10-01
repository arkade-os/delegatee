package e2e

import (
	"encoding/hex"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/config"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRestartAndKeys(t *testing.T) {
	first := startDelegatee(t)
	w, renewal := boardingWatch(t, first, newOwner(t, first))
	first.stop()
	faucet(t, w.Address, 20_000)

	stranger := restart(t, first, func(c *config.Config) {
		key, _ := btcec.NewPrivateKey()
		c.DelegateKeys = []*btcec.PrivateKey{key}
	})
	require.Eventually(t, func() bool {
		row, err := summaryOf(t, stranger, w.Id)
		return err == nil && !row.Managed && strings.Contains(row.UnmanagedReason, "another key")
	}, 30*time.Second, time.Second, "the watch is not reported unmanaged")
	neverBoarded(t, w.Address)
	stranger.stop()

	rotated, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	again := restart(t, first, func(c *config.Config) {
		c.DelegateKeys = []*btcec.PrivateKey{rotated, first.cfg.DelegateKeys[0]}
	})
	landed(t, again, w, renewal, 1)
	landed(t, again, renewal, renewal, 1)
}

func TestCancelStopsRenewals(t *testing.T) {
	// scans far enough apart to cancel a coin before the next one renews it
	d := startDelegatee(t, func(c *config.Config) { c.PollInterval = 10 * time.Second })
	owner := newOwner(t, d)
	w, renewal := boardingWatch(t, d, owner)
	faucet(t, w.Address, 20_000)

	boarded := landed(t, d, w, renewal, 1)[0]
	_, err := d.admin.CancelDelegation(t.Context(), &delegateev1.CancelDelegationRequest{Id: renewal.Id})
	require.NoError(t, err)
	neverSpent(t, d, boarded.Outpoint.String())

	tmpl := fixtureID(t, "renewal.json")
	_, err = d.client.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{TemplateId: tmpl, Variables: owner.variables(0)})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "the owner cannot undo an operator cancel")
	_, err = d.admin.ResumeDelegation(t.Context(), &delegateev1.ResumeDelegationRequest{Id: renewal.Id})
	require.NoError(t, err)
	require.Equal(t, renewal.Id, renewalWatch(t, d, owner, 0).Id, "the cancelled row renews again")
	landed(t, d, renewal, renewal, 1)
}

func TestStopWaitsForTheBatch(t *testing.T) {
	d := startDelegatee(t)
	w, renewal := boardingWatch(t, d, newOwner(t, d))
	faucet(t, w.Address, 20_000)

	require.Eventually(t, func() bool {
		st, err := d.admin.GetStatus(t.Context(), &delegateev1.GetStatusRequest{})
		return err == nil && st.RenewingVtxos == 1
	}, time.Minute, 20*time.Millisecond, "never saw the boarding in flight")
	d.stop()

	// the daemon is gone: a coin boarded now was boarded before stop returned
	script, err := hex.DecodeString(scriptOf(t, renewal))
	require.NoError(t, err)
	waitForVtxo(t, d, script, "")
}

func TestSeveralCoinsAtOneAddress(t *testing.T) {
	d := startDelegatee(t)
	w, renewal := boardingWatch(t, d, newOwner(t, d))
	for _, sats := range []int64{10_000, 10_000, 30_000} {
		faucet(t, w.Address, sats)
	}

	boarded := landed(t, d, w, renewal, 3)
	var amounts []uint64
	for _, b := range boarded {
		amounts = append(amounts, b.Amount)
	}
	slices.Sort(amounts)
	require.Equal(t, []uint64{10_000, 10_000, 30_000}, amounts)
	landed(t, d, renewal, renewal, 3)
}

func TestWalletFlowOverREST(t *testing.T) {
	d := startDelegatee(t)
	boarding := fixtureID(t, "boarding.json")
	base := "http://" + d.addr
	var list struct{ Templates []struct{ Id string } }
	getJSON(t, base+"/v1/template", &list)
	require.True(t, slices.ContainsFunc(list.Templates, func(tpl struct{ Id string }) bool { return tpl.Id == boarding }))

	owner := newOwner(t, d)
	code, out := postJSON(t, base+"/v1/delegate", map[string]any{"templateId": boarding, "variables": owner.boardingVariables()})
	require.Equal(t, http.StatusOK, code, "%v", out)
	address := out["delegation"].(map[string]any)["address"].(string)
	require.Equal(t, owner.boardingAddress(t), address)
	var detail struct {
		Delegation struct{ Status, TemplateId string }
	}
	getJSON(t, base+"/v1/delegate/"+address, &detail)
	require.Equal(t, "active", detail.Delegation.Status)
	require.Equal(t, boarding, detail.Delegation.TemplateId)

	invalid := owner.boardingVariables()
	invalid["owner"] = "zz"
	code, _ = postJSON(t, base+"/v1/delegate", map[string]any{"templateId": boarding, "variables": invalid})
	require.Equal(t, http.StatusBadRequest, code)
	code, _ = postJSON(t, base+"/v1/delegate", map[string]any{"templateId": "nope", "variables": owner.boardingVariables()})
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, http.StatusNotFound, statusOf(t, http.MethodDelete, base+"/v1/admin/delegate/"+address), "no admin API on the public port")
}
