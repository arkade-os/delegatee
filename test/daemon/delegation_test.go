package daemon

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/config"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRegisterDelegationOverREST(t *testing.T) {
	d := Start(t)
	_, templateID := registerRenewal(t, d)
	variables := renewalVariables(t)

	first := registerDelegationWith(t, d, templateID, variables)
	require.NotEmpty(t, first.ID)
	require.Len(t, first.Fingerprint, 64)
	require.Equal(t, templateID, first.TemplateID)
	require.Equal(t, variables, first.Variables)
	require.Equal(t, "active", first.Status)
	require.Equal(t, "0", first.StreamID)
	require.Equal(t, "0", first.ExpiresAt)
	require.NotEmpty(t, first.CreatedAt)
	require.Len(t, first.Inputs, 1)
	require.Equal(t, "funds", first.Inputs[0].Name)
	require.False(t, first.Inputs[0].Onchain)
	require.NotEmpty(t, first.Inputs[0].Script)
	require.NotEmpty(t, first.Inputs[0].Tapscripts)
	require.Empty(t, first.Inputs[0].Outpoint)

	addr, err := arklib.DecodeAddressV0(first.Address)
	require.NoError(t, err)
	require.Equal(t, "5120"+hex.EncodeToString(schnorr.SerializePubKey(addr.VtxoTapKey)), first.Inputs[0].Script)
	require.Equal(t, schnorr.SerializePubKey(d.Server), schnorr.SerializePubKey(addr.Signer))

	code, body := get(t, d.RestURL+"/v1/delegation?id="+first.ID)
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, first, decodeDelegation(t, body))
	code, body = get(t, d.RestURL+"/v1/delegation?address="+first.Address)
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, first, decodeDelegation(t, body))

	code, body = post(t, d.RestURL+"/v1/delegation", map[string]any{"templateId": templateID, "variables": variables})
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, first.ID, decodeDelegation(t, body).ID)
	require.Equal(t, 1, tableRows(t, d, "delegations"))

	got, err := d.Client.GetDelegation(t.Context(), &delegateev1.GetDelegationRequest{Address: first.Address})
	require.NoError(t, err)
	require.Equal(t, first.Fingerprint, got.GetDelegation().GetFingerprint())
	code, _ = get(t, d.RestURL+"/v1/delegation?id=404")
	require.Equal(t, http.StatusNotFound, code)
	code, _ = get(t, d.RestURL+"/v1/delegation?address=nowhere")
	require.Equal(t, http.StatusNotFound, code)
}

func TestRegisterDelegationRefused(t *testing.T) {
	d := Start(t, func(c *config.Config) { c.MaxDelegations = 1 })
	_, templateID := registerRenewal(t, d)
	register := func(id string, variables map[string]string, expiresAt int64) (int, []byte) {
		return post(t, d.RestURL+"/v1/delegation", map[string]any{"templateId": id, "variables": variables, "expiresAt": expiresAt})
	}

	code, body := post(t, d.AdminURL+"/v1/admin/template/"+templateID, map[string]string{"status": "disabled"})
	require.Equal(t, http.StatusOK, code, string(body))
	code, body = register(templateID, renewalVariables(t), 0)
	require.Equal(t, http.StatusPreconditionFailed, code, string(body))
	code, body = post(t, d.AdminURL+"/v1/admin/template/"+templateID, map[string]string{"status": "active"})
	require.Equal(t, http.StatusOK, code, string(body))

	two := registerFixture(t, d, "counter.json")
	code, body = register(two, nil, 0)
	require.Equal(t, http.StatusBadRequest, code, string(body))

	release := registerFixture(t, d, "delegate_release.json")
	code, body = register(release, nil, 0)
	require.Equal(t, http.StatusPreconditionFailed, code, string(body))
	_, err := d.Client.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{TemplateId: release})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	code, body = register(templateID, renewalVariables(t), time.Now().Add(time.Hour).Unix())
	require.Equal(t, http.StatusBadRequest, code, string(body))
	code, body = register(templateID, map[string]string{"owner": "nope"}, 0)
	require.Equal(t, http.StatusBadRequest, code, string(body))
	code, body = register("missing", nil, 0)
	require.Equal(t, http.StatusNotFound, code, string(body))
	require.Equal(t, 0, tableRows(t, d, "delegations"))

	code, body = register(templateID, renewalVariables(t), 0)
	require.Equal(t, http.StatusOK, code, string(body))

	code, body = register(templateID, renewalVariables(t), 0)
	require.Equal(t, http.StatusTooManyRequests, code, string(body))
	_, err = d.Client.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{TemplateId: templateID, Variables: renewalVariables(t)})
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
	require.Equal(t, 1, tableRows(t, d, "delegations"))
}

func TestGetInfoOverREST(t *testing.T) {
	d := Start(t)
	code, body := get(t, d.RestURL+"/v1/info")
	require.Equal(t, http.StatusOK, code, string(body))
	var info struct {
		Version          string `json:"version"`
		Network          string `json:"network"`
		CosignerPubkey   string `json:"cosignerPubkey"`
		ServerPubkey     string `json:"serverPubkey"`
		EmulatorPubkey   string `json:"emulatorPubkey"`
		EncryptionPubkey string `json:"encryptionPubkey"`
	}
	require.NoError(t, json.Unmarshal(body, &info))
	require.Equal(t, "test", info.Version)
	require.Equal(t, "regtest", info.Network)
	require.Equal(t, hex.EncodeToString(d.Cosigner.SerializeCompressed()), info.CosignerPubkey)
	require.Equal(t, hex.EncodeToString(d.Server.SerializeCompressed()), info.ServerPubkey)
	require.Equal(t, hex.EncodeToString(d.Emulator.SerializeCompressed()), info.EmulatorPubkey)
	require.Empty(t, info.EncryptionPubkey)

	encryption := newKey(9)
	d = d.Restart(t, func(c *config.Config) { c.EncryptionKey = encryption })
	code, body = get(t, d.RestURL+"/v1/info")
	require.Equal(t, http.StatusOK, code, string(body))
	require.NoError(t, json.Unmarshal(body, &info))
	require.Equal(t, hex.EncodeToString(encryption.PubKey().SerializeCompressed()), info.EncryptionPubkey)
}

func TestCancelThenResumeDelegation(t *testing.T) {
	d := Start(t)
	_, templateID := registerRenewal(t, d)
	variables := renewalVariables(t)
	dlg := registerDelegationWith(t, d, templateID, variables)

	code, body := post(t, d.AdminURL+"/v1/admin/delegation/"+dlg.ID+"/cancel", map[string]any{})
	require.Equal(t, http.StatusOK, code, string(body))
	code, body = get(t, d.RestURL+"/v1/delegation?id="+dlg.ID)
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, "cancelled", decodeDelegation(t, body).Status)
	code, body = post(t, d.RestURL+"/v1/delegation", map[string]any{"templateId": templateID, "variables": variables})
	require.Equal(t, http.StatusPreconditionFailed, code, string(body))
	code, body = post(t, d.AdminURL+"/v1/admin/delegation/"+dlg.ID+"/cancel", map[string]any{})
	require.Equal(t, http.StatusPreconditionFailed, code, string(body))

	code, body = post(t, d.AdminURL+"/v1/admin/delegation/"+dlg.ID+"/resume", map[string]any{})
	require.Equal(t, http.StatusOK, code, string(body))
	code, body = get(t, d.RestURL+"/v1/delegation?id="+dlg.ID)
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, "active", decodeDelegation(t, body).Status)
	code, body = post(t, d.RestURL+"/v1/delegation", map[string]any{"templateId": templateID, "variables": variables})
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, dlg.ID, decodeDelegation(t, body).ID)
	code, body = post(t, d.AdminURL+"/v1/admin/delegation/"+dlg.ID+"/resume", map[string]any{})
	require.Equal(t, http.StatusPreconditionFailed, code, string(body))
	require.Equal(t, 1, tableRows(t, d, "delegations"))

	_, err := d.Admin.CancelDelegation(t.Context(), &delegateev1.CancelDelegationRequest{Id: 404})
	require.Equal(t, codes.NotFound, status.Code(err))
	code, _ = post(t, d.RestURL+"/v1/admin/delegation/"+dlg.ID+"/cancel", map[string]any{})
	require.Equal(t, http.StatusNotFound, code, "admin routes stay off the public port")
}

func TestExpireAndListDelegations(t *testing.T) {
	d := Start(t, func(c *config.Config) { c.MinDelegationExpiry, c.ExpiryInterval = 0, 100*time.Millisecond })
	_, templateID := registerRenewal(t, d)
	code, body := post(t, d.RestURL+"/v1/delegation", map[string]any{
		"templateId": templateID, "variables": renewalVariables(t), "expiresAt": time.Now().Add(2 * time.Second).Unix(),
	})
	require.Equal(t, http.StatusOK, code, string(body))
	expiring := decodeDelegation(t, body)

	var ids []string
	for range 4 {
		code, body = post(t, d.RestURL+"/v1/delegation", map[string]any{"templateId": templateID, "variables": renewalVariables(t)})
		require.Equal(t, http.StatusOK, code, string(body))
		ids = append(ids, decodeDelegation(t, body).ID)
	}
	require.Eventually(t, func() bool {
		_, body := get(t, d.RestURL+"/v1/delegation?id="+expiring.ID)
		return decodeDelegation(t, body).Status == "expired"
	}, 10*time.Second, 100*time.Millisecond)

	code, body = get(t, d.AdminURL+"/v1/admin/delegations?status=expired")
	require.Equal(t, http.StatusOK, code, string(body))
	expired := decodeDelegations(t, body)
	require.Len(t, expired, 1)
	require.Equal(t, expiring.ID, expired[0].ID)
	code, body = get(t, d.AdminURL+"/v1/admin/delegations?status=active")
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, ids, delegationIDs(decodeDelegations(t, body)), "without coins, oldest first")

	var paged []string
	cursor := ""
	for {
		code, body = get(t, d.AdminURL+"/v1/admin/delegations?limit=2&cursor="+cursor)
		require.Equal(t, http.StatusOK, code, string(body))
		page := decodeDelegations(t, body)
		require.LessOrEqual(t, len(page), 2)
		paged = append(paged, delegationIDs(page)...)
		if cursor = decodeNextCursor(t, body); cursor == "" {
			break
		}
	}
	require.Equal(t, append([]string{expiring.ID}, ids...), paged)

	code, body = get(t, d.AdminURL+"/v1/admin/delegations?limit=1001")
	require.Equal(t, http.StatusBadRequest, code, string(body))
	list, err := d.Admin.ListDelegations(t.Context(), &delegateev1.ListDelegationsRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetDelegations(), 5)
}

type delegation struct {
	ID          string            `json:"id"`
	Fingerprint string            `json:"fingerprint"`
	Address     string            `json:"address"`
	TemplateID  string            `json:"templateId"`
	Variables   map[string]string `json:"variables"`
	Inputs      []input           `json:"inputs"`
	StreamID    string            `json:"streamId"`
	ExpiresAt   string            `json:"expiresAt"`
	Status      string            `json:"status"`
	CreatedAt   string            `json:"createdAt"`
	UpdatedAt   string            `json:"updatedAt"`
}

type input struct {
	Name       string   `json:"name"`
	Onchain    bool     `json:"onchain"`
	Script     string   `json:"script"`
	Tapscripts []string `json:"tapscripts"`
	Outpoint   string   `json:"outpoint"`
}

func decodeDelegations(t *testing.T, body []byte) []delegation {
	t.Helper()
	var resp struct {
		Delegations []struct {
			Delegation delegation `json:"delegation"`
		} `json:"delegations"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	out := make([]delegation, 0, len(resp.Delegations))
	for _, s := range resp.Delegations {
		out = append(out, s.Delegation)
	}
	return out
}

func decodeNextCursor(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		NextCursor string `json:"nextCursor"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.NextCursor
}

func delegationIDs(list []delegation) []string {
	ids := make([]string, 0, len(list))
	for _, d := range list {
		ids = append(ids, d.ID)
	}
	return ids
}

func decodeDelegation(t *testing.T, body []byte) delegation {
	t.Helper()
	var resp struct {
		Delegation delegation `json:"delegation"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Delegation
}

func registerFixture(t *testing.T, d *Daemon, name string) string {
	t.Helper()
	doc, err := os.ReadFile("../../pkg/template/testdata/" + name)
	require.NoError(t, err)
	code, body := post(t, d.RestURL+"/v1/template", map[string]string{"document": string(doc)})
	require.Equal(t, http.StatusOK, code, string(body))
	return decodeTemplate(t, body).ID
}

func renewalVariables(t *testing.T) map[string]string {
	t.Helper()
	owner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return map[string]string{
		"owner": hex.EncodeToString(owner.PubKey().SerializeCompressed()), "exit_delay": ScriptNum(1<<22 | 1),
		"renewal_window": ScriptNum(1024), "max_fee": ScriptNum(1000),
	}
}

func tableRows(t *testing.T, d *Daemon, table string) int {
	t.Helper()
	var n int
	require.NoError(t, d.DB.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table).Scan(&n))
	return n
}
