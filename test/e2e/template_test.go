//go:build e2e

package e2e

import (
	"net/http"
	"slices"
	"testing"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestTemplateRegistry(t *testing.T) {
	ctx := t.Context()
	d := start(t)
	require.Equal(t, registerTemplate(t, d, "renew.json"), registerTemplate(t, d, "renew.json"))
	_, err := d.client.RegisterTemplate(ctx, &delegateev1.RegisterTemplateRequest{Document: `{"format":"template/v1"}`})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)

	boarding := registerTemplate(t, d, "board.json")
	registerDelegation(t, d, boarding, newOwner(t, d).boardingVariables())
	_, err = d.admin.UpdateTemplate(ctx, &delegateev1.UpdateTemplateRequest{Id: boarding, Status: "disabled"})
	require.NoError(t, err)

	_, err = d.client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{TemplateId: boarding, Variables: newOwner(t, d).boardingVariables()})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)
	_, err = d.admin.DeleteTemplate(ctx, &delegateev1.DeleteTemplateRequest{Id: boarding})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)
	listed, err := d.client.ListTemplates(ctx, &delegateev1.ListTemplatesRequest{})
	require.NoError(t, err)
	require.True(t, slices.ContainsFunc(listed.Templates, func(tpl *delegateev1.Template) bool {
		return tpl.Id == boarding && tpl.Status == "disabled"
	}), "the disabled template is listed")
}

func TestTemplateCannotNameTheCosignerKey(t *testing.T) {
	d := start(t)
	release := registerTemplate(t, d, "delegate_release.json")

	_, err := d.client.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{TemplateId: release})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)
}

func TestWalletFlowOverREST(t *testing.T) {
	d := start(t)
	boarding := registerTemplate(t, d, "board.json")
	var list struct{ Templates []struct{ Id string } }
	getJSON(t, d.url+"/v1/templates", &list)
	require.True(t, slices.ContainsFunc(list.Templates, func(tpl struct{ Id string }) bool { return tpl.Id == boarding }))

	owner := newOwner(t, d)
	code, out := postJSON(t, d.url+"/v1/delegation", map[string]any{"templateId": boarding, "variables": owner.boardingVariables()})
	require.Equal(t, http.StatusOK, code, "%v", out)
	address := out["delegation"].(map[string]any)["address"].(string)
	require.Equal(t, owner.boardingAddress(t), address)
	var detail struct {
		Delegation struct{ Status, TemplateId string }
	}
	getJSON(t, d.url+"/v1/delegation?address="+address, &detail)
	require.Equal(t, "active", detail.Delegation.Status)
	require.Equal(t, boarding, detail.Delegation.TemplateId)

	invalid := owner.boardingVariables()
	invalid["owner"] = "zz"
	code, _ = postJSON(t, d.url+"/v1/delegation", map[string]any{"templateId": boarding, "variables": invalid})
	require.Equal(t, http.StatusBadRequest, code)
	code, _ = postJSON(t, d.url+"/v1/delegation", map[string]any{"templateId": "nope", "variables": owner.boardingVariables()})
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, http.StatusNotFound, statusOf(t, http.MethodDelete, d.url+"/v1/admin/template/"+boarding), "no admin API on the public port")
}
