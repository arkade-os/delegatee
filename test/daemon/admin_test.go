package daemon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"slices"
	"testing"

	executorv1 "github.com/arkade-os/executor/api-spec/protobuf/gen/executor/v1"
	"github.com/arkade-os/executor/internal/config"
	tpl "github.com/arkade-os/executor/pkg/template"
	"github.com/arkade-os/executor/templates"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestDisableThenEnableTemplate(t *testing.T) {
	d := Start(t)
	_, id := registerRenewal(t, d)

	code, body := post(t, d.AdminURL+"/v1/admin/template/"+id, map[string]string{"status": "disabled"})
	require.Equal(t, http.StatusOK, code, string(body))
	code, body = get(t, d.RestURL+"/v1/templates?status=active")
	require.Equal(t, http.StatusOK, code, string(body))
	require.Empty(t, decodeTemplates(t, body))
	code, body = get(t, d.AdminURL+"/v1/templates")
	require.Equal(t, http.StatusOK, code, string(body))
	all := decodeTemplates(t, body)
	require.Len(t, all, 1)
	require.Equal(t, id, all[0].ID)
	require.Equal(t, "disabled", all[0].Status)
	require.Empty(t, all[0].Document)

	_, err := d.DB.ExecContext(t.Context(), "UPDATE templates SET failures = 3 WHERE id = $1", id)
	require.NoError(t, err)
	code, body = post(t, d.AdminURL+"/v1/admin/template/"+id, map[string]string{"status": "active"})
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, 0, failures(t, d, id))
	code, body = get(t, d.RestURL+"/v1/templates?status=active")
	require.Equal(t, http.StatusOK, code, string(body))
	require.Len(t, decodeTemplates(t, body), 1)

	code, body = post(t, d.AdminURL+"/v1/admin/template/"+id, map[string]string{"status": "paused"})
	require.Equal(t, http.StatusBadRequest, code, string(body))
	code, _ = post(t, d.RestURL+"/v1/admin/template/"+id, map[string]string{"status": "disabled"})
	require.Equal(t, http.StatusNotFound, code, "admin routes stay off the public port")
}

func TestDeleteArtifactRefusedWhileReferenced(t *testing.T) {
	d := Start(t)
	artifactID, templateID := registerRenewal(t, d)

	code, body := del(t, d.AdminURL+"/v1/admin/artifact/"+artifactID)
	require.Equal(t, http.StatusPreconditionFailed, code, string(body))
	require.Equal(t, 1, tableRows(t, d, "artifacts"))
	_, err := d.Admin.DeleteArtifact(t.Context(), &executorv1.DeleteArtifactRequest{Id: artifactID})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	code, body = get(t, d.AdminURL+"/v1/admin/artifacts")
	require.Equal(t, http.StatusOK, code, string(body))
	var list struct {
		Artifacts []artifact `json:"artifacts"`
	}
	require.NoError(t, json.Unmarshal(body, &list))
	require.Len(t, list.Artifacts, 1)
	require.Equal(t, artifactID, list.Artifacts[0].ID)
	require.Empty(t, list.Artifacts[0].Document)

	code, body = del(t, d.AdminURL+"/v1/admin/template/"+templateID)
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, 0, tableRows(t, d, "templates"))
	code, body = del(t, d.AdminURL+"/v1/admin/artifact/"+artifactID)
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, 0, tableRows(t, d, "artifacts"))
	code, _ = del(t, d.AdminURL+"/v1/admin/artifact/"+artifactID)
	require.Equal(t, http.StatusNotFound, code)
}

func TestDeleteTemplateRefusedWhileReferenced(t *testing.T) {
	d := Start(t)
	_, templateID := registerRenewal(t, d)
	dlg := registerDelegationWith(t, d, templateID, renewalVariables(t))
	code, body := post(t, d.AdminURL+"/v1/admin/delegation/"+dlg.ID+"/cancel", map[string]any{})
	require.Equal(t, http.StatusOK, code, string(body))

	code, body = del(t, d.AdminURL+"/v1/admin/template/"+templateID)
	require.Equal(t, http.StatusPreconditionFailed, code, string(body))
	_, err := d.Admin.DeleteTemplate(t.Context(), &executorv1.DeleteTemplateRequest{Id: templateID})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, 1, tableRows(t, d, "templates"))
	code, body = get(t, d.RestURL+"/v1/template/"+templateID)
	require.Equal(t, http.StatusOK, code, string(body))
}

func TestDefaultTemplates(t *testing.T) {
	d := Start(t)
	d = d.Restart(t, func(c *config.Config) { c.DefaultTemplates = true })
	require.Equal(t, len(templates.Artifacts), tableRows(t, d, "artifacts"))
	all, err := d.Client.ListTemplates(t.Context(), &executorv1.ListTemplatesRequest{})
	require.NoError(t, err)
	require.Len(t, all.GetTemplates(), len(templates.Templates))
	var id string
	for _, tpl := range all.GetTemplates() {
		require.Equal(t, "active", tpl.GetStatus(), tpl.GetId())
		id = tpl.GetId()
	}

	// the operator's choice survives a restart
	_, err = d.Admin.UpdateTemplate(t.Context(), &executorv1.UpdateTemplateRequest{Id: id, Status: "disabled"})
	require.NoError(t, err)
	d = d.Restart(t, func(c *config.Config) { c.DefaultTemplates = true })
	got, err := d.Client.GetTemplate(t.Context(), &executorv1.GetTemplateRequest{Id: id})
	require.NoError(t, err)
	require.Equal(t, "disabled", got.GetTemplate().GetStatus())
	require.Equal(t, len(templates.Templates), tableRows(t, d, "templates"))
}

func TestAdminAuthentication(t *testing.T) {
	d := Start(t, WithAdminUser(t, "alice", "secret"))

	_, err := d.Admin.ListArtifacts(t.Context(), &executorv1.ListArtifactsRequest{})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	ctx := metadata.AppendToOutgoingContext(t.Context(), "authorization", "Basic "+basic("alice", "secret"))
	_, err = d.Admin.ListArtifacts(ctx, &executorv1.ListArtifactsRequest{})
	require.NoError(t, err)
	wrong := metadata.AppendToOutgoingContext(t.Context(), "authorization", "Basic "+basic("alice", "nope"))
	_, err = d.Admin.ListArtifacts(wrong, &executorv1.ListArtifactsRequest{})
	require.Equal(t, codes.Unauthenticated, status.Code(err))

	resp := send(t, d.AdminURL+"/v1/admin/artifacts", "", "")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Contains(t, resp.Header.Get("WWW-Authenticate"), "Basic")
	resp = send(t, d.AdminURL+"/v1/admin/artifacts", "alice", "secret")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = send(t, d.AdminURL+"/v1/templates", "alice", "secret")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = send(t, d.AdminURL+"/v1/templates", "", "")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "the public service needs credentials on the admin port too")

	resp = send(t, d.RestURL+"/v1/templates", "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = d.Client.ListTemplates(t.Context(), &executorv1.ListTemplatesRequest{})
	require.NoError(t, err)
}

func registerRenewal(t *testing.T, d *Daemon) (artifactID, templateID string) {
	t.Helper()
	return registerShipped(t, d, "renew.json")
}

// registerShipped registers a template of templates/ with the artifacts it references; artifactID is the DelegatedVtxo one.
func registerShipped(t *testing.T, d *Daemon, name string) (artifactID, templateID string) {
	t.Helper()
	doc, err := os.ReadFile("../../pkg/template/testdata/" + name)
	if errors.Is(err, fs.ErrNotExist) {
		doc, err = os.ReadFile("../../templates/" + name)
	}
	require.NoError(t, err)
	for _, file := range slices.Sorted(maps.Keys(templates.Artifacts)) {
		a, err := tpl.ParseArtifact(templates.Artifacts[file])
		require.NoError(t, err)
		if !bytes.Contains(doc, []byte(a.ID)) {
			continue
		}
		code, body := post(t, d.RestURL+"/v1/artifact", map[string]string{"document": string(templates.Artifacts[file])})
		require.Equal(t, http.StatusOK, code, string(body))
		if file == "delegated_vtxo.json" {
			artifactID = decodeArtifact(t, body).ID
		}
	}
	code, body := post(t, d.RestURL+"/v1/template", map[string]string{"document": string(doc)})
	require.Equal(t, http.StatusOK, code, string(body))
	return artifactID, decodeTemplate(t, body).ID
}

func decodeTemplates(t *testing.T, body []byte) []template {
	t.Helper()
	var resp struct {
		Templates []template `json:"templates"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Templates
}

func failures(t *testing.T, d *Daemon, id string) int {
	t.Helper()
	var n int
	require.NoError(t, d.DB.QueryRowContext(t.Context(), "SELECT failures FROM templates WHERE id = $1", id).Scan(&n))
	return n
}

func basic(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// send gets url with basic credentials when user is set and drains the body.
func send(t *testing.T, url, user, pass string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}
