package daemon

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRegisterTemplateOverREST(t *testing.T) {
	d := Start(t)
	code, body := post(
		t, d.RestURL+"/v1/artifact", map[string]string{"document": artifactDocument(t)},
	)
	require.Equal(t, http.StatusOK, code, string(body))
	artifactID := decodeArtifact(t, body).ID
	doc := templateDocument(t)

	code, body = post(t, d.RestURL+"/v1/template", map[string]string{"document": doc})
	require.Equal(t, http.StatusOK, code, string(body))
	first := decodeTemplate(t, body)
	require.Len(t, first.ID, 64)
	require.Equal(t, doc, first.Document)
	require.Equal(t, []string{artifactID}, first.ArtifactIDs)
	require.Equal(t, "proof", first.Type)
	require.Equal(t, "active", first.Status)
	require.Contains(t, first.Params, param{Name: "owner", Type: "pubkey"})
	require.NotZero(t, first.CreatedAt)

	code, body = get(t, d.RestURL+"/v1/templates?status=active")
	require.Equal(t, http.StatusOK, code, string(body))
	var list struct {
		Templates []template `json:"templates"`
	}
	require.NoError(t, json.Unmarshal(body, &list))
	require.Len(t, list.Templates, 1)
	require.Equal(t, first.ID, list.Templates[0].ID)
	require.Equal(t, "active", list.Templates[0].Status)
	require.Empty(t, list.Templates[0].Document)

	code, body = get(t, d.RestURL+"/v1/template/"+first.ID)
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, first, decodeTemplate(t, body))

	code, body = post(t, d.RestURL+"/v1/template", map[string]string{"document": doc})
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, first.ID, decodeTemplate(t, body).ID)
	require.Equal(t, 1, tableRows(t, d, "templates"))
}

func TestRegisterTemplateRefused(t *testing.T) {
	d := Start(t)

	code, body := post(t, d.RestURL+"/v1/template", map[string]string{"document": "not a template"})
	require.Equal(t, http.StatusBadRequest, code, string(body))

	code, body = post(
		t, d.RestURL+"/v1/template", map[string]string{"document": templateDocument(t)},
	)
	require.Equal(t, http.StatusNotFound, code, string(body))
	require.Equal(t, 0, tableRows(t, d, "templates"))

	code, _ = get(t, d.RestURL+"/v1/template/missing")
	require.Equal(t, http.StatusNotFound, code)
}

func TestRegisterOnchainTemplateIsUnsupported(t *testing.T) {
	d := Start(t)
	doc, err := os.ReadFile("../../pkg/template/testdata/onchain_release.json")
	require.NoError(t, err)
	code, body := post(t, d.RestURL+"/v1/template", map[string]string{"document": string(doc)})
	require.Equal(t, http.StatusPreconditionFailed, code, string(body))
	require.Equal(t, 0, tableRows(t, d, "templates"))
}

func TestTemplateIsDisabledByItsFailures(t *testing.T) {
	d := Start(t, WithSessions(500*time.Millisecond, 128), WithTemplateMaxFailures(3))
	d.Emu.Refuse(status.Error(codes.InvalidArgument, "covenant not satisfied"))
	templateID, w := refusedDelegation(t, d)

	require.Eventually(
		t, func() bool { return getTemplate(t, d, templateID).Status == "disabled" },
		15*time.Second, 50*time.Millisecond,
	)
	require.Equal(t, 3, failures(t, d, templateID))
	time.Sleep(2 * time.Second)
	require.Len(t, listAttempts(t, d, w.ID), 3, "its delegations are not attempted again")
}

func TestOutagesDoNotCountAndASuccessResetsTheFailures(t *testing.T) {
	d := Start(t, WithSessions(500*time.Millisecond, 128), WithTemplateMaxFailures(3))
	d.Emu.Refuse(errors.New("connection refused"))
	templateID, w := refusedDelegation(t, d)
	require.Eventually(
		t, func() bool { return len(listAttempts(t, d, w.ID)) >= 4 }, 15*time.Second,
		50*time.Millisecond,
	)
	require.Zero(t, failures(t, d, templateID), "an outage is not the template's fault")
	require.Equal(t, "active", getTemplate(t, d, templateID).Status)

	d.Emu.Refuse(status.Error(codes.InvalidArgument, "covenant not satisfied"))
	require.Eventually(
		t, func() bool { return failures(t, d, templateID) == 2 }, 15*time.Second,
		5*time.Millisecond,
	)
	d.Emu.Refuse(nil)
	require.Eventually(
		t, func() bool { return attemptRows(t, d, "succeeded") == 1 }, 15*time.Second,
		20*time.Millisecond,
	)
	require.Eventually(
		t, func() bool { return failures(t, d, templateID) == 0 }, 5*time.Second,
		20*time.Millisecond,
	)
	require.Equal(t, "active", getTemplate(t, d, templateID).Status)
}

// refusedDelegation registers the renewal template and a delegation whose coin is due at once.
func refusedDelegation(t *testing.T, d *Daemon) (string, delegation) {
	t.Helper()
	_, templateID := registerRenewal(t, d)
	w := renewalDelegation(t, d, templateID, 1024, 1000)
	d.Arkd.FundAged(w.Inputs[0].Script, 10_000, time.Hour, time.Now().Add(500*time.Second))
	return templateID, w
}

func getTemplate(t *testing.T, d *Daemon, id string) template {
	t.Helper()
	code, body := get(t, d.RestURL+"/v1/template/"+id)
	require.Equal(t, http.StatusOK, code, string(body))
	return decodeTemplate(t, body)
}

type template struct {
	ID          string   `json:"id"`
	Document    string   `json:"document"`
	ArtifactIDs []string `json:"artifactIds"`
	Params      []param  `json:"params"`
	Type        string   `json:"type"`
	Status      string   `json:"status"`
	CreatedAt   string   `json:"createdAt"`
}

type param struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func decodeTemplate(t *testing.T, body []byte) template {
	t.Helper()
	var resp struct {
		Template template `json:"template"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Template
}

func templateDocument(t *testing.T) string {
	t.Helper()
	doc, err := os.ReadFile("../../templates/renew.json")
	require.NoError(t, err)
	return string(doc)
}
