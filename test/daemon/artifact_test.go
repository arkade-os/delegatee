package daemon

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/config"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRegisterArtifactOverREST(t *testing.T) {
	d := Start(t)
	doc := artifactDocument(t)

	code, body := post(t, d.RestURL+"/v1/artifact", map[string]string{"document": doc})
	require.Equal(t, http.StatusOK, code, string(body))
	first := decodeArtifact(t, body)
	require.Len(t, first.ID, 64)
	require.Equal(t, doc, first.Document)
	require.NotZero(t, first.CreatedAt)

	code, body = get(t, d.RestURL+"/v1/artifact/"+first.ID)
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, first, decodeArtifact(t, body))

	code, body = post(t, d.RestURL+"/v1/artifact", map[string]string{"document": doc})
	require.Equal(t, http.StatusOK, code, string(body))
	require.Equal(t, first.ID, decodeArtifact(t, body).ID)
	require.Equal(t, 1, tableRows(t, d, "artifacts"))

	got, err := d.Client.GetArtifact(t.Context(), &delegateev1.GetArtifactRequest{Id: first.ID})
	require.NoError(t, err)
	require.Equal(t, doc, got.GetArtifact().GetDocument())
}

func TestRegisterArtifactRefused(t *testing.T) {
	d := Start(t, func(c *config.Config) { c.MaxArtifacts = 1 })
	doc := artifactDocument(t)

	code, body := post(t, d.RestURL+"/v1/artifact", map[string]string{"document": "not an artifact"})
	require.Equal(t, http.StatusBadRequest, code, string(body))
	require.Equal(t, 0, tableRows(t, d, "artifacts"))

	_, err := d.Client.RegisterArtifact(t.Context(), &delegateev1.RegisterArtifactRequest{Document: doc})
	require.NoError(t, err)
	other := strings.Replace(doc, `"DelegatedVtxo"`, `"Other"`, 1)
	code, body = post(t, d.RestURL+"/v1/artifact", map[string]string{"document": other})
	require.Equal(t, http.StatusTooManyRequests, code, string(body))
	_, err = d.Client.RegisterArtifact(t.Context(), &delegateev1.RegisterArtifactRequest{Document: other})
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
	require.Equal(t, 1, tableRows(t, d, "artifacts"))

	code, _ = get(t, d.RestURL+"/v1/artifact/missing")
	require.Equal(t, http.StatusNotFound, code)
}

type artifact struct {
	ID        string `json:"id"`
	Document  string `json:"document"`
	CreatedAt string `json:"createdAt"`
}

func decodeArtifact(t *testing.T, body []byte) artifact {
	t.Helper()
	var resp struct {
		Artifact artifact `json:"artifact"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Artifact
}

func artifactDocument(t *testing.T) string {
	t.Helper()
	doc, err := os.ReadFile("../../templates/artifacts/delegated_vtxo.json")
	require.NoError(t, err)
	return string(doc)
}

func post(t *testing.T, url string, body any) (int, []byte) {
	t.Helper()
	return call(t, http.MethodPost, url, body)
}

func get(t *testing.T, url string) (int, []byte) {
	t.Helper()
	return call(t, http.MethodGet, url, nil)
}

func del(t *testing.T, url string) (int, []byte) {
	t.Helper()
	return call(t, http.MethodDelete, url, nil)
}

func call(t *testing.T, method, url string, body any) (int, []byte) {
	t.Helper()
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, url, payload)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, out
}
