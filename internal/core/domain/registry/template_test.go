package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/arkade-os/executor/pkg/template"
	"github.com/stretchr/testify/require"
)

func TestNewTemplateDerivesFieldsFromDocument(t *testing.T) {
	doc := testTemplate(t, "renew.json")
	tpl, err := NewTemplate(doc, 0, testArtifacts(t))
	require.NoError(t, err)
	require.Len(t, tpl.ID, 64)
	require.Equal(t, doc, tpl.Document)
	require.Equal(t, []string{testArtifactID(t)}, tpl.ArtifactIDs)
	require.Equal(t, template.Intent, tpl.Type)
	require.Equal(t, TemplateStatusActive, tpl.Status)
	require.Zero(t, tpl.Failures)
	require.True(t, tpl.CreatedAt.IsZero())
	require.Contains(t, tpl.Params, Param{Name: "owner", Type: "pubkey"})
	require.Contains(t, tpl.Params, Param{Name: "exit_delay", Type: "int"})

	var v any
	require.NoError(t, json.Unmarshal(doc, &v))
	spaced, err := json.MarshalIndent(v, "", "    ")
	require.NoError(t, err)
	again, err := NewTemplate(spaced, 0, testArtifacts(t))
	require.NoError(t, err)
	require.Equal(t, tpl.ID, again.ID)
}

func TestNewTemplateNeedsNoArtifactsWhenItReferencesNone(t *testing.T) {
	tpl, err := NewTemplate(testTemplate(t, "vhtlc_claim.json"), 0, nil)
	require.NoError(t, err)
	require.Empty(t, tpl.ArtifactIDs)
	require.NotEmpty(t, tpl.Params)
	require.NotEmpty(t, tpl.Type)
}

func TestNewTemplateRejectsInvalidDocument(t *testing.T) {
	for name, doc := range map[string][]byte{
		"not json":     []byte("nope"),
		"empty":        nil,
		"wrong schema": []byte(`{"format":"template/v1"}`),
	} {
		_, err := NewTemplate(doc, 0, testArtifacts(t))
		require.ErrorIs(t, err, ErrInvalidDocument, name)
	}
}

func TestNewTemplateRefusesAnOnchainTemplate(t *testing.T) {
	doc, err := os.ReadFile("../../../../pkg/template/testdata/onchain_release.json")
	require.NoError(t, err)
	_, err = NewTemplate(doc, 0, nil)
	require.ErrorIs(t, err, ErrUnsupported)
	require.NotErrorIs(t, err, ErrInvalidDocument)
}

func TestNewTemplateRefusesAnOffchainTemplateWithoutAnArkadePacket(t *testing.T) {
	doc, err := os.ReadFile("../../../../pkg/template/testdata/delegate_release.json")
	require.NoError(t, err)
	doc = bytes.Replace(doc, []byte(`"type": "intent"`), []byte(`"type": "offchain"`), 1)
	doc = bytes.Replace(doc, []byte(`,
  "fees": {"from": "funds", "max": 1000}`), nil, 1)
	_, err = NewTemplate(doc, 0, nil)
	require.ErrorIs(t, err, ErrUnsupported)
	require.NotErrorIs(t, err, ErrInvalidDocument)
	require.ErrorContains(t, err, "arkade packet")

	_, err = NewTemplate(testTemplate(t, "vhtlc_claim.json"), 0, nil)
	require.NoError(t, err)
}

func TestNewTemplateRejectsAReferencedArtifactThatIsNotStored(t *testing.T) {
	_, err := NewTemplate(testTemplate(t, "renew.json"), 0, nil)
	require.ErrorIs(t, err, ErrInvalidDocument)
}

func TestNewTemplateEnforcesSizeLimit(t *testing.T) {
	doc := testTemplate(t, "vhtlc_claim.json")
	_, err := NewTemplate(doc, len(doc)-1, nil)
	require.ErrorIs(t, err, ErrInvalidDocument)
	_, err = NewTemplate(doc, len(doc), nil)
	require.NoError(t, err)
}

func TestReenablingATemplateResetsFailuresAndUnknownStatusIsRefused(t *testing.T) {
	tpl := Template{Status: TemplateStatusActive, Failures: 3}
	require.NoError(t, tpl.SetStatus(TemplateStatusDisabled))
	require.Equal(t, TemplateStatusDisabled, tpl.Status)
	require.Equal(t, 3, tpl.Failures)

	require.NoError(t, tpl.SetStatus(TemplateStatusActive))
	require.Equal(t, TemplateStatusActive, tpl.Status)
	require.Zero(t, tpl.Failures)

	tpl.Failures = 2
	require.ErrorIs(t, tpl.SetStatus("paused"), ErrInvalidStatus)
	require.ErrorIs(t, tpl.SetStatus(""), ErrInvalidStatus)
	require.Equal(t, TemplateStatusActive, tpl.Status)
	require.Equal(t, 2, tpl.Failures)
}

func testTemplate(t *testing.T, name string) []byte {
	t.Helper()
	doc, err := os.ReadFile("../../../../pkg/template/testdata/" + name)
	if errors.Is(err, fs.ErrNotExist) {
		doc, err = os.ReadFile("../../../../templates/" + name)
	}
	require.NoError(t, err)
	return doc
}

func testArtifactID(t *testing.T) string {
	t.Helper()
	a, err := NewArtifact(testDocument(t), 0)
	require.NoError(t, err)
	return a.ID
}

// testArtifacts serves the one default artifact.
func testArtifacts(t *testing.T) map[string][]byte {
	t.Helper()
	return map[string][]byte{testArtifactID(t): testDocument(t)}
}
