package registry

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewArtifactDerivesIDFromCanonicalDocument(t *testing.T) {
	doc := testDocument(t)
	a, err := NewArtifact(doc, 0)
	require.NoError(t, err)
	require.Equal(t, doc, a.Document)
	require.True(t, a.CreatedAt.IsZero())

	require.Len(t, a.ID, 64)

	var v any
	require.NoError(t, json.Unmarshal(doc, &v))
	spaced, err := json.MarshalIndent(v, "", "    ")
	require.NoError(t, err)
	b, err := NewArtifact(spaced, 0)
	require.NoError(t, err)
	require.Equal(t, a.ID, b.ID)
}

func TestNewArtifactRejectsInvalidDocument(t *testing.T) {
	for name, doc := range map[string][]byte{
		"not json":     []byte("nope"),
		"empty":        nil,
		"wrong schema": []byte(`{"contractName":"x"}`),
	} {
		_, err := NewArtifact(doc, 0)
		require.ErrorIs(t, err, ErrInvalidDocument, name)
	}
}

func TestNewArtifactEnforcesSizeLimit(t *testing.T) {
	doc := testDocument(t)
	_, err := NewArtifact(doc, len(doc)-1)
	require.ErrorIs(t, err, ErrInvalidDocument)
	_, err = NewArtifact(doc, len(doc))
	require.NoError(t, err)
}

func testDocument(t *testing.T) []byte {
	t.Helper()
	doc, err := os.ReadFile("../../../../templates/artifacts/delegated_vtxo.json")
	require.NoError(t, err)
	return doc
}
