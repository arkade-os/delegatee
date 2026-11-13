package artifact_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/executor/pkg/template/artifact"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T) (string, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../testdata/vectors/v1/renew-fee.json")
	require.NoError(t, err)
	var v struct {
		Artifacts map[string]json.RawMessage `json:"artifacts"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	for id, doc := range v.Artifacts {
		return id, doc
	}
	t.Fatal("missing artifact")
	return "", nil
}
func TestIndependentArtifactProfile(t *testing.T) {
	id, raw := fixture(t)
	a, err := artifact.ParseVersion(artifact.Version1, raw)
	require.NoError(t, err)
	require.Equal(t, id, a.ID())
	require.Equal(t, artifact.Version1, a.Version())
	again, err := artifact.Parse(a.Canonical())
	require.NoError(t, err)
	require.Equal(t, id, again.ID())
	_, err = artifact.ParseVersion("artifact/v2", raw)
	require.ErrorIs(t, err, artifact.ErrUnsupportedVersion)
	// Compiler metadata is not a language discriminator in the existing format.
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	doc["formatVersion"] = 2
	doc["compiler"] = map[string]any{"version": "9.0.0"}
	raw, err = json.Marshal(doc)
	require.NoError(t, err)
	metadata, err := artifact.Parse(raw)
	require.NoError(t, err)
	require.Equal(t, id, metadata.ID())
}
func TestArtifactOwnsDefinition(t *testing.T) {
	id, raw := fixture(t)
	a, err := artifact.Parse(raw)
	require.NoError(t, err)
	expected := a.Definition()
	canonical := a.Canonical()
	canonical[0] = '!'
	clear(raw)
	d := a.Definition()
	d.ConstructorInputs[0].Name = "changed"
	d.Functions[0].Leaves[0].Asm[0] = "OP_RETURN"
	for i := range d.Functions {
		if d.Functions[i].Arkade != nil {
			d.Functions[i].Arkade.Asm[0] = "OP_RETURN"
		}
	}
	require.Equal(t, expected, a.Definition())
	require.Equal(t, id, a.ID())
	require.NotEqual(t, canonical, a.Canonical())
}
func TestArtifactSetChecksIdentity(t *testing.T) {
	id, raw := fixture(t)
	set, err := artifact.ParseSet(artifact.Version1, map[string][]byte{id: raw})
	require.NoError(t, err)
	require.Equal(t, id, set[id].ID())
	_, err = artifact.ParseSet(artifact.Version1, map[string][]byte{"wrong": raw})
	require.ErrorIs(t, err, artifact.ErrInvalid)
	_, err = artifact.ParseSet("artifact/v2", nil)
	require.ErrorIs(t, err, artifact.ErrUnsupportedVersion)
}
