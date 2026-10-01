package application

import (
	"strings"
	"testing"

	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/stretchr/testify/require"
)

func TestRegisterTemplate(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	doc := document(t, "boarding.json")
	_, err := env.svc.RegisterTemplate(ctx, doc)
	require.ErrorIs(t, err, ErrInvalidDocument, "its artifact is not registered")
	id := env.fixture(t, "boarding.json")
	tmpl, err := env.svc.GetTemplate(ctx, id)
	require.NoError(t, err)
	require.Equal(t, domain.TemplateStatusActive, tmpl.Status)
	require.Equal(t, []domain.Param{
		{Name: "boarding_exit_delay", Type: "int"}, {Name: "exit_delay", Type: "int"}, {Name: "max_fee", Type: "int"},
		{Name: "owner", Type: "pubkey"}, {Name: "renewal_window", Type: "int"},
	}, tmpl.Params)
	require.Len(t, tmpl.ArtifactIDs, 1)
	require.False(t, tmpl.Trusted)

	again, err := env.svc.RegisterTemplate(ctx, []byte(" "+strings.ReplaceAll(string(doc), "\n", "")+" "))
	require.NoError(t, err)
	require.Equal(t, tmpl.ID, again.ID, "idempotent on the canonical form")
	require.Equal(t, doc, again.Document, "first bytes win")

	_, err = env.svc.RegisterTemplate(ctx, []byte(`{"format":"nope"}`))
	require.ErrorIs(t, err, ErrInvalidDocument)
	_, err = env.svc.RegisterTemplate(ctx, []byte(strings.Repeat(" ", env.svc.limits.MaxDocumentBytes+1)))
	require.ErrorIs(t, err, ErrInvalidDocument)
	_, err = env.svc.RegisterTemplate(ctx, nil)
	require.ErrorIs(t, err, ErrInvalidDocument)

	listed, err := env.svc.ListTemplates(ctx, domain.TemplateStatusActive)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	_, err = env.svc.GetTemplate(ctx, "nope")
	require.ErrorIs(t, err, domain.ErrTemplateNotFound)

	require.NoError(t, env.svc.SetTemplateStatus(ctx, id, domain.TemplateStatusDisabled))
	require.ErrorIs(t, env.svc.SetTemplateStatus(ctx, id, "weird"), ErrInvalidStatus)
	listed, err = env.svc.ListTemplates(ctx, domain.TemplateStatusActive)
	require.NoError(t, err)
	require.Empty(t, listed)
	require.ErrorIs(t, env.svc.DeleteArtifact(ctx, tmpl.ArtifactIDs[0]), domain.ErrArtifactInUse)
	require.NoError(t, env.svc.DeleteTemplate(ctx, id))
	require.ErrorIs(t, env.svc.DeleteTemplate(ctx, id), domain.ErrTemplateNotFound)
	require.NoError(t, env.svc.DeleteArtifact(ctx, tmpl.ArtifactIDs[0]))
}

func TestTemplateTrusted(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	id := env.fixture(t, "renewal.json")
	got, err := env.svc.GetTemplate(ctx, id)
	require.NoError(t, err)
	require.False(t, got.Trusted, "a template registered through the API is not trusted")
	require.NoError(t, env.svc.SetTemplateTrusted(ctx, id, true))
	got, err = env.svc.GetTemplate(ctx, id)
	require.NoError(t, err)
	require.True(t, got.Trusted)
	require.NoError(t, env.svc.Bootstrap(ctx))
	got, err = env.svc.GetTemplate(ctx, id)
	require.NoError(t, err)
	require.True(t, got.Trusted, "a start keeps the operator's choice")
	require.ErrorIs(t, env.svc.SetTemplateTrusted(ctx, "nope", true), domain.ErrTemplateNotFound)
}

func TestRegisterTemplateCap(t *testing.T) {
	env := newTestEnv(t)
	id := env.fixture(t, "renewal.json")
	env.svc.limits.MaxTemplates = 1
	_, err := env.svc.RegisterTemplate(t.Context(), document(t, "onchain_release.json"))
	require.ErrorIs(t, err, ErrFull)
	again, err := env.svc.RegisterTemplate(t.Context(), document(t, "renewal.json"))
	require.NoError(t, err, "an existing template bypasses the cap")
	require.Equal(t, id, again.ID)
}

func TestRegisterUnsupportedTemplate(t *testing.T) {
	env := newTestEnv(t)
	// an absolute locktime in a leaf
	doc := strings.Replace(string(document(t, "minimal.json")), `"<DELEGATE_KEY>", "OP_CHECKSIG"`, `"100", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP", "<DELEGATE_KEY>", "OP_CHECKSIG"`, 1)
	_, err := env.svc.RegisterTemplate(t.Context(), []byte(doc))
	require.ErrorIs(t, err, ErrUnsupported)
	require.NotErrorIs(t, err, ErrInvalidDocument)
}

func TestRegisterArtifact(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, err := env.svc.RegisterArtifact(ctx, []byte(`{}`))
	require.ErrorIs(t, err, ErrInvalidDocument)
	_, err = env.svc.RegisterArtifact(ctx, document(t, "artifacts/single_sig.compiler.json"))
	require.ErrorIs(t, err, ErrInvalidDocument, "an artifact the engine refuses")

	doc := document(t, "artifacts/delegated_vtxo.json")
	a, err := env.svc.RegisterArtifact(ctx, doc)
	require.NoError(t, err)
	require.Len(t, a.ID, 64)
	again, err := env.svc.RegisterArtifact(ctx, doc)
	require.NoError(t, err)
	require.Equal(t, a.ID, again.ID)
	got, err := env.svc.GetArtifact(ctx, a.ID)
	require.NoError(t, err)
	require.Equal(t, doc, got.Document)
	listed, err := env.svc.ListArtifacts(ctx)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	require.Equal(t, a.ID, listed[0].ID)
	require.Empty(t, listed[0].Document, "lists omit documents")
	env.svc.limits.MaxArtifacts = 1
	_, err = env.svc.RegisterArtifact(ctx, []byte(strings.Replace(string(doc), `"DelegatedVtxo"`, `"OtherVtxo"`, 1)))
	require.ErrorIs(t, err, ErrFull)
	require.NoError(t, env.svc.DeleteArtifact(ctx, a.ID))
	require.ErrorIs(t, env.svc.DeleteArtifact(ctx, a.ID), domain.ErrArtifactNotFound)
}

// listings leave documents out, and Bootstrap reads each one
func TestBootstrap(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	kept, broken := env.fixture(t, "renewal.json"), env.fixture(t, "onchain_release.json")
	env.repo.mu.Lock()
	stored := env.repo.templates[broken]
	stored.Document = []byte(`{"format":"delegateed-template/v0"}`)
	env.repo.templates[broken] = stored
	env.repo.mu.Unlock()

	require.NoError(t, env.svc.Bootstrap(ctx))
	for id, want := range map[string]string{kept: domain.TemplateStatusActive, broken: domain.TemplateStatusDisabled} {
		tmpl, err := env.svc.GetTemplate(ctx, id)
		require.NoError(t, err)
		require.Equal(t, want, tmpl.Status)
	}
	listed, err := env.svc.ListTemplates(ctx, "")
	require.NoError(t, err)
	require.Len(t, listed, 2)
	for _, tmpl := range listed {
		require.Empty(t, tmpl.Document)
	}

	// a database outage while reading an artifact is not the document's fault
	boarding := env.fixture(t, "boarding.json")
	env.repo.artifactErr = errBoom
	require.ErrorIs(t, env.svc.Bootstrap(ctx), errBoom)
	tmpl, err := env.svc.GetTemplate(ctx, boarding)
	require.NoError(t, err)
	require.Equal(t, domain.TemplateStatusActive, tmpl.Status)
	_, err = env.svc.RegisterTemplate(ctx, []byte(strings.Replace(string(document(t, "boarding.json")), `"min_confirmations": 1`, `"min_confirmations": 2`, 1)))
	require.ErrorIs(t, err, errBoom)
	require.NotErrorIs(t, err, ErrInvalidDocument)
}

func TestParseTemplateResolvesArtifacts(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, err := env.svc.RegisterTemplate(ctx, document(t, "boarding.json"))
	require.ErrorIs(t, err, ErrInvalidDocument)
	require.ErrorContains(t, err, "artifact not found")
	_, err = env.svc.RegisterArtifact(ctx, document(t, "artifacts/delegated_vtxo.json"))
	require.NoError(t, err)
	tmpl, err := env.svc.RegisterTemplate(ctx, document(t, "boarding.json"))
	require.NoError(t, err)
	_, err = env.svc.parseTemplate(ctx, tmpl.ID)
	require.NoError(t, err, "the stored template resolves its artifact again")
}
