package handlers

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	executorv1 "github.com/arkade-os/executor/api-spec/protobuf/gen/executor/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRegisterTemplateThenGetAndList(t *testing.T) {
	h := testHandler(t, 10)
	art, err := h.RegisterArtifact(t.Context(), &executorv1.RegisterArtifactRequest{Document: testDocument(t)})
	require.NoError(t, err)
	doc := testTemplateDocument(t, "renew.json")

	reg, err := h.RegisterTemplate(t.Context(), &executorv1.RegisterTemplateRequest{Document: doc})
	require.NoError(t, err)
	tpl := reg.GetTemplate()
	require.Len(t, tpl.GetId(), 64)
	require.Equal(t, doc, tpl.GetDocument())
	require.Equal(t, []string{art.GetArtifact().GetId()}, tpl.GetArtifactIds())
	require.Equal(t, "intent", tpl.GetType())
	require.Equal(t, "active", tpl.GetStatus())
	require.NotEmpty(t, tpl.GetParams())
	require.NotZero(t, tpl.GetCreatedAt())

	got, err := h.GetTemplate(t.Context(), &executorv1.GetTemplateRequest{Id: tpl.GetId()})
	require.NoError(t, err)
	require.Equal(t, doc, got.GetTemplate().GetDocument())

	list, err := h.ListTemplates(t.Context(), &executorv1.ListTemplatesRequest{Status: "active"})
	require.NoError(t, err)
	require.Len(t, list.GetTemplates(), 1)
	require.Equal(t, tpl.GetId(), list.GetTemplates()[0].GetId())
	require.Empty(t, list.GetTemplates()[0].GetDocument())

	list, err = h.ListTemplates(t.Context(), &executorv1.ListTemplatesRequest{Status: "disabled"})
	require.NoError(t, err)
	require.Empty(t, list.GetTemplates())
}

func TestRegisterTemplateErrors(t *testing.T) {
	h := testHandler(t, 1)
	_, err := h.RegisterTemplate(t.Context(), &executorv1.RegisterTemplateRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = h.RegisterTemplate(t.Context(), &executorv1.RegisterTemplateRequest{Document: "nope"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	onchain, err := os.ReadFile("../../../../pkg/template/testdata/onchain_release.json")
	require.NoError(t, err)
	_, err = h.RegisterTemplate(t.Context(), &executorv1.RegisterTemplateRequest{Document: string(onchain)})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "unsupported")

	renewal := testTemplateDocument(t, "renew.json")
	_, err = h.RegisterTemplate(t.Context(), &executorv1.RegisterTemplateRequest{Document: renewal})
	require.Equal(t, codes.NotFound, status.Code(err))

	_, err = h.RegisterTemplate(t.Context(), &executorv1.RegisterTemplateRequest{Document: testTemplateDocument(t, "vhtlc_claim.json")})
	require.NoError(t, err)
	_, err = h.RegisterTemplate(t.Context(), &executorv1.RegisterTemplateRequest{Document: testTemplateDocument(t, "vhtlc_refund.json")})
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestGetTemplateErrors(t *testing.T) {
	h := testHandler(t, 0)
	_, err := h.GetTemplate(t.Context(), &executorv1.GetTemplateRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = h.GetTemplate(t.Context(), &executorv1.GetTemplateRequest{Id: "missing"})
	require.Equal(t, codes.NotFound, status.Code(err))
}

func testTemplateDocument(t *testing.T, name string) string {
	t.Helper()
	doc, err := os.ReadFile("../../../../pkg/template/testdata/" + name)
	if errors.Is(err, fs.ErrNotExist) {
		doc, err = os.ReadFile("../../../../templates/" + name)
	}
	require.NoError(t, err)
	return string(doc)
}
