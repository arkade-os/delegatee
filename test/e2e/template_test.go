package e2e

import (
	"slices"
	"testing"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestTemplateRegistry(t *testing.T) {
	ctx := t.Context()
	d := startDelegatee(t)
	require.Equal(t, registerTemplate(t, d, "renewal.json"), registerTemplate(t, d, "renewal.json"))
	_, err := d.client.RegisterTemplate(ctx, &delegateev1.RegisterTemplateRequest{Document: `{"format":"delegateed-template/v1"}`})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)

	boarding := registerTemplate(t, d, "boarding.json")
	watch(t, d, boarding, newOwner(t, d).boardingVariables())
	setTemplateStatus(t, d, boarding, "disabled")

	_, err = d.client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{TemplateId: boarding, Variables: newOwner(t, d).boardingVariables()})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)
	_, err = d.admin.DeleteTemplate(ctx, &delegateev1.DeleteTemplateRequest{Id: boarding})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)
	listed, err := d.admin.ListAllTemplates(ctx, &delegateev1.ListAllTemplatesRequest{Status: "disabled"})
	require.NoError(t, err)
	i := slices.IndexFunc(listed.Templates, func(s *delegateev1.TemplateSummary) bool { return s.Template.Id == boarding })
	require.GreaterOrEqual(t, i, 0, "the disabled template is listed")
	require.Positive(t, listed.Templates[i].Delegations)
}
