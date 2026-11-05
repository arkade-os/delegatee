package handlers

import (
	"context"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/core/domain/registry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (h *Delegatee) RegisterTemplate(
	ctx context.Context, req *delegateev1.RegisterTemplateRequest,
) (*delegateev1.RegisterTemplateResponse, error) {
	if req.GetDocument() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing document")
	}
	t, err := h.registry.RegisterTemplate(ctx, []byte(req.GetDocument()))
	if err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.RegisterTemplateResponse{Template: toTemplate(t)}, nil
}

func (h *Delegatee) GetTemplate(
	ctx context.Context, req *delegateev1.GetTemplateRequest,
) (*delegateev1.GetTemplateResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	t, err := h.registry.GetTemplate(ctx, req.GetId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.GetTemplateResponse{Template: toTemplate(t)}, nil
}

func (h *Delegatee) ListTemplates(
	ctx context.Context, req *delegateev1.ListTemplatesRequest,
) (*delegateev1.ListTemplatesResponse, error) {
	list, err := h.registry.ListTemplates(ctx, req.GetStatus())
	if err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.ListTemplatesResponse{Templates: toTemplates(list)}, nil
}

func toTemplates(list []registry.Template) []*delegateev1.Template {
	out := make([]*delegateev1.Template, 0, len(list))
	for _, t := range list {
		out = append(out, toTemplate(&t))
	}
	return out
}

func toTemplate(t *registry.Template) *delegateev1.Template {
	out := &delegateev1.Template{
		Id: t.ID, Document: string(t.Document), ArtifactIds: t.ArtifactIDs, Type: string(t.Type),
		Status: t.Status, CreatedAt: t.CreatedAt.Unix(),
	}
	for _, p := range t.Params {
		out.Params = append(out.Params, &delegateev1.Param{Name: p.Name, Type: p.Type})
	}
	return out
}
