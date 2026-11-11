package handlers

import (
	"context"

	executorv1 "github.com/arkade-os/executor/api-spec/protobuf/gen/executor/v1"
	"github.com/arkade-os/executor/internal/core/domain/registry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (h *Executor) RegisterTemplate(
	ctx context.Context, req *executorv1.RegisterTemplateRequest,
) (*executorv1.RegisterTemplateResponse, error) {
	if req.GetDocument() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing document")
	}
	t, err := h.registry.RegisterTemplate(ctx, []byte(req.GetDocument()))
	if err != nil {
		return nil, toStatus(err)
	}
	return &executorv1.RegisterTemplateResponse{Template: toTemplate(t)}, nil
}

func (h *Executor) GetTemplate(
	ctx context.Context, req *executorv1.GetTemplateRequest,
) (*executorv1.GetTemplateResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	t, err := h.registry.GetTemplate(ctx, req.GetId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &executorv1.GetTemplateResponse{Template: toTemplate(t)}, nil
}

func (h *Executor) ListTemplates(
	ctx context.Context, req *executorv1.ListTemplatesRequest,
) (*executorv1.ListTemplatesResponse, error) {
	list, err := h.registry.ListTemplates(ctx, req.GetStatus())
	if err != nil {
		return nil, toStatus(err)
	}
	return &executorv1.ListTemplatesResponse{Templates: toTemplates(list)}, nil
}

func toTemplates(list []registry.Template) []*executorv1.Template {
	out := make([]*executorv1.Template, 0, len(list))
	for _, t := range list {
		out = append(out, toTemplate(&t))
	}
	return out
}

func toTemplate(t *registry.Template) *executorv1.Template {
	out := &executorv1.Template{
		Id: t.ID, Document: string(t.Document), ArtifactIds: t.ArtifactIDs, Type: string(t.Type),
		Status: t.Status, CreatedAt: t.CreatedAt.Unix(),
	}
	for _, p := range t.Params {
		out.Params = append(out.Params, &executorv1.Param{Name: p.Name, Type: p.Type})
	}
	return out
}
