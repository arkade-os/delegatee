package handlers

import (
	"context"
	"errors"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	delegationapp "github.com/arkade-os/delegatee/internal/core/application/delegation"
	executionapp "github.com/arkade-os/delegatee/internal/core/application/execution"
	app "github.com/arkade-os/delegatee/internal/core/application/registry"
	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/internal/core/domain/registry"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Delegatee struct {
	registry    *app.Service
	delegations *delegationapp.Service
	execution   *executionapp.Service
	version     string
}

func NewDelegatee(
	registry *app.Service, delegations *delegationapp.Service, execution *executionapp.Service, version string,
) *Delegatee {
	return &Delegatee{registry: registry, delegations: delegations, execution: execution, version: version}
}

func (h *Delegatee) RegisterArtifact(
	ctx context.Context, req *delegateev1.RegisterArtifactRequest,
) (*delegateev1.RegisterArtifactResponse, error) {
	if req.GetDocument() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing document")
	}
	a, err := h.registry.RegisterArtifact(ctx, []byte(req.GetDocument()))
	if err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.RegisterArtifactResponse{Artifact: toArtifact(a)}, nil
}

func (h *Delegatee) GetArtifact(
	ctx context.Context, req *delegateev1.GetArtifactRequest,
) (*delegateev1.GetArtifactResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	a, err := h.registry.GetArtifact(ctx, req.GetId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.GetArtifactResponse{Artifact: toArtifact(a)}, nil
}

func toArtifact(a *registry.Artifact) *delegateev1.Artifact {
	return &delegateev1.Artifact{Id: a.ID, Document: string(a.Document), CreatedAt: a.CreatedAt.Unix()}
}

func toStatus(err error) error {
	switch {
	case errors.Is(err, registry.ErrInvalidDocument), errors.Is(err, registry.ErrInvalidStatus),
		errors.Is(err, delegation.ErrInvalidArgs):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, registry.ErrArtifactInUse), errors.Is(err, registry.ErrTemplateInUse),
		errors.Is(err, registry.ErrTemplateDisabled), errors.Is(err, registry.ErrUnsupported), errors.Is(err, delegation.ErrStreamOnly),
		errors.Is(err, delegation.ErrNoEncryptionKey), errors.Is(err, delegation.ErrCosignerKeyLeaf),
		errors.Is(err, delegation.ErrBlocked), errors.Is(err, delegation.ErrNotActive),
		errors.Is(err, delegation.ErrNotCancelled), errors.Is(err, delegation.ErrNotStream):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, registry.ErrCapReached), errors.Is(err, delegation.ErrCapReached):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, registry.ErrArtifactNotFound), errors.Is(err, registry.ErrTemplateNotFound),
		errors.Is(err, delegation.ErrDelegationNotFound), errors.Is(err, delegation.ErrStreamNotFound):
		return status.Error(codes.NotFound, err.Error())
	}
	log.WithError(err).Error("request failed")
	return status.Error(codes.Internal, "internal error")
}
