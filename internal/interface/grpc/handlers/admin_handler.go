package handlers

import (
	"context"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/core/application"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type adminHandler struct {
	svc application.Service
}

func NewAdmin(svc application.Service) delegateev1.AdminServiceServer {
	return &adminHandler{svc: svc}
}

func (h *adminHandler) ListDelegations(
	ctx context.Context, _ *delegateev1.ListDelegationsRequest,
) (*delegateev1.ListDelegationsResponse, error) {
	ds, err := h.svc.ListDelegations(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*delegateev1.Delegation, len(ds))
	for i := range ds {
		out[i] = toDelegation(&ds[i])
	}
	return &delegateev1.ListDelegationsResponse{Delegations: out}, nil
}

func (h *adminHandler) GetDelegation(
	ctx context.Context, req *delegateev1.GetDelegationRequest,
) (*delegateev1.GetDelegationResponse, error) {
	if req.GetAddress() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing address")
	}
	d, err := h.svc.GetDelegation(ctx, req.GetAddress())
	if err != nil {
		return nil, toStatus(err)
	}
	vtxos, err := h.svc.Vtxos(ctx, d)
	if err != nil {
		return nil, toStatus(err)
	}
	renewals, err := h.svc.ListRenewals(ctx, d)
	if err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.GetDelegationResponse{
		Delegation: toDelegation(d),
		Vtxos:      toVtxos(vtxos),
		Renewals:   toRenewals(renewals),
	}, nil
}

func (h *adminHandler) CancelDelegation(
	ctx context.Context, req *delegateev1.CancelDelegationRequest,
) (*delegateev1.CancelDelegationResponse, error) {
	if req.GetAddress() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing address")
	}
	if err := h.svc.CancelDelegation(ctx, req.GetAddress()); err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.CancelDelegationResponse{}, nil
}
