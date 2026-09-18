package handlers

import (
	"context"
	"time"

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
	last, err := h.svc.LastRenewals(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	st := h.svc.Status()
	out := make([]*delegateev1.Delegation, len(ds))
	for i := range ds {
		out[i] = toDelegation(&ds[i])
		out[i].Tapscripts = nil // most of a row's bytes, and only GetDelegation's callers use them
		if ren, ok := last[ds[i].ID]; ok {
			out[i].LastRenewal = toRenewal(ren)
		}
		if held, ok := st.Holdings[ds[i].ID]; ok {
			out[i].Managed = true
			out[i].VtxoCount = int32(held.Vtxos)
			out[i].TotalAmount = held.Amount
			if !held.NextExpiry.IsZero() {
				out[i].NextExpiry = held.NextExpiry.Unix()
				out[i].NextRenewalAt = held.NextDue.Unix()
			}
		}
	}
	return &delegateev1.ListDelegationsResponse{Delegations: out}, nil
}

func (h *adminHandler) GetStatus(
	ctx context.Context, _ *delegateev1.GetStatusRequest,
) (*delegateev1.GetStatusResponse, error) {
	st := h.svc.Status()
	resp := &delegateev1.GetStatusResponse{
		RenewingVtxos: int32(st.RenewingVtxos),
		PollInterval:  int64(st.PollInterval.Seconds()),
	}
	// bounded and optional: the UI polls this, also while arkd is down
	feesCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if f, err := h.svc.IntentFees(feesCtx); err == nil {
		resp.IntentFees = &delegateev1.IntentFees{
			OffchainInput:  f.IntentOffchainInputProgram,
			OnchainInput:   f.IntentOnchainInputProgram,
			OffchainOutput: f.IntentOffchainOutputProgram,
			OnchainOutput:  f.IntentOnchainOutputProgram,
		}
	}
	if !st.LastScan.IsZero() {
		resp.LastScanAt = st.LastScan.Unix()
	}
	return resp, nil
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
