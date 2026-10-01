package handlers

import (
	"cmp"
	"context"
	"strconv"
	"time"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/core/application"
	"github.com/arkade-os/delegatee/internal/core/domain"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type adminHandler struct {
	svc application.Service
}

func NewAdmin(svc application.Service) delegateev1.AdminServiceServer {
	return &adminHandler{svc: svc}
}

func (h *adminHandler) GetDelegationById(
	ctx context.Context, req *delegateev1.GetDelegationByIdRequest,
) (*delegateev1.GetDelegationByIdResponse, error) {
	d, err := h.svc.GetDelegationByID(ctx, req.GetId())
	if err != nil {
		return nil, toStatus(err)
	}
	detail, err := delegationDetail(ctx, h.svc, d)
	if err != nil {
		return nil, err
	}
	return &delegateev1.GetDelegationByIdResponse{Delegation: detail.Delegation, Vtxos: detail.Vtxos, Renewals: detail.Renewals}, nil
}

func (h *adminHandler) ListDelegations(
	ctx context.Context, req *delegateev1.ListDelegationsRequest,
) (*delegateev1.ListDelegationsResponse, error) {
	size, err := pageSize(req.GetPageSize())
	if err != nil {
		return nil, err
	}
	ds, err := h.svc.ListDelegations(ctx, req.GetStatus(), req.GetCursor(), size+1)
	if err != nil {
		return nil, toStatus(err)
	}
	var next int64
	if len(ds) > size {
		ds = ds[:size]
		next = ds[size-1].ID
	}
	last, err := h.svc.LastRenewals(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	st := h.svc.Status()
	out := make([]*delegateev1.DelegationSummary, len(ds))
	for i := range ds {
		del := toDelegation(&ds[i])
		for _, slot := range del.Slots {
			slot.Tapscripts = nil // most of a row's bytes, and only GetDelegation's callers use them
		}
		summary := &delegateev1.DelegationSummary{Delegation: del}
		if ren, ok := last[ds[i].ID]; ok {
			summary.LastRenewal = toRenewal(ren)
		}
		if held, ok := st.Holdings[ds[i].ID]; ok {
			summary.Managed = true
			summary.VtxoCount = int32(held.Vtxos)
			summary.TotalAmount = held.Amount
			if !held.NextExpiry.IsZero() {
				summary.NextExpiry = held.NextExpiry.Unix()
				summary.NextRenewalAt = held.NextDue.Unix()
			}
		}
		summary.UnmanagedReason = st.Unwatched[ds[i].ID]
		out[i] = summary
	}
	return &delegateev1.ListDelegationsResponse{Delegations: out, NextCursor: next}, nil
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
	var err error
	switch {
	case req.GetId() > 0:
		err = h.svc.CancelDelegationByID(ctx, req.GetId())
	case req.GetAddress() != "":
		err = h.svc.CancelDelegation(ctx, req.GetAddress())
	default:
		return nil, status.Error(codes.InvalidArgument, "missing id or address")
	}
	if err != nil {
		return nil, toStatus(err)
	}
	audit(ctx, "cancel delegation", cmp.Or(idString(req.GetId()), req.GetAddress()), "", "")
	return &delegateev1.CancelDelegationResponse{}, nil
}

func (h *adminHandler) ResumeDelegation(
	ctx context.Context, req *delegateev1.ResumeDelegationRequest,
) (*delegateev1.ResumeDelegationResponse, error) {
	if req.GetId() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	if err := h.svc.ResumeDelegation(ctx, req.GetId()); err != nil {
		return nil, toStatus(err)
	}
	audit(ctx, "resume delegation", idString(req.GetId()), "", "")
	return &delegateev1.ResumeDelegationResponse{}, nil
}

func (h *adminHandler) ListAllTemplates(ctx context.Context, req *delegateev1.ListAllTemplatesRequest) (*delegateev1.ListAllTemplatesResponse, error) {
	ts, err := h.svc.ListTemplates(ctx, req.GetStatus())
	if err != nil {
		return nil, toStatus(err)
	}
	counts, err := h.svc.DelegationsByTemplate(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*delegateev1.TemplateSummary, len(ts))
	for i := range ts {
		out[i] = toAdminTemplate(&ts[i], counts)
	}
	return &delegateev1.ListAllTemplatesResponse{Templates: out}, nil
}

func (h *adminHandler) SetTemplateStatus(ctx context.Context, req *delegateev1.SetTemplateStatusRequest) (*delegateev1.SetTemplateStatusResponse, error) {
	if req.GetId() == "" || req.GetStatus() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id or status")
	}
	t, err := h.svc.GetTemplate(ctx, req.GetId())
	if err != nil {
		return nil, toStatus(err)
	}
	before := t.Status
	if err := h.svc.SetTemplateStatus(ctx, req.GetId(), req.GetStatus()); err != nil {
		return nil, toStatus(err)
	}
	audit(ctx, "set template status", req.GetId(), before, req.GetStatus())
	out, err := h.adminTemplate(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &delegateev1.SetTemplateStatusResponse{Template: out}, nil
}

func (h *adminHandler) SetTemplateTrusted(ctx context.Context, req *delegateev1.SetTemplateTrustedRequest) (*delegateev1.SetTemplateTrustedResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	t, err := h.svc.GetTemplate(ctx, req.GetId())
	if err != nil {
		return nil, toStatus(err)
	}
	before := strconv.FormatBool(t.Trusted)
	if err := h.svc.SetTemplateTrusted(ctx, req.GetId(), req.GetTrusted()); err != nil {
		return nil, toStatus(err)
	}
	audit(ctx, "set template trusted", req.GetId(), before, strconv.FormatBool(req.GetTrusted()))
	out, err := h.adminTemplate(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &delegateev1.SetTemplateTrustedResponse{Template: out}, nil
}

func (h *adminHandler) DeleteTemplate(ctx context.Context, req *delegateev1.DeleteTemplateRequest) (*delegateev1.DeleteTemplateResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	if err := h.svc.DeleteTemplate(ctx, req.GetId()); err != nil {
		return nil, toStatus(err)
	}
	audit(ctx, "delete template", req.GetId(), "", "")
	return &delegateev1.DeleteTemplateResponse{}, nil
}

func (h *adminHandler) DeleteArtifact(ctx context.Context, req *delegateev1.DeleteArtifactRequest) (*delegateev1.DeleteArtifactResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	if err := h.svc.DeleteArtifact(ctx, req.GetId()); err != nil {
		return nil, toStatus(err)
	}
	audit(ctx, "delete artifact", req.GetId(), "", "")
	return &delegateev1.DeleteArtifactResponse{}, nil
}

func (h *adminHandler) ListArtifacts(ctx context.Context, _ *delegateev1.ListArtifactsRequest) (*delegateev1.ListArtifactsResponse, error) {
	as, err := h.svc.ListArtifacts(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*delegateev1.Artifact, len(as))
	for i := range as {
		out[i] = toArtifact(&as[i]) // Document is empty in a listing
	}
	return &delegateev1.ListArtifactsResponse{Artifacts: out}, nil
}

func (h *adminHandler) adminTemplate(ctx context.Context, id string) (*delegateev1.TemplateSummary, error) {
	t, err := h.svc.GetTemplate(ctx, id)
	if err != nil {
		return nil, toStatus(err)
	}
	counts, err := h.svc.DelegationsByTemplate(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	return toAdminTemplate(t, counts), nil
}

// toAdminTemplate adds the operator-only fields.
func toAdminTemplate(t *domain.Template, counts map[string]int64) *delegateev1.TemplateSummary {
	return &delegateev1.TemplateSummary{
		Template: toTemplate(t, false),
		Failures: int32(t.Failures), Delegations: counts[t.ID], Trusted: t.Trusted,
	}
}

const defaultPageSize, maxPageSize = 100, 1000

func pageSize(requested int32) (int, error) {
	if requested < 0 {
		return 0, status.Error(codes.InvalidArgument, "negative page_size")
	}
	if requested == 0 {
		return defaultPageSize, nil
	}
	return min(int(requested), maxPageSize), nil
}

type adminKey struct{}

// WithAdmin marks a call made on the admin port by user, empty when no user authenticated.
func WithAdmin(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, adminKey{}, cmp.Or(user, "loopback"))
}

// audit logs a mutation made on the admin port.
func audit(ctx context.Context, action, target, before, after string) {
	admin, ok := ctx.Value(adminKey{}).(string)
	if !ok {
		return
	}
	fields := log.Fields{"admin": admin, "action": action, "target": target}
	if before != "" || after != "" {
		fields["before"], fields["after"] = before, after
	}
	log.WithFields(fields).Info("admin mutation")
}

func idString(id int64) string {
	if id <= 0 {
		return ""
	}
	return strconv.FormatInt(id, 10)
}
