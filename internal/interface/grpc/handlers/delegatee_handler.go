package handlers

import (
	"context"
	"errors"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/core/application"
	"github.com/arkade-os/delegatee/internal/core/domain"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type handler struct {
	version string
	svc     application.Service
}

func New(version string, svc application.Service) delegateev1.DelegateeServiceServer {
	return &handler{version: version, svc: svc}
}

func (h *handler) GetInfo(context.Context, *delegateev1.GetInfoRequest) (*delegateev1.GetInfoResponse, error) {
	info := h.svc.Info()
	return &delegateev1.GetInfoResponse{
		Version: h.version, Network: info.Network, DelegatePubkey: info.DelegatePubKey,
		ServerPubkey: info.ServerPubKey, EmulatorPubkey: info.EmulatorPubKey,
		EncryptionPubkey: info.EncryptionPubKey,
	}, nil
}

func (h *handler) RegisterDelegation(
	ctx context.Context, req *delegateev1.RegisterDelegationRequest,
) (*delegateev1.RegisterDelegationResponse, error) {
	if req.GetTemplateId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing template_id")
	}
	var expiresAt *time.Time
	if req.GetExpiresAt() < 0 {
		return nil, status.Error(codes.InvalidArgument, "negative expires_at")
	} else if req.GetExpiresAt() > 0 {
		at := time.Unix(req.GetExpiresAt(), 0)
		expiresAt = &at
	}
	d, err := h.svc.RegisterDelegation(ctx, req.GetTemplateId(), variablesOf(req.GetVariables()), expiresAt)
	if err != nil {
		return nil, toStatus(err)
	}
	audit(ctx, "register delegation", idString(d.ID), "", "")
	return &delegateev1.RegisterDelegationResponse{Delegation: toDelegation(d)}, nil
}

func (h *handler) GetDelegation(
	ctx context.Context, req *delegateev1.GetDelegationRequest,
) (*delegateev1.GetDelegationResponse, error) {
	if req.GetAddress() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing address")
	}
	d, err := h.svc.GetDelegation(ctx, req.GetAddress())
	if err != nil {
		return nil, toStatus(err)
	}
	return delegationDetail(ctx, h.svc, d)
}

func (h *handler) RegisterSpend(
	ctx context.Context, req *delegateev1.RegisterSpendRequest,
) (*delegateev1.RegisterSpendResponse, error) {
	d, err := h.svc.RegisterSpend(
		ctx, req.GetTemplateId(), variablesOf(req.GetVariables()), req.GetOutpoints(), time.Unix(req.GetExpiresAt(), 0),
		req.GetPubkey(), req.GetSignature(),
	)
	if err != nil {
		return nil, toStatus(err)
	}
	audit(ctx, "register spend", idString(d.ID), "", "")
	return &delegateev1.RegisterSpendResponse{Id: d.Fingerprint, Delegation: toDelegation(d)}, nil
}

func (h *handler) GetSpend(ctx context.Context, req *delegateev1.GetSpendRequest) (*delegateev1.GetSpendResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	d, err := h.svc.GetSpend(ctx, req.GetId())
	if err != nil {
		return nil, toStatus(err)
	}
	detail, err := delegationDetail(ctx, h.svc, d)
	if err != nil {
		return nil, err
	}
	return &delegateev1.GetSpendResponse{Delegation: detail.Delegation, Vtxos: detail.Vtxos, Renewals: detail.Renewals}, nil
}

func delegationDetail(ctx context.Context, svc application.Service, d *domain.Delegation) (*delegateev1.GetDelegationResponse, error) {
	vtxos, err := svc.Vtxos(ctx, d)
	if err != nil {
		return nil, toStatus(err)
	}
	renewals, err := svc.ListRenewals(ctx, d)
	if err != nil {
		return nil, toStatus(err)
	}
	due, err := svc.RenewableAt(ctx, d, vtxos)
	if err != nil {
		log.WithError(err).WithField("address", d.Address).Debug("delegation cannot be instantiated")
	}
	converted := toVtxos(vtxos, due)
	for i, v := range vtxos {
		for _, slot := range d.Slots {
			if slot.Onchain && slot.Script == v.Script {
				converted[i].Onchain = true
			}
		}
	}
	return &delegateev1.GetDelegationResponse{
		Delegation: toDelegation(d), Vtxos: converted, Renewals: toRenewals(renewals),
	}, nil
}

func (h *handler) RegisterArtifact(ctx context.Context, req *delegateev1.RegisterArtifactRequest) (*delegateev1.RegisterArtifactResponse, error) {
	if req.GetDocument() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing document")
	}
	a, err := h.svc.RegisterArtifact(ctx, []byte(req.GetDocument()))
	if err != nil {
		return nil, toStatus(err)
	}
	audit(ctx, "register artifact", a.ID, "", "")
	return &delegateev1.RegisterArtifactResponse{Artifact: toArtifact(a)}, nil
}

func (h *handler) GetArtifact(ctx context.Context, req *delegateev1.GetArtifactRequest) (*delegateev1.GetArtifactResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	a, err := h.svc.GetArtifact(ctx, req.GetId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.GetArtifactResponse{Artifact: toArtifact(a)}, nil
}

func (h *handler) RegisterTemplate(ctx context.Context, req *delegateev1.RegisterTemplateRequest) (*delegateev1.RegisterTemplateResponse, error) {
	if req.GetDocument() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing document")
	}
	t, err := h.svc.RegisterTemplate(ctx, []byte(req.GetDocument()))
	if err != nil {
		return nil, toStatus(err)
	}
	audit(ctx, "register template", t.ID, "", "")
	return &delegateev1.RegisterTemplateResponse{Template: toTemplate(t, true)}, nil
}

func (h *handler) GetTemplate(ctx context.Context, req *delegateev1.GetTemplateRequest) (*delegateev1.GetTemplateResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	t, err := h.svc.GetTemplate(ctx, req.GetId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.GetTemplateResponse{Template: toTemplate(t, true)}, nil
}

func (h *handler) ListTemplates(ctx context.Context, _ *delegateev1.ListTemplatesRequest) (*delegateev1.ListTemplatesResponse, error) {
	ts, err := h.svc.ListTemplates(ctx, domain.TemplateStatusActive)
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*delegateev1.Template, len(ts))
	for i := range ts {
		out[i] = toTemplate(&ts[i], false)
	}
	return &delegateev1.ListTemplatesResponse{Templates: out}, nil
}

func toStatus(err error) error {
	switch {
	case errors.Is(err, domain.ErrDelegationNotFound), errors.Is(err, domain.ErrTemplateNotFound), errors.Is(err, domain.ErrArtifactNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, domain.ErrDelegationAlreadyExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, application.ErrFull):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, domain.ErrTemplateInUse), errors.Is(err, domain.ErrArtifactInUse), errors.Is(err, domain.ErrTemplateDisabled), errors.Is(err, domain.ErrBlocked), errors.Is(err, domain.ErrNotCancelled),
		errors.Is(err, application.ErrDelegateKeyLeaf), errors.Is(err, application.ErrSecretsRequired),
		errors.Is(err, application.ErrUnsupported), errors.Is(err, application.ErrIneligible):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, application.ErrInvalidDocument), errors.Is(err, application.ErrInvalidStatus),
		errors.Is(err, application.ErrInvalidArgs):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		log.WithError(err).Error("request failed")
		return status.Error(codes.Internal, "internal error")
	}
}

func toArtifact(a *domain.Artifact) *delegateev1.Artifact {
	return &delegateev1.Artifact{Id: a.ID, Document: string(a.Document), CreatedAt: a.CreatedAt.Unix()}
}

func toTemplate(t *domain.Template, withDocument bool) *delegateev1.Template {
	params := make([]*delegateev1.Param, len(t.Params))
	for i, p := range t.Params {
		params[i] = &delegateev1.Param{Name: p.Name, Type: p.Type}
	}
	out := &delegateev1.Template{
		Id: t.ID, ArtifactIds: t.ArtifactIDs, Params: params, Status: t.Status,
		CreatedAt: t.CreatedAt.Unix(),
	}
	if withDocument {
		out.Document = string(t.Document)
	}
	return out
}

func toDelegation(d *domain.Delegation) *delegateev1.Delegation {
	slots := make([]*delegateev1.Slot, len(d.Slots))
	for i, s := range d.Slots {
		slots[i] = &delegateev1.Slot{Name: s.Name, Onchain: s.Onchain, Tapscripts: s.Tapscripts, Outpoint: s.Outpoint}
	}
	out := &delegateev1.Delegation{
		Id:         d.ID,
		Address:    d.Address,
		Status:     d.Status,
		TemplateId: d.TemplateID,
		Variables:  d.Variables,
		ParentId:   d.ParentID,
		Slots:      slots,
		CreatedAt:  d.CreatedAt.Unix(),
		UpdatedAt:  d.UpdatedAt.Unix(),
	}
	if d.ExpiresAt != nil {
		out.ExpiresAt = d.ExpiresAt.Unix()
	}
	return out
}

// toVtxos leaves RenewableAt unset without due: a rotated key or a removed template still lists its vtxos.
func toVtxos(vtxos []clientlib.Vtxo, due []time.Time) []*delegateev1.Vtxo {
	out := make([]*delegateev1.Vtxo, len(vtxos))
	for i, v := range vtxos {
		assets := make([]*delegateev1.Asset, len(v.Assets))
		for j, a := range v.Assets {
			assets[j] = &delegateev1.Asset{AssetId: a.AssetId, Amount: a.Amount}
		}
		out[i] = &delegateev1.Vtxo{
			Outpoint:     v.Outpoint.String(),
			Amount:       v.Amount,
			ExpiresAt:    unix(v.ExpiresAt),
			CreatedAt:    unix(v.CreatedAt),
			Preconfirmed: v.Preconfirmed,
			Assets:       assets,
		}
		if due != nil {
			out[i].RenewableAt = unix(due[i])
		}
	}
	return out
}

// unix is 0 for the zero time: an onchain coin has no expiry.
func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func toRenewals(renewals []domain.Renewal) []*delegateev1.Renewal {
	out := make([]*delegateev1.Renewal, len(renewals))
	for i, r := range renewals {
		out[i] = toRenewal(r)
	}
	return out
}

func toRenewal(r domain.Renewal) *delegateev1.Renewal {
	return &delegateev1.Renewal{
		Outpoints:      r.Outpoints,
		CommitmentTxid: r.CommitmentTxid,
		Success:        r.Success,
		Error:          r.Error,
		AttemptedAt:    r.AttemptedAt.Unix(),
	}
}

func variablesOf(v map[string]string) map[string]string {
	if v == nil {
		return map[string]string{}
	}
	return v
}
