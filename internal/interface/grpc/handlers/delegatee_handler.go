package handlers

import (
	"context"
	"errors"

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

func (h *handler) GetInfo(
	_ context.Context, req *delegateev1.GetInfoRequest,
) (*delegateev1.GetInfoResponse, error) {
	info, err := h.svc.Info(domain.Params{
		RenewalWindow: req.GetRenewalWindow(), MaxFee: req.GetMaxFee(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.GetInfoResponse{
		Version:               h.version,
		Network:               info.Network,
		DelegatePubkey:        info.DelegatePubKey,
		ServerPubkey:          info.ServerPubKey,
		EmulatorPubkey:        info.EmulatorPubKey,
		EmulatorTweakedPubkey: info.EmulatorTweakedPubKey,
		ArkadeScript:          info.ArkadeScript,
		DelegateTapscript:     info.DelegateTapscript,
		RenewalWindow:         info.Params.RenewalWindow,
		MaxFee:                info.Params.MaxFee,
	}, nil
}

func (h *handler) RegisterDelegation(
	ctx context.Context, req *delegateev1.RegisterDelegationRequest,
) (*delegateev1.RegisterDelegationResponse, error) {
	if len(req.GetTapscripts()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing tapscripts")
	}
	d, err := h.svc.RegisterDelegation(ctx, req.GetTapscripts(), domain.Params{
		RenewalWindow: req.GetRenewalWindow(), MaxFee: req.GetMaxFee(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
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
		Vtxos:      h.toVtxos(d, vtxos),
		Renewals:   toRenewals(renewals),
	}, nil
}

func (h *handler) RevokeDelegation(
	ctx context.Context, req *delegateev1.RevokeDelegationRequest,
) (*delegateev1.RevokeDelegationResponse, error) {
	if req.GetAddress() == "" || req.GetPubkey() == "" || req.GetSignature() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing address, pubkey or signature")
	}
	if err := h.svc.RevokeDelegation(ctx, req.GetAddress(), req.GetPubkey(), req.GetSignature(), req.GetTimestamp()); err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.RevokeDelegationResponse{}, nil
}

func toStatus(err error) error {
	switch {
	case errors.Is(err, domain.ErrDelegationNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, domain.ErrDelegationAlreadyExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, application.ErrFull):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, application.ErrInvalidSignature):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, application.ErrInvalidScript):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		log.WithError(err).Error("request failed")
		return status.Error(codes.Internal, "internal error")
	}
}

func toDelegation(d *domain.Delegation) *delegateev1.Delegation {
	return &delegateev1.Delegation{
		Id:            d.ID,
		Address:       d.Address,
		Status:        d.Status,
		Tapscripts:    d.Tapscripts,
		RenewalWindow: d.RenewalWindow,
		MaxFee:        d.MaxFee,
		CreatedAt:     d.CreatedAt.Unix(),
		UpdatedAt:     d.UpdatedAt.Unix(),
	}
}

func (h *handler) toVtxos(d *domain.Delegation, vtxos []clientlib.Vtxo) []*delegateev1.Vtxo {
	out := make([]*delegateev1.Vtxo, len(vtxos))
	for i, v := range vtxos {
		assets := make([]*delegateev1.Asset, len(v.Assets))
		for j, a := range v.Assets {
			assets[j] = &delegateev1.Asset{AssetId: a.AssetId, Amount: a.Amount}
		}
		out[i] = &delegateev1.Vtxo{
			Outpoint:     v.Outpoint.String(),
			Amount:       v.Amount,
			ExpiresAt:    v.ExpiresAt.Unix(),
			CreatedAt:    v.CreatedAt.Unix(),
			RenewableAt:  h.svc.DueAt(d, v).Unix(),
			Preconfirmed: v.Preconfirmed,
			Assets:       assets,
		}
	}
	return out
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
