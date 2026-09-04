package handlers

import (
	"context"
	"errors"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
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
	info, err := h.svc.Info(req.GetRenewalWindow())
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
		RenewalWindow:         info.RenewalWindow,
	}, nil
}

func (h *handler) RegisterDelegation(
	ctx context.Context, req *delegateev1.RegisterDelegationRequest,
) (*delegateev1.RegisterDelegationResponse, error) {
	if len(req.GetTapscripts()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing tapscripts")
	}
	d, err := h.svc.RegisterDelegation(ctx, req.GetTapscripts(), req.GetRenewalWindow())
	if err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.RegisterDelegationResponse{Delegation: toDelegation(d)}, nil
}

func toStatus(err error) error {
	switch {
	case errors.Is(err, domain.ErrDelegationNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, domain.ErrDelegationAlreadyExists):
		return status.Error(codes.AlreadyExists, err.Error())
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
		CreatedAt:     d.CreatedAt.Unix(),
		UpdatedAt:     d.UpdatedAt.Unix(),
	}
}

func toVtxos(vtxos []types.Vtxo) []*delegateev1.Vtxo {
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
			Preconfirmed: v.Preconfirmed,
			Assets:       assets,
		}
	}
	return out
}

func toRenewals(renewals []domain.Renewal) []*delegateev1.Renewal {
	out := make([]*delegateev1.Renewal, len(renewals))
	for i, r := range renewals {
		out[i] = &delegateev1.Renewal{
			Outpoints:      r.Outpoints,
			CommitmentTxid: r.CommitmentTxid,
			Success:        r.Success,
			Error:          r.Error,
			AttemptedAt:    r.AttemptedAt.Unix(),
		}
	}
	return out
}
