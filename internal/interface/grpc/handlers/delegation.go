package handlers

import (
	"context"
	"time"

	executorv1 "github.com/arkade-os/executor/api-spec/protobuf/gen/executor/v1"
	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (h *Executor) RegisterDelegation(
	ctx context.Context, req *executorv1.RegisterDelegationRequest,
) (*executorv1.RegisterDelegationResponse, error) {
	if req.GetTemplateId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing template id")
	}
	var expiresAt *time.Time
	if req.GetExpiresAt() != 0 {
		at := time.Unix(req.GetExpiresAt(), 0)
		expiresAt = &at
	}
	d, err := h.delegations.RegisterDelegation(ctx, req.GetTemplateId(), req.GetVariables(), expiresAt)
	if err != nil {
		return nil, toStatus(err)
	}
	return &executorv1.RegisterDelegationResponse{Delegation: toDelegation(d)}, nil
}

func (h *Executor) GetDelegation(
	ctx context.Context, req *executorv1.GetDelegationRequest,
) (*executorv1.GetDelegationResponse, error) {
	var d *delegation.Delegation
	var err error
	switch {
	case req.GetId() != 0:
		d, err = h.delegations.GetDelegation(ctx, req.GetId())
	case req.GetAddress() != "":
		d, err = h.delegations.GetDelegationByAddress(ctx, req.GetAddress())
	default:
		return nil, status.Error(codes.InvalidArgument, "missing id or address")
	}
	if err != nil {
		return nil, toStatus(err)
	}
	coins, err := h.execution.Coins(ctx, d.ID)
	if err != nil {
		return nil, toStatus(err)
	}
	return &executorv1.GetDelegationResponse{Delegation: toDelegation(d), Coins: toCoins(coins)}, nil
}

func toCoins(coins []delegation.Coin) []*executorv1.Coin {
	out := make([]*executorv1.Coin, 0, len(coins))
	for _, c := range coins {
		coin := &executorv1.Coin{
			Outpoint: c.Outpoint, Input: int32(c.Input), Amount: c.Amount, Status: string(c.Status), SpentBy: c.SpentBy,
			Confirmations: int32(c.Confirmations),
		}
		if !c.ExpiresAt.IsZero() {
			coin.ExpiresAt = c.ExpiresAt.Unix()
		}
		if !c.Due.IsZero() {
			coin.Due = c.Due.Unix()
		}
		out = append(out, coin)
	}
	return out
}

func toDelegation(d *delegation.Delegation) *executorv1.Delegation {
	out := &executorv1.Delegation{
		Id: d.ID, Fingerprint: d.Fingerprint, Address: d.Address, TemplateId: d.TemplateID,
		Variables: d.Variables, StreamId: d.StreamID, Status: d.Status, CreatedAt: d.CreatedAt.Unix(), UpdatedAt: d.UpdatedAt.Unix(),
	}
	if d.ExpiresAt != nil {
		out.ExpiresAt = d.ExpiresAt.Unix()
	}
	for _, in := range d.Inputs {
		out.Inputs = append(out.Inputs, &executorv1.Input{
			Name: in.Name, Onchain: in.Onchain, Script: in.Script, Tapscripts: in.Tapscripts, Locktime: uint32(in.Locktime),
		})
	}
	return out
}
