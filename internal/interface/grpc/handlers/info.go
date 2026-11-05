package handlers

import (
	"context"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
)

func (h *Delegatee) GetInfo(context.Context, *delegateev1.GetInfoRequest) (*delegateev1.GetInfoResponse, error) {
	info := h.delegations.Info()
	return &delegateev1.GetInfoResponse{
		Version: h.version, Network: info.Network, CosignerPubkey: info.CosignerKey,
		ServerPubkey: info.ServerKey, EmulatorPubkey: info.EmulatorKey, EncryptionPubkey: info.EncryptionKey,
	}, nil
}
