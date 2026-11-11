package handlers

import (
	"context"

	executorv1 "github.com/arkade-os/executor/api-spec/protobuf/gen/executor/v1"
)

func (h *Executor) GetInfo(context.Context, *executorv1.GetInfoRequest) (*executorv1.GetInfoResponse, error) {
	info := h.delegations.Info()
	return &executorv1.GetInfoResponse{
		Version: h.version, Network: info.Network, CosignerPubkey: info.CosignerKey,
		ServerPubkey: info.ServerKey, EmulatorPubkey: info.EmulatorKey, EncryptionPubkey: info.EncryptionKey,
	}, nil
}
