package handlers

import (
	"context"

	"github.com/arkade-os/delegatee/internal/core/application"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

type healthHandler struct {
	svc application.Service
}

func NewHealthHandler(svc application.Service) grpchealth.HealthServer {
	return &healthHandler{svc: svc}
}

func (h *healthHandler) Check(
	ctx context.Context, _ *grpchealth.HealthCheckRequest,
) (*grpchealth.HealthCheckResponse, error) {
	list, _ := h.List(ctx, nil)
	for _, s := range list.Statuses {
		if s.Status != grpchealth.HealthCheckResponse_SERVING {
			return s, nil
		}
	}
	return &grpchealth.HealthCheckResponse{Status: grpchealth.HealthCheckResponse_SERVING}, nil
}

func (h *healthHandler) Watch(_ *grpchealth.HealthCheckRequest, _ grpchealth.Health_WatchServer) error {
	return nil
}

func (h *healthHandler) List(
	ctx context.Context, _ *grpchealth.HealthListRequest,
) (*grpchealth.HealthListResponse, error) {
	statuses := map[string]*grpchealth.HealthCheckResponse{}
	for name, err := range h.svc.Health(ctx) {
		s := grpchealth.HealthCheckResponse_SERVING
		if err != nil {
			s = grpchealth.HealthCheckResponse_NOT_SERVING
		}
		statuses[name] = &grpchealth.HealthCheckResponse{Status: s}
	}
	return &grpchealth.HealthListResponse{Statuses: statuses}, nil
}
