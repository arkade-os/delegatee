package grpcservice

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/config"
	"github.com/arkade-os/delegatee/internal/core/application"
	interfaces "github.com/arkade-os/delegatee/internal/interface"
	"github.com/arkade-os/delegatee/internal/interface/grpc/handlers"
	"github.com/arkade-os/delegatee/internal/interface/grpc/interceptors"
	"github.com/meshapi/grpc-api-gateway/gateway"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

const maxRequestBodySize = 1 << 20

type service struct {
	version string
	config  Config
	cfg     *config.Config
	appSvc  application.Service
	servers []*http.Server
	grpcs   []*grpc.Server
}

func NewService(version string, cfg *config.Config) (interfaces.Service, error) {
	svcConfig := Config{Port: cfg.Port, AdminPort: cfg.AdminPort}
	if err := svcConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid service config: %s", err)
	}
	return &service{version: version, config: svcConfig, cfg: cfg}, nil
}

func (s *service) Start() error {
	ctx := context.Background()
	appSvc, err := s.cfg.AppService(ctx)
	if err != nil {
		return err
	}
	s.appSvc = appSvc

	public, err := s.newServer(ctx, s.config.Port, func(srv *grpc.Server, gw *gateway.ServeMux, conn *grpc.ClientConn) {
		delegateev1.RegisterDelegateeServiceServer(srv, handlers.New(s.version, appSvc))
		delegateev1.RegisterDelegateeServiceHandler(ctx, gw, conn)
	})
	if err != nil {
		return err
	}
	admin, err := s.newServer(ctx, s.config.AdminPort, func(srv *grpc.Server, gw *gateway.ServeMux, conn *grpc.ClientConn) {
		delegateev1.RegisterAdminServiceServer(srv, handlers.NewAdmin(appSvc))
		delegateev1.RegisterAdminServiceHandler(ctx, gw, conn)
	})
	if err != nil {
		return err
	}
	for _, srv := range []*http.Server{public, admin} {
		// nolint:all
		go srv.ListenAndServe()
	}
	appSvc.Start()
	log.Infof("started listening at %s", address(s.config.Port))
	log.Infof("started admin listening at %s", address(s.config.AdminPort))
	return nil
}

func (s *service) Stop() {
	for _, g := range s.grpcs {
		g.Stop()
	}
	for _, srv := range s.servers {
		// nolint
		srv.Shutdown(context.Background())
	}
	if s.appSvc != nil {
		s.appSvc.Stop()
	}
	log.Info("shutdown service")
}

// newServer builds a grpc server plus its JSON gateway on one port; register
// wires the services on both.
func (s *service) newServer(
	ctx context.Context, port uint32,
	register func(*grpc.Server, *gateway.ServeMux, *grpc.ClientConn),
) (*http.Server, error) {
	grpcServer := grpc.NewServer(
		grpc.Creds(insecure.NewCredentials()),
		grpc.MaxRecvMsgSize(maxRequestBodySize),
		interceptors.UnaryInterceptor(),
	)
	grpchealth.RegisterHealthServer(grpcServer, handlers.NewHealthHandler(s.appSvc))

	conn, err := grpc.NewClient(gatewayAddress(port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	gwmux := gateway.NewServeMux(
		gateway.WithHealthzEndpoint(grpchealth.NewHealthClient(conn)),
	)
	register(grpcServer, gwmux, conn)

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	srv := &http.Server{
		Addr:      address(port),
		Handler:   router(grpcServer, gwmux),
		Protocols: protocols,
	}
	s.grpcs = append(s.grpcs, grpcServer)
	s.servers = append(s.servers, srv)
	return srv, nil
}

func router(grpcServer *grpc.Server, grpcGateway http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			cors(w)
			return
		}
		if isHttpRequest(r) {
			cors(w)
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
			grpcGateway.ServeHTTP(w, r)
			return
		}
		grpcServer.ServeHTTP(w, r)
	})
}

func cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Add("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS")
}

func isHttpRequest(req *http.Request) bool {
	return req.Method == http.MethodGet || req.Method == http.MethodDelete ||
		strings.Contains(req.Header.Get("Content-Type"), "application/json")
}
