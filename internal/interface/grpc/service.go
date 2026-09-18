package grpcservice

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/config"
	"github.com/arkade-os/delegatee/internal/core/application"
	interfaces "github.com/arkade-os/delegatee/internal/interface"
	"github.com/arkade-os/delegatee/internal/interface/grpc/handlers"
	"github.com/arkade-os/delegatee/internal/interface/grpc/interceptors"
	"github.com/meshapi/grpc-api-gateway/gateway"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

const maxRequestBodySize = 1 << 20

// the operator web UI, served at / on the admin port
//
//go:embed web/index.html
var adminUI []byte

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
	return s.serve(ctx, appSvc)
}

// serve exposes appSvc on both ports and starts it.
func (s *service) serve(ctx context.Context, appSvc application.Service) error {
	s.appSvc = appSvc

	public, err := s.newServer(ctx, s.config.Port, nil, func(srv *grpc.Server, gw *gateway.ServeMux, conn *grpc.ClientConn) {
		delegateev1.RegisterDelegateeServiceServer(srv, handlers.New(s.version, appSvc))
		delegateev1.RegisterDelegateeServiceHandler(ctx, gw, conn)
	})
	if err != nil {
		return err
	}
	// the admin port is a superset of the public one, so the UI needs a single origin
	admin, err := s.newServer(ctx, s.config.AdminPort, adminUI, func(srv *grpc.Server, gw *gateway.ServeMux, conn *grpc.ClientConn) {
		delegateev1.RegisterDelegateeServiceServer(srv, handlers.New(s.version, appSvc))
		delegateev1.RegisterDelegateeServiceHandler(ctx, gw, conn)
		delegateev1.RegisterAdminServiceServer(srv, handlers.NewAdmin(appSvc))
		delegateev1.RegisterAdminServiceHandler(ctx, gw, conn)
	})
	if err != nil {
		return err
	}
	for _, srv := range []*http.Server{public, admin} {
		go func() {
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				log.WithError(err).Fatalf("server on %s stopped", srv.Addr)
			}
		}()
	}
	if s.cfg.AdminPassword == "" {
		log.Warn("admin port has no password (DELEGATEE_ADMIN_PASSWORD): keep it on a private network")
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
// wires the services on both. index, when set, is the page served at /.
func (s *service) newServer(
	ctx context.Context, port uint32, index []byte,
	register func(*grpc.Server, *gateway.ServeMux, *grpc.ClientConn),
) (*http.Server, error) {
	grpcServer := grpc.NewServer(
		grpc.Creds(insecure.NewCredentials()),
		grpc.MaxRecvMsgSize(maxRequestBodySize),
		interceptors.UnaryInterceptor(),
	)
	grpchealth.RegisterHealthServer(grpcServer, handlers.NewHealthHandler(s.appSvc))

	password := ""
	if index != nil {
		password = s.cfg.AdminPassword
	}
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if password != "" {
		// the gateway reaches grpc through this same guarded port
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(loopbackAuth(password)))
	}
	conn, err := grpc.NewClient(gatewayAddress(port), dialOpts...)
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

	var metrics http.Handler
	if index != nil { // admin port only
		registry := prometheus.NewRegistry()
		registry.MustRegister(collector{s.appSvc})
		metrics = promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	}
	handler := router(grpcServer, gwmux, index, metrics)
	if password != "" {
		handler = basicAuth(password, handler)
	}
	if index == nil && s.cfg.PublicRateLimit > 0 {
		handler = newRateLimiter(s.cfg.PublicRateLimit).middleware(handler)
	}
	srv := &http.Server{
		Addr:      address(port),
		Handler:   handler,
		Protocols: protocols,
		// no body timeouts: they would cut grpc streams. Headers are enough against slow clients.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	s.grpcs = append(s.grpcs, grpcServer)
	s.servers = append(s.servers, srv)
	return srv, nil
}

// loopbackAuth authenticates the gateway's own grpc calls, which only happen
// for requests basicAuth already let through.
type loopbackAuth string

func (p loopbackAuth) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:"+string(p))),
	}, nil
}
func (loopbackAuth) RequireTransportSecurity() bool { return false }

// basicAuth guards the admin port, grpc and REST alike: user "admin".
func basicAuth(password string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(password))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		got := sha256.Sum256([]byte(pass))
		if !ok || user != "admin" || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="delegateed admin", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func router(grpcServer *grpc.Server, grpcGateway http.Handler, index []byte, metrics http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if metrics != nil && r.Method == http.MethodGet && r.URL.Path == "/metrics" {
			metrics.ServeHTTP(w, r)
			return
		}
		if index != nil && r.Method == http.MethodGet && r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
			_, _ = w.Write(index)
			return
		}
		// no CORS on the admin port: the UI is same-origin, and a wildcard
		// would let any page in the operator's browser cancel delegations
		if r.Method == http.MethodOptions {
			if index == nil {
				cors(w)
			}
			return
		}
		if isHttpRequest(r) {
			if index == nil {
				cors(w)
			}
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
