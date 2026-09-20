package grpcservice

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
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
	"golang.org/x/crypto/bcrypt"
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
	version       string
	config        Config
	cfg           *config.Config
	appSvc        application.Service
	servers       []*http.Server
	grpcs         []*grpc.Server
	conns         []*grpc.ClientConn
	loopbackToken string
	authLimiter   *rateLimiter
	stopOnce      sync.Once
}

func NewService(version string, cfg *config.Config) (interfaces.Service, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	svcConfig := Config{Port: cfg.Port, AdminPort: cfg.AdminPort}
	if err := svcConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid service config: %s", err)
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("create loopback credential: %w", err)
	}
	return &service{
		version: version, config: svcConfig, cfg: cfg,
		loopbackToken: hex.EncodeToString(token), authLimiter: newRateLimiter(5),
	}, nil
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
func (s *service) serve(ctx context.Context, appSvc application.Service) (err error) {
	s.appSvc = appSvc
	defer func() {
		if err != nil {
			s.closeServers()
			appSvc.Stop()
			s.appSvc = nil
		}
	}()

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
	if len(s.cfg.AdminUsers) == 0 {
		log.Warn("admin port has no authentication: keep it on a private network")
	}
	appSvc.Start()
	log.Infof("started listening at %s", address(s.config.Port))
	log.Infof("started admin listening at %s", address(s.config.AdminPort))
	return nil
}

func (s *service) Stop() {
	s.stopOnce.Do(func() {
		s.closeServers()
		if s.appSvc != nil {
			s.appSvc.Stop()
		}
		log.Info("shutdown service")
	})
}

func (s *service) closeServers() {
	for _, g := range s.grpcs {
		g.Stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, srv := range s.servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.WithError(err).WithField("server", srv.Addr).Warn("shutdown server")
		}
	}
	for _, conn := range s.conns {
		if err := conn.Close(); err != nil {
			log.WithError(err).Warn("close gateway connection")
		}
	}
	s.grpcs = nil
	s.servers = nil
	s.conns = nil
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

	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if index != nil && len(s.cfg.AdminUsers) > 0 {
		// the gateway reaches grpc through this same guarded port
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(loopbackAuth(s.loopbackToken)))
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
	if index != nil && len(s.cfg.AdminUsers) > 0 {
		handler = basicAuth(s.cfg.AdminUsers, s.loopbackToken, s.authLimiter, handler)
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
	s.conns = append(s.conns, conn)
	return srv, nil
}

type loopbackAuth string

func (p loopbackAuth) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"x-delegatee-loopback": string(p)}, nil
}
func (loopbackAuth) RequireTransportSecurity() bool { return false }

type basicAuthCredentials struct {
	Username string
	Password string
}

func (c basicAuthCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)),
	}, nil
}
func (basicAuthCredentials) RequireTransportSecurity() bool { return false }

var dummyAdminPasswordHash = func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("delegateed-invalid-password"), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return hash
}()

func basicAuth(users []config.AdminUser, loopbackToken string, limiter *rateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loopbackToken != "" && isLoopback(r.RemoteAddr) && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Delegatee-Loopback")), []byte(loopbackToken)) == 1 {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		valid := false
		passwordHash := dummyAdminPasswordHash
		for _, candidate := range users {
			if user == candidate.Username {
				passwordHash = []byte(candidate.PasswordHash)
			}
		}
		if ok && bcrypt.CompareHashAndPassword(passwordHash, []byte(pass)) == nil {
			for _, candidate := range users {
				if user == candidate.Username {
					valid = true
					break
				}
			}
		}
		if !valid {
			if limiter != nil && !limiter.allow(clientIP(r), time.Now()) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="delegateed admin", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func isLoopback(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
