package grpc

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	executorv1 "github.com/arkade-os/executor/api-spec/protobuf/gen/executor/v1"
	"github.com/arkade-os/executor/internal/core/application/health"
	"github.com/arkade-os/executor/internal/interface/grpc/handlers"
	"github.com/meshapi/grpc-api-gateway/gateway"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const maxRequestBodySize = 1 << 20

//go:embed web/index.html
var index []byte

// Server serves gRPC and its JSON gateway over h2c on the public and the admin port.
type Server struct {
	public, admin *port
}

type port struct {
	listener net.Listener
	http     *http.Server
	grpc     *grpc.Server
	conn     *grpc.ClientConn
}

// Options configures the two ports; a port of 0 picks a free one.
type Options struct {
	PublicPort, AdminPort int
	PublicRateLimit       int // requests per second per client address on the public port, 0 for no limit
	Users                 []AdminUser
	Status                StatusSource
	Health                handlers.Health
}

// Listen binds both ports. The admin port serves AdminService as well, the operator UI, /metrics
// and /healthz, and, when there are users, checks their credentials on every call.
func Listen(
	ctx context.Context, opts Options, executor *handlers.Executor, admin *handlers.Admin,
) (*Server, error) {
	publicServices := func(s *grpc.Server, mux *gateway.ServeMux, conn *grpc.ClientConn) {
		executorv1.RegisterExecutorServiceServer(s, executor)
		executorv1.RegisterExecutorServiceHandler(ctx, mux, conn)
	}
	adminServices := func(s *grpc.Server, mux *gateway.ServeMux, conn *grpc.ClientConn) {
		publicServices(s, mux, conn)
		executorv1.RegisterAdminServiceServer(s, admin)
		executorv1.RegisterAdminServiceHandler(ctx, mux, conn)
	}
	interceptors := []grpc.UnaryServerInterceptor{logUnary}
	pages := adminPages(opts.Status, opts.Health)
	if len(opts.Users) > 0 {
		auth := newBasicAuth(opts.Users)
		interceptors = append(interceptors, auth.unary)
		pages = auth.pages(pages)
	}
	publicSrv, err := listen(opts.PublicPort, publicServices, nil, logUnary)
	if err != nil {
		return nil, err
	}
	if opts.PublicRateLimit > 0 {
		publicSrv.http.Handler = newRateLimiter(
			opts.PublicRateLimit,
		).middleware(publicSrv.http.Handler)
	}
	adminSrv, err := listen(opts.AdminPort, adminServices, pages, interceptors...)
	if err != nil {
		publicSrv.close()
		return nil, err
	}
	return &Server{public: publicSrv, admin: adminSrv}, nil
}

func (s *Server) PublicAddr() string { return s.public.listener.Addr().String() }
func (s *Server) AdminAddr() string  { return s.admin.listener.Addr().String() }

// Serve blocks until Stop or until a port fails.
func (s *Server) Serve() error {
	errs := make(chan error, 2)
	for _, p := range []*port{s.public, s.admin} {
		go func() { errs <- p.http.Serve(p.listener) }()
	}
	log.Infof("listening on %s, admin on %s", s.PublicAddr(), s.AdminAddr())
	if err := <-errs; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) Stop() {
	s.public.close()
	s.admin.close()
}

func (p *port) close() {
	p.grpc.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := p.http.Shutdown(ctx); err != nil {
		log.WithError(err).Warn("shutdown server")
	}
	_ = p.conn.Close()
}

// listen serves on portNumber; without pages it is the public port, which allows any origin.
func listen(
	portNumber int, register func(*grpc.Server, *gateway.ServeMux, *grpc.ClientConn),
	pages http.Handler, interceptors ...grpc.UnaryServerInterceptor,
) (*port, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", portNumber))
	if err != nil {
		return nil, err
	}
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxRequestBodySize), grpc.ChainUnaryInterceptor(interceptors...),
	)

	// the gateway reaches grpc through the same port
	_, boundPort, _ := net.SplitHostPort(listener.Addr().String())
	conn, err := grpc.NewClient(
		"127.0.0.1:"+boundPort, grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	gatewayMux := gateway.NewServeMux(gateway.WithErrorHandler(restError))
	register(grpcServer, gatewayMux, conn)

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	return &port{
		listener: listener,
		grpc:     grpcServer,
		conn:     conn,
		http: &http.Server{
			Handler:           route(grpcServer, gatewayMux, pages),
			Protocols:         protocols,
			ReadHeaderTimeout: 10 * time.Second,
			// without ReadTimeout, h2c connections die after ReadHeaderTimeout
			ReadTimeout: 30 * time.Second,
			IdleTimeout: 2 * time.Minute,
		},
	}, nil
}

func route(grpcServer *grpc.Server, gatewayMux, pages http.Handler) http.Handler {
	open := pages == nil // only the public port allows any origin
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pages != nil && r.Method == http.MethodGet && servesPage(r) {
			pages.ServeHTTP(w, r)
			return
		}
		if open {
			cors(w)
		}
		if r.Method == http.MethodOptions {
			return
		}
		if isRest(r) {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
			gatewayMux.ServeHTTP(w, r)
			return
		}
		grpcServer.ServeHTTP(w, r)
	})
}

func adminPages(status StatusSource, checks handlers.Health) http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector{status: status, health: checks})
	metrics := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().
			Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		_, _ = w.Write(index)
	})
	mux.Handle("/metrics", metrics)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		entries := checks.Check(r.Context())
		body := struct {
			Healthy bool              `json:"healthy"`
			Checks  map[string]string `json:"checks"`
		}{Healthy: health.Healthy(entries), Checks: map[string]string{}}
		for _, e := range entries {
			body.Checks[e.Name] = "ok"
			if e.Err != nil {
				body.Checks[e.Name] = e.Err.Error()
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if !body.Healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	return mux
}

func cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS")
}

func servesPage(r *http.Request) bool {
	return r.URL.Path == "/" || r.URL.Path == "/metrics" || r.URL.Path == "/healthz"
}

func isRest(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodDelete ||
		strings.Contains(r.Header.Get("Content-Type"), "application/json")
}

// restError answers FailedPrecondition with 412 where the gateway would send 400.
func restError(
	ctx context.Context, mux *gateway.ServeMux, m gateway.Marshaler, w http.ResponseWriter,
	r *http.Request, err error,
) {
	if status.Code(err) == codes.FailedPrecondition {
		err = gateway.HTTPStatusError{HTTPStatus: http.StatusPreconditionFailed, Err: err}
	}
	gateway.DefaultHTTPErrorHandler(ctx, mux, m, w, r, err)
}

// logUnary logs failures as warnings, the rest at debug level.
func logUnary(
	ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	start := time.Now()
	resp, err := handler(ctx, req)
	entry := log.WithFields(
		log.Fields{"method": info.FullMethod, "duration": time.Since(start).String()},
	)
	if err != nil {
		entry.WithError(err).Warn("grpc call failed")
	} else {
		entry.Debug("grpc call")
	}
	return resp, err
}
