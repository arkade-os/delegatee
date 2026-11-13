package grpc

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AdminUser is an operator allowed on the admin port.
type AdminUser struct {
	Name         string
	PasswordHash string
}

// the gateway sends the Unauthenticated message as the WWW-Authenticate header
const challenge = `Basic realm="executor admin"`

var dummyHash, _ = bcrypt.GenerateFromPassword(
	[]byte("executor-invalid-password"), bcrypt.DefaultCost,
)

// basicAuth checks the authorization metadata, which the gateway forwards from the HTTP header.
type basicAuth struct {
	hashes   map[string][]byte
	failures *rate.Limiter
}

func (a *basicAuth) unary(
	ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	if err := a.check(ctx); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (a *basicAuth) check(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	return a.verify(md.Get("authorization"))
}

func (a *basicAuth) pages(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch status.Code(a.verify(r.Header.Values("Authorization"))) {
		case codes.OK:
			next.ServeHTTP(w, r)
		case codes.ResourceExhausted:
			http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
		default:
			w.Header().Set("WWW-Authenticate", challenge)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	})
}

func (a *basicAuth) verify(authorization []string) error {
	user, pass, ok := parseBasic(authorization)
	if !ok {
		return status.Error(codes.Unauthenticated, challenge)
	}
	if a.failures.Tokens() < 1 {
		return status.Error(codes.ResourceExhausted, "too many failed attempts")
	}
	// an unknown user pays the same bcrypt cost
	hash, known := a.hashes[user]
	if !known {
		hash = dummyHash
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(pass)) != nil || !known {
		a.failures.Allow()
		return status.Error(codes.Unauthenticated, challenge)
	}
	return nil
}

func newBasicAuth(users []AdminUser) *basicAuth {
	a := &basicAuth{
		hashes:   map[string][]byte{},
		failures: rate.NewLimiter(rate.Every(time.Second), 5),
	}
	for _, u := range users {
		a.hashes[u.Name] = []byte(u.PasswordHash)
	}
	return a
}

func parseBasic(values []string) (user, pass string, ok bool) {
	if len(values) == 0 {
		return "", "", false
	}
	scheme, encoded, _ := strings.Cut(values[0], " ")
	if !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", "", false
	}
	return strings.Cut(string(raw), ":")
}
