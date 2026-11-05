package grpc

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestBasicAuthCheck(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)
	auth := newBasicAuth([]AdminUser{{Name: "admin", PasswordHash: string(hash)}})

	require.NoError(t, auth.check(withBasic(t, "admin:secret")))
	require.Equal(t, codes.Unauthenticated, status.Code(auth.check(t.Context())))
	require.Equal(t, codes.Unauthenticated, status.Code(auth.check(withBasic(t, "admin:wrong"))))
	require.Equal(t, codes.Unauthenticated, status.Code(auth.check(withBasic(t, "nobody:secret"))))
	require.Equal(t, challenge, status.Convert(auth.check(t.Context())).Message())

	bearer := metadata.NewIncomingContext(t.Context(), metadata.Pairs("authorization", "Bearer x"))
	require.Equal(t, codes.Unauthenticated, status.Code(auth.check(bearer)))
}

func TestBasicAuthThrottlesFailures(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)
	auth := newBasicAuth([]AdminUser{{Name: "admin", PasswordHash: string(hash)}})
	for range 5 {
		require.Equal(t, codes.Unauthenticated, status.Code(auth.check(withBasic(t, "admin:wrong"))))
	}
	require.Equal(t, codes.ResourceExhausted, status.Code(auth.check(withBasic(t, "admin:secret"))))
	// missing credentials never count as attempts
	require.Equal(t, codes.Unauthenticated, status.Code(auth.check(t.Context())))
}

func TestBasicAuthPages(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)
	guarded := newBasicAuth([]AdminUser{{Name: "admin", PasswordHash: string(hash)}}).pages(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("page")) }),
	)

	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Equal(t, challenge, rec.Header().Get("WWW-Authenticate"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "wrong")
	rec = httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "secret")
	rec = httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "page", rec.Body.String())
}

func withBasic(t *testing.T, credentials string) context.Context {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	return metadata.NewIncomingContext(t.Context(), metadata.Pairs("authorization", "Basic "+encoded))
}
