package interceptors

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestUnaryInterceptorPassesThrough(t *testing.T) {
	require.NotNil(t, UnaryInterceptor())
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}
	resp, err := logUnary(t.Context(), "req", info, func(_ context.Context, req any) (any, error) {
		return req.(string) + "!", nil
	})
	require.NoError(t, err)
	require.Equal(t, "req!", resp)

	boom := errors.New("boom")
	_, err = logUnary(t.Context(), nil, info, func(context.Context, any) (any, error) { return nil, boom })
	require.ErrorIs(t, err, boom)
}
