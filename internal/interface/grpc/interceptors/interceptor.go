package interceptors

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

func UnaryInterceptor() grpc.ServerOption { return grpc.UnaryInterceptor(logUnary) }

// logUnary logs every call: failures as warnings, the rest at debug level.
func logUnary(
	ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	start := time.Now()
	resp, err := handler(ctx, req)
	entry := log.WithFields(log.Fields{
		"method":   info.FullMethod,
		"duration": time.Since(start).String(),
		"code":     status.Code(err).String(),
	})
	if err != nil {
		entry.WithError(err).Warn("grpc call failed")
	} else {
		entry.Debug("grpc call")
	}
	return resp, err
}
