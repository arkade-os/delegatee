package execution

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRefusal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		cancelled bool
		refused   bool
	}{
		{name: "invalid argument", err: status.Error(codes.InvalidArgument, "invalid"), refused: true},
		{name: "failed precondition", err: status.Error(codes.FailedPrecondition, "precondition"), refused: true},
		{name: "not found", err: status.Error(codes.NotFound, "missing"), refused: true},
		{name: "already exists", err: status.Error(codes.AlreadyExists, "exists"), refused: true},
		{name: "out of range", err: status.Error(codes.OutOfRange, "range"), refused: true},
		{name: "unavailable", err: status.Error(codes.Unavailable, "offline")},
		{name: "deadline", err: status.Error(codes.DeadlineExceeded, "timeout")},
		{name: "cancelled rpc", err: status.Error(codes.Canceled, "cancelled")},
		{name: "ordinary error", err: errors.New("offline")},
		{name: "cancelled context", err: status.Error(codes.InvalidArgument, "invalid"), cancelled: true},
		{name: "ineligible", err: fmt.Errorf("%w: broken", template.ErrIneligible), refused: true},
		{name: "unaffordable", err: fmt.Errorf("%w: %w: fee 100 exceeds the cap 0", template.ErrIneligible, template.ErrUnaffordable)},
		{name: "duplicate transaction", err: status.Error(codes.AlreadyExists, "arkd: duplicated offchain tx: txid")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			got := refusal(ctx, tc.err)
			require.Equal(t, tc.refused, chargesTemplate(got))
			require.ErrorIs(t, got, tc.err)
			require.EqualError(t, got, tc.err.Error())
			if !tc.refused {
				require.Same(t, tc.err, got)
			}
		})
	}
}
