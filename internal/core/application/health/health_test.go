package health

import (
	"context"
	"errors"
	"testing"
	"time"

	executionapp "github.com/arkade-os/executor/internal/core/application/execution"
	"github.com/arkade-os/executor/internal/core/ports"
	"github.com/stretchr/testify/require"
)

func TestCheckNamesEveryDependencyWithItsError(t *testing.T) {
	arkErr := errors.New("arkd down")
	c := NewChecker(pinger{}, arkStub{err: arkErr}, emulatorStub{}, newLoop())

	entries := c.Check(t.Context())
	require.Len(t, entries, 5)
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name
	}
	require.Equal(t, []string{"db", "arkd", "electrum", "emulator", "loop"}, names)
	require.NoError(t, entries[0].Err)
	require.Equal(t, arkErr, entries[1].Err)
	require.Error(t, entries[2].Err, "no chain connection")
	require.NoError(t, entries[3].Err)
	require.NoError(t, entries[4].Err)
	require.False(t, Healthy(entries))

	entries[1].Err, entries[2].Err = nil, nil
	require.True(t, Healthy(entries))
}

func TestCheckBoundsASlowDependency(t *testing.T) {
	c := NewChecker(pinger{}, arkStub{wait: true}, emulatorStub{}, newLoop())
	c.timeout = 50 * time.Millisecond
	start := time.Now()
	entries := c.Check(t.Context())
	require.Less(t, time.Since(start), time.Second)
	require.ErrorIs(t, entries[1].Err, context.DeadlineExceeded)
	require.NoError(t, entries[0].Err)
}

type pinger struct{ err error }

func (p pinger) Ping(context.Context) error { return p.err }

type arkStub struct {
	ports.Signer
	err  error
	wait bool
}

func (a arkStub) Info(ctx context.Context) (ports.ArkInfo, error) {
	if a.wait {
		<-ctx.Done()
		return ports.ArkInfo{}, ctx.Err()
	}
	return ports.ArkInfo{}, a.err
}

type emulatorStub struct{ ports.Emulator }

func (emulatorStub) Info(context.Context) (ports.EmulatorInfo, error) {
	return ports.EmulatorInfo{}, nil
}

func newLoop() *executionapp.Service {
	return executionapp.NewService(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, executionapp.Limits{})
}
