//go:build e2e

package e2e

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/config"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/arkade-os/delegatee/internal/infrastructure/arkd"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// the daemon dies once its forfeits reached arkd, before the batch reported its end
func TestRestartMidBatch(t *testing.T) {
	crash := &crashingArk{afterForfeits: true}
	d := start(t, crash.dial(t))
	w, renewal := boardingDelegations(t, d, newOwner(t, d))
	faucet(t, w.Address, 20_000)
	crash.wait(t)
	require.Equal(t, "submitted", attemptsOf(t, d, w.Id)[0].Status)
	d.stop()

	again := d.restart(t, realArk)
	boarded := waitForVtxo(t, again, renewal.Inputs[0].Script, "")
	require.EqualValues(t, 20_000, boarded.Amount)
	require.Eventually(t, func() bool {
		attempts := attemptsOf(t, again, w.Id)
		return len(attempts) == 1 && attempts[0].Status == "succeeded"
	}, time.Minute, time.Second, "the boarding is not recorded once")
}

// the daemon dies once the forfeits of a renewal reached arkd
func TestRestartMidRenewal(t *testing.T) {
	d := start(t)
	w, renewal := boardingDelegations(t, d, newOwner(t, d))
	// cancelled, the renewal leaves the boarded coin alone until the daemon is ready to crash
	_, err := d.admin.CancelDelegation(t.Context(), &delegateev1.CancelDelegationRequest{Id: renewal.Id})
	require.NoError(t, err)
	faucet(t, w.Address, 20_000)
	boarded := landed(t, d, w, renewal, 1)[0]
	d.stop()

	crash := &crashingArk{afterForfeits: true}
	mid := d.restart(t, crash.dial(t))
	_, err = mid.admin.ResumeDelegation(t.Context(), &delegateev1.ResumeDelegationRequest{Id: renewal.Id})
	require.NoError(t, err)
	crash.wait(t)
	mid.stop()

	again := mid.restart(t, realArk)
	renewed := landed(t, again, renewal, renewal, 1)[0]
	require.EqualValues(t, 20_000, renewed.Amount)
	require.Eventually(t, func() bool {
		var spending, succeeded int
		for _, a := range attemptsOf(t, again, renewal.Id) {
			if slices.Contains(a.Coins, boarded.Outpoint.String()) {
				spending++
				if a.Status == "succeeded" {
					succeeded++
				}
			}
		}
		return spending == 1 && succeeded == 1
	}, time.Minute, time.Second, "the renewal is not recorded once")
	require.Eventually(t, func() bool {
		unspent := slices.DeleteFunc(vtxosAt(t, again, renewal.Inputs[0].Script), func(v clientlib.Vtxo) bool { return v.Spent })
		return len(unspent) == 1 && unspent[0].Amount == 20_000
	}, time.Minute, time.Second, "no single unspent output of the full amount")
}

// realArk makes a restarted daemon dial arkd itself.
func realArk(c *config.Config) { c.Ark, c.Indexer = nil, nil }

// crashingArk is arkd as the daemon sees it until it dies: then every call fails and the batch events end.
type crashingArk struct {
	ports.Signer
	afterForfeits bool // dies once its forfeits reached arkd
	crashed       chan struct{}
	once          sync.Once
}

// dial points the daemon at arkd through the crash.
func (a *crashingArk) dial(t *testing.T) func(*config.Config) {
	return func(c *config.Config) {
		client, err := arkd.NewClient(arkURL)
		require.NoError(t, err)
		t.Cleanup(client.Close)
		a.Signer, a.crashed = client, make(chan struct{})
		c.Ark, c.Indexer = a, client
	}
}

func (a *crashingArk) wait(t *testing.T) {
	t.Helper()
	select {
	case <-a.crashed:
	case <-time.After(2 * time.Minute):
		t.Fatal("the daemon never reached its crash")
	}
}

func (a *crashingArk) crash() { a.once.Do(func() { close(a.crashed) }) }

func (a *crashingArk) dead() error {
	select {
	case <-a.crashed:
		return status.Error(codes.Unavailable, "crashed")
	default:
		return nil
	}
}

func (a *crashingArk) BatchEvents(ctx context.Context) (<-chan ports.BatchEvent, func(), error) {
	events, stop, err := a.Signer.BatchEvents(ctx)
	if err != nil {
		return nil, nil, err
	}
	out := make(chan ports.BatchEvent)
	go func() {
		defer close(out)
		for {
			select {
			case <-a.crashed:
				return
			case event, ok := <-events:
				if !ok {
					return
				}
				select {
				case out <- event:
				case <-a.crashed:
					return
				}
			}
		}
	}()
	return out, stop, nil
}

func (a *crashingArk) SubmitTreeNonces(ctx context.Context, batchID, cosigner string, nonces tree.TreeNonces) error {
	if err := a.dead(); err != nil {
		return err
	}
	return a.Signer.SubmitTreeNonces(ctx, batchID, cosigner, nonces)
}

func (a *crashingArk) SubmitSignedForfeitTxs(ctx context.Context, forfeits []string, commitment string) error {
	if err := a.dead(); err != nil {
		return err
	}
	err := a.Signer.SubmitSignedForfeitTxs(ctx, forfeits, commitment)
	if err == nil && a.afterForfeits {
		a.crash()
	}
	return err
}
