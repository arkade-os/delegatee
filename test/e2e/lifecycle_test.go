//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCancelStopsRenewals(t *testing.T) {
	d := start(t)
	owner := newOwner(t, d)
	w, renewal := boardingDelegations(t, d, owner)
	_, err := d.admin.CancelDelegation(t.Context(), &delegateev1.CancelDelegationRequest{Id: renewal.Id})
	require.NoError(t, err)
	faucet(t, w.Address, 20_000)

	boarded := landed(t, d, w, renewal, 1)[0]
	neverSpent(t, d, boarded.Outpoint.String())

	_, err = d.client.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{
		TemplateId: registerTemplate(t, d, "renew.json"), Variables: owner.variables(0),
	})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "the owner cannot undo an operator cancel")
	_, err = d.admin.ResumeDelegation(t.Context(), &delegateev1.ResumeDelegationRequest{Id: renewal.Id})
	require.NoError(t, err)
	require.Equal(t, renewal.Id, renewalDelegation(t, d, owner, 0).Id, "the cancelled delegation renews again")
	landed(t, d, renewal, renewal, 1)
}

func TestStopWaitsForTheBatch(t *testing.T) {
	d := start(t)
	w, renewal := boardingDelegations(t, d, newOwner(t, d))
	signing := batchSigning(t)
	faucet(t, w.Address, 20_000)

	select {
	case <-signing:
	case <-time.After(time.Minute):
		t.Fatal("never saw the boarding in a batch")
	}
	d.stop()

	// the daemon is gone: a coin boarded now was boarded before stop returned
	waitForVtxo(t, d, renewal.Inputs[0].Script, "")
}

func TestRestart(t *testing.T) {
	first := start(t)
	w, renewal := boardingDelegations(t, first, newOwner(t, first))
	first.stop()
	faucet(t, w.Address, 20_000)

	again := first.restart(t)
	landed(t, again, w, renewal, 1)
	landed(t, again, renewal, renewal, 1)
}

// batchSigning is closed once a batch asks its cosigners to sign, when every intent it carries is confirmed.
func batchSigning(t *testing.T) <-chan struct{} {
	t.Helper()
	ark, err := client.NewClient(arkURL, "e2e")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	events, stop, err := ark.GetEventStream(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { stop(); cancel(); ark.Close() })
	signing := make(chan struct{})
	go func() {
		for ev := range events {
			if _, ok := ev.Event.(clientlib.TreeSigningStartedEvent); ok {
				close(signing)
				return
			}
		}
	}()
	return signing
}
