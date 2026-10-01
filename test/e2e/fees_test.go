package e2e

import (
	"testing"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/stretchr/testify/require"
)

// a fee-paying renewal waits half the coin's life, then pays at most max_fee
func TestIntentFees(t *testing.T) {
	d := startDelegatee(t)
	alice := fundedWallet(t)
	paying, free := renewalWatch(t, d, newOwner(t, d), 100), renewalWatch(t, d, newOwner(t, d), 0)

	chargeIntentFees(t, d, `{"offchainInputFee":"100.0"}`)
	pay(t, alice, paying.Address)
	unpaid := pay(t, alice, free.Address)
	renewed := landed(t, d, paying, paying, 1)
	require.Equal(t, delegateAmount-100, renewed[0].Amount)

	refused(t, d, free.Id, "exceeds the cap 0")
	neverSpent(t, d, unpaid)
}

func TestFeeDropUnblocksRenewal(t *testing.T) {
	d := startDelegatee(t)
	alice := fundedWallet(t)
	w := renewalWatch(t, d, newOwner(t, d), 0)

	chargeIntentFees(t, d, `{"offchainInputFee":"100.0"}`)
	st, err := d.admin.GetStatus(t.Context(), &delegateev1.GetStatusRequest{})
	require.NoError(t, err)
	require.Equal(t, "100.0", st.GetIntentFees().GetOffchainInput(), "the operator sees what arkd charges")
	paid := pay(t, alice, w.Address)
	refused(t, d, w.Id, "exceeds the cap 0")
	neverSpent(t, d, paid)

	clearIntentFees(t)
	require.Equal(t, delegateAmount, landed(t, d, w, w, 1)[0].Amount)
}
