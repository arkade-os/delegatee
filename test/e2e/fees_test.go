//go:build e2e

package e2e

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIntentFees(t *testing.T) {
	d := start(t)
	alice := fundedWallet(t)
	paying, free := renewalDelegation(t, d, newOwner(t, d), 100), renewalDelegation(t, d, newOwner(t, d), 0)

	chargeIntentFees(t, `{"offchainInputFee":"100.0"}`)
	pay(t, alice, paying.Address)
	unpaid := pay(t, alice, free.Address)
	renewed := landed(t, d, paying, paying, 1)
	require.Equal(t, delegateAmount-100, renewed[0].Amount)

	refused(t, d, free.Id, "exceeds the cap 0")
	neverSpent(t, d, unpaid)
}

func TestFeeDropUnblocksRenewal(t *testing.T) {
	d := start(t)
	alice := fundedWallet(t)
	w := renewalDelegation(t, d, newOwner(t, d), 0)

	chargeIntentFees(t, `{"offchainInputFee":"100.0"}`)
	paid := pay(t, alice, w.Address)
	refused(t, d, w.Id, "exceeds the cap 0")
	neverSpent(t, d, paid)

	clearIntentFees(t)
	require.Equal(t, delegateAmount, landed(t, d, w, w, 1)[0].Amount)
}
