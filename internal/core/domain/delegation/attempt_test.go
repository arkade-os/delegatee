package delegation

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSubmittedAttemptSucceedsAndIsThenFinal(t *testing.T) {
	a := offchainAttempt(t)
	require.Equal(t, Submitted, a.Status)
	require.True(t, a.Pending())

	require.NoError(t, a.Succeeded())
	require.Equal(t, Succeeded, a.Status)
	require.False(t, a.Pending())
	require.ErrorIs(t, a.Succeeded(), errAttemptState)
	require.ErrorIs(t, a.Fail(errors.New("late")), errAttemptState)
}

func TestSubmittedAttemptFailsWithItsErrorAndIsThenFinal(t *testing.T) {
	a := offchainAttempt(t)
	require.NoError(t, a.Fail(errors.New("refused")))
	require.Equal(t, Failed, a.Status)
	require.Equal(t, "refused", a.Error)
	require.False(t, a.Pending())
	require.ErrorIs(t, a.Fail(errors.New("again")), errAttemptState)
	require.ErrorIs(t, a.Succeeded(), errAttemptState)
}

func TestBatchedAttemptSucceedsOnceTheBatchSpendsItsCoins(t *testing.T) {
	a := batchedAttempt(t)
	require.Equal(t, Submitted, a.Status)
	proof, ok := a.Proof()
	require.True(t, ok)
	require.Equal(t, Tx{Raw: []byte{1}, Txid: "proof"}, proof)
	require.Empty(t, a.Spenders(), "the batch is not known yet")
	require.True(t, a.Pending())

	a.AddTx(Tx{Txid: "commitment", Onchain: true, Spends: true})
	require.Equal(t, []string{"commitment"}, a.Spenders())
	require.Equal(
		t, []Tx{{Raw: []byte{1}, Txid: "proof"}, {Txid: "commitment", Onchain: true, Spends: true}},
		a.Txs,
	)
	require.True(t, a.Pending(), "its coins are not seen spent yet")

	require.NoError(t, a.Succeeded())
	require.False(t, a.Pending())
	require.ErrorIs(t, a.Fail(errors.New("late")), errAttemptState)
}

func TestAttemptNeedsAnActiveDelegationOwningTheCoins(t *testing.T) {
	d := &Delegation{ID: 7, Status: StatusActive}
	a, err := d.Attempt(
		[]Coin{{Outpoint: "a:0", DelegationID: 7}, {Outpoint: "b:1", DelegationID: 7}},
	)
	require.NoError(t, err)
	require.Equal(t, Attempt{DelegationID: 7, Coins: []string{"a:0", "b:1"}, Status: Submitted}, a)

	_, err = d.Attempt([]Coin{{Outpoint: "a:0", DelegationID: 8}})
	require.ErrorIs(t, err, errNotOwned)
	d.Status = StatusCancelled
	_, err = d.Attempt([]Coin{{Outpoint: "a:0", DelegationID: 7}})
	require.ErrorIs(t, err, ErrNotActive)
}

func TestAttemptRecordsItsSubmittedTxsOnceAndNamesTheSpendingOne(t *testing.T) {
	off, batched := offchainAttempt(t), batchedAttempt(t)
	require.Equal(t, []string{"tx"}, off.Spenders())
	_, ok := off.Proof()
	require.False(t, ok)
	require.ErrorIs(t, off.Submit(Tx{Txid: "again"}), errAttemptState, "submitted once")
	require.ErrorIs(t, batched.Submit(Tx{Txid: "again"}), errAttemptState)
	require.NoError(t, off.Succeeded())
	require.ErrorIs(t, off.Submit(Tx{Txid: "tx"}), errAttemptState)

	a, err := (&Delegation{ID: 7, Status: StatusActive}).Attempt(
		[]Coin{{Outpoint: "a:0", DelegationID: 7}},
	)
	require.NoError(t, err)
	require.Empty(t, a.Spenders())
	require.NoError(t, a.Submit(Tx{Raw: []byte{2}, Txid: "raw", Onchain: true, Spends: true}))
	require.Equal(t, []Tx{{Raw: []byte{2}, Txid: "raw", Onchain: true, Spends: true}}, a.Txs)
	require.Equal(t, []string{"raw"}, a.Spenders())
	require.True(t, a.Pending())

	b, err := (&Delegation{ID: 7, Status: StatusActive}).Attempt(
		[]Coin{{Outpoint: "a:0", DelegationID: 7}},
	)
	require.NoError(t, err)
	require.NoError(t, b.Submit(Tx{Txid: "ark", Spends: true}, Tx{Txid: "checkpoint"}))
	require.Len(t, b.Txs, 2)
	require.Equal(t, []string{"ark"}, b.Spenders())
}

func offchainAttempt(t *testing.T) Attempt {
	t.Helper()
	a, err := (&Delegation{ID: 7, Status: StatusActive}).Attempt(
		[]Coin{{Outpoint: "a:0", DelegationID: 7}},
	)
	require.NoError(t, err)
	require.NoError(t, a.Submit(Tx{Raw: []byte{1}, Txid: "tx", Spends: true}))
	return a
}

func batchedAttempt(t *testing.T) Attempt {
	t.Helper()
	a, err := (&Delegation{ID: 7, Status: StatusActive}).Attempt(
		[]Coin{{Outpoint: "a:0", DelegationID: 7}},
	)
	require.NoError(t, err)
	require.NoError(t, a.Submit(Tx{Raw: []byte{1}, Txid: "proof"}))
	return a
}
