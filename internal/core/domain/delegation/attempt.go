package delegation

import (
	"context"
	"fmt"
	"slices"
	"time"
)

type AttemptStatus string

const (
	// Submitted is when the offchain or onchain transaction is sent to arkd or the bitcoin network.
	Submitted AttemptStatus = "submitted"
	Succeeded AttemptStatus = "succeeded"
	Failed    AttemptStatus = "failed"
)

// Attempt is one run of a delegation over coins: the transactions it involves, its progress, its
// outcome.
type Attempt struct {
	ID           int64
	DelegationID int64
	Coins        []string // outpoints
	Status       AttemptStatus
	Error        string
	Txs          []Tx // in order: what the attempt built, then what spent the coins when it is not ours
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Tx is a transaction of an attempt; Raw is empty for one the daemon did not build (a batch's
// commitment).
type Tx struct {
	Raw     []byte `json:"raw"` // serialized psbt or raw transaction
	Txid    string `json:"txid"`
	Onchain bool   `json:"onchain"`
	Spends  bool   `json:"spends"` // it spends the attempt's coins; an intent's proof does not
}

type AttemptRepository interface {
	// AddOrUpdate inserts a when its id is zero, filling the id and times in, else persists its
	// status, txs and error; ErrAttemptNotFound when no row has its id.
	AddOrUpdate(ctx context.Context, a *Attempt) error
	// ListPending returns the attempts that neither succeeded nor failed, oldest first.
	ListPending(ctx context.Context) ([]Attempt, error)
	// ListByDelegation returns the attempts of a delegation newest first, below cursor when not
	// zero.
	ListByDelegation(ctx context.Context, id, cursor int64, limit int) ([]Attempt, error)
}

// Spenders returns the txids expected to spend the coins, empty while unknown.
func (a Attempt) Spenders() []string {
	var out []string
	for _, tx := range a.Txs {
		if tx.Txid != "" && tx.Spends {
			out = append(out, tx.Txid)
		}
	}
	return out
}

// Proof returns the first transaction that does not spend the coins: the intent's proof.
func (a Attempt) Proof() (Tx, bool) {
	for _, tx := range a.Txs {
		if !tx.Spends {
			return tx, true
		}
	}
	return Tx{}, false
}

// Attempt starts d's attempt to spend coins. d must be active and own the coins.
func (d *Delegation) Attempt(coins []Coin) (Attempt, error) {
	if d.Status != StatusActive {
		return Attempt{}, ErrNotActive
	}
	outpoints := make([]string, len(coins))
	for i, c := range coins {
		if c.DelegationID != d.ID {
			return Attempt{}, fmt.Errorf("%w: %s", errNotOwned, c.Outpoint)
		}
		outpoints[i] = c.Outpoint
	}
	return Attempt{DelegationID: d.ID, Coins: outpoints, Status: Submitted}, nil
}

// Submit records the attempt's own transactions: the ark transaction sent to arkd and its
// checkpoints, the intent proof registered at arkd or the transaction broadcast to the bitcoin
// network.
func (a *Attempt) Submit(txs ...Tx) error {
	if a.Status != Submitted || len(a.Txs) > 0 {
		return fmt.Errorf("%w: %s", errAttemptState, a.Status)
	}
	a.Txs = slices.Clone(txs)
	return nil
}

func (a *Attempt) AddTx(tx Tx) {
	a.Txs = append(slices.Clone(a.Txs), tx)
}

// Succeeded records that the coins were seen spent by the transaction.
func (a *Attempt) Succeeded() error {
	if !a.Pending() {
		return fmt.Errorf("%w: %s", errAttemptState, a.Status)
	}
	a.Status = Succeeded
	return nil
}

func (a *Attempt) Fail(err error) error {
	if !a.Pending() {
		return fmt.Errorf("%w: %s", errAttemptState, a.Status)
	}
	a.Status, a.Error = Failed, err.Error()
	return nil
}

// Pending reports whether something outside still has to happen.
func (a Attempt) Pending() bool { return a.Status == Submitted }
