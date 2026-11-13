package delegation

import (
	"cmp"
	"context"
	"slices"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
)

// CoinStatus is whether a coin is still at its script.
type CoinStatus string

const (
	Present CoinStatus = "present"
	Spent   CoinStatus = "spent"
)

// Coin is a vtxo or an onchain utxo found at a delegation's input, with its due time.
type Coin struct {
	Outpoint      string
	DelegationID  int64
	Input         int
	Script        string
	Amount        uint64
	ExpiresAt     time.Time // zero when none
	CreatedAt     time.Time
	Due           time.Time
	Status        CoinStatus
	SpentBy       string
	Onchain       bool
	Height        int64 // of the block holding an onchain coin, 0 in mempool
	Confirmations int
}

type CoinRepository interface {
	Upsert(ctx context.Context, coins ...Coin) error
	ListByDelegation(ctx context.Context, id int64) ([]Coin, error)
	// Watched returns those of scripts the active delegations claim, with their present coins.
	Watched(ctx context.Context, scripts []string) ([]Watched, error)
	// Scripts lists the scripts the active delegations claim, onchain or offchain.
	Scripts(ctx context.Context, onchain bool) ([]string, error)
	// Stranded lists the claimed scripts holding present coins of an inactive delegation.
	Stranded(ctx context.Context) ([]string, error)
	// Move gives the present coins at script to owner and returns those that moved.
	Move(ctx context.Context, script string, owner Claim) ([]Coin, error)
	// Onchain lists the present onchain coins of the active delegations.
	Onchain(ctx context.Context) ([]Coin, error)
	// Hold keeps the coins, and the other coins of their delegations, from Ready until Release.
	Hold(ctx context.Context, outpoints []string) error
	// Release gives the coins back, ready no earlier than readyAt, and never sooner than a retry
	// they already wait for.
	Release(ctx context.Context, outpoints []string, readyAt time.Time) error
	// ResetHolds holds exactly the coins of the pending attempts.
	ResetHolds(ctx context.Context) error
	// Ready lists, for at most limit active delegations holding no coin, the oldest coin ready by
	// now at each input past its locktime at tip; only delegations with every input filled, coins
	// by input.
	Ready(ctx context.Context, now time.Time, tip Tip, limit int) ([][]Coin, error)
	// NextReady is the earliest time after now a coin becomes ready, zero when none will.
	NextReady(ctx context.Context, now time.Time, tip Tip) (time.Time, error)
	// Totals counts the present coins of the active delegations and adds up their amount.
	Totals(ctx context.Context) (coins int, amount uint64, err error)
	// ScriptStatus is the electrum status hash stored for script, and whether it is claimed
	// onchain.
	ScriptStatus(ctx context.Context, script string) (status string, watched bool, err error)
	SetScriptStatus(ctx context.Context, script, status string) error
}

// Tip is the chain's latest block.
type Tip struct {
	Height     int64
	Time       time.Time
	MedianTime time.Time // of the last eleven blocks
}

// Claim is a delegation's right to the coins landing at the script of one of its inputs.
type Claim struct {
	DelegationID int64
	Input        int
	Onchain      bool
	Spawned      bool                    // the delegation was spawned by a stream
	Locktime     arklib.AbsoluteLocktime // of the input's spend leaf, zero without one
}

// Watched is a script the active delegations claim, with its present coins.
type Watched struct {
	Script string
	Claims []Claim
	Coins  []Coin
}

// Confirmations is how many blocks deep an output mined at height is, zero in the mempool.
func (t Tip) Confirmations(height int64) int {
	if height <= 0 || height > t.Height {
		return 0
	}
	return int(t.Height - height + 1)
}

// Owner is the claim that holds the coins: a spawned delegation before a public one, then the
// oldest.
func (w Watched) Owner() Claim {
	return slices.MinFunc(w.Claims, func(a, b Claim) int {
		return cmp.Or(
			-cmp.Compare(boolInt(a.Spawned), boolInt(b.Spawned)),
			cmp.Compare(a.DelegationID, b.DelegationID),
		)
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
