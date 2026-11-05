package ports

import (
	"context"
	"errors"

	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/btcsuite/btcd/wire/v2"
)

// ErrDisconnected says the chain server cannot be reached; the watcher keeps reconnecting.
var ErrDisconnected = errors.New("chain server disconnected")

// MaxChainScripts is how many scripts the chain watcher subscribes or lists in one round trip.
const MaxChainScripts = 345

// ChainWatcher reports the unspent outputs at onchain scripts, by query and by push.
type ChainWatcher interface {
	// Subscribe follows the scripts and the tip; an empty list is allowed and grows through Update.
	// The events open with the tip and each script's status.
	Subscribe(ctx context.Context, scripts []string) (ChainSubscription, error)
	// Unspents lists the utxos at the script, those in the mempool included.
	Unspents(ctx context.Context, script string) ([]Output, error)
	Tip(ctx context.Context) (delegation.Tip, error)
	Transaction(ctx context.Context, txid string) (*wire.MsgTx, error)
}

// ChainEvent is a script's new status hash, or a new tip when Tip is set.
type ChainEvent struct {
	Script string
	Status string // empty for a script without history
	Tip    *delegation.Tip
}

// ChainSubscription pushes the tip and the status of its scripts. After a reconnect it pushes
// the tip and every script's status again.
type ChainSubscription interface {
	Events() <-chan ChainEvent
	// Connected says the chain server is reachable.
	Connected() bool
	Update(ctx context.Context, add, remove []string) error
	Stop()
}
