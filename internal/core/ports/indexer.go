package ports

import (
	"context"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
)

// MaxScripts is how many scripts arkd takes per subscription or vtxo query.
const MaxScripts = 1000

// Output is a coin at a script as the indexer reports it.
type Output struct {
	Outpoint  string
	Script    string
	Amount    uint64
	ExpiresAt time.Time // offchain only
	CreatedAt time.Time // offchain only
	Height    int64     // onchain only, 0 in mempool
	Spent     bool      // spent, swept or unrolled
	Swept     bool      // arkd swept its batch; unspent, it is recoverable in a batch without a forfeit
	SpentBy   string    // the batch or transaction that spent it, empty when unknown
}

// ScriptEvent is what one transaction did at watched scripts: the outputs it created, then those it
// spent.
type ScriptEvent struct {
	Txid    string
	Outputs []Output
}

// Indexer reports the vtxos at scripts, by query and by push.
type Indexer interface {
	// Vtxos lists every vtxo at the scripts, spent ones included, however many scripts.
	Vtxos(ctx context.Context, scripts []string) ([]Output, error)
	// Subscribe follows the scripts; an empty list is allowed and grows through Update.
	Subscribe(ctx context.Context, scripts []string) (Subscription, error)
	// VirtualTxs returns the transactions by txid; every txid must be found.
	VirtualTxs(ctx context.Context, txids []string) (map[string]*wire.MsgTx, error)
	// Transactions follows every ark transaction arkd accepts, as base64 psbts, until ctx ends or
	// stop is called.
	Transactions(ctx context.Context) (txs <-chan string, stop func(), err error)
}

type Subscription interface {
	Events() <-chan ScriptEvent
	// Reconnects signals that events may have been missed.
	Reconnects() <-chan struct{}
	Update(ctx context.Context, add, remove []string) error
	Stop()
}
