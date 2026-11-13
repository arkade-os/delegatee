package arkd

import (
	"context"
	"errors"
	"testing"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/stretchr/testify/require"
)

func TestTransactionsPassesArkTransactionsOn(t *testing.T) {
	events := make(chan clientlib.TransactionEvent, 4)
	stopped := false
	w := NewIndexer(nil, fakeStream{events: events, stop: func() { stopped = true }})
	txs, stop, err := w.Transactions(t.Context())
	require.NoError(t, err)

	events <- clientlib.TransactionEvent{CommitmentTx: &clientlib.TxNotification{TxData: clientlib.TxData{Tx: "commitment"}}}
	events <- clientlib.TransactionEvent{Err: errors.New("cut")}
	events <- clientlib.TransactionEvent{Connection: &clientlib.StreamConnectionEvent{}}
	events <- clientlib.TransactionEvent{ArkTx: &clientlib.TxNotification{TxData: clientlib.TxData{Tx: "ark"}}}
	require.Equal(t, "ark", <-txs)

	stop()
	require.True(t, stopped)
	close(events)
	_, open := <-txs
	require.False(t, open)
}

func TestTransactionsFailsToOpen(t *testing.T) {
	w := NewIndexer(nil, fakeStream{err: errors.New("down")})
	_, _, err := w.Transactions(t.Context())
	require.Error(t, err)
}

type fakeStream struct {
	events chan clientlib.TransactionEvent
	stop   func()
	err    error
}

func (f fakeStream) GetTransactionsStream(
	context.Context,
) (<-chan clientlib.TransactionEvent, func(), error) {
	return f.events, f.stop, f.err
}
