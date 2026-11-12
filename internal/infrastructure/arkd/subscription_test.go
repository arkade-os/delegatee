package arkd

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/executor/internal/core/ports"
	"github.com/stretchr/testify/require"
)

func TestSubscriptionShardsAndMerges(t *testing.T) {
	idx := &fakeIndexer{streams: map[string]chan clientlib.ScriptEvent{}}
	scripts := make([]string, 1001)
	for i := range scripts {
		scripts[i] = fmt.Sprint(i)
	}
	sub, err := subscribe(t.Context(), idx, scripts)
	require.NoError(t, err)
	defer sub.Stop()
	require.Equal(t, []int{1000, 1}, idx.sizes)

	idx.streams["1"] <- clientlib.ScriptEvent{Data: &clientlib.ScriptEventData{Txid: "a", NewVtxos: []clientlib.Vtxo{{Script: "0", Amount: 5}}}}
	idx.streams["2"] <- clientlib.ScriptEvent{Data: &clientlib.ScriptEventData{Txid: "b", SpentVtxos: []clientlib.Vtxo{{Script: "1000", SpentBy: "c"}}}}
	got := map[string]ports.ScriptEvent{}
	for range 2 {
		ev := <-sub.Events()
		got[ev.Txid] = ev
	}
	require.Equal(t, uint64(5), got["a"].Outputs[0].Amount)
	require.False(t, got["a"].Outputs[0].Spent)
	require.True(t, got["b"].Outputs[0].Spent)
	require.Equal(t, "c", got["b"].Outputs[0].SpentBy)

	idx.streams["2"] <- clientlib.ScriptEvent{Connection: &clientlib.StreamConnectionEvent{State: clientlib.StreamConnectionStateReconnected}}
	select {
	case <-sub.Reconnects():
	case <-time.After(time.Second):
		t.Fatal("no reconnect signal")
	}

	require.NoError(t, sub.Update(t.Context(), []string{"new"}, []string{"0"}))
	require.Equal(t, [][]string{{"new"}}, idx.added["1"], "the freed room is used first")
	require.Equal(t, [][]string{{"0"}}, idx.removed["1"])
	require.Len(t, idx.sizes, 2)
}

func TestSubscriptionReopensAShardItsIdNoLongerServes(t *testing.T) {
	idx := &fakeIndexer{streams: map[string]chan clientlib.ScriptEvent{}, updateErr: errors.New("subscription not found")}
	sub, err := subscribe(t.Context(), idx, []string{"a", "b"})
	require.NoError(t, err)
	defer sub.Stop()

	require.NoError(t, sub.Update(t.Context(), []string{"c"}, nil))
	require.Equal(t, []int{2, 3}, idx.sizes, "reopened over the whole shard")
	require.Equal(t, 1, idx.stopped)
	select {
	case <-sub.Reconnects():
	case <-time.After(time.Second):
		t.Fatal("a reopen must ask for a reconcile")
	}
}

func TestToOutput(t *testing.T) {
	v := clientlib.Vtxo{Script: "aa", Amount: 1, ArkTxid: "ark"}
	require.False(t, toOutput(v).Spent)
	require.Empty(t, toOutput(v).SpentBy, "a present vtxo is spent by nothing")

	v.Spent = true
	require.Equal(t, "ark", toOutput(v).SpentBy)
	v.SpentBy = "by"
	require.Equal(t, "ark", toOutput(v).SpentBy, "the ark tx, not its checkpoint")
	v.SettledBy = "commitment"
	require.Equal(t, "commitment", toOutput(v).SpentBy, "the batch, not its forfeit")
	require.Equal(t, "by", toOutput(clientlib.Vtxo{Spent: true, SpentBy: "by"}).SpentBy)

	for _, set := range []func(*clientlib.Vtxo){func(v *clientlib.Vtxo) { v.Swept = true }, func(v *clientlib.Vtxo) { v.Unrolled = true }} {
		gone := clientlib.Vtxo{Script: "aa"}
		set(&gone)
		require.True(t, toOutput(gone).Spent)
	}
	require.True(t, toOutput(clientlib.Vtxo{Swept: true}).Swept)
	require.False(t, toOutput(clientlib.Vtxo{Unrolled: true}).Swept)
}

func TestScriptEventSpentByFallsBackToItsTxid(t *testing.T) {
	ev := toScriptEvent(&clientlib.ScriptEventData{
		Txid: "tx3", NewVtxos: []clientlib.Vtxo{{Script: "aa"}}, SpentVtxos: []clientlib.Vtxo{{Script: "aa"}, {Script: "aa", ArkTxid: "ark"}},
	})
	require.Len(t, ev.Outputs, 3)
	require.False(t, ev.Outputs[0].Spent, "created first")
	require.True(t, ev.Outputs[1].Spent, "a spent vtxo is spent even when arkd does not flag it")
	require.Equal(t, "tx3", ev.Outputs[1].SpentBy)
	require.Equal(t, "ark", ev.Outputs[2].SpentBy)
}

// fakeIndexer records subscriptions; streams are keyed by the subscription id.
type fakeIndexer struct {
	clientlib.Indexer
	sizes     []int
	streams   map[string]chan clientlib.ScriptEvent
	added     map[string][][]string
	removed   map[string][][]string
	updateErr error
	stopped   int
}

func (f *fakeIndexer) NewSubscription(_ context.Context, scripts []string) (string, <-chan clientlib.ScriptEvent, func(), error) {
	f.sizes = append(f.sizes, len(scripts))
	id := fmt.Sprint(len(f.sizes))
	ch := make(chan clientlib.ScriptEvent, 8)
	f.streams[id] = ch
	return id, ch, func() { f.stopped++ }, nil
}

func (f *fakeIndexer) UpdateSubscription(_ context.Context, id string, add, remove []string) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	if f.added == nil {
		f.added, f.removed = map[string][][]string{}, map[string][][]string{}
	}
	if len(add) > 0 {
		f.added[id] = append(f.added[id], add)
	}
	if len(remove) > 0 {
		f.removed[id] = append(f.removed[id], remove)
	}
	return nil
}
