package arkd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/executor/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestConvertBatchEvents(t *testing.T) {
	r := trees{intents: &intents{}}
	require.Nil(t, r.convert(clientlib.BatchEventChannel{Err: errors.New("stream cut")}))
	require.Equal(t, ports.StreamReconnected{}, r.convert(connection(clientlib.StreamConnectionStateReconnected)))
	require.Nil(t, r.convert(connection(clientlib.StreamConnectionStateReady)))
	require.Nil(t, r.convert(event(clientlib.StreamStartedEvent{Id: "listener"})))
	require.Nil(t, r.convert(event(clientlib.TreeSignatureEvent{Id: "b"})))

	started := r.convert(event(clientlib.BatchStartedEvent{Id: "b", HashedIntentIds: []string{"h"}, BatchExpiry: 144}))
	require.Equal(t, ports.BatchStarted{
		ID: "b", BatchExpiry: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
	}, started)
	started = r.convert(event(clientlib.BatchStartedEvent{Id: "b", BatchExpiry: 1024}))
	require.Equal(t, arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1024}, started.(ports.BatchStarted).BatchExpiry)

	vtxoNodes, connectorNodes := flatTree(t, 3), flatTree(t, 2)
	for _, n := range vtxoNodes {
		require.Nil(t, r.convert(event(clientlib.TreeTxEvent{Id: "b", BatchIndex: 0, Node: n})))
	}
	for _, n := range connectorNodes {
		require.Nil(t, r.convert(event(clientlib.TreeTxEvent{Id: "b", BatchIndex: 1, Node: n})))
	}
	signing := r.convert(event(clientlib.TreeSigningStartedEvent{Id: "b", UnsignedCommitmentTx: "tx", CosignersPubkeys: []string{"k"}}))
	got := signing.(ports.TreeSigningStarted)
	require.Equal(t, "tx", got.UnsignedCommitmentTx)
	require.Equal(t, []string{"k"}, got.CosignersPubkeys)
	require.Len(t, got.VtxoTree.Leaves(), 3)

	require.Equal(t, ports.TreeNoncesAggregated{ID: "b"}, r.convert(event(clientlib.TreeNoncesAggregatedEvent{Id: "b"})))
	finalization := r.convert(event(clientlib.BatchFinalizationEvent{Id: "b", Tx: "tx"})).(ports.BatchFinalization)
	require.Equal(t, "tx", finalization.CommitmentTx)
	require.Len(t, finalization.ConnectorTree.Leaves(), 2)
	require.Equal(t, ports.BatchFinalized{ID: "b", CommitmentTxid: "c"}, r.convert(event(clientlib.BatchFinalizedEvent{Id: "b", Txid: "c"})))
	require.Equal(t, ports.BatchFailed{ID: "b", Reason: "late"}, r.convert(event(clientlib.BatchFailedEvent{Id: "b", Reason: "late"})))

	r.convert(event(clientlib.BatchStartedEvent{Id: "next"}))
	require.Nil(t, r.convert(event(clientlib.TreeSigningStartedEvent{Id: "next"})), "no transaction of a tree came in")
	require.Nil(t, r.convert(event(clientlib.BatchFinalizationEvent{Id: "next"})).(ports.BatchFinalization).ConnectorTree, "no vtxo to forfeit")
	r.connectorTree = []tree.TxTreeNode{{Txid: "broken"}}
	require.Nil(t, r.convert(event(clientlib.BatchFinalizationEvent{Id: "next"})))
}

func TestBatchStartedSelectsOurIntents(t *testing.T) {
	m := &intents{}
	register(m, "proof-a", "id-a")
	register(m, "proof-b", "id-b")
	r := trees{intents: m}

	started := r.convert(event(clientlib.BatchStartedEvent{Id: "b", HashedIntentIds: []string{hashed("id-b"), hashed("someone else")}})).(ports.BatchStarted)
	require.Equal(t, []string{"proof-b"}, started.Selected)

	started = r.convert(event(clientlib.BatchStartedEvent{Id: "c", HashedIntentIds: []string{hashed("someone else")}})).(ports.BatchStarted)
	require.Empty(t, started.Selected, "unknown intents are ignored")
}

func TestBatchFailedBlamesOurIntents(t *testing.T) {
	m := &intents{}
	register(m, "proof-a", "id-a")
	register(m, "proof-b", "id-b")
	r := trees{intents: m}
	both := []string{hashed("id-a"), hashed("id-b")}

	r.convert(event(clientlib.BatchStartedEvent{Id: "1", HashedIntentIds: both}))
	failed := r.convert(event(clientlib.BatchFailedEvent{Id: "1", Reason: "intent id-b did not confirm"})).(ports.BatchFailed)
	require.Equal(t, []string{"proof-b"}, failed.Blamed)
	_, known := m.id("proof-a")
	require.False(t, known, "a failed batch frees its intents")

	register(m, "proof-a", "id-a")
	register(m, "proof-b", "id-b")
	r.convert(event(clientlib.BatchStartedEvent{Id: "2", HashedIntentIds: both}))
	failed = r.convert(event(clientlib.BatchFailedEvent{Id: "2", Reason: "missing nonces"})).(ports.BatchFailed)
	require.ElementsMatch(t, []string{"proof-a", "proof-b"}, failed.Blamed)

	register(m, "proof-a", "id-a")
	r.convert(event(clientlib.BatchStartedEvent{Id: "3", HashedIntentIds: both}))
	failed = r.convert(event(clientlib.BatchFailedEvent{Id: "3", Reason: "not enough participants"})).(ports.BatchFailed)
	require.Empty(t, failed.Blamed)

	r.convert(event(clientlib.BatchStartedEvent{Id: "4", HashedIntentIds: []string{"x"}}))
	failed = r.convert(event(clientlib.BatchFailedEvent{Id: "4", Reason: "missing nonces"})).(ports.BatchFailed)
	require.Empty(t, failed.Blamed, "none of ours was in it")
	failed = r.convert(event(clientlib.BatchFailedEvent{Id: "other", Reason: "missing nonces"})).(ports.BatchFailed)
	require.Empty(t, failed.Blamed, "a batch we did not follow")
}

func TestBlamed(t *testing.T) {
	ours := []intent{{"proof-a", "intent-a"}, {"proof-b", "intent-b"}}
	all := []string{"proof-a", "proof-b"}
	tests := []struct {
		name   string
		reason string
		want   []string
	}{
		{"names one", "intent intent-b did not confirm", []string{"proof-b"}},
		{"names both", "intent-a and intent-b are invalid", all},
		{"names one among our faults", "intent-a sent its forfeits late", []string{"proof-a"}},
		{"our nonces", "missing nonces", all},
		{"our signatures", "invalid Signatures", all},
		{"our forfeits", "missing forfeits", all},
		{"our refusal", "refusing to forfeit: malformed batch", all},
		{"another's fault", "not enough participants", nil},
		{"nothing of ours", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, blamed(tt.reason, ours))
		})
	}
	require.Empty(t, blamed("missing nonces", nil))
	require.Empty(t, blamed("intent  failed", []intent{{"proof", ""}}), "an unknown id names nothing")
}

func TestBatchStartedWaitsForARegistrationInFlight(t *testing.T) {
	m := &intents{}
	m.begin()
	go func() {
		time.Sleep(50 * time.Millisecond)
		m.end("proof-a", "id-a")
	}()
	m.settle(time.Second)
	sum := sha256.Sum256([]byte("id-a"))
	require.Equal(t, []string{"proof-a"}, proofTxids(m.selected([]string{hex.EncodeToString(sum[:])})))

	m.begin()
	start := time.Now()
	m.settle(20 * time.Millisecond)
	require.Less(t, time.Since(start), time.Second, "a registration that never returns delays a batch by the bound only")
}

func hashed(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func event(ev any) clientlib.BatchEventChannel { return clientlib.BatchEventChannel{Event: ev} }

func connection(state clientlib.StreamConnectionState) clientlib.BatchEventChannel {
	return clientlib.BatchEventChannel{Connection: &clientlib.StreamConnectionEvent{State: state}}
}

// flatTree is the transactions of a tree with n leaves, as arkd streams them.
func flatTree(t *testing.T, n int) []tree.TxTreeNode {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	cosigner := hex.EncodeToString(key.PubKey().SerializeCompressed())
	leaves := make([]tree.Leaf, n)
	for i := range leaves {
		leaves[i] = tree.Leaf{
			Outputs:             []tree.LeafOutput{{Amount: 1000, Script: "5120" + hex.EncodeToString(make([]byte, 32))}},
			CosignersPublicKeys: []string{cosigner},
		}
	}
	vtxoTree, err := tree.BuildVtxoTree(&wire.OutPoint{Index: 1}, leaves, make([]byte, 32), arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1024})
	require.NoError(t, err)
	flat, err := vtxoTree.Serialize()
	require.NoError(t, err)
	return flat
}

func register(m *intents, proofTxid, id string) {
	m.begin()
	m.end(proofTxid, id)
}
