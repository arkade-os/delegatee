package execution

import (
	"testing"
	"time"

	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/internal/core/ports"
	"github.com/stretchr/testify/require"
)

func TestSyncEventAddsThenSpends(t *testing.T) {
	w := watched("aa", delegation.Claim{DelegationID: 1})
	v := vtxo("tx1:0", "aa", 1000)
	changes := syncVtxos(w, []ports.Output{v, vtxo("x:0", "bb", 1)}, false)
	require.Equal(t, []delegation.Coin{{
		Outpoint: "tx1:0", DelegationID: 1, Script: "aa", Amount: 1000,
		ExpiresAt: v.ExpiresAt, CreatedAt: v.CreatedAt, Status: delegation.Present,
	}}, changes, "another script's vtxo is not ours; its due time is left to ask")
	w.Coins = []delegation.Coin{changes[0]}
	require.Empty(t, syncVtxos(w, []ports.Output{v}, false), "a known coin")
	require.Empty(t, syncVtxos(w, nil, false), "an event lists only what it touched")

	spent := v
	spent.Spent, spent.SpentBy = true, "tx2"
	unknown := vtxo("nope:0", "aa", 1)
	unknown.Spent = true
	changes = syncVtxos(w, []ports.Output{spent, unknown}, false)
	require.Len(t, changes, 1, "an unknown coin is not spent")
	require.Equal(t, delegation.Spent, changes[0].Status)
	require.Equal(t, "tx2", changes[0].SpentBy)
}

func TestSyncGivesNewCoinsToTheOwner(t *testing.T) {
	w := watched(
		"aa", delegation.Claim{DelegationID: 1},
		delegation.Claim{DelegationID: 2, Input: 1, Spawned: true},
	)
	changes := syncVtxos(w, []ports.Output{vtxo("a:0", "aa", 1)}, false)
	require.Equal(t, int64(2), changes[0].DelegationID)
	require.Equal(t, 1, changes[0].Input)
}

func TestSyncCompleteSpendsWhatIsMissing(t *testing.T) {
	w := watched(
		"aa", delegation.Claim{DelegationID: 1}, coin("old:0", 1, "aa"), coin("gone:0", 1, "aa"),
	)
	gone := vtxo("gone:0", "aa", 1)
	gone.Spent, gone.SpentBy = true, "spender"
	changes := syncVtxos(
		w,
		[]ports.Output{vtxo("old:0", "aa", 1), gone, vtxo("new:0", "aa", 5), vtxo("x:0", "bb", 1)},
		true,
	)
	require.Len(t, changes, 2)
	require.Equal(t, delegation.Spent, changes[0].Status)
	require.Equal(t, "gone:0", changes[0].Outpoint)
	require.Equal(t, "spender", changes[0].SpentBy)
	require.Equal(t, delegation.Present, changes[1].Status)
	require.Equal(t, "new:0", changes[1].Outpoint)

	changes = syncVtxos(w, nil, true)
	require.Len(t, changes, 2, "a coin arkd no longer reports is spent")
	for _, c := range changes {
		require.Equal(t, delegation.Spent, c.Status)
		require.Empty(t, c.SpentBy, "by nobody known")
	}
}

func TestSyncUtxosAddsUpdatesAndSpends(t *testing.T) {
	w := watched("aa", delegation.Claim{DelegationID: 1, Onchain: true})
	tip := delegation.Tip{Height: 100, Time: now}
	changes := syncUtxos(
		w,
		[]ports.Output{
			{Outpoint: "tx1:0", Script: "aa", Amount: 5000},
			{Outpoint: "tx2:1", Script: "aa", Amount: 7, Height: 100},
			{Outpoint: "x:0", Script: "bb"},
		},
		tip,
		now,
	)
	require.Len(t, changes, 2)
	require.Equal(t, delegation.Coin{
		Outpoint: "tx1:0", DelegationID: 1, Script: "aa", Amount: 5000, Status: delegation.Present,
		Onchain: true,
	}, changes[0])
	require.Equal(t, delegation.Coin{
		Outpoint: "tx2:1", DelegationID: 1, Script: "aa", Amount: 7, Status: delegation.Present,
		Onchain: true, Height: 100, Confirmations: 1, CreatedAt: now,
	}, changes[1], "created in the tip's block")

	w.Coins = []delegation.Coin{changes[0], changes[1]}
	tip = delegation.Tip{Height: 101, Time: now.Add(10 * time.Minute)}
	changes = syncUtxos(
		w, []ports.Output{{Outpoint: "tx1:0", Script: "aa", Amount: 5000, Height: 101}}, tip, now,
	)
	require.Len(t, changes, 2)
	require.Equal(t, delegation.Present, changes[0].Status)
	require.Equal(t, 1, changes[0].Confirmations)
	require.Equal(t, tip.Time, changes[0].CreatedAt)
	require.Equal(t, delegation.Spent, changes[1].Status)
	require.Equal(t, "tx2:1", changes[1].Outpoint)

	due := changes[0]
	due.Due = now
	w.Coins = []delegation.Coin{due}
	require.Empty(
		t,
		syncUtxos(
			w, []ports.Output{{Outpoint: "tx1:0", Script: "aa", Amount: 5000, Height: 101}}, tip,
			now,
		),
		"nothing changed",
	)
}

func TestRefresh(t *testing.T) {
	c := coin("tx1:0", 1, "aa")
	c.Onchain, c.Height, c.Confirmations, c.Due = true, 100, 1, now.Add(time.Hour)
	next, changed := refresh(c, 100, delegation.Tip{Height: 101}, now)
	require.True(t, changed)
	require.Equal(t, 2, next.Confirmations)
	require.Zero(t, next.Due, "not due yet, its due time is asked again")

	next.Due = now
	next, changed = refresh(next, 100, delegation.Tip{Height: 102}, now)
	require.True(t, changed)
	require.Equal(t, 3, next.Confirmations)
	require.Equal(t, now, next.Due, "a due coin keeps its due time")
	_, changed = refresh(next, 100, delegation.Tip{Height: 102}, now)
	require.False(t, changed)

	moved, changed := refresh(next, 101, delegation.Tip{Height: 102}, now)
	require.True(t, changed)
	require.Zero(t, moved.Due, "a new height asks again")
	require.Equal(t, 2, moved.Confirmations)

	mempool := coin("mp:0", 1, "aa")
	mempool.Onchain, mempool.Due = true, now
	_, changed = refresh(mempool, 0, delegation.Tip{Height: 103}, now)
	require.False(t, changed, "a mempool coin has no height to count from")
}

func TestScriptsOf(t *testing.T) {
	outputs := []ports.Output{
		vtxo("a:0", "aa", 1), vtxo("b:0", "bb", 1), vtxo("c:0", "aa", 1), vtxo("d:0", "cc", 1),
	}
	require.Equal(t, []string{"aa", "bb", "cc"}, scriptsOf(outputs))
}

var now = time.Unix(1_800_000_000, 0)

func watched(script string, claim delegation.Claim, rest ...any) delegation.Watched {
	w := delegation.Watched{Script: script, Claims: []delegation.Claim{claim}}
	for _, r := range rest {
		switch r := r.(type) {
		case delegation.Claim:
			w.Claims = append(w.Claims, r)
		case delegation.Coin:
			w.Coins = append(w.Coins, r)
		}
	}
	return w
}

func vtxo(outpoint, script string, amount uint64) ports.Output {
	return ports.Output{
		Outpoint: outpoint, Script: script, Amount: amount, CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
}

func coin(outpoint string, delegationID int64, script string) delegation.Coin {
	return delegation.Coin{
		Outpoint: outpoint, DelegationID: delegationID, Script: script, Amount: 1, CreatedAt: now,
		Status: delegation.Present,
	}
}
