package postgres

import (
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/stretchr/testify/require"
)

func TestCoinUpsertThenList(t *testing.T) {
	repo, id := testCoins(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	first := testCoin("a:0", id, now)
	second := testCoin("b:1", id, now.Add(time.Second))
	second.ExpiresAt, second.Due = time.Time{}, time.Time{}
	require.NoError(t, repo.Upsert(t.Context(), first, second))
	require.NoError(t, repo.Upsert(t.Context()))

	got, err := repo.ListByDelegation(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, []delegation.Coin{first, second}, got)
	got, err = repo.ListByDelegation(t.Context(), id+1)
	require.NoError(t, err)
	require.Empty(t, got)

	first.Amount, first.Due = 5, now.Add(time.Hour)
	require.NoError(t, repo.Upsert(t.Context(), first))
	require.Equal(t, []delegation.Coin{first, second}, presentAt(t, repo, "5120aa"))
}

func TestCoinUpsertMovesTheCoinToItsNewOwner(t *testing.T) {
	repo, id := testCoins(t)
	owner := testDelegation("b")
	require.NoError(t, repo.db.Delegations().AddOrUpdate(t.Context(), &owner))
	c := testCoin("a:0", id, time.Now().UTC().Truncate(time.Microsecond))
	require.NoError(t, repo.Upsert(t.Context(), c))
	c.DelegationID, c.Input = owner.ID, 1
	require.NoError(t, repo.Upsert(t.Context(), c))

	got, err := repo.ListByDelegation(t.Context(), owner.ID)
	require.NoError(t, err)
	require.Equal(t, []delegation.Coin{c}, got)
}

func TestCoinUpsertSpent(t *testing.T) {
	repo, id := testCoins(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := testCoin("a:0", id, now)
	spent := c
	spent.Status, spent.SpentBy = delegation.Spent, "tx2"
	require.NoError(t, repo.Upsert(t.Context(), c, spent), "the last change of a coin wins")

	require.Empty(t, presentAt(t, repo, "5120aa"))
	got, err := repo.ListByDelegation(t.Context(), id)
	require.NoError(t, err)
	c.Status, c.SpentBy = delegation.Spent, "tx2"
	require.Equal(t, []delegation.Coin{c}, got)

	// a spent coin reported present again is present again
	c.Status, c.SpentBy = delegation.Present, ""
	require.NoError(t, repo.Upsert(t.Context(), c))
	require.Equal(t, []delegation.Coin{c}, presentAt(t, repo, "5120aa"))
}

func TestCoinOnchainUpdatesWithConfirmations(t *testing.T) {
	repo, id := testCoins(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := testCoin("a:0", id, time.Time{})
	c.ExpiresAt, c.Onchain = time.Time{}, true
	require.NoError(t, repo.Upsert(t.Context(), c))

	c.Height, c.Confirmations, c.CreatedAt, c.Due = 120, 3, now, now.Add(time.Hour)
	require.NoError(t, repo.Upsert(t.Context(), c))
	got, err := repo.Onchain(t.Context())
	require.NoError(t, err)
	require.Equal(t, []delegation.Coin{c}, got)
}

func TestScriptStatus(t *testing.T) {
	repo, _ := testCoins(t)
	ctx := t.Context()
	boarding := testDelegation("b")
	boarding.Inputs = []delegation.Input{{Name: "boarding", Onchain: true, Script: "5120bb"}}
	require.NoError(t, repo.db.Delegations().AddOrUpdate(ctx, &boarding))

	status, watched, err := repo.ScriptStatus(ctx, "5120bb")
	require.NoError(t, err)
	require.True(t, watched)
	require.Empty(t, status)
	require.NoError(t, repo.SetScriptStatus(ctx, "5120bb", "s1"))
	require.NoError(t, repo.SetScriptStatus(ctx, "5120bb", "s2"))
	status, _, err = repo.ScriptStatus(ctx, "5120bb")
	require.NoError(t, err)
	require.Equal(t, "s2", status)

	require.NoError(t, repo.SetScriptStatus(ctx, "5120aa", "s3"))
	status, watched, err = repo.ScriptStatus(ctx, "5120aa")
	require.NoError(t, err)
	require.False(t, watched, "offchain")
	require.Equal(t, "s3", status)
	_, watched, err = repo.ScriptStatus(ctx, "5120zz")
	require.NoError(t, err)
	require.False(t, watched)
}

func TestCoinNeedsItsDelegation(t *testing.T) {
	repo, id := testCoins(t)
	require.Error(t, repo.Upsert(t.Context(), testCoin("a:0", id+1, time.Now())))
}

func TestClaimsFollowTheActiveDelegations(t *testing.T) {
	repo, id := testCoins(t)
	ctx := t.Context()
	boarding := testDelegation("b")
	boarding.Inputs = []delegation.Input{{Name: "boarding", Onchain: true, Script: "5120bb", Locktime: 800}}
	require.NoError(t, repo.db.Delegations().AddOrUpdate(ctx, &boarding))
	stream := testStream()
	require.NoError(t, repo.db.Streams().AddOrUpdate(ctx, &stream))
	spawned := testSpawned("c", stream.ID)
	require.NoError(t, repo.db.Delegations().AddOrUpdate(ctx, &spawned))

	require.NoError(t, repo.Upsert(ctx, testCoin("a:0", id, time.Now().UTC().Truncate(time.Microsecond))))
	watched, err := repo.Watched(ctx, []string{"5120bb", "5120aa", "5120zz"})
	require.NoError(t, err)
	require.Len(t, watched, 2)
	require.Equal(t, "5120bb", watched[0].Script)
	require.Equal(t, []delegation.Claim{{DelegationID: boarding.ID, Onchain: true, Locktime: 800}}, watched[0].Claims)
	require.Empty(t, watched[0].Coins)
	require.Equal(t, []delegation.Claim{{DelegationID: id}, {DelegationID: spawned.ID, Spawned: true}}, watched[1].Claims)
	require.Equal(t, []string{"a:0"}, outpointsOf(watched[1].Coins))
	scripts, err := repo.Scripts(ctx, false)
	require.NoError(t, err)
	require.Equal(t, []string{"5120aa"}, scripts)
	scripts, err = repo.Scripts(ctx, true)
	require.NoError(t, err)
	require.Equal(t, []string{"5120bb"}, scripts)

	require.NoError(t, spawned.Cancel())
	require.NoError(t, repo.db.Delegations().AddOrUpdate(ctx, &spawned))
	watched, err = repo.Watched(ctx, []string{"5120aa"})
	require.NoError(t, err)
	require.Equal(t, []delegation.Claim{{DelegationID: id}}, watched[0].Claims)
}

func TestReadyCoins(t *testing.T) {
	repo, id := testCoins(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	tip := delegation.Tip{Height: 100, MedianTime: now}
	add := func(fingerprint, script string, locktime arklib.AbsoluteLocktime) int64 {
		d := testDelegation(fingerprint)
		d.Inputs[0].Script, d.Inputs[0].Locktime = script, locktime
		require.NoError(t, repo.db.Delegations().AddOrUpdate(ctx, &d))
		return d.ID
	}
	locked := add("locked", "5120bb", 101)
	byTime := add("by time", "5120cc", arklib.AbsoluteLocktime(now.Add(-time.Hour).Unix()))
	blocked := add("blocked", "5120dd", 0)
	retried := add("retried", "5120ee", 0)
	cancelled := add("cancelled", "5120ff", 0)
	pair := testDelegation("pair")
	pair.Inputs = append(pair.Inputs, delegation.Input{Name: "second", Script: "5120ab"})
	pair.Inputs[0].Script = "5120ac"
	require.NoError(t, repo.db.Delegations().AddOrUpdate(ctx, &pair))
	coin := func(outpoint, script string, owner int64, due time.Time) delegation.Coin {
		c := testCoin(outpoint, owner, now.Add(-time.Hour))
		c.Script, c.Due = script, due
		return c
	}
	past := now.Add(-time.Minute)
	require.NoError(t, repo.Upsert(ctx,
		coin("a:0", "5120aa", id, past), coin("a:1", "5120aa", id, now.Add(time.Hour)),
		coin("b:0", "5120bb", locked, past), coin("c:0", "5120cc", byTime, past),
		coin("d:0", "5120dd", blocked, past), coin("d:1", "5120dd", blocked, past),
		coin("e:0", "5120ee", retried, past), coin("f:0", "5120ff", cancelled, past),
		coin("g:0", "5120ac", pair.ID, past), coin("g:1", "5120ac", pair.ID, past),
	))
	d, err := repo.db.Delegations().Get(ctx, cancelled)
	require.NoError(t, err)
	require.NoError(t, d.Cancel())
	require.NoError(t, repo.db.Delegations().AddOrUpdate(ctx, d))
	require.NoError(t, repo.Hold(ctx, []string{"d:1"}))
	require.NoError(t, repo.Release(ctx, []string{"e:0"}, now.Add(30*time.Minute)))

	ready, err := repo.Ready(ctx, now, tip, 10)
	require.NoError(t, err)
	require.Equal(t, [][]string{{"a:0"}, {"c:0"}}, readyOutpoints(ready), "the locked, the blocked, the retried, the cancelled and the half filled wait")
	coins, amount, err := repo.Totals(ctx)
	require.NoError(t, err)
	require.Equal(t, 9, coins)
	require.Equal(t, uint64(9000), amount)

	second := coin("h:0", "5120ab", pair.ID, past)
	second.Input = 1
	require.NoError(t, repo.Upsert(ctx, second))
	ready, err = repo.Ready(ctx, now, tip, 10)
	require.NoError(t, err)
	require.Equal(t, [][]string{{"a:0"}, {"c:0"}, {"g:0", "h:0"}}, readyOutpoints(ready), "one coin per input, the oldest")
	ready, err = repo.Ready(ctx, now, tip, 1)
	require.NoError(t, err)
	require.Equal(t, [][]string{{"a:0"}}, readyOutpoints(ready), "limit counts delegations")

	require.NoError(t, repo.Hold(ctx, []string{"a:0", "c:0", "g:0"}))
	next, err := repo.NextReady(ctx, now, tip)
	require.NoError(t, err)
	require.Equal(t, now.Add(30*time.Minute), next, "the retried coin, a held one keeps its delegation's others back")
	next, err = repo.NextReady(ctx, now.Add(31*time.Minute), tip)
	require.NoError(t, err)
	require.Zero(t, next, "what is ready already is not next")

	require.NoError(t, repo.Release(ctx, []string{"d:1"}, time.Time{}))
	ready, err = repo.Ready(ctx, now.Add(31*time.Minute), delegation.Tip{Height: 101, MedianTime: now}, 10)
	require.NoError(t, err)
	require.Equal(t, [][]string{{"b:0"}, {"d:0"}, {"e:0"}}, readyOutpoints(ready), "the locktime is reached")
}

func TestReleaseNeverShortensARetry(t *testing.T) {
	repo, id := testCoins(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	past := now.Add(-time.Minute)
	require.NoError(t, repo.Upsert(ctx, testCoin("a:0", id, past)))
	ban := now.Add(time.Hour)

	require.NoError(t, repo.Hold(ctx, []string{"a:0"}))
	require.NoError(t, repo.Release(ctx, []string{"a:0"}, ban))
	for name, readyAt := range map[string]time.Time{"an earlier time": now.Add(time.Minute), "zero": {}} {
		require.NoError(t, repo.Hold(ctx, []string{"a:0"}), name)
		require.NoError(t, repo.Release(ctx, []string{"a:0"}, readyAt), name)
		ready, err := repo.Ready(ctx, now.Add(30*time.Minute), delegation.Tip{}, 10)
		require.NoError(t, err, name)
		require.Empty(t, ready, "%s keeps the ban", name)
	}
	next, err := repo.NextReady(ctx, now, delegation.Tip{})
	require.NoError(t, err)
	require.Equal(t, ban, next)
	ready, err := repo.Ready(ctx, ban, delegation.Tip{}, 10)
	require.NoError(t, err)
	require.Equal(t, [][]string{{"a:0"}}, readyOutpoints(ready), "the ban is over")

	later := ban.Add(time.Hour)
	require.NoError(t, repo.Hold(ctx, []string{"a:0"}))
	require.NoError(t, repo.Release(ctx, []string{"a:0"}, later))
	next, err = repo.NextReady(ctx, now, delegation.Tip{})
	require.NoError(t, err)
	require.Equal(t, later, next, "a later time extends it")
}

func TestResetHolds(t *testing.T) {
	repo, id := testCoins(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	require.NoError(t, repo.Upsert(ctx, testCoin("a:0", id, now), testCoin("a:1", id, now), testCoin("a:2", id, now)))
	require.NoError(t, repo.Hold(ctx, []string{"a:0", "a:1"}))
	a := delegation.Attempt{DelegationID: id, Txs: []delegation.Tx{{Txid: "tx"}}, Coins: []string{"a:1", "a:2"}, Status: delegation.Submitted}
	require.NoError(t, repo.db.Attempts().AddOrUpdate(ctx, &a))

	require.NoError(t, repo.ResetHolds(ctx))
	var held string
	require.NoError(t, repo.db.db.QueryRowContext(ctx, "SELECT string_agg(outpoint, ',' ORDER BY outpoint) FROM coins WHERE held").Scan(&held))
	require.Equal(t, "a:1,a:2", held, "exactly the coins of the pending attempt")
}

func TestMoveCoinsToTheirNewOwner(t *testing.T) {
	repo, id := testCoins(t)
	ctx := t.Context()
	other := testDelegation("b")
	require.NoError(t, repo.db.Delegations().AddOrUpdate(ctx, &other))
	now := time.Now().UTC().Truncate(time.Microsecond)
	spent := testCoin("a:1", id, now)
	spent.Status = delegation.Spent
	require.NoError(t, repo.Upsert(ctx, testCoin("a:0", id, now), spent))

	moved, err := repo.Move(ctx, "5120aa", delegation.Claim{DelegationID: other.ID})
	require.NoError(t, err)
	require.Equal(t, []string{"a:0"}, outpointsOf(moved), "a spent coin stays with its delegation")
	require.Equal(t, other.ID, moved[0].DelegationID)
	moved, err = repo.Move(ctx, "5120aa", delegation.Claim{DelegationID: other.ID})
	require.NoError(t, err)
	require.Empty(t, moved)
	at := presentAt(t, repo, "5120aa")
	require.Len(t, at, 1)
	require.Equal(t, other.ID, at[0].DelegationID)
}

func TestStrandedScripts(t *testing.T) {
	repo, id := testCoins(t)
	ctx := t.Context()
	other := testDelegation("b")
	require.NoError(t, repo.db.Delegations().AddOrUpdate(ctx, &other))
	require.NoError(t, repo.Upsert(ctx, testCoin("a:0", id, time.Now().UTC().Truncate(time.Microsecond))))
	stranded, err := repo.Stranded(ctx)
	require.NoError(t, err)
	require.Empty(t, stranded)

	d, err := repo.db.Delegations().Get(ctx, id)
	require.NoError(t, err)
	require.NoError(t, d.Cancel())
	require.NoError(t, repo.db.Delegations().AddOrUpdate(ctx, d))
	stranded, err = repo.Stranded(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"5120aa"}, stranded, "another delegation watches it")

	require.NoError(t, other.Cancel())
	require.NoError(t, repo.db.Delegations().AddOrUpdate(ctx, &other))
	stranded, err = repo.Stranded(ctx)
	require.NoError(t, err)
	require.Empty(t, stranded, "nobody watches it")
}

func testCoins(t *testing.T) (*CoinRepository, int64) {
	t.Helper()
	db := testDB(t)
	tpl := testTemplate("t")
	require.NoError(t, db.Templates().AddOrUpdate(t.Context(), &tpl))
	d := testDelegation("a")
	require.NoError(t, db.Delegations().AddOrUpdate(t.Context(), &d))
	return db.Coins(), d.ID
}

func testCoin(outpoint string, delegationID int64, createdAt time.Time) delegation.Coin {
	return delegation.Coin{
		Outpoint: outpoint, DelegationID: delegationID, Input: 0, Script: "5120aa", Amount: 1000,
		ExpiresAt: createdAt.Add(time.Hour), CreatedAt: createdAt, Due: createdAt.Add(30 * time.Minute),
		Status: delegation.Present,
	}
}

func presentAt(t *testing.T, repo *CoinRepository, script string) []delegation.Coin {
	t.Helper()
	watched, err := repo.Watched(t.Context(), []string{script})
	require.NoError(t, err)
	if len(watched) == 0 {
		return nil
	}
	return watched[0].Coins
}

func readyOutpoints(ready [][]delegation.Coin) [][]string {
	out := make([][]string, len(ready))
	for i, coins := range ready {
		out[i] = outpointsOf(coins)
	}
	return out
}

func outpointsOf(coins []delegation.Coin) []string {
	out := make([]string, len(coins))
	for i, c := range coins {
		out[i] = c.Outpoint
	}
	return out
}
