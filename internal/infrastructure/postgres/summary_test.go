package postgres

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/stretchr/testify/require"
)

func TestSummariesOrderByNextDueWithoutCoinsLast(t *testing.T) {
	repo, ids := testSummaries(t)

	list, err := repo.List(t.Context(), ports.SummaryFilter{Limit: 10})
	require.NoError(t, err)
	require.Equal(t, []int64{ids["soon"], ids["tied"], ids["later"], ids["empty"], ids["spent"]}, summaryIDs(list))

	soon, later := list[0], list[2]
	require.Equal(t, 2, soon.Coins)
	require.Equal(t, uint64(3000), soon.Amount)
	require.Equal(t, delegation.Failed, soon.LastAttempt)
	require.Equal(t, 1, later.Coins)
	require.Equal(t, uint64(1000), later.Amount)
	require.Empty(t, later.LastAttempt)
	require.True(t, soon.NextDue.Before(later.NextDue))
	for _, idle := range list[3:] {
		require.Zero(t, idle.Coins)
		require.Zero(t, idle.Amount)
		require.True(t, idle.NextDue.IsZero())
	}
	require.Zero(t, soon.StreamID)
	require.Equal(t, "5120aa", soon.Inputs[0].Script)
}

func TestSummariesPageByCursor(t *testing.T) {
	repo, ids := testSummaries(t)
	want := []int64{ids["soon"], ids["tied"], ids["later"], ids["empty"], ids["spent"]}

	for _, size := range []int{1, 2, 3} {
		var got []int64
		var after ports.Cursor
		for {
			page, err := repo.List(t.Context(), ports.SummaryFilter{After: after, Limit: size})
			require.NoError(t, err)
			require.LessOrEqual(t, len(page), size)
			if len(page) == 0 {
				break
			}
			got = append(got, summaryIDs(page)...)
			last := page[len(page)-1]
			after = ports.Cursor{NextDue: last.NextDue, ID: last.ID}
		}
		require.Equal(t, want, got, "pages of "+strconv.Itoa(size))
	}
}

func TestSummariesFilterByStatus(t *testing.T) {
	repo, ids := testSummaries(t)
	require.NoError(t, repo.db.Delegations().AddOrUpdate(t.Context(), &delegation.Delegation{ID: ids["tied"], Status: delegation.StatusCancelled}))
	require.NoError(t, repo.db.Delegations().AddOrUpdate(t.Context(), &delegation.Delegation{ID: ids["empty"], Status: delegation.StatusCancelled}))

	list, err := repo.List(t.Context(), ports.SummaryFilter{Status: delegation.StatusCancelled, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, []int64{ids["tied"], ids["empty"]}, summaryIDs(list))
	list, err = repo.List(t.Context(), ports.SummaryFilter{Status: delegation.StatusActive, Limit: 10})
	require.NoError(t, err)
	require.Equal(t, []int64{ids["soon"], ids["later"], ids["spent"]}, summaryIDs(list))
}

func TestSummariesOfNothing(t *testing.T) {
	list, err := testDB(t).Summaries().List(t.Context(), ports.SummaryFilter{Limit: 10})
	require.NoError(t, err)
	require.Empty(t, list)
}

// testSummaries stores five delegations: soon holds two coins, the first due in an hour, and two failed attempts,
// tied one coin due at the same time as that one, later one coin due after, empty none and spent only a spent one.
func testSummaries(t *testing.T) (*SummaryRepository, map[string]int64) {
	t.Helper()
	db := testDB(t)
	tpl := testTemplate("t")
	require.NoError(t, db.Templates().AddOrUpdate(t.Context(), &tpl))
	ids := map[string]int64{}
	for _, name := range []string{"soon", "tied", "later", "empty", "spent"} {
		d := testDelegation(name)
		require.NoError(t, db.Delegations().AddOrUpdate(t.Context(), &d))
		ids[name] = d.ID
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	coin := func(outpoint, owner string, due time.Time, amount uint64) delegation.Coin {
		c := testCoin(outpoint, ids[owner], now)
		c.Due, c.Amount = due, amount
		return c
	}
	spent := coin("s:0", "spent", now.Add(time.Minute), 9000)
	spent.Status = delegation.Spent
	require.NoError(t, db.Coins().Upsert(t.Context(),
		coin("a:0", "soon", now.Add(time.Hour), 1000), coin("a:1", "soon", now.Add(3*time.Hour), 2000),
		coin("b:0", "tied", now.Add(time.Hour), 500), coin("c:0", "later", now.Add(2*time.Hour), 1000), spent,
	))
	for _, status := range []error{errors.New("first"), errors.New("second")} {
		a := delegation.Attempt{DelegationID: ids["soon"], Txs: []delegation.Tx{{Txid: "tx"}}, Coins: []string{"a:0"}, Status: delegation.Submitted}
		require.NoError(t, db.Attempts().AddOrUpdate(t.Context(), &a))
		require.NoError(t, a.Fail(status))
		require.NoError(t, db.Attempts().AddOrUpdate(t.Context(), &a))
	}
	return db.Summaries(), ids
}

func summaryIDs(list []ports.Summary) []int64 {
	ids := make([]int64, 0, len(list))
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	return ids
}
