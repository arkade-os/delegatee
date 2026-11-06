package execution

import (
	"testing"
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/stretchr/testify/require"
)

func TestPlanHoldsRenewalsInOneGroupAtTheEarliestDeadline(t *testing.T) {
	r := Session{Duration: 30 * time.Second, MaxIntents: 10}
	first, second := entry(1, time.Hour), entry(2, 2*time.Hour)
	p := NewPlan([]Entry{second, first}, r, now)
	require.Equal(t, []PlannedBatch{{
		At: now.Add(time.Hour), RegisterAt: now.Add(time.Hour - r.Duration), Entries: []Entry{first, second},
	}}, p.Batches, "every renewal rides in the batch the earliest deadline forces")
	require.Empty(t, p.Late)
	require.Equal(t, now.Add(time.Hour-r.Duration), p.NextRegistration(now))
}

func TestPlanSplitsTheGroupByCapacity(t *testing.T) {
	r := Session{Duration: 30 * time.Second, MaxIntents: 2}
	var entries []Entry
	for i := int64(5); i >= 1; i-- {
		entries = append(entries, entry(i, time.Hour+time.Duration(i)*time.Second))
	}
	p := NewPlan(entries, r, now)
	end := now.Add(time.Hour + time.Second)
	require.Len(t, p.Batches, 3)
	for i, want := range []struct {
		at  time.Time
		ids []int64
	}{
		{end.Add(-2 * r.Duration), []int64{1, 2}},
		{end.Add(-r.Duration), []int64{3, 4}},
		{end, []int64{5}},
	} {
		require.Equal(t, want.at, p.Batches[i].At, i)
		require.Equal(t, want.at.Add(-r.Duration), p.Batches[i].RegisterAt, i)
		require.Equal(t, want.ids, delegations(p.Batches[i].Entries), "the earliest deadlines go first")
	}
	require.Empty(t, p.Late)
}

func TestPlanOfAnOverdueCoinGoesAtTheNextSession(t *testing.T) {
	r := Session{Duration: 30 * time.Second, MaxIntents: 2}
	var entries []Entry
	for i := int64(1); i <= 5; i++ {
		entries = append(entries, entry(i, -time.Minute))
	}
	p := NewPlan(entries, r, now)
	require.Len(t, p.Batches, 3)
	for i, b := range p.Batches {
		require.Equal(t, now.Add(time.Duration(i+1)*r.Duration), b.At, "a batch after another from the next one")
		require.Equal(t, now.Add(time.Duration(i)*r.Duration), b.RegisterAt)
	}
	require.Equal(t, []string{"op1", "op2", "op3", "op4", "op5"}, p.Late, "no batch comes before their deadline")
}

func TestPlanPutsBoardingsFirstAndNow(t *testing.T) {
	r := Session{Duration: 30 * time.Second, MaxIntents: 10}
	boarding := Entry{DelegationID: 9, Coins: []delegation.Coin{{Outpoint: "dep:0", Onchain: true, Amount: 500}}, Due: now.Add(-time.Hour), Deadline: now.Add(-time.Hour)}
	renewal := entry(1, time.Hour)
	p := NewPlan([]Entry{renewal, boarding}, r, now)
	require.Len(t, p.Batches, 2)
	require.Equal(t, []int64{9}, delegations(p.Batches[0].Entries))
	require.Equal(t, now, p.Batches[0].RegisterAt)
	require.Equal(t, []int64{1}, delegations(p.Batches[1].Entries))
	require.Empty(t, p.Late, "a boarding coin is never late")
	require.Equal(t, []int64{9}, delegations(p.Registrations(now, 10)), "the renewal waits")
}

func TestPlanCountsAReservedEntryAsTaken(t *testing.T) {
	r := Session{Duration: 30 * time.Second, MaxIntents: 10}
	held, waiting := entry(1, 10*time.Second), entry(2, 10*time.Second)
	held.Reserved = true
	p := NewPlan([]Entry{held}, r, now)
	require.Equal(t, now.Add(10*time.Second), p.Batches[0].At, "its batch is the next one, not one more away")
	require.Empty(t, p.Late)
	require.Empty(t, p.Registrations(now.Add(time.Hour), 10))
	require.True(t, p.NextRegistration(now).IsZero())

	p = NewPlan([]Entry{waiting}, r, now)
	require.Equal(t, now.Add(r.Duration), p.Batches[0].At, "reserved now it gets the batch after")
	require.Equal(t, []string{"op2"}, p.Late)
}

func TestPlanReportsCoinsWhoseDeadlinePrecedesTheirBatch(t *testing.T) {
	r := Session{Duration: time.Minute, MaxIntents: 1}
	p := NewPlan([]Entry{entry(1, 30*time.Second), entry(2, 200*time.Second), entry(3, 100*time.Second)}, r, now)
	require.Equal(t, []string{"op1", "op3"}, p.Late, "the first batch is at 1m, the second at 2m, the third at 3m")
}

func TestPlanBreaksTiesDeterministically(t *testing.T) {
	r := Session{Duration: time.Second, MaxIntents: 1}
	a, b, c := entry(3, time.Hour), entry(1, time.Hour), entry(2, time.Hour)
	c.Due = now.Add(-time.Minute)
	want := []int64{2, 1, 3}
	for _, in := range [][]Entry{{a, b, c}, {c, b, a}, {b, a, c}} {
		before := append([]Entry(nil), in...)
		p := NewPlan(in, r, now)
		var got []int64
		for _, batch := range p.Batches {
			got = append(got, delegations(batch.Entries)...)
		}
		require.Equal(t, want, got, "the earlier due, then the lower delegation")
		require.Equal(t, before, in, "the input is left as it was")
	}
}

func TestPlanOfNoEntriesIsEmptyAndABatchHoldsAtLeastOneIntent(t *testing.T) {
	p := NewPlan(nil, Session{Duration: time.Second, MaxIntents: 3}, now)
	require.Empty(t, p.Batches)
	require.Empty(t, p.Late)
	require.True(t, p.NextRegistration(now).IsZero())

	p = NewPlan([]Entry{entry(1, time.Hour), entry(2, time.Hour)}, Session{Duration: time.Second}, now)
	require.Len(t, p.Batches, 2, "a batch holds at least one intent")
}

func TestRegistrationsOpenAtBatchRegisterTimeLimitedByFreeSlots(t *testing.T) {
	r := Session{Duration: 30 * time.Second, MaxIntents: 2}
	var entries []Entry
	for i := int64(1); i <= 4; i++ {
		entries = append(entries, entry(i, time.Hour+time.Duration(i)*time.Second))
	}
	entries[0].Reserved = true
	p := NewPlan(entries, r, now)
	require.Empty(t, p.Registrations(now, 10), "nothing is registered early")
	require.Equal(t, []int64{2}, delegations(p.Registrations(p.Batches[0].RegisterAt, 10)), "the reserved one is skipped")
	require.Equal(t, []int64{2, 3, 4}, delegations(p.Registrations(p.Batches[1].RegisterAt, 10)))
	require.Equal(t, []int64{2, 3}, delegations(p.Registrations(p.Batches[1].RegisterAt, 2)), "no more than the slots")
	require.Empty(t, p.Registrations(p.Batches[1].RegisterAt, 0))
}

func TestNextRegistrationSkipsReservedBatches(t *testing.T) {
	r := Session{Duration: 30 * time.Second, MaxIntents: 1}
	first, second := entry(1, time.Hour), entry(2, time.Hour+time.Second)
	first.Reserved = true
	p := NewPlan([]Entry{first, second}, r, now)
	require.Equal(t, p.Batches[1].RegisterAt, p.NextRegistration(now))
	require.True(t, p.NextRegistration(p.Batches[1].RegisterAt).IsZero())
}

func TestEntryIsDueWithItsLastCoinAndDeadlineAtEarliestCoinReserve(t *testing.T) {
	reserve := 6 * time.Hour
	early := delegation.Coin{DelegationID: 7, Outpoint: "a:0", Due: now.Add(time.Hour), ExpiresAt: now.Add(10 * time.Hour)}
	late := delegation.Coin{DelegationID: 7, Outpoint: "b:0", Due: now.Add(2 * time.Hour), ExpiresAt: now.Add(20 * time.Hour)}
	e := NewEntry([]delegation.Coin{late, early}, reserve)
	require.Equal(t, int64(7), e.DelegationID)
	require.Equal(t, now.Add(2*time.Hour), e.Due, "due when the last coin is")
	require.Equal(t, now.Add(4*time.Hour), e.Deadline, "by the earliest deadline, never before due")
	require.Equal(t, []string{"b:0", "a:0"}, e.Outpoints())
	require.False(t, e.Reserved)
}

func TestDeadlineIsReserveBeforeExpiryButNeverBeforeDue(t *testing.T) {
	expiry := now.Add(10 * time.Hour)
	reserve := 6 * time.Hour
	for name, tc := range map[string]struct {
		expiry, due, want time.Time
	}{
		"the reserve before expiry":      {expiry, now, expiry.Add(-reserve)},
		"never before due":               {expiry, now.Add(5 * time.Hour), now.Add(5 * time.Hour)},
		"due after the reserve":          {expiry, now.Add(9 * time.Hour), now.Add(9 * time.Hour)},
		"due after expiry":               {expiry, expiry.Add(time.Hour), expiry.Add(time.Hour)},
		"no expiry is due":               {time.Time{}, now.Add(time.Minute), now.Add(time.Minute)},
		"the reserve beyond the life":    {now.Add(time.Hour), now, now},
		"the reserve exactly at the due": {now.Add(reserve), now, now},
	} {
		require.Equal(t, tc.want, deadline(delegation.Coin{ExpiresAt: tc.expiry}, tc.due, reserve), name)
	}
}

func TestEntryListsItsCoinOutpointsAndSumsTheirAmounts(t *testing.T) {
	e := Entry{Coins: []delegation.Coin{{Outpoint: "a:0", Amount: 3}, {Outpoint: "b:1", Amount: 4}}}
	require.Equal(t, []string{"a:0", "b:1"}, e.Outpoints())
	require.Equal(t, uint64(7), e.Amount())
}

func TestPlanOfFutureRenewalsFormsAGroupPerFarApartDeadline(t *testing.T) {
	r := Session{Duration: 30 * time.Second, MaxIntents: 10}
	first, second := entry(1, 2*time.Hour), entry(2, 5*time.Hour)
	first.Due, second.Due = now.Add(time.Hour), now.Add(4*time.Hour)
	p := NewPlan([]Entry{second, first}, r, now)
	require.Len(t, p.Batches, 2)
	require.Equal(t, now.Add(2*time.Hour), p.Batches[0].At)
	require.Equal(t, []int64{1}, delegations(p.Batches[0].Entries))
	require.Equal(t, now.Add(5*time.Hour), p.Batches[1].At)
	require.Equal(t, []int64{2}, delegations(p.Batches[1].Entries))
	require.Empty(t, p.Late)
}

func TestPlanOfAFutureRenewalDueBeforeTheEarliestDeadlineJoinsItsGroup(t *testing.T) {
	r := Session{Duration: 30 * time.Second, MaxIntents: 10}
	first, second := entry(1, 2*time.Hour), entry(2, 5*time.Hour)
	second.Due = now.Add(time.Hour)
	p := NewPlan([]Entry{first, second}, r, now)
	require.Len(t, p.Batches, 1)
	require.Equal(t, now.Add(2*time.Hour), p.Batches[0].At)
	require.Equal(t, []int64{1, 2}, delegations(p.Batches[0].Entries))
}

func TestPlanPutsAFutureBoardingAtItsDueTime(t *testing.T) {
	r := Session{Duration: 30 * time.Second, MaxIntents: 10}
	boarding := Entry{DelegationID: 9, Coins: []delegation.Coin{{Outpoint: "dep:0", Onchain: true, Amount: 500}}, Due: now.Add(3 * time.Hour), Deadline: now.Add(3 * time.Hour)}
	renewal := entry(1, 6*time.Hour)
	p := NewPlan([]Entry{renewal, boarding}, r, now)
	require.Len(t, p.Batches, 2)
	require.Equal(t, now.Add(3*time.Hour), p.Batches[0].At)
	require.Equal(t, []int64{9}, delegations(p.Batches[0].Entries))
	require.Equal(t, now.Add(6*time.Hour), p.Batches[1].At)
	require.Empty(t, p.Late)
}

func entry(id int64, deadline time.Duration) Entry {
	return Entry{
		DelegationID: id, Coins: []delegation.Coin{{Outpoint: "op" + string(rune('0'+id)), DelegationID: id, Amount: 1000}},
		Due: now, Deadline: now.Add(deadline),
	}
}

func delegations(entries []Entry) []int64 {
	out := make([]int64, len(entries))
	for i, e := range entries {
		out[i] = e.DelegationID
	}
	return out
}
