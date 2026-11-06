package execution

import (
	"cmp"
	"slices"
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
)

// Session is how arkd runs its batches: one per Duration, taking at most MaxIntents intents.
type Session struct {
	Duration   time.Duration
	MaxIntents int
}

// Entry is a delegation's coins waiting for a batch.
type Entry struct {
	DelegationID int64
	Coins        []delegation.Coin
	Due          time.Time
	Deadline     time.Time
	Reserved     bool // a batch slot is taken and the intent is handed to the worker
}

func (e Entry) Outpoints() []string {
	out := make([]string, len(e.Coins))
	for i, c := range e.Coins {
		out[i] = c.Outpoint
	}
	return out
}

func (e Entry) Amount() uint64 {
	var sum uint64
	for _, c := range e.Coins {
		sum += c.Amount
	}
	return sum
}

// NewEntry is the entry of a delegation's coins: due when the last coin is, by the earliest deadline.
func NewEntry(coins []delegation.Coin, reserve time.Duration) Entry {
	e := Entry{DelegationID: coins[0].DelegationID, Coins: coins}
	for _, c := range coins {
		if c.Due.After(e.Due) {
			e.Due = c.Due
		}
	}
	for i, c := range coins {
		if d := deadline(c, e.Due, reserve); i == 0 || d.Before(e.Deadline) {
			e.Deadline = d
		}
	}
	return e
}

// Plan is when the queued entries go to which batch.
type Plan struct {
	Batches []PlannedBatch // by time
	Late    []string       // outpoints whose deadline is before their batch
}

// Registrations lists the unreserved entries of the batches whose registration time has come, at most slots.
func (p Plan) Registrations(now time.Time, slots int) []Entry {
	var out []Entry
	for _, b := range p.Batches {
		if b.RegisterAt.After(now) {
			break
		}
		for _, e := range b.Entries {
			if len(out) == slots {
				return out
			}
			if !e.Reserved {
				out = append(out, e)
			}
		}
	}
	return out
}

// NextRegistration is when the next batch still to be registered comes up, zero when none does.
func (p Plan) NextRegistration(now time.Time) time.Time {
	for _, b := range p.Batches {
		if b.RegisterAt.After(now) && slices.ContainsFunc(b.Entries, func(e Entry) bool { return !e.Reserved }) {
			return b.RegisterAt
		}
	}
	return time.Time{}
}

// NewPlan puts the entries in batches. The earliest remaining deadline forces a group: every renewal due by
// then rides in it, split into batches of at most MaxIntents, the earliest deadlines first and the last at the
// group's time. Entries not due yet are those due by a later deadline's group. Boarding coins go at their due
// time, or now, those sharing a time in one group.
func NewPlan(entries []Entry, s Session, now time.Time) Plan {
	var boardings, renewals []Entry
	for _, e := range slices.Clone(entries) {
		if e.renewal() {
			renewals = append(renewals, e)
		} else {
			boardings = append(boardings, e)
		}
	}
	slices.SortFunc(renewals, func(a, b Entry) int {
		return cmp.Or(a.Deadline.Compare(b.Deadline), a.Due.Compare(b.Due), cmp.Compare(a.DelegationID, b.DelegationID))
	})
	slices.SortFunc(boardings, func(a, b Entry) int {
		return cmp.Or(a.Due.Compare(b.Due), cmp.Compare(a.DelegationID, b.DelegationID))
	})

	type group struct {
		entries []Entry
		at      time.Time
	}
	var groups []group
	for len(boardings) > 0 {
		at := latest(boardings[0].Due, now)
		n := 1
		for n < len(boardings) && latest(boardings[n].Due, now).Equal(at) {
			n++
		}
		groups = append(groups, group{boardings[:n], at})
		boardings = boardings[n:]
	}
	for len(renewals) > 0 {
		// the head always rides, even overdue or due past its deadline
		at := latest(renewals[0].Deadline, now, renewals[0].Due)
		var in, rest []Entry
		for _, e := range renewals {
			if e.Due.After(at) {
				rest = append(rest, e)
			} else {
				in = append(in, e)
			}
		}
		groups = append(groups, group{in, at})
		renewals = rest
	}
	slices.SortStableFunc(groups, func(a, b group) int { return a.at.Compare(b.at) })

	var p Plan
	perBatch := max(s.MaxIntents, 1)
	previous := now.Add(-s.Duration)
	for _, g := range groups {
		n := (len(g.entries) + perBatch - 1) / perBatch
		for i := range n {
			chunk := g.entries[i*perBatch : min((i+1)*perBatch, len(g.entries))]
			desired := g.at.Add(-time.Duration(n-1-i) * s.Duration)
			earliest := now
			if slices.ContainsFunc(chunk, func(e Entry) bool { return !e.Reserved }) {
				earliest = now.Add(s.Duration)
			}
			at := latest(desired, previous.Add(s.Duration), earliest)
			previous = at
			p.Batches = append(p.Batches, PlannedBatch{At: at, RegisterAt: at.Add(-s.Duration), Entries: chunk})
			for _, e := range chunk {
				if e.renewal() && e.Deadline.Before(at) {
					p.Late = append(p.Late, e.Outpoints()...)
				}
			}
		}
	}
	slices.Sort(p.Late)
	return p
}

// PlannedBatch is a batch expected to carry Entries of ours.
type PlannedBatch struct {
	At         time.Time // when the batch settles them
	RegisterAt time.Time // when they must be registered at arkd for it to take them
	Entries    []Entry
}

// deadline is the latest a coin may be settled in a batch: the reserve before its expiry, never before due.
func deadline(c delegation.Coin, due time.Time, reserve time.Duration) time.Time {
	if c.ExpiresAt.IsZero() {
		return due
	}
	return latest(due, c.ExpiresAt.Add(-reserve))
}

// renewal reports whether every coin is offchain; anything else is a boarding coin.
func (e Entry) renewal() bool {
	return !slices.ContainsFunc(e.Coins, func(c delegation.Coin) bool { return c.Onchain })
}

func latest(times ...time.Time) time.Time {
	return slices.MaxFunc(times, time.Time.Compare)
}
