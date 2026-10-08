package application

import (
	"cmp"
	"slices"
	"time"
)

// planEntry is one future intent of the batch lane: a coin, or every coin of a multi-slot delegation.
type planEntry struct {
	outpoints  []string
	delegation int64
	amount     uint64
	due        time.Time // the latest of its coins'
	deadline   time.Time // a vtxo entry's; a deposit's is the batch it joins, else its due
	deposit    bool      // every coin onchain
	confirmed  time.Time // deposits: block time of the confirmation
}

type PlannedBatch struct {
	At          time.Time
	Vtxos       int
	Amount      uint64
	Delegations int
	// the entry with the earliest deadline, which forces the batch
	ForcedBy           string
	ForcedByDelegation int64
}

// plan is one scan's forecast of the batch lane, published whole: readers never see a partial one.
type plan struct {
	batches []PlannedBatch
	batchAt map[string]time.Time // by outpoint
}

// deadline is the latest moment the batch lane submits a vtxo: the reserve before expiry, never before due.
// A locktime past expiry cannot be renewed in time: its deadline is its expiry.
func (s *service) deadline(c coin, due time.Time) time.Time {
	if c.Expiry.IsZero() {
		return due
	}
	if !due.Before(c.Expiry) {
		return c.Expiry
	}
	return maxTime(due, c.Expiry.Add(-s.renewalReserve))
}

// planBatches simulates the lane forward: a batch at the earliest deadline left carries everything due by then.
// Deposits ride along with a vtxo batch within their max wait, else go at once: a wait would gain nothing known.
func (s *service) planBatches(entries []planEntry, now time.Time) *plan {
	p := &plan{batchAt: make(map[string]time.Time, len(entries))}
	var vtxos, deposits []planEntry
	for _, e := range entries {
		if e.deposit {
			deposits = append(deposits, e)
		} else {
			vtxos = append(vtxos, e)
		}
	}
	slices.SortStableFunc(vtxos, func(a, b planEntry) int {
		return cmp.Or(a.deadline.Compare(b.deadline), a.due.Compare(b.due))
	})
	// deadline >= due: the entry with the earliest deadline is always in its batch, so this ends
	for len(vtxos) > 0 {
		at := vtxos[0].deadline
		b := PlannedBatch{At: at, ForcedBy: vtxos[0].outpoints[0], ForcedByDelegation: vtxos[0].delegation}
		var rest []planEntry
		for _, e := range vtxos {
			if e.due.After(at) {
				rest = append(rest, e)
				continue
			}
			p.join(&b, e, at)
		}
		vtxos = rest
		p.batches = append(p.batches, b)
	}
	for _, e := range deposits {
		bound := e.confirmed.Add(s.boardingMaxWait)
		i := slices.IndexFunc(p.batches, func(b PlannedBatch) bool { return !b.At.Before(e.due) && !b.At.After(bound) })
		if i < 0 {
			b := PlannedBatch{At: e.due, ForcedBy: e.outpoints[0], ForcedByDelegation: e.delegation}
			p.join(&b, e, e.due)
			p.batches = append(p.batches, b)
			continue
		}
		p.join(&p.batches[i], e, p.batches[i].At)
	}
	slices.SortStableFunc(p.batches, func(a, b PlannedBatch) int { return a.At.Compare(b.At) })
	// a batch forced by an overdue coin is due now
	for i := range p.batches {
		p.batches[i].At = maxTime(p.batches[i].At, now)
	}
	return p
}

func (p *plan) join(b *PlannedBatch, e planEntry, at time.Time) {
	b.Vtxos += len(e.outpoints)
	b.Amount += e.amount
	b.Delegations++
	for _, op := range e.outpoints {
		p.batchAt[op] = at
	}
}

// submitAt is when the lane's next batch is, zero to submit now; an empty plan submits now.
func (p *plan) submitAt(now time.Time) time.Time {
	if len(p.batches) == 0 || !now.Before(p.batches[0].At) {
		return time.Time{}
	}
	return p.batches[0].At
}

func (s *service) nextScanDelay(now time.Time) time.Duration {
	if !s.collectUntil.IsZero() {
		return min(s.pollInterval, max(0, s.collectUntil.Sub(now)))
	}
	return s.pollInterval
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
