package application

import (
	"slices"
	"time"
)

// collectionDeadline returns zero when work should be submitted now. Deadlines
// are anchored to eligibility, not observation, so arrivals and restarts cannot
// keep postponing an existing renewal. Inputs are refreshed on every scan.
func (s *service) collectionDeadline(inputs []renewalInput, now time.Time) time.Time {
	if s.collectionWindow == 0 || len(inputs) == 0 {
		return time.Time{}
	}
	var deadline time.Time
	counts := make(map[*cosigner]int)
	for _, in := range inputs {
		key := in.cosigner
		if key == nil {
			key = s.cosigners[0]
		}
		counts[key]++
		if counts[key] >= s.maxVtxosPerIntent {
			return time.Time{}
		}
		due := dueAt(in.vtxo, in.delegation.Params)
		until := due.Add(s.collectionWindow)
		// Preserve at least half the effective renewal window and two minutes
		// for submission. This limits added delay; it cannot guarantee that
		// arkd finishes a round before expiry.
		reserve := max(in.vtxo.ExpiresAt.Sub(due)/2, 2*time.Minute)
		if urgent := in.vtxo.ExpiresAt.Add(-reserve); urgent.Before(until) {
			until = urgent
		}
		if !now.Before(until) {
			return time.Time{}
		}
		if deadline.IsZero() || until.Before(deadline) {
			deadline = until
		}
	}
	return deadline
}

// Wake at the collection deadline even when the normal polling interval is
// longer. A failed scan clears the deadline and uses normal polling to retry.
func (s *service) nextScanDelay(now time.Time) time.Duration {
	if !s.collectUntil.IsZero() {
		return min(s.pollInterval, max(0, s.collectUntil.Sub(now)))
	}
	return s.pollInterval
}

func sortRenewalInputs(inputs []renewalInput) {
	slices.SortStableFunc(inputs, func(a, b renewalInput) int {
		return a.vtxo.ExpiresAt.Compare(b.vtxo.ExpiresAt)
	})
}
