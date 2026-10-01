package application

import "time"

// zero means submit now; anchored to eligibility so arrivals and restarts cannot postpone a renewal
func (s *service) collectionDeadline(inputs []renewalInput, now time.Time) time.Time {
	if s.collectionWindow == 0 || len(inputs) == 0 {
		return time.Time{}
	}
	var deadline time.Time
	for _, in := range inputs {
		until := in.due.Add(s.collectionWindow)
		reserve := max(in.coin.Expiry.Sub(in.due)/2, 2*time.Minute)
		if urgent := in.coin.Expiry.Add(-reserve); urgent.Before(until) {
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

func (s *service) nextScanDelay(now time.Time) time.Duration {
	if !s.collectUntil.IsZero() {
		return min(s.pollInterval, max(0, s.collectUntil.Sub(now)))
	}
	return s.pollInterval
}
