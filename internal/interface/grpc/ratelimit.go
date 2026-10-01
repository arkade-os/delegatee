package grpcservice

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// rateLimiter keys on the connection's address: behind a reverse proxy it sees a single client.
type rateLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	clients map[string]*client
}

type client struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newRateLimiter(perSecond float64) *rateLimiter {
	return &rateLimiter{limit: rate.Limit(perSecond), burst: max(1, int(perSecond*10)), clients: map[string]*client{}}
}

func (l *rateLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.clients[ip]
	if !ok {
		c = &client{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.clients[ip] = c
		// purge on insert keeps the map bounded without a goroutine
		if len(l.clients)%1024 == 0 {
			for ip, c := range l.clients {
				if now.Sub(c.lastSeen) > time.Minute {
					delete(l.clients, ip)
				}
			}
		}
	}
	c.lastSeen = now
	return c.limiter.AllowN(now, 1)
}

func (l *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r), time.Now()) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
