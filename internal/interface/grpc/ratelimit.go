package grpc

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// rateLimiter keeps a token bucket per client address; behind a reverse proxy every request has the
// proxy's.
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

func (l *rateLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.clients[ip]
	if !ok {
		c = &client{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.clients[ip] = c
		// purging on insert keeps the map bounded without a goroutine
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

// middleware refuses the clients over their rate; loopback is exempt, which is where the gateway
// calls from.
func (l *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if parsed := net.ParseIP(
			ip,
		); (parsed == nil || !parsed.IsLoopback()) &&
			!l.allow(ip, time.Now()) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func newRateLimiter(perSecond int) *rateLimiter {
	return &rateLimiter{
		limit:   rate.Limit(perSecond),
		burst:   perSecond * 10,
		clients: map[string]*client{},
	}
}
