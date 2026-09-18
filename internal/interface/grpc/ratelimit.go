package grpcservice

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// rateLimiter bounds requests per client IP. It reads the address the
// connection came from: put the reverse proxy's limits in front when one
// terminates the connections, this one would then see a single client.
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
		// ponytail: purge on insert keeps the map bounded without a goroutine
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
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !l.allow(ip, time.Now()) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
