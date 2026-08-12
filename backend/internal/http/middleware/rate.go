package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type rateBucket struct {
	start time.Time
	count int
}

// RateLimit is a per-process safeguard. Distributed deployments should add an
// equivalent shared or edge limit; authorization checks remain mandatory.
func RateLimit(maximum int, window time.Duration) func(http.Handler) http.Handler {
	var mu sync.Mutex
	buckets := map[string]rateBucket{}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := string(AgentID(r.Context()))
			if key == "" {
				key = r.RemoteAddr
				if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
					key = host
				}
			}
			now := time.Now()
			mu.Lock()
			bucket := buckets[key]
			if bucket.start.IsZero() || now.Sub(bucket.start) >= window {
				bucket = rateBucket{start: now}
			}
			bucket.count++
			buckets[key] = bucket
			if len(buckets) > 4096 {
				for item, value := range buckets {
					if now.Sub(value.start) > 2*window {
						delete(buckets, item)
					}
				}
			}
			limited := bucket.count > maximum
			mu.Unlock()
			if limited {
				WriteError(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "sensitive Agent API rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
