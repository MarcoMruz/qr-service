package main

import (
	"net/netip"
	"sync"
	"time"
)

// maxTrackedClients bounds memory when many distinct IPs arrive within one window.
const maxTrackedClients = 10_000

// rateLimiter allows `limit` requests per key in each fixed `window`.
type rateLimiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	windows   map[string]*window
	lastSweep time.Time
	now       func() time.Time
}

type window struct {
	start time.Time
	count int
}

func newRateLimiter(limit int, period time.Duration) *rateLimiter {
	return &rateLimiter{
		limit:   limit,
		window:  period,
		windows: make(map[string]*window),
		now:     time.Now,
	}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweepExpired(now)

	w, ok := l.windows[key]
	if !ok || now.Sub(w.start) >= l.window {
		if !ok && len(l.windows) >= maxTrackedClients {
			return false
		}
		l.windows[key] = &window{start: now, count: 1}
		return true
	}
	if w.count >= l.limit {
		return false
	}
	w.count++
	return true
}

// sweepExpired drops stale entries once per window so memory stays bounded by active clients.
func (l *rateLimiter) sweepExpired(now time.Time) {
	if now.Sub(l.lastSweep) < l.window {
		return
	}
	for key, w := range l.windows {
		if now.Sub(w.start) >= l.window {
			delete(l.windows, key)
		}
	}
	l.lastSweep = now
}

// rateLimitKey groups IPv6 clients by /64, because one host usually controls the whole prefix.
func rateLimitKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return ip
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return ip
	}
	return prefix.String()
}
