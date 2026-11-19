package httpapi

import (
	"net"
	"sync"
	"time"
)

const (
	loginAttempts   = 10
	limiterCapacity = 4096
	loginWindow     = time.Minute
)

type bucket struct {
	attempts int
	expires  time.Time
}

type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]bucket
	now     func() time.Time
}

func newLimiter() *loginLimiter {
	return &loginLimiter{entries: make(map[string]bucket), now: time.Now}
}

func (l *loginLimiter) allow(remoteAddr string) bool {
	// Only the TCP peer is trusted, even behind a user-provided reverse proxy.
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	key := "unknown"
	if ip != nil {
		key = ip.String()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, exists := l.entries[key]
	if !exists || !now.Before(entry.expires) {
		for k, b := range l.entries {
			if !now.Before(b.expires) {
				delete(l.entries, k)
			}
		}
		if len(l.entries) >= limiterCapacity {
			return false
		}
		entry = bucket{expires: now.Add(loginWindow)}
	}
	if entry.attempts >= loginAttempts {
		return false
	}
	entry.attempts++
	l.entries[key] = entry
	return true
}
