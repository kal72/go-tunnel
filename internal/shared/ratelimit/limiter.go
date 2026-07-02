package ratelimit

import (
	"sync"
	"time"
)

// Bucket represents a token bucket for rate limiting.
type Bucket struct {
	lastUpdate time.Time
	tokens     float64
}

// Limiter manages token buckets per key (e.g., hostname or username).
type Limiter struct {
	buckets map[string]*Bucket
	mu      sync.Mutex
}

// NewLimiter creates a new thread-safe token bucket limiter.
func NewLimiter() *Limiter {
	return &Limiter{
		buckets: make(map[string]*Bucket),
	}
}

// Allow checks if one request is permitted under the given rate (req/s) and burst limits.
func (l *Limiter) Allow(key string, rate, burst int) bool {
	if rate <= 0 || burst <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, exists := l.buckets[key]
	if !exists {
		b = &Bucket{
			tokens:     float64(burst) - 1,
			lastUpdate: now,
		}
		l.buckets[key] = b
		return true
	}

	elapsed := now.Sub(b.lastUpdate).Seconds()
	b.tokens += elapsed * float64(rate)
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.lastUpdate = now

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}
	return false
}

// Cleanup removes stale buckets that haven't been updated within idleDuration.
func (l *Limiter) Cleanup(idleDuration time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, b := range l.buckets {
		if now.Sub(b.lastUpdate) > idleDuration {
			delete(l.buckets, k)
		}
	}
}
