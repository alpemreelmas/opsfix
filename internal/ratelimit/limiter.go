package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

// tokenBucket is a simple per-server token bucket.
type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

func newBucket(rps float64, burst int) *tokenBucket {
	return &tokenBucket{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: rps,
		lastRefill: time.Now(),
	}
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	b.lastRefill = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Limiter manages per-server rate limits.
type Limiter struct {
	mu      sync.RWMutex
	buckets map[string]*tokenBucket
	rps     float64
	burst   int
}

// New creates a Limiter with the given default rate and burst.
func New(rps float64, burst int) *Limiter {
	return &Limiter{
		buckets: make(map[string]*tokenBucket),
		rps:     rps,
		burst:   burst,
	}
}

// Allow returns nil if the request is within rate limit, error otherwise.
func (l *Limiter) Allow(server string) error {
	l.mu.RLock()
	b, ok := l.buckets[server]
	l.mu.RUnlock()

	if !ok {
		l.mu.Lock()
		if b, ok = l.buckets[server]; !ok {
			b = newBucket(l.rps, l.burst)
			l.buckets[server] = b
		}
		l.mu.Unlock()
	}

	if !b.allow() {
		return fmt.Errorf("rate_limited: server %q exceeded %g req/s limit", server, l.rps)
	}
	return nil
}
