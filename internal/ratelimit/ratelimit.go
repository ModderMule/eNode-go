// Package ratelimit is a keyed token bucket: one bucket per client IP or account,
// each refilled continuously. Idle buckets are dropped so a scan of many addresses
// cannot grow the map without bound.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter allows perMinute events per key, with bursts up to perMinute.
type Limiter struct {
	perMinute float64
	now       func() time.Time

	mu       sync.Mutex
	buckets  map[string]*bucket
	lastGC   time.Time
	maxIdle  time.Duration
	disabled bool
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter allowing perMinute events per key. perMinute <= 0 returns a
// limiter that allows everything.
func New(perMinute int) *Limiter {
	return NewWithClock(perMinute, time.Now)
}

// NewWithClock is New with an injected clock, for tests.
func NewWithClock(perMinute int, now func() time.Time) *Limiter {
	return &Limiter{
		perMinute: float64(perMinute),
		now:       now,
		buckets:   map[string]*bucket{},
		maxIdle:   2 * time.Minute,
		disabled:  perMinute <= 0,
	}
}

// Allow takes one token from key's bucket and reports whether there was one.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.disabled {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gc(now)
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.perMinute, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.perMinute, b.tokens+now.Sub(b.last).Minutes()*l.perMinute)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// gc drops buckets idle long enough to be full again; they are indistinguishable
// from a new one. Runs at most once per maxIdle. Callers hold mu.
func (l *Limiter) gc(now time.Time) {
	if now.Sub(l.lastGC) < l.maxIdle {
		return
	}
	l.lastGC = now
	for k, b := range l.buckets {
		if now.Sub(b.last) >= l.maxIdle {
			delete(l.buckets, k)
		}
	}
}
