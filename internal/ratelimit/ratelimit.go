// Package ratelimit is a keyed token bucket: one bucket per client IP or account,
// each refilled continuously. Idle buckets are dropped so a scan of many addresses
// cannot grow the map without bound.
package ratelimit

import (
	"sync"
	"sync/atomic"
	"time"
)

// Limiter allows perMinute events per key, with bursts up to perMinute.
type Limiter struct {
	now func() time.Time
	// disabled is read without mu, so a limiter that is off costs one load.
	disabled atomic.Bool

	mu        sync.Mutex
	perMinute float64
	buckets   map[string]*bucket
	lastGC    time.Time
	maxIdle   time.Duration
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
	l := &Limiter{
		perMinute: float64(perMinute),
		now:       now,
		buckets:   map[string]*bucket{},
		maxIdle:   2 * time.Minute,
	}
	l.disabled.Store(perMinute <= 0)
	return l
}

// SetRate changes the limit to perMinute events per key; perMinute <= 0 allows
// everything. A key keeps the tokens it has left, capped at the new limit.
func (l *Limiter) SetRate(perMinute int) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.perMinute = float64(perMinute)
	l.disabled.Store(perMinute <= 0)
	if perMinute <= 0 {
		clear(l.buckets)
	}
}

// Allow takes one token from key's bucket and reports whether there was one.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.disabled.Load() {
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
