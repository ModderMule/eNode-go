// Package ratelimit is a keyed token bucket: one bucket per client IP or account,
// each refilled continuously. Idle buckets are dropped so a scan of many addresses
// cannot grow the map without bound.
package ratelimit

import (
	"sync"
	"sync/atomic"
	"time"
)

// Limiter allows perMinute events per key, with bursts up to burst (perMinute
// unless set apart with NewBurst).
type Limiter struct {
	now func() time.Time
	// disabled is read without mu, so a limiter that is off costs one load.
	disabled atomic.Bool

	mu        sync.Mutex
	perMinute float64
	burst     float64
	// burstSet keeps burst apart from perMinute across SetRate.
	burstSet bool
	buckets  map[string]*bucket
	lastGC   time.Time
	maxIdle  time.Duration
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
		burst:     float64(perMinute),
		now:       now,
		buckets:   map[string]*bucket{},
		maxIdle:   2 * time.Minute,
	}
	l.disabled.Store(perMinute <= 0)
	return l
}

// NewBurst returns a limiter whose buckets hold burst tokens and refill at perMinute.
// burst <= 0 means burst == perMinute; perMinute <= 0 allows everything.
func NewBurst(perMinute, burst int) *Limiter {
	return NewBurstWithClock(perMinute, burst, time.Now)
}

// NewBurstWithClock is NewBurst with an injected clock, for tests.
func NewBurstWithClock(perMinute, burst int, now func() time.Time) *Limiter {
	l := NewWithClock(perMinute, now)
	l.setBurstLocked(burst)
	return l
}

// SetLimits changes both the refill rate and the burst, as NewBurst takes them. A key
// keeps the tokens it has left, capped at the new burst.
func (l *Limiter) SetLimits(perMinute, burst int) {
	if l == nil {
		return
	}
	l.SetRate(perMinute)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.setBurstLocked(burst)
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
	if !l.burstSet {
		l.burst = l.perMinute
	}
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
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Minutes()*l.perMinute)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// gc drops buckets idle long enough to be full again; they are indistinguishable
// from a new one. Runs at most once per idle span. Callers hold mu.
func (l *Limiter) gc(now time.Time) {
	idle := l.maxIdle
	if l.perMinute > 0 {
		// A burst above 2 min of refill takes longer to fill up.
		idle = max(idle, time.Duration(l.burst/l.perMinute*float64(time.Minute)))
	}
	if now.Sub(l.lastGC) < idle {
		return
	}
	l.lastGC = now
	for k, b := range l.buckets {
		if now.Sub(b.last) >= idle {
			delete(l.buckets, k)
		}
	}
}

// setBurstLocked sets the bucket capacity; burst <= 0 follows perMinute. Callers
// hold mu or own l exclusively.
func (l *Limiter) setBurstLocked(burst int) {
	l.burstSet = burst > 0
	l.burst = l.perMinute
	if l.burstSet {
		l.burst = float64(burst)
	}
	for _, b := range l.buckets {
		b.tokens = min(b.tokens, l.burst)
	}
}
