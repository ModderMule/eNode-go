package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterBurstAndRefill(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewWithClock(3, func() time.Time { return now })
	var got []bool
	for i := 0; i < 4; i++ {
		got = append(got, l.Allow("1.2.3.4"))
	}
	t.Logf("input: 4 calls at t=0, limit 3/min output: %v", got)
	if !got[0] || !got[1] || !got[2] || got[3] {
		t.Fatalf("burst: got %v, want [true true true false]", got)
	}
	if !l.Allow("5.6.7.8") {
		t.Fatalf("another key must have its own bucket")
	}
	now = now.Add(20 * time.Second) // one token back
	a, b := l.Allow("1.2.3.4"), l.Allow("1.2.3.4")
	t.Logf("input: 2 calls at t=20s output: %v %v", a, b)
	if !a || b {
		t.Fatalf("refill: got %v %v, want true false", a, b)
	}
}

func TestLimiterDisabled(t *testing.T) {
	l := New(0)
	for i := 0; i < 100; i++ {
		if !l.Allow("k") {
			t.Fatalf("a disabled limiter refused call %d", i)
		}
	}
	var nilLimiter *Limiter
	t.Logf("input: 100 calls on limit 0, one on a nil limiter output: all allowed=%v", nilLimiter.Allow("k"))
}

func TestLimiterDropsIdleBuckets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewWithClock(1, func() time.Time { return now })
	for _, k := range []string{"a", "b", "c"} {
		l.Allow(k)
	}
	now = now.Add(3 * time.Minute)
	l.Allow("d")
	t.Logf("input: 3 keys, 3 min idle, then one call output: %d buckets", len(l.buckets))
	if len(l.buckets) != 1 {
		t.Fatalf("idle buckets kept: %d, want 1", len(l.buckets))
	}
}
