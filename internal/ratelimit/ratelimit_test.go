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

// TestLimiterSetRate covers a limit changed while the limiter is in use: lowered,
// raised, turned off and turned on again.
func TestLimiterSetRate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewWithClock(4, func() time.Time { return now })
	allowed := func(calls int) int {
		n := 0
		for i := 0; i < calls; i++ {
			if l.Allow("k") {
				n++
			}
		}
		return n
	}
	first := allowed(1) // 3 tokens left
	l.SetRate(2)
	lowered := allowed(5)
	l.SetRate(0)
	off := allowed(50)
	l.SetRate(3)
	on := allowed(5)
	now = now.Add(time.Minute)
	l.SetRate(10)
	raised := allowed(20)
	t.Logf("input: limit 4, 1 call; SetRate(2), 5 calls; SetRate(0), 50 calls; SetRate(3), 5 calls; +1min, SetRate(10), 20 calls")
	t.Logf("output: allowed %d, %d, %d, %d, %d", first, lowered, off, on, raised)
	if first != 1 || lowered != 2 || off != 50 || on != 3 || raised != 10 {
		t.Fatalf("allowed %d %d %d %d %d, want 1 2 50 3 10", first, lowered, off, on, raised)
	}
	var none *Limiter
	none.SetRate(5)
}

// Burst apart from the rate: 10 at once, then one per second at 60/min.
func TestLimiterSeparateBurst(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewBurstWithClock(60, 10, func() time.Time { return now })
	n := 0
	for i := 0; i < 20; i++ {
		if l.Allow("k") {
			n++
		}
	}
	now = now.Add(time.Second)
	a, b := l.Allow("k"), l.Allow("k")
	now = now.Add(time.Hour)
	refilled := 0
	for i := 0; i < 20; i++ {
		if l.Allow("k") {
			refilled++
		}
	}
	t.Logf("input: 20 calls, +1 s 2 calls, +1 h 20 calls, burst 10 rate 60/min output: %d, %v %v, %d", n, a, b, refilled)
	if n != 10 || !a || b || refilled != 10 {
		t.Fatalf("got %d, %v %v, %d; want 10, true false, 10", n, a, b, refilled)
	}

	l.SetLimits(60, 3)
	now = now.Add(time.Hour)
	capped := 0
	for i := 0; i < 10; i++ {
		if l.Allow("k") {
			capped++
		}
	}
	l.SetRate(120) // burst stays 3
	now = now.Add(time.Hour)
	kept := 0
	for i := 0; i < 10; i++ {
		if l.Allow("k") {
			kept++
		}
	}
	t.Logf("input: SetLimits(60,3), then SetRate(120) output: %d, %d", capped, kept)
	if capped != 3 || kept != 3 {
		t.Fatalf("got %d, %d; want 3, 3", capped, kept)
	}
	if New(5).burst != 5 {
		t.Fatal("New must keep burst == perMinute")
	}
}
