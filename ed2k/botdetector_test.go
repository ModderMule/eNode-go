package ed2k

import (
	"net"
	"testing"
	"time"
)

// feedBot records count queries from source, gap apart, on a fake clock.
func feedBot(d *botDetector, clock *time.Time, source string, count int, gap func(i int) time.Duration) (flagged int) {
	cfg := BotDetectionConfig{Enabled: true}
	for i := 0; i < count; i++ {
		*clock = clock.Add(gap(i))
		if d.record(source, cfg) {
			flagged++
		}
	}
	return flagged
}

func newTestBotDetector() (*botDetector, *time.Time) {
	clock := time.Unix(1_700_000_000, 0)
	d := newBotDetector()
	d.now = func() time.Time { return clock }
	return d, &clock
}

func TestBotDetectorSlowQuerierIsNotFlagged(t *testing.T) {
	d, clock := newTestBotDetector()
	flagged := feedBot(d, clock, "203.0.113.9", 100, func(int) time.Duration { return 2 * time.Second })
	t.Logf("input: 100 queries, one every 2s (30 qpm)")
	t.Logf("output: flagged=%d detections=%+v", flagged, d.snapshot())
	if flagged != 0 || len(d.snapshot()) != 0 {
		t.Fatalf("a 30 qpm querier was flagged")
	}
}

func TestBotDetectorFlagsFlood(t *testing.T) {
	d, clock := newTestBotDetector()
	// Irregular gaps averaging 50 ms: 1200 qpm, far from uniform.
	flagged := feedBot(d, clock, "203.0.113.9", 200, func(i int) time.Duration {
		return time.Duration(10+(i%9)*10) * time.Millisecond
	})
	got := d.snapshot()
	t.Logf("input: 200 queries with gaps of 10..90 ms")
	t.Logf("output: flagged=%d detections=%+v", flagged, got)
	if flagged != 1 || len(got) != 1 {
		t.Fatalf("flagged=%d detections=%d, want one detection inside the cooldown", flagged, len(got))
	}
	if got[0].Reason[:5] != "flood" {
		t.Fatalf("reason = %q, want a flood", got[0].Reason)
	}
}

func TestBotDetectorFlagsUniformTiming(t *testing.T) {
	d, clock := newTestBotDetector()
	// Exactly 200 ms apart: 300 qpm, between the two thresholds, with no jitter.
	flagged := feedBot(d, clock, "203.0.113.9", 100, func(int) time.Duration { return 200 * time.Millisecond })
	got := d.snapshot()
	t.Logf("input: 100 queries exactly 200 ms apart (300 qpm)")
	t.Logf("output: flagged=%d detections=%+v", flagged, got)
	if len(got) != 1 {
		t.Fatalf("detections = %d, want 1", len(got))
	}
	if got[0].IntervalStddevMs > 1 {
		t.Fatalf("stddev = %.2f ms, want ~0", got[0].IntervalStddevMs)
	}
}

func TestBotDetectorIgnoresJitteryMidRate(t *testing.T) {
	d, clock := newTestBotDetector()
	// 300 qpm on average, with gaps alternating 20 ms and 380 ms.
	flagged := feedBot(d, clock, "203.0.113.9", 100, func(i int) time.Duration {
		if i%2 == 0 {
			return 20 * time.Millisecond
		}
		return 380 * time.Millisecond
	})
	t.Logf("input: 100 queries with gaps alternating 20 ms / 380 ms (300 qpm)")
	t.Logf("output: flagged=%d detections=%+v", flagged, d.snapshot())
	if flagged != 0 {
		t.Fatalf("a jittery 300 qpm querier was flagged")
	}
}

func TestBotDetectorCountsAnIPv6PrefixAsOneSource(t *testing.T) {
	d, clock := newTestBotDetector()
	cfg := BotDetectionConfig{Enabled: true}
	for i := 0; i < 200; i++ {
		*clock = clock.Add(20 * time.Millisecond)
		ip := net.ParseIP("2001:db8:1:2::").To16()
		ip[15] = byte(i)
		d.record(addressKey(ip), cfg)
	}
	got := d.snapshot()
	t.Logf("input: 200 queries from 200 addresses in 2001:db8:1:2::/64")
	t.Logf("output: detections=%+v", got)
	if len(got) != 1 || got[0].Source != "2001:db8:1:2::" {
		t.Fatalf("detections = %+v, want one for the /64", got)
	}
}

func TestBotDetectorDisabledRecordsNothing(t *testing.T) {
	d, clock := newTestBotDetector()
	for i := 0; i < 500; i++ {
		*clock = clock.Add(time.Millisecond)
		d.record("203.0.113.9", BotDetectionConfig{})
	}
	t.Logf("input: 500 queries 1 ms apart with detection disabled")
	t.Logf("output: trackers=%d detections=%d", len(d.trackers), len(d.snapshot()))
	if len(d.trackers) != 0 || len(d.snapshot()) != 0 {
		t.Fatalf("a disabled detector kept state")
	}
}

func TestBotDetectorPrunesIdleSources(t *testing.T) {
	d, clock := newTestBotDetector()
	feedBot(d, clock, "203.0.113.9", 10, func(int) time.Duration { return time.Second })
	*clock = clock.Add(3 * time.Minute)
	d.record("203.0.113.10", BotDetectionConfig{Enabled: true})
	t.Logf("input: 10 queries from .9, then 3 idle minutes, then one query from .10")
	t.Logf("output: trackers=%d", len(d.trackers))
	if _, ok := d.trackers["203.0.113.9"]; ok {
		t.Fatalf("the idle source was not pruned")
	}
}
