package ed2k

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Bot detection watches the UDP searches and source requests of each address for two
// signs of an automated querier: a rate no user produces, and gaps between queries
// too even to be a person. It only observes. A flagged address is listed for the
// operator and keeps being throttled by udp.rateLimitPerIPPerMinute like any other;
// nothing is banned or dropped here. See docs/bot-detection.md.

const (
	// botWindow is the sliding window the rate and the gaps are measured over.
	botWindow = 60 * time.Second
	// botMinSamples is how many queries the window must hold before an address is
	// judged at all.
	botMinSamples = 30
	// botMaxSamples caps what one address can make the detector remember. The rate is
	// the sample count over the span they cover, so a capped window still reads true.
	botMaxSamples = 4096
	// botCooldown is how long a flagged address is left alone before it is measured
	// again, which keeps the variance pass off the per-datagram path.
	botCooldown = 30 * time.Second
	// botDetectionTTL is how long a detection stays listed after it was last seen.
	botDetectionTTL = 24 * time.Hour
	// botMaxSources bounds the tracked addresses. UDP source addresses are forgeable,
	// so without it a spoofed flood would grow the table without limit.
	botMaxSources = 100_000

	defaultBotMinQueriesPerMinute   = 200
	defaultBotFloodQueriesPerMinute = 600
	defaultBotMaxIntervalStddevMs   = 50
)

// BotDetectionConfig is udp.botDetection. A zero threshold selects its default.
type BotDetectionConfig struct {
	Enabled bool
	// MinQueriesPerMinute is the rate below which an address is never flagged.
	MinQueriesPerMinute int
	// FloodQueriesPerMinute flags an address on its rate alone.
	FloodQueriesPerMinute int
	// MaxIntervalStddevMs flags an address above MinQueriesPerMinute whose gaps
	// between queries vary by less than this.
	MaxIntervalStddevMs int
}

// BotDetection is one flagged address. Source is the address the rate limiter buckets
// on: an IPv4 address, or the /64 of an IPv6 one.
type BotDetection struct {
	Source string
	// Detections counts how many times the address was flagged, at most once per
	// botCooldown.
	Detections       uint64
	QueriesPerMinute float64
	IntervalStddevMs float64
	Reason           string
	FirstSeen        time.Time
	LastSeen         time.Time
}

// botDetector holds the per-address query windows and the detections.
type botDetector struct {
	mu         sync.Mutex
	trackers   map[string]*botTracker
	detections map[string]*BotDetection
	lastPrune  time.Time
	now        func() time.Time
}

// botTracker is one address's query times inside the window, oldest first, in Unix
// nanoseconds.
type botTracker struct {
	times []int64
}

func newBotDetector() *botDetector {
	return &botDetector{
		trackers:   make(map[string]*botTracker),
		detections: make(map[string]*BotDetection),
		now:        time.Now,
	}
}

// record notes one query from source and reports whether it was flagged just now.
func (d *botDetector) record(source string, cfg BotDetectionConfig) bool {
	if d == nil || !cfg.Enabled {
		return false
	}
	minRate := float64(positiveOr(cfg.MinQueriesPerMinute, defaultBotMinQueriesPerMinute))
	floodRate := float64(positiveOr(cfg.FloodQueriesPerMinute, defaultBotFloodQueriesPerMinute))
	maxStddev := float64(positiveOr(cfg.MaxIntervalStddevMs, defaultBotMaxIntervalStddevMs))

	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked(now)

	tr := d.trackers[source]
	if tr == nil {
		if len(d.trackers) >= botMaxSources {
			return false
		}
		tr = &botTracker{}
		d.trackers[source] = tr
	}
	tr.add(now)

	n := len(tr.times)
	if n < botMinSamples {
		return false
	}
	span := time.Duration(now.UnixNano() - tr.times[0]).Seconds()
	qpm := float64(n) / math.Max(span, 0.001) * 60
	if qpm < minRate {
		return false
	}
	existing := d.detections[source]
	if existing != nil && now.Sub(existing.LastSeen) < botCooldown {
		return false
	}

	stddev := tr.intervalStddevMs()
	var reason string
	switch {
	case qpm > floodRate:
		reason = fmt.Sprintf("flood %.0f qpm", qpm)
	case stddev < maxStddev:
		reason = fmt.Sprintf("%.0f qpm + uniform timing (%.0f ms stddev)", qpm, stddev)
	default:
		return false
	}

	if existing == nil {
		existing = &BotDetection{Source: source, FirstSeen: now}
		d.detections[source] = existing
	}
	existing.Detections++
	existing.QueriesPerMinute = qpm
	existing.IntervalStddevMs = stddev
	existing.Reason = reason
	existing.LastSeen = now
	return true
}

// snapshot returns copies of the detections, highest rate first.
func (d *botDetector) snapshot() []BotDetection {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	out := make([]BotDetection, 0, len(d.detections))
	for _, det := range d.detections {
		out = append(out, *det)
	}
	d.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].QueriesPerMinute != out[j].QueriesPerMinute {
			return out[i].QueriesPerMinute > out[j].QueriesPerMinute
		}
		return out[i].Source < out[j].Source
	})
	return out
}

// pruneLocked drops idle windows and expired detections, at most once per window.
func (d *botDetector) pruneLocked(now time.Time) {
	if now.Sub(d.lastPrune) < botWindow {
		return
	}
	d.lastPrune = now
	cutoff := now.Add(-botWindow).UnixNano()
	for source, tr := range d.trackers {
		if n := len(tr.times); n == 0 || tr.times[n-1] < cutoff {
			delete(d.trackers, source)
		}
	}
	for source, det := range d.detections {
		if now.Sub(det.LastSeen) > botDetectionTTL {
			delete(d.detections, source)
		}
	}
}

// add appends one query time and drops those that left the window.
func (t *botTracker) add(now time.Time) {
	cutoff := now.Add(-botWindow).UnixNano()
	drop := 0
	for drop < len(t.times) && t.times[drop] < cutoff {
		drop++
	}
	if over := len(t.times) - drop + 1 - botMaxSamples; over > 0 {
		drop += over
	}
	if drop > 0 {
		t.times = append(t.times[:0], t.times[drop:]...)
	}
	t.times = append(t.times, now.UnixNano())
}

// intervalStddevMs is the standard deviation of the gaps between queries.
func (t *botTracker) intervalStddevMs() float64 {
	n := len(t.times) - 1
	if n < 1 {
		return 0
	}
	var sum float64
	for i := 1; i < len(t.times); i++ {
		sum += float64(t.times[i]-t.times[i-1]) / 1e6
	}
	mean := sum / float64(n)
	var variance float64
	for i := 1; i < len(t.times); i++ {
		gap := float64(t.times[i]-t.times[i-1])/1e6 - mean
		variance += gap * gap
	}
	return math.Sqrt(variance / float64(n))
}

func positiveOr(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}
