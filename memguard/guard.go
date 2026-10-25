// Package memguard keeps the process clear of an out-of-memory kill. It gives the Go
// GC a soft memory limit, and after every GC cycle compares the live heap with it:
// above memory.shedAtPercent it tells the registered caches to shed, least recently
// used entries first, before their TTL runs out.
//
// The GC cannot do this by itself. Go has no soft references: a weak.Pointer is
// cleared at the next cycle whatever the pressure, which would empty the caches every
// few seconds, and a memory limit alone only makes the GC run harder against memory
// the caches still reference. See docs/memory-guard.md.
package memguard

import (
	"context"
	"fmt"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"enode/config"
	"enode/logging"
)

// Limit sources, as Stats reports them.
const (
	SourceOff    = "off"
	SourceConfig = "config"
	SourceEnv    = "GOMEMLIMIT"
	SourceCgroup = "cgroup"
	SourceRAM    = "ram"
	SourceNone   = "none"
)

// minShedInterval keeps two sheds apart, so a heap that stays high cannot drain the
// caches on every cycle of a GC running back to back.
const minShedInterval = time.Second

// Shedder is a cache that can give memory back.
type Shedder interface {
	// Shed drops expired entries, then least recently used ones until at most keep
	// (0..1) of its bytes remain, and returns the bytes dropped.
	Shed(keep float64) int64
	Bytes() int64
	Len() int
}

// CacheStats is one registered cache as of now.
type CacheStats struct {
	Name    string `json:"name"`
	Entries int    `json:"entries"`
	Bytes   int64  `json:"bytes"`
}

// Stats is the guard's state for /api/runtime.
type Stats struct {
	Enabled bool `json:"enabled"`
	// Limit is the soft limit in bytes; 0 = none, the guard sheds nothing.
	Limit         int64        `json:"limit"`
	Source        string       `json:"source"`
	ShedAtPercent int          `json:"shedAtPercent"`
	KeepPercent   int          `json:"keepPercent"`
	LiveHeap      int64        `json:"liveHeap"`
	Sheds         uint64       `json:"sheds"`
	LastShed      time.Time    `json:"lastShed,omitzero"`
	LastShedBytes int64        `json:"lastShedBytes"`
	Caches        []CacheStats `json:"caches"`
}

// Guard is the memory guard. The zero value is not usable; call New.
type Guard struct {
	// envLimit is the GOMEMLIMIT the process started with; math.MaxInt64 = unset.
	envLimit int64
	// Probes, replaced in tests.
	cgroupLimit func() int64
	physicalRAM func() int64
	liveHeap    func() int64
	setLimit    func(int64) int64
	now         func() time.Time

	kick    chan struct{}
	stopped atomic.Bool

	mu            sync.Mutex
	cfg           config.MemoryConfig
	limit         int64
	source        string
	caches        []namedCache
	lastLive      int64
	sheds         uint64
	lastShed      time.Time
	lastShedBytes int64
}

type namedCache struct {
	name string
	// get returns the cache in effect now, nil when there is none: a reload can
	// swap a cache for a new one.
	get func() Shedder
}

// New returns a guard for cfg. It does nothing until Start.
func New(cfg config.MemoryConfig) *Guard {
	env := int64(math.MaxInt64)
	if os.Getenv("GOMEMLIMIT") != "" {
		// The runtime has parsed it already; a negative argument only reads.
		env = debug.SetMemoryLimit(-1)
	}
	return &Guard{
		envLimit:    env,
		cgroupLimit: cgroupMemoryLimit,
		physicalRAM: physicalMemory,
		liveHeap:    readLiveHeap,
		setLimit:    debug.SetMemoryLimit,
		now:         time.Now,
		kick:        make(chan struct{}, 1),
		cfg:         cfg,
	}
}

// Register adds a cache to shed under pressure. get is called at each shed, so it
// must be cheap and may return nil. Nil-receiver safe.
func (g *Guard) Register(name string, get func() Shedder) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.caches = append(g.caches, namedCache{name: name, get: get})
}

// Start applies the limit and watches every GC cycle until ctx ends.
func (g *Guard) Start(ctx context.Context) {
	g.mu.Lock()
	g.applyLocked()
	g.mu.Unlock()
	go g.run(ctx)
	g.arm()
}

// Reload applies a new memory section. Nil-receiver safe.
func (g *Guard) Reload(cfg config.MemoryConfig) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cfg = cfg
	g.applyLocked()
}

// Check runs one pressure check now, as after a GC cycle. The GC hook calls it; it
// is public for tests and the admin UI.
func (g *Guard) Check() {
	live := g.liveHeap()
	g.mu.Lock()
	g.lastLive = live
	limit, shedAt, keep := g.limit, g.cfg.ShedAtPercent, g.cfg.KeepPercent
	now := g.now()
	if limit <= 0 || live*100 <= limit*int64(shedAt) || now.Sub(g.lastShed) < minShedInterval {
		g.mu.Unlock()
		return
	}
	g.lastShed = now
	caches := append([]namedCache(nil), g.caches...)
	g.mu.Unlock()

	var total int64
	var parts []string
	for _, c := range caches {
		s := c.get()
		if s == nil {
			continue
		}
		freed := s.Shed(float64(keep) / 100)
		total += freed
		parts = append(parts, fmt.Sprintf("%s %s", c.name, mib(freed)))
	}

	g.mu.Lock()
	g.sheds++
	g.lastShedBytes = total
	g.mu.Unlock()
	logging.Warnf("memory pressure: live heap %s of %s limit (shedAt %d%%), caches shed %s (%s)",
		mib(live), mib(limit), shedAt, mib(total), strings.Join(parts, ", "))
}

// Stats reports the guard's state.
func (g *Guard) Stats() Stats {
	g.mu.Lock()
	st := Stats{
		Enabled:       g.cfg.EnabledOrDefault(),
		Limit:         g.limit,
		Source:        g.source,
		ShedAtPercent: g.cfg.ShedAtPercent,
		KeepPercent:   g.cfg.KeepPercent,
		LiveHeap:      g.lastLive,
		Sheds:         g.sheds,
		LastShed:      g.lastShed,
		LastShedBytes: g.lastShedBytes,
	}
	caches := append([]namedCache(nil), g.caches...)
	g.mu.Unlock()
	st.Caches = []CacheStats{}
	for _, c := range caches {
		if s := c.get(); s != nil {
			st.Caches = append(st.Caches, CacheStats{Name: c.name, Entries: s.Len(), Bytes: s.Bytes()})
		}
	}
	return st
}

// applyLocked resolves the limit and hands it to the runtime. Callers hold mu.
func (g *Guard) applyLocked() {
	limit, source := g.resolveLocked()
	if limit != g.limit || source != g.source {
		logging.Infof("memory guard: limit %s (%s), shed at %d%%, keep %d%%",
			mib(limit), source, g.cfg.ShedAtPercent, g.cfg.KeepPercent)
	}
	g.limit, g.source = limit, source
	switch source {
	case SourceConfig, SourceCgroup, SourceRAM:
		g.setLimit(limit)
	default:
		// Off, none, or GOMEMLIMIT: the limit the process started with stands.
		g.setLimit(g.envLimit)
	}
}

// resolveLocked picks the limit: config, then GOMEMLIMIT, then a share of the
// cgroup limit, then of physical RAM.
func (g *Guard) resolveLocked() (int64, string) {
	c := g.cfg
	switch {
	case !c.EnabledOrDefault():
		return 0, SourceOff
	case c.LimitBytes > 0:
		return c.LimitBytes, SourceConfig
	case g.envLimit != math.MaxInt64:
		return g.envLimit, SourceEnv
	}
	if n := g.cgroupLimit(); n > 0 {
		return n / 100 * int64(c.AutoPercent), SourceCgroup
	}
	if n := g.physicalRAM(); n > 0 {
		return n / 100 * int64(c.AutoPercent), SourceRAM
	}
	return 0, SourceNone
}

func (g *Guard) run(ctx context.Context) {
	defer g.stopped.Store(true)
	for {
		select {
		case <-ctx.Done():
			return
		case <-g.kick:
			g.Check()
		}
	}
}

// arm sets a sentinel whose cleanup runs once the GC has found it unreachable, that
// is after the next cycle; the cleanup re-arms, so the guard sees every cycle. The
// cleanup only signals run: cleanups share one goroutine and must not block.
func (g *Guard) arm() {
	if g.stopped.Load() {
		return
	}
	// Large enough to stay out of the tiny allocator, whose blocks may never be
	// cleaned up one by one.
	sentinel := new([64]byte)
	runtime.AddCleanup(sentinel, func(g *Guard) {
		select {
		case g.kick <- struct{}{}:
		default:
		}
		g.arm()
	}, g)
}

// readLiveHeap is the heap the last GC cycle marked live.
func readLiveHeap() int64 {
	sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return int64(sample[0].Value.Uint64())
}

func mib(n int64) string {
	return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
}
