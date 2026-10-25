package memguard

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"enode/config"
)

type fakeShedder struct {
	bytes int64
	keeps []float64
}

func (f *fakeShedder) Shed(keep float64) int64 {
	f.keeps = append(f.keeps, keep)
	freed := f.bytes - int64(float64(f.bytes)*keep)
	f.bytes -= freed
	return freed
}
func (f *fakeShedder) Bytes() int64 { return f.bytes }
func (f *fakeShedder) Len() int     { return 1 }

// testGuard is a guard over fake probes: no cgroup, the given RAM and live heap, and
// a recorded SetMemoryLimit.
func testGuard(cfg config.MemoryConfig, ram int64, live *int64, applied *int64) *Guard {
	if cfg.AutoPercent == 0 {
		cfg.AutoPercent = 75
	}
	if cfg.ShedAtPercent == 0 {
		cfg.ShedAtPercent = 80
	}
	if cfg.KeepPercent == 0 {
		cfg.KeepPercent = 50
	}
	g := New(cfg)
	g.envLimit = math.MaxInt64
	g.cgroupLimit = func() int64 { return 0 }
	g.physicalRAM = func() int64 { return ram }
	g.liveHeap = func() int64 { return *live }
	g.setLimit = func(n int64) int64 { *applied = n; return 0 }
	return g
}

func TestGuardShedsAboveThresholdOnly(t *testing.T) {
	var live, applied int64
	g := testGuard(config.MemoryConfig{LimitBytes: 1000}, 0, &live, &applied)
	now := time.Unix(1000, 0)
	g.now = func() time.Time { return now }
	cache := &fakeShedder{bytes: 400}
	g.Register("c", func() Shedder { return cache })
	g.Register("gone", func() Shedder { return nil })
	g.mu.Lock()
	g.applyLocked()
	g.mu.Unlock()

	live = 800 // exactly 80%: not above
	g.Check()
	t.Logf("input: live=800 limit=1000 shedAt=80%%; output: sheds=%d cache=%d", g.Stats().Sheds, cache.bytes)
	if g.Stats().Sheds != 0 || cache.bytes != 400 {
		t.Fatalf("shed at the threshold: sheds=%d cache=%d", g.Stats().Sheds, cache.bytes)
	}

	live = 900
	g.Check()
	st := g.Stats()
	t.Logf("input: live=900; output: sheds=%d lastShedBytes=%d cache=%d keeps=%v applied=%d",
		st.Sheds, st.LastShedBytes, cache.bytes, cache.keeps, applied)
	if st.Sheds != 1 || st.LastShedBytes != 200 || cache.bytes != 200 || applied != 1000 {
		t.Fatalf("want one shed of 200 to 200 with the limit applied: %+v cache=%d applied=%d", st, cache.bytes, applied)
	}

	g.Check() // same instant: debounced
	now = now.Add(minShedInterval)
	g.Check()
	t.Logf("input: two more checks, the second %s later; output: sheds=%d cache=%d", minShedInterval, g.Stats().Sheds, cache.bytes)
	if g.Stats().Sheds != 2 || cache.bytes != 100 {
		t.Fatalf("debounce: sheds=%d cache=%d, want 2 and 100", g.Stats().Sheds, cache.bytes)
	}
}

func TestGuardLimitResolution(t *testing.T) {
	cases := []struct {
		name       string
		cfg        config.MemoryConfig
		env        int64
		cgroup     int64
		ram        int64
		wantLimit  int64
		wantSource string
		wantSet    int64
	}{
		{"config wins", config.MemoryConfig{LimitBytes: 500}, 700, 900, 1000, 500, SourceConfig, 500},
		{"GOMEMLIMIT next", config.MemoryConfig{}, 700, 900, 1000, 700, SourceEnv, 700},
		{"cgroup share", config.MemoryConfig{}, math.MaxInt64, 1000, 4000, 750, SourceCgroup, 750},
		{"RAM share", config.MemoryConfig{AutoPercent: 50}, math.MaxInt64, 0, 4000, 2000, SourceRAM, 2000},
		{"nothing known", config.MemoryConfig{}, math.MaxInt64, 0, 0, 0, SourceNone, math.MaxInt64},
		{"disabled", config.MemoryConfig{Enabled: new(false), LimitBytes: 500}, math.MaxInt64, 0, 4000, 0, SourceOff, math.MaxInt64},
	}
	for _, tc := range cases {
		var live, applied int64
		g := testGuard(tc.cfg, tc.ram, &live, &applied)
		g.envLimit = tc.env
		g.cgroupLimit = func() int64 { return tc.cgroup }
		g.mu.Lock()
		g.applyLocked()
		g.mu.Unlock()
		st := g.Stats()
		t.Logf("input: %s cfg=%+v env=%d cgroup=%d ram=%d; output: limit=%d source=%s set=%d",
			tc.name, tc.cfg, tc.env, tc.cgroup, tc.ram, st.Limit, st.Source, applied)
		if st.Limit != tc.wantLimit || st.Source != tc.wantSource || applied != tc.wantSet {
			t.Errorf("%s: limit=%d source=%s set=%d, want %d %s %d", tc.name, st.Limit, st.Source, applied,
				tc.wantLimit, tc.wantSource, tc.wantSet)
		}
	}
}

func TestGuardReloadAppliesNewLimit(t *testing.T) {
	var live, applied int64
	g := testGuard(config.MemoryConfig{LimitBytes: 1000}, 0, &live, &applied)
	g.mu.Lock()
	g.applyLocked()
	g.mu.Unlock()
	g.Reload(config.MemoryConfig{LimitBytes: 2000, ShedAtPercent: 90, KeepPercent: 25})
	st := g.Stats()
	t.Logf("input: reload limit 1000 -> 2000; output: limit=%d set=%d shedAt=%d keep=%d", st.Limit, applied, st.ShedAtPercent, st.KeepPercent)
	if st.Limit != 2000 || applied != 2000 || st.ShedAtPercent != 90 || st.KeepPercent != 25 {
		t.Fatalf("reload not applied: %+v set=%d", st, applied)
	}
	var nilGuard *Guard
	nilGuard.Reload(config.MemoryConfig{})
	nilGuard.Register("x", func() Shedder { return nil })
}

func TestGuardRunsAfterEveryGC(t *testing.T) {
	var live, applied int64
	g := testGuard(config.MemoryConfig{LimitBytes: 1 << 40}, 0, &live, &applied)
	checks := make(chan struct{}, 16)
	g.liveHeap = func() int64 { checks <- struct{}{}; return 0 }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)

	seen := 0
	for range 3 {
		runtime.GC()
		select {
		case <-checks:
			seen++
		case <-time.After(2 * time.Second):
		}
	}
	t.Logf("input: 3 forced GC cycles; output: %d checks", seen)
	if seen < 2 {
		t.Fatalf("the GC hook ran %d times over 3 cycles", seen)
	}
}

func TestParseCgroupLimit(t *testing.T) {
	cases := map[string]int64{
		"max\n":               0,
		"":                    0,
		"536870912\n":         536870912,
		"9223372036854771712": 0, // v1 "unlimited"
		"garbage":             0,
		"-1":                  0,
	}
	for in, want := range cases {
		got := ParseCgroupLimit(in)
		t.Logf("input: %q; output: %d", in, got)
		if got != want {
			t.Errorf("ParseCgroupLimit(%q) = %d, want %d", in, got, want)
		}
	}
	dir := t.TempDir()
	v2, v1 := filepath.Join(dir, "memory.max"), filepath.Join(dir, "limit_in_bytes")
	_ = os.WriteFile(v2, []byte("max\n"), 0o600)
	_ = os.WriteFile(v1, []byte("1073741824\n"), 0o600)
	got := readCgroupLimit([]string{filepath.Join(dir, "missing"), v2, v1})
	t.Logf("input: missing, v2=max, v1=1 GiB; output: %d", got)
	if got != 1<<30 {
		t.Fatalf("readCgroupLimit = %d, want the v1 limit", got)
	}
}
