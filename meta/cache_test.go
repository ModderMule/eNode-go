package meta

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enode/storage"
)

func rowsNamed(names ...string) []storage.File {
	out := make([]storage.File, len(names))
	for i, n := range names {
		out[i] = storage.File{Name: n, Hash: []byte(n)}
	}
	return out
}

func TestCacheHitMissAndTTL(t *testing.T) {
	c := NewCache(10, 100, time.Minute)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }

	var loads int
	load := func() ([]storage.File, error) { loads++; return rowsNamed("a", "b"), nil }

	first, _ := c.Get(context.Background(), "k", load)
	second, _ := c.Get(context.Background(), "k", load)
	t.Logf("input: two Gets within TTL; output: loads=%d rows=%d/%d", loads, len(first), len(second))
	if loads != 1 || len(second) != 2 {
		t.Fatalf("loads=%d rows=%d, want one load and a hit", loads, len(second))
	}

	now = now.Add(time.Minute)
	_, _ = c.Get(context.Background(), "k", load)
	t.Logf("input: Get at TTL expiry; output: loads=%d", loads)
	if loads != 2 {
		t.Fatalf("an expired entry was served: loads=%d, want 2", loads)
	}
}

func TestCacheEvictsLeastRecentlyUsedAndCapsRows(t *testing.T) {
	c := NewCache(2, 3, time.Minute)
	load := func(names ...string) func() ([]storage.File, error) {
		return func() ([]storage.File, error) { return rowsNamed(names...), nil }
	}
	_, _ = c.Get(context.Background(), "a", load("1", "2", "3", "4", "5"))
	_, _ = c.Get(context.Background(), "b", load("x"))
	_, _ = c.Get(context.Background(), "a", load()) // touch a, so b is the oldest
	_, _ = c.Get(context.Background(), "c", load("y"))

	var reloaded bool
	rows, _ := c.Get(context.Background(), "a", func() ([]storage.File, error) { reloaded = true; return nil, nil })
	var bReloaded bool
	_, _ = c.Get(context.Background(), "b", func() ([]storage.File, error) { bReloaded = true; return nil, nil })
	t.Logf("input: maxEntries=2 maxRows=3, keys a(5 rows) b c; output: len=%d aRows=%d aReloaded=%t bReloaded=%t",
		c.Len(), len(rows), reloaded, bReloaded)
	if reloaded || len(rows) != 3 {
		t.Fatalf("a: reloaded=%t rows=%d, want a hit capped at 3 rows", reloaded, len(rows))
	}
	if !bReloaded {
		t.Fatal("b should have been evicted as least recently used")
	}
}

func TestCacheCollapsesConcurrentMisses(t *testing.T) {
	c := NewCache(10, 100, time.Minute)
	var loads atomic.Int32
	release := make(chan struct{})
	load := func() ([]storage.File, error) {
		loads.Add(1)
		<-release
		return rowsNamed("r"), nil
	}

	const callers = 8
	var wg sync.WaitGroup
	results := make([]int, callers)
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rows, _ := c.Get(context.Background(), "k", load)
			results[i] = len(rows)
		}(i)
	}
	time.Sleep(50 * time.Millisecond) // let every caller reach Get
	close(release)
	wg.Wait()
	t.Logf("input: %d concurrent misses on one key; output: loads=%d rows=%v", callers, loads.Load(), results)
	if loads.Load() != 1 {
		t.Fatalf("%d loads for one key, want 1", loads.Load())
	}
	for i, n := range results {
		if n != 1 {
			t.Fatalf("caller %d got %d rows, want the shared answer", i, n)
		}
	}
}

func TestCacheWaiterHonoursItsOwnDeadline(t *testing.T) {
	c := NewCache(10, 100, time.Minute)
	release := make(chan struct{})
	defer close(release)
	go func() {
		_, _ = c.Get(context.Background(), "k", func() ([]storage.File, error) { <-release; return nil, nil })
	}()
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Get(ctx, "k", func() ([]storage.File, error) { t.Fatal("a waiter must not load"); return nil, nil })
	t.Logf("input: waiter with 30ms deadline behind a stuck load; output: err=%v after %s", err, time.Since(start))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v, want the waiter's own deadline", err)
	}
}

func TestCacheDoesNotStoreFailures(t *testing.T) {
	c := NewCache(10, 100, time.Minute)
	boom := errors.New("daemon down")
	_, err := c.Get(context.Background(), "k", func() ([]storage.File, error) { return nil, boom })
	rows, _ := c.Get(context.Background(), "k", func() ([]storage.File, error) { return rowsNamed("ok"), nil })
	t.Logf("input: failed load then good load; output: firstErr=%v secondRows=%d cached=%d", err, len(rows), c.Len())
	if !errors.Is(err, boom) || len(rows) != 1 {
		t.Fatalf("a failure was cached: err=%v rows=%d", err, len(rows))
	}
}
