package meta

import (
	"context"
	"strings"
	"testing"
	"time"

	"enode/storage"
)

// sizedRows is n rows whose names are each width bytes long.
func sizedRows(n, width int) []storage.File {
	out := make([]storage.File, n)
	for i := range out {
		out[i] = storage.File{Name: strings.Repeat("n", width), Hash: make([]byte, 16)}
	}
	return out
}

func TestCacheEvictsByBytes(t *testing.T) {
	one := FileRowsBytes(sizedRows(10, 100))
	c := NewCache(CacheLimits{MaxEntries: 100, MaxBytes: 3 * one}, 100, time.Minute)
	for _, k := range []string{"a", "b", "c", "d"} {
		_, _ = c.Get(context.Background(), k, func() ([]storage.File, error) { return sizedRows(10, 100), nil })
	}
	var reloadedA, reloadedD bool
	_, _ = c.Get(context.Background(), "d", func() ([]storage.File, error) { reloadedD = true; return nil, nil })
	_, _ = c.Get(context.Background(), "a", func() ([]storage.File, error) { reloadedA = true; return nil, nil })
	t.Logf("input: 4 values of %d B into a %d B cache; output: len=%d bytes=%d aReloaded=%t dReloaded=%t",
		one, 3*one, c.Len(), c.Bytes(), reloadedA, reloadedD)
	if !reloadedA || reloadedD {
		t.Fatalf("byte cap must evict the least recently used: aReloaded=%t dReloaded=%t", reloadedA, reloadedD)
	}
	if c.Bytes() > 3*one {
		t.Fatalf("bytes=%d over the cap %d", c.Bytes(), 3*one)
	}
}

func TestCacheDoesNotKeepValueLargerThanCap(t *testing.T) {
	c := NewCache(CacheLimits{MaxEntries: 100, MaxBytes: 1000}, 1000, time.Minute)
	rows, _ := c.Get(context.Background(), "big", func() ([]storage.File, error) { return sizedRows(50, 100), nil })
	t.Logf("input: %d B value into a 1000 B cache; output: rows=%d len=%d bytes=%d", FileRowsBytes(rows), len(rows), c.Len(), c.Bytes())
	if len(rows) != 50 || c.Len() != 0 || c.Bytes() != 0 {
		t.Fatalf("an oversize value must be served but not kept: rows=%d len=%d bytes=%d", len(rows), c.Len(), c.Bytes())
	}
}

func TestCacheBytesFollowExpiryAndReplace(t *testing.T) {
	c := NewCache(CacheLimits{MaxEntries: 10, MaxBytes: 1 << 20}, 100, time.Minute)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	_, _ = c.Get(context.Background(), "k", func() ([]storage.File, error) { return sizedRows(10, 100), nil })
	afterLoad := c.Bytes()
	now = now.Add(time.Minute)
	_, _ = c.Get(context.Background(), "k", func() ([]storage.File, error) { return sizedRows(2, 10), nil })
	want := FileRowsBytes(sizedRows(2, 10))
	t.Logf("input: 10 rows, expiry, reload with 2 rows; output: bytes %d -> %d (want %d)", afterLoad, c.Bytes(), want)
	if c.Bytes() != want {
		t.Fatalf("bytes=%d, want %d after the expired entry was replaced", c.Bytes(), want)
	}
}

func TestCacheShedDropsExpiredThenLeastRecentlyUsed(t *testing.T) {
	c := NewCache(CacheLimits{MaxEntries: 10, MaxBytes: 1 << 20}, 100, time.Minute)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	_, _ = c.Get(context.Background(), "stale", func() ([]storage.File, error) { return sizedRows(10, 100), nil })
	now = now.Add(2 * time.Minute)
	for _, k := range []string{"a", "b", "c", "d"} {
		_, _ = c.Get(context.Background(), k, func() ([]storage.File, error) { return sizedRows(10, 100), nil })
	}
	one := FileRowsBytes(sizedRows(10, 100))
	freed := c.Shed(0.5)
	var reloadedA, reloadedD bool
	_, _ = c.Get(context.Background(), "d", func() ([]storage.File, error) { reloadedD = true; return nil, nil })
	_, _ = c.Get(context.Background(), "a", func() ([]storage.File, error) { reloadedA = true; return nil, nil })
	t.Logf("input: 5 values of %d B (one expired), Shed(0.5); output: freed=%d aReloaded=%t dReloaded=%t",
		one, freed, reloadedA, reloadedD)
	// 5 held; keep half of the bytes on entry (2.5 values): the expired one and the two
	// oldest go.
	if freed != 3*one || !reloadedA || reloadedD {
		t.Fatalf("freed=%d (want %d) aReloaded=%t dReloaded=%t", freed, 3*one, reloadedA, reloadedD)
	}
}

func TestCacheShedWithoutSizerCountsEntries(t *testing.T) {
	c := NewValueCache[int](CacheLimits{MaxEntries: 10}, time.Minute, nil, nil)
	for i, k := range []string{"a", "b", "c", "d"} {
		_, _ = c.Get(context.Background(), k, func() (int, error) { return i, nil })
	}
	c.Shed(0.5)
	t.Logf("input: 4 unsized values, Shed(0.5); output: len=%d", c.Len())
	if c.Len() != 2 {
		t.Fatalf("len=%d, want 2", c.Len())
	}
}

func TestCacheTrimReleasesCutRows(t *testing.T) {
	c := NewCache(CacheLimits{MaxEntries: 10}, 3, time.Minute)
	rows, _ := c.Get(context.Background(), "k", func() ([]storage.File, error) { return sizedRows(100, 10), nil })
	t.Logf("input: 100 rows, maxRows=3; output: len=%d cap=%d", len(rows), cap(rows))
	if len(rows) != 3 || cap(rows) != 3 {
		t.Fatalf("len=%d cap=%d, want a 3-row copy that does not pin the 100-row array", len(rows), cap(rows))
	}
}
