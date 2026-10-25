package meta

import (
	"container/list"
	"context"
	"slices"
	"sync"
	"time"

	"enode/storage"
)

// Cache keeps recent live Search answers. It is an LRU bounded by entry count and,
// when a sizer is given, by an estimate of the bytes its values hold, with a TTL per
// entry. It collapses concurrent misses for one key into a single daemon call: a
// popular search arriving from many clients at once costs the daemon one query, not
// one per client.
//
// V is what one key holds. The eD2K search path caches []storage.File per network
// and Query.Key (NewCache); cached rows are unprefixed and unfiltered — the
// post-filter depends on the whole search tree, not just the forwarded part the key
// describes. MetaApi.Search caches one Chunk of daemon entries per network, request
// and page window (NewValueCache), in an instance of its own so paging cannot evict
// what eD2K searches rely on.
//
// Under memory pressure the memory guard calls Shed, which gives entries back before
// their TTL runs out (see docs/memory-guard.md).
type Cache[V any] struct {
	maxEntries int
	// maxBytes bounds the sum of size over the values held; 0 = no byte bound.
	maxBytes int64
	// trim bounds a loaded value before it is stored and returned; nil keeps it whole.
	trim func(V) V
	// size estimates the bytes one value keeps alive; nil counts every value as 0.
	size func(V) int64
	ttl  time.Duration
	now  func() time.Time

	mu       sync.Mutex
	bytes    int64
	order    *list.List // front = most recently used; values are *cacheEntry[V]
	entries  map[string]*list.Element
	inflight map[string]*cacheCall[V]
}

// CacheLimits bounds a Cache. MaxBytes 0 leaves it bounded by entry count alone.
type CacheLimits struct {
	MaxEntries int
	MaxBytes   int64
}

type cacheEntry[V any] struct {
	key     string
	value   V
	bytes   int64
	expires time.Time
}

// cacheCall is one daemon call that other callers for the same key wait on.
type cacheCall[V any] struct {
	done  chan struct{}
	value V
	err   error
}

// NewCache returns a cache holding up to limits.MaxEntries queries of up to maxRows
// rows each, and up to limits.MaxBytes of rows (estimated by FileRowsBytes), for ttl.
func NewCache(limits CacheLimits, maxRows int, ttl time.Duration) *Cache[[]storage.File] {
	return NewValueCache(limits, ttl, func(rows []storage.File) []storage.File {
		if len(rows) > maxRows {
			// A copy, so the rows cut off (and their strings) are not kept alive by
			// the backing array.
			return slices.Clone(rows[:maxRows])
		}
		return rows
	}, FileRowsBytes)
}

// NewValueCache returns a cache holding up to limits.MaxEntries values for ttl. trim,
// when not nil, bounds each loaded value before it is kept. size, when not nil,
// estimates a value's bytes for limits.MaxBytes.
func NewValueCache[V any](limits CacheLimits, ttl time.Duration, trim func(V) V, size func(V) int64) *Cache[V] {
	return &Cache[V]{
		maxEntries: limits.MaxEntries,
		maxBytes:   limits.MaxBytes,
		trim:       trim,
		size:       size,
		ttl:        ttl,
		now:        time.Now,
		order:      list.New(),
		entries:    map[string]*list.Element{},
		inflight:   map[string]*cacheCall[V]{},
	}
}

// Get returns the cached value for key, loading it with load on a miss. A caller that
// arrives while another is loading the same key waits for that load rather than
// starting its own, but never past its own ctx. A failed load is not cached.
func (c *Cache[V]) Get(ctx context.Context, key string, load func() (V, error)) (V, error) {
	c.mu.Lock()
	if value, ok := c.lookupLocked(key); ok {
		c.mu.Unlock()
		return value, nil
	}
	if call, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.value, call.err
		case <-ctx.Done():
			var zero V
			return zero, ctx.Err()
		}
	}
	call := &cacheCall[V]{done: make(chan struct{})}
	c.inflight[key] = call
	c.mu.Unlock()

	value, err := load()
	if c.trim != nil {
		value = c.trim(value)
	}
	call.value, call.err = value, err
	var size int64
	if err == nil && c.size != nil {
		// Sized outside the lock: a chunk of releases takes a while to walk.
		size = c.size(value)
	}

	c.mu.Lock()
	delete(c.inflight, key)
	if err == nil {
		c.storeLocked(key, value, size)
	}
	c.mu.Unlock()
	close(call.done)
	return value, err
}

// Len reports how many queries are cached.
func (c *Cache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// Bytes reports the estimated bytes the cached values hold.
func (c *Cache[V]) Bytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytes
}

// Shed gives memory back under pressure: it drops every expired entry, then the
// least recently used ones until at most keep (0..1) of the bytes held on entry
// remain. A cache without a sizer sheds by entry count instead. It returns the
// bytes dropped.
func (c *Cache[V]) Shed(keep float64) int64 {
	keep = min(max(keep, 0), 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	before := c.bytes
	now := c.now()
	for el := c.order.Back(); el != nil; {
		prev := el.Prev()
		if !now.Before(el.Value.(*cacheEntry[V]).expires) {
			c.removeLocked(el)
		}
		el = prev
	}
	if c.size != nil {
		target := int64(float64(before) * keep)
		for c.bytes > target && c.order.Len() > 0 {
			c.removeLocked(c.order.Back())
		}
	} else {
		target := int(float64(c.order.Len()) * keep)
		for c.order.Len() > target {
			c.removeLocked(c.order.Back())
		}
	}
	return before - c.bytes
}

func (c *Cache[V]) lookupLocked(key string) (V, bool) {
	var zero V
	el, ok := c.entries[key]
	if !ok {
		return zero, false
	}
	entry := el.Value.(*cacheEntry[V])
	if !c.now().Before(entry.expires) {
		c.removeLocked(el)
		return zero, false
	}
	c.order.MoveToFront(el)
	return entry.value, true
}

func (c *Cache[V]) storeLocked(key string, value V, size int64) {
	if el, ok := c.entries[key]; ok {
		c.removeLocked(el)
	}
	if c.maxBytes > 0 && size > c.maxBytes {
		// Larger than the whole cache: served to its callers, never kept.
		return
	}
	c.entries[key] = c.order.PushFront(&cacheEntry[V]{key: key, value: value, bytes: size, expires: c.now().Add(c.ttl)})
	c.bytes += size
	for c.order.Len() > c.maxEntries || (c.maxBytes > 0 && c.bytes > c.maxBytes) {
		c.removeLocked(c.order.Back())
	}
}

// removeLocked drops one element. Callers hold mu.
func (c *Cache[V]) removeLocked(el *list.Element) {
	entry := el.Value.(*cacheEntry[V])
	c.order.Remove(el)
	delete(c.entries, entry.key)
	c.bytes -= entry.bytes
}
