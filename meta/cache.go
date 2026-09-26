package meta

import (
	"container/list"
	"context"
	"sync"
	"time"

	"enode/storage"
)

// Cache keeps recent live Search answers. It is an LRU bounded by entry count with a
// TTL per entry, and it collapses concurrent misses for one key into a single daemon
// call: a popular search arriving from many clients at once costs the daemon one
// query, not one per client.
//
// V is what one key holds. The eD2K search path caches []storage.File per network
// and Query.Key (NewCache); cached rows are unprefixed and unfiltered — the
// post-filter depends on the whole search tree, not just the forwarded part the key
// describes. MetaApi.Search caches one Chunk of daemon entries per network, request
// and page window (NewValueCache), in an instance of its own so paging cannot evict
// what eD2K searches rely on.
type Cache[V any] struct {
	maxEntries int
	// trim bounds a loaded value before it is stored and returned; nil keeps it whole.
	trim func(V) V
	ttl  time.Duration
	now  func() time.Time

	mu       sync.Mutex
	order    *list.List // front = most recently used; values are *cacheEntry[V]
	entries  map[string]*list.Element
	inflight map[string]*cacheCall[V]
}

type cacheEntry[V any] struct {
	key     string
	value   V
	expires time.Time
}

// cacheCall is one daemon call that other callers for the same key wait on.
type cacheCall[V any] struct {
	done  chan struct{}
	value V
	err   error
}

// NewCache returns a cache holding up to maxEntries queries of up to maxRows rows
// each, for ttl.
func NewCache(maxEntries, maxRows int, ttl time.Duration) *Cache[[]storage.File] {
	return NewValueCache(maxEntries, ttl, func(rows []storage.File) []storage.File {
		if len(rows) > maxRows {
			return rows[:maxRows]
		}
		return rows
	})
}

// NewValueCache returns a cache holding up to maxEntries values for ttl. trim, when
// not nil, bounds each loaded value before it is kept.
func NewValueCache[V any](maxEntries int, ttl time.Duration, trim func(V) V) *Cache[V] {
	return &Cache[V]{
		maxEntries: maxEntries,
		trim:       trim,
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

	c.mu.Lock()
	delete(c.inflight, key)
	if err == nil {
		c.storeLocked(key, value)
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

func (c *Cache[V]) lookupLocked(key string) (V, bool) {
	var zero V
	el, ok := c.entries[key]
	if !ok {
		return zero, false
	}
	entry := el.Value.(*cacheEntry[V])
	if !c.now().Before(entry.expires) {
		c.order.Remove(el)
		delete(c.entries, key)
		return zero, false
	}
	c.order.MoveToFront(el)
	return entry.value, true
}

func (c *Cache[V]) storeLocked(key string, value V) {
	expires := c.now().Add(c.ttl)
	if el, ok := c.entries[key]; ok {
		entry := el.Value.(*cacheEntry[V])
		entry.value, entry.expires = value, expires
		c.order.MoveToFront(el)
		return
	}
	c.entries[key] = c.order.PushFront(&cacheEntry[V]{key: key, value: value, expires: expires})
	for c.order.Len() > c.maxEntries {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*cacheEntry[V]).key)
	}
}
