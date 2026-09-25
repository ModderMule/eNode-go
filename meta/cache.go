package meta

import (
	"container/list"
	"context"
	"sync"
	"time"

	"enode/storage"
)

// Cache keeps recent live Search answers, keyed by network and Query.Key. It is an
// LRU bounded by entry count with a TTL per entry, and it collapses concurrent misses
// for one key into a single daemon call: a popular search arriving from many clients
// at once costs the daemon one query, not one per client.
//
// Cached rows are unprefixed and unfiltered — the post-filter depends on the whole
// search tree, not just the forwarded part the key describes.
type Cache struct {
	maxEntries int
	maxRows    int
	ttl        time.Duration
	now        func() time.Time

	mu       sync.Mutex
	order    *list.List // front = most recently used; values are *cacheEntry
	entries  map[string]*list.Element
	inflight map[string]*cacheCall
}

type cacheEntry struct {
	key     string
	rows    []storage.File
	expires time.Time
}

// cacheCall is one daemon call that other callers for the same key wait on.
type cacheCall struct {
	done chan struct{}
	rows []storage.File
	err  error
}

// NewCache returns a cache holding up to maxEntries queries of up to maxRows rows
// each, for ttl.
func NewCache(maxEntries, maxRows int, ttl time.Duration) *Cache {
	return &Cache{
		maxEntries: maxEntries,
		maxRows:    maxRows,
		ttl:        ttl,
		now:        time.Now,
		order:      list.New(),
		entries:    map[string]*list.Element{},
		inflight:   map[string]*cacheCall{},
	}
}

// Get returns the cached rows for key, loading them with load on a miss. A caller that
// arrives while another is loading the same key waits for that load rather than
// starting its own, but never past its own ctx. A failed load is not cached.
func (c *Cache) Get(ctx context.Context, key string, load func() ([]storage.File, error)) ([]storage.File, error) {
	c.mu.Lock()
	if rows, ok := c.lookupLocked(key); ok {
		c.mu.Unlock()
		return rows, nil
	}
	if call, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.rows, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &cacheCall{done: make(chan struct{})}
	c.inflight[key] = call
	c.mu.Unlock()

	rows, err := load()
	if len(rows) > c.maxRows {
		rows = rows[:c.maxRows]
	}
	call.rows, call.err = rows, err

	c.mu.Lock()
	delete(c.inflight, key)
	if err == nil {
		c.storeLocked(key, rows)
	}
	c.mu.Unlock()
	close(call.done)
	return rows, err
}

// Len reports how many queries are cached.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

func (c *Cache) lookupLocked(key string) ([]storage.File, bool) {
	el, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := el.Value.(*cacheEntry)
	if !c.now().Before(entry.expires) {
		c.order.Remove(el)
		delete(c.entries, key)
		return nil, false
	}
	c.order.MoveToFront(el)
	return entry.rows, true
}

func (c *Cache) storeLocked(key string, rows []storage.File) {
	expires := c.now().Add(c.ttl)
	if el, ok := c.entries[key]; ok {
		entry := el.Value.(*cacheEntry)
		entry.rows, entry.expires = rows, expires
		c.order.MoveToFront(el)
		return
	}
	c.entries[key] = c.order.PushFront(&cacheEntry{key: key, rows: rows, expires: expires})
	for c.order.Len() > c.maxEntries {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*cacheEntry).key)
	}
}
