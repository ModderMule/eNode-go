package ed2k

import (
	"sync"
	"time"

	"enode/storage"
)

// defaultCounterCacheTTL bounds how stale the advertised client and file counts
// may be. These feed the totals in OP_SERVERSTATUS and OP_GLOBSERVSTATRES, which
// clients only display — nothing branches on them — so a minute is invisible
// to a user and is still fresher than the five-minute cadence at which any
// client is told anything. Ten seconds, the earlier value, kept a busy database
// answering count queries back to back. Configurable as storage.countCacheSeconds.
//
// The TTL is deliberately not tied to ServerStatusInterval: it is what bounds
// the cost of a UDP status flood, which arrives at whatever rate an attacker
// chooses.
const defaultCounterCacheTTL = time.Minute

// counterCache serves ClientsCount and FilesCountEstimate from one shared,
// briefly cached reading.
//
// Both callers issued two COUNT(*) queries per call: the per-client status
// ticker (one goroutine per logged-in client) and udpGlobServStatReq, which is
// unauthenticated and unthrottled. `SELECT COUNT(*) FROM clients WHERE online=1`
// had no index to use, so a UDP status flood turned into unbounded concurrent
// full table scans — cheap to send, expensive to serve.
//
// Refresh is lazy rather than driven by a background ticker. A ticker costs
// 2/TTL queries per second unconditionally, so it only pays off above roughly
// interval/TTL concurrent clients (~30 at the defaults) and is a straight
// regression below that — on a single-client server it would turn 0.007 q/s into
// 0.2 q/s. Refreshing on read is never worse than not caching, and still caps
// cost at 2/TTL under any load.
type counterCache struct {
	engine storage.Engine

	mu      sync.Mutex
	ttl     time.Duration
	clients int
	files   int
	fetched time.Time
	// refreshing serialises concurrent readers onto one query, so a burst of
	// datagrams arriving on a cold cache does not each start their own.
	refreshing bool
	done       chan struct{}
}

func newCounterCache(engine storage.Engine, ttl time.Duration) *counterCache {
	if ttl <= 0 {
		ttl = defaultCounterCacheTTL
	}
	return &counterCache{engine: engine, ttl: ttl}
}

// setTTL changes how long a reading is served; zero or less uses defaultCounterCacheTTL.
// The reading already held is judged by the new value.
func (c *counterCache) setTTL(ttl time.Duration) {
	if ttl <= 0 {
		ttl = defaultCounterCacheTTL
	}
	c.mu.Lock()
	c.ttl = ttl
	c.mu.Unlock()
}

// Counts returns the cached client and file totals, refreshing them if stale.
func (c *counterCache) Counts() (clients, files int) {
	for {
		c.mu.Lock()
		if !c.fetched.IsZero() && time.Since(c.fetched) < c.ttl {
			clients, files = c.clients, c.files
			c.mu.Unlock()
			return clients, files
		}
		if c.refreshing {
			// Someone else is already querying. Wait for their result rather than
			// issuing a duplicate; this is the single-flight that keeps a flood
			// from multiplying into one query per datagram.
			wait := c.done
			c.mu.Unlock()
			<-wait
			continue
		}
		c.refreshing = true
		c.done = make(chan struct{})
		c.mu.Unlock()

		newClients := c.engine.ClientsCount()
		newFiles := c.engine.FilesCountEstimate()

		c.mu.Lock()
		c.clients, c.files = newClients, newFiles
		c.fetched = time.Now()
		c.refreshing = false
		close(c.done)
		c.done = nil
		clients, files = c.clients, c.files
		c.mu.Unlock()
		return clients, files
	}
}
