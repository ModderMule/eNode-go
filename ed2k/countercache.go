package ed2k

import (
	"errors"
	"sync"
	"time"

	"enode/logging"
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
	// lastErr is the error of the latest refresh, nil once one succeeds again, and
	// failingSince is when the current run of failures began.
	lastErr      error
	failingSince time.Time
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

		newClients, clientsErr := c.engine.ClientsCountChecked()
		newFiles, filesErr := c.engine.FilesCountEstimateChecked()

		c.mu.Lock()
		// A failed read keeps the last good value rather than replacing it with 0:
		// a database outage is not an empty server, and these counts go to every
		// client in OP_SERVERSTATUS as well as to the dashboard.
		if clientsErr == nil {
			c.clients = newClients
		}
		if filesErr == nil {
			c.files = newFiles
		}
		c.recordResult(errors.Join(clientsErr, filesErr))
		// A failed refresh is also held for the TTL, so a database that is down is
		// asked once per TTL rather than once per status request.
		c.fetched = time.Now()
		c.refreshing = false
		close(c.done)
		c.done = nil
		clients, files = c.clients, c.files
		c.mu.Unlock()
		return clients, files
	}
}

// Failure reports whether the latest refresh failed, with its error and when the
// current run of failures began. The counts Counts returns meanwhile are the last
// good ones (or 0 if there never was one). Zero values mean the counts are live.
func (c *counterCache) Failure() (since time.Time, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failingSince, c.lastErr
}

// recordResult tracks the start and end of a run of failed refreshes, logging each
// transition once rather than every TTL. Must be called with c.mu held.
func (c *counterCache) recordResult(err error) {
	switch {
	case err != nil && c.lastErr == nil:
		c.failingSince = time.Now()
		logging.Warnf("storage counts unavailable, serving last known clients=%d files=%d: %v", c.clients, c.files, err)
	case err == nil && c.lastErr != nil:
		logging.Infof("storage counts available again after %s", time.Since(c.failingSince).Round(time.Second))
		c.failingSince = time.Time{}
	}
	c.lastErr = err
}
