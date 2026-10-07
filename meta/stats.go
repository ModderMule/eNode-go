package meta

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"enode/logging"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
)

// defaultInfoInterval is how often each daemon's GetInfo is polled. The figures feed
// the admin dashboard and, with countInServerStatus, the advertised file total; both
// are display-only, and GetInfo makes the daemon count its catalogue, so once a
// minute is plenty.
const defaultInfoInterval = time.Minute

// infoTimeout bounds one GetInfo call.
const infoTimeout = 5 * time.Second

// staleWindow is how recent a Search answer must be for a failed GetInfo to count
// as stale figures rather than an unreachable daemon: two polls, so one answer
// covers the poll that follows it.
const staleWindow = 2 * defaultInfoInterval

// maxStatusFiles caps one network's contribution to the status file total, and to
// the user total, so the int conversion cannot overflow on a 32-bit build. The wire field is a uint32 and
// the ed2k side clamps the sum.
const maxStatusFiles = 1<<31 - 1

// NetworkStats is one network's figures for the admin dashboard: its configuration,
// what its daemon last reported, what the feed holds, and counters since start.
type NetworkStats struct {
	Network             string
	URL                 string
	Prefix              string
	LiveSearch          bool
	FeedEnabled         bool
	CountInServerStatus bool

	// Reachable is whether the last GetInfo succeeded; InfoAt is when one last did.
	// The daemon figures below are from that call and are kept across a failure.
	Reachable bool
	LastError string
	InfoAt    time.Time
	// Down is whether live searches are paused after an answer that will not change
	// between searches (unavailable, unimplemented, unauthenticated).
	Down bool
	// LiveOKAt is when the daemon last answered a Search, zero for never.
	LiveOKAt time.Time
	// StatsStale is whether the last GetInfo failed although the daemon answered a
	// Search within staleWindow: it is up and only its figures are old.
	StatsStale bool

	Daemon          string
	Version         string
	Indexer         string
	SearchAvailable bool
	Catalogued      uint64
	Published       uint64
	Files           uint64
	LastSeq         uint64

	// NetworkUsers and NetworkUsersExperimental are the daemon's two estimates of
	// how many users its whole network has, eMule's routing-table figure and its
	// experimental one, and NetworkFiles its estimate of the files that network
	// holds. They are not what the daemon catalogued, and 0 is no estimate.
	NetworkUsers             uint64
	NetworkUsersExperimental uint64
	NetworkFiles             uint64

	// NetworkUsersSeen is how many users the daemon has seen in its network over
	// NetworkUsersSeenWindow, and NetworkUsersSeenDay over the last 24 hours. They
	// count node ids, so a user whose id changed is counted once for each. A zero
	// window says the daemon does not count them. NetworkUsersSeenSince is when it
	// began counting, the zero time when unknown.
	NetworkUsersSeen       uint64
	NetworkUsersSeenDay    uint64
	NetworkUsersSeenWindow time.Duration
	NetworkUsersSeenSince  time.Time

	FeedReleases int
	FeedRows     int
	FeedCursor   uint64
	FeedCaughtUp bool

	SearchesTCP  uint64
	SearchesUDP  uint64
	RowsServed   uint64
	LiveCalls    uint64
	LiveErrors   uint64
	LiveTimeouts uint64
	CacheHits    uint64
	CacheMisses  uint64
	// UDPSkipped counts UDP searches that made no live call because every
	// udpMaxConcurrent slot was taken.
	UDPSkipped uint64
	// CatalogCalls, CatalogErrors and CatalogCacheHits are MetaApi.Search's daemon
	// calls, failed chunk loads and cached chunks served.
	CatalogCalls     uint64
	CatalogErrors    uint64
	CatalogCacheHits uint64

	// Counted is what this network adds to the file total in the server status: 0
	// unless CountInServerStatus is set.
	Counted int
}

// Stats returns every enabled network's figures, in configuration order.
func (s *Searcher) Stats() []NetworkStats {
	out := make([]NetworkStats, 0, len(s.sources))
	for _, src := range s.sources {
		out = append(out, src.stats())
	}
	return out
}

// AdvertisedFiles is the number of files the networks with countInServerStatus add
// to the file total in OP_SERVERSTATUS and OP_GLOBSERVSTATRES. It reads only what
// the info poller and the feeds already hold, so the status path never waits on a
// daemon.
func (s *Searcher) AdvertisedFiles() int {
	total := 0
	for _, src := range s.sources {
		if src.countInStatus {
			total += src.filesForStatus()
		}
	}
	return total
}

// NetworkUsers is the daemon's routing-table estimate of how many users a network
// has, for statsBoost.kadUsers and statsBoost.torrentUsers. It is 0 for a network
// that is not enabled, has not been polled, reports no estimate, or whose last good
// GetInfo is older than staleWindow: a stopped daemon must not keep its users in the
// server status. Like AdvertisedFiles it reads only what the poller holds.
func (s *Searcher) NetworkUsers(network string) int {
	for _, src := range s.sources {
		if src.network == network {
			return src.usersForStatus()
		}
	}
	return 0
}

// CacheEntries reports how many queries the shared result cache holds; 0 when the
// cache is off.
func (s *Searcher) CacheEntries() int {
	if s.cache == nil {
		return 0
	}
	return s.cache.Len()
}

// sourceCounters are one network's search counters since start.
type sourceCounters struct {
	searchesTCP  atomic.Uint64
	searchesUDP  atomic.Uint64
	rowsServed   atomic.Uint64
	liveCalls    atomic.Uint64
	liveErrors   atomic.Uint64
	liveTimeouts atomic.Uint64
	cacheHits    atomic.Uint64
	cacheMisses  atomic.Uint64
	udpSkipped   atomic.Uint64
	// catalogCalls, catalogErrors and catalogCacheHits count MetaApi.Search chunk
	// loads: daemon calls, failed loads (errors and timeouts), cached chunks served.
	catalogCalls     atomic.Uint64
	catalogErrors    atomic.Uint64
	catalogCacheHits atomic.Uint64
}

// daemonInfo is the poller's view of one daemon. info survives a failed poll so the
// dashboard keeps the last known figures.
type daemonInfo struct {
	mu        sync.Mutex
	info      *metav1.GetInfoResponse
	at        time.Time
	reachable bool
	lastErr   string
	// polled is set after the first poll, so a daemon that is down at start is
	// reported once as a warning rather than only at debug level.
	polled bool
}

// pollInfo calls GetInfo at once and then every interval until ctx ends.
func (src *source) pollInfo(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		src.refreshInfo(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (src *source) refreshInfo(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, infoTimeout)
	defer cancel()
	resp, err := src.client.GetInfo(ctx, &metav1.GetInfoRequest{})
	if parent.Err() != nil {
		// The process is stopping; that says nothing about the daemon.
		return
	}

	d := &src.daemon
	d.mu.Lock()
	wasReachable, first := d.reachable, !d.polled
	d.polled = true
	if err != nil {
		d.reachable = false
		d.lastErr = err.Error()
	} else {
		d.info = resp
		d.at = time.Now()
		d.reachable = true
		d.lastErr = ""
	}
	d.mu.Unlock()

	switch {
	case err != nil && wasReachable:
		logging.Warnf("meta %s: GetInfo failed, keeping the last figures: %v", src.network, err)
	case err != nil && first:
		logging.Warnf("meta %s: daemon not reachable at %s: %v", src.network, src.url, err)
	case err != nil:
		logging.Debugf("meta %s: GetInfo failed: %v", src.network, err)
	case !wasReachable:
		logging.Infof("meta %s: daemon %s %s, %d releases / %d files catalogued, %d published, search available=%t",
			src.network, resp.GetDaemon(), resp.GetVersion(), resp.GetCatalogued(), resp.GetFiles(),
			resp.GetPublished(), resp.GetSearchAvailable())
	}
}

// filesForStatus is what this network counts toward the server's file total: with
// live search the daemon's whole catalogue is reachable, so its GetInfo file count;
// without it only the feed answers, so the rows the feed holds.
func (src *source) filesForStatus() int {
	if src.live {
		src.daemon.mu.Lock()
		defer src.daemon.mu.Unlock()
		return int(min(src.daemon.info.GetFiles(), uint64(maxStatusFiles)))
	}
	if src.feed != nil {
		return src.feed.Rows()
	}
	return 0
}

// usersForStatus is the network's estimated user count, 0 once the figure is older
// than staleWindow.
func (src *source) usersForStatus() int {
	src.daemon.mu.Lock()
	defer src.daemon.mu.Unlock()
	if src.daemon.info == nil || time.Since(src.daemon.at) > staleWindow {
		return 0
	}
	return int(min(src.daemon.info.GetNetworkUsers(), uint64(maxStatusFiles)))
}

func (src *source) stats() NetworkStats {
	st := NetworkStats{
		Network:             src.network,
		URL:                 src.url,
		Prefix:              src.prefix,
		LiveSearch:          src.live,
		FeedEnabled:         src.feed != nil,
		CountInServerStatus: src.countInStatus,
		Down:                src.isDown(),
		SearchesTCP:         src.counters.searchesTCP.Load(),
		SearchesUDP:         src.counters.searchesUDP.Load(),
		RowsServed:          src.counters.rowsServed.Load(),
		LiveCalls:           src.counters.liveCalls.Load(),
		LiveErrors:          src.counters.liveErrors.Load(),
		LiveTimeouts:        src.counters.liveTimeouts.Load(),
		CacheHits:           src.counters.cacheHits.Load(),
		CacheMisses:         src.counters.cacheMisses.Load(),
		UDPSkipped:          src.counters.udpSkipped.Load(),
		CatalogCalls:        src.counters.catalogCalls.Load(),
		CatalogErrors:       src.counters.catalogErrors.Load(),
		CatalogCacheHits:    src.counters.catalogCacheHits.Load(),
	}

	src.daemon.mu.Lock()
	info := src.daemon.info
	st.Reachable = src.daemon.reachable
	st.LastError = src.daemon.lastErr
	st.InfoAt = src.daemon.at
	pollFailed := src.daemon.polled && !src.daemon.reachable
	src.daemon.mu.Unlock()
	if ok := src.liveOK.Load(); ok != 0 {
		st.LiveOKAt = time.Unix(0, ok)
		st.StatsStale = pollFailed && time.Since(st.LiveOKAt) < staleWindow
	}
	st.Daemon = info.GetDaemon()
	st.Version = info.GetVersion()
	st.Indexer = info.GetIndexer()
	st.SearchAvailable = info.GetSearchAvailable()
	st.Catalogued = info.GetCatalogued()
	st.Published = info.GetPublished()
	st.Files = info.GetFiles()
	st.LastSeq = info.GetLastSeq()
	st.NetworkUsers = info.GetNetworkUsers()
	st.NetworkUsersExperimental = info.GetNetworkUsersExperimental()
	st.NetworkFiles = info.GetNetworkFiles()
	st.NetworkUsersSeen = info.GetNetworkUsersSeen()
	st.NetworkUsersSeenDay = info.GetNetworkUsersSeenDay()
	st.NetworkUsersSeenWindow = time.Duration(info.GetNetworkUsersSeenWindow()) * time.Second
	if since := info.GetNetworkUsersSeenSince(); since > 0 {
		st.NetworkUsersSeenSince = time.Unix(int64(since), 0)
	}

	if src.feed != nil {
		fs := src.feed.Stats()
		st.FeedReleases, st.FeedRows, st.FeedCursor, st.FeedCaughtUp = fs.Releases, fs.Rows, fs.Cursor, fs.CaughtUp
	}
	if src.countInStatus {
		st.Counted = src.filesForStatus()
	}
	return st
}
