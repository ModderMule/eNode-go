// Package meta merges torrent, Usenet, Kad and web releases into eD2K search answers.
// The rows come from catalogue daemons (torrent-crawler, usenet-crawler,
// kademlia-crawler, web-crawler) that serve the
// enode.meta.v1 MetaIngest service defined in github.com/ModderMule/enodemeta.
//
// Everything that depends on the contract module or on connect lives here; the ed2k
// package sees only a Search method returning storage.File rows. See
// docs/meta-search.md.
package meta

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"enode/config"
	"enode/logging"
	"enode/storage"

	"connectrpc.com/connect/v2"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
	"github.com/ModderMule/enodemeta/metahash"
)

// Network names, as used in config keys and log lines.
const (
	NetworkTorrent = "torrent"
	NetworkUsenet  = "usenet"
	// NetworkKad is the kademlia-crawler daemon. Its rows are native: real eD2K files.
	NetworkKad = "kad"
	// NetworkWeb is the web-crawler daemon. Its rows are pseudo-hash rows like a
	// torrent's, and the links behind one are its metafile. Since amendment 27 of
	// the ingest contract it also sends what its pages offer besides: eD2K files
	// as native rows, torrents as BitTorrent rows and link containers.
	NetworkWeb = "web"
)

// downBackoff is how long a daemon that answered "unavailable", "unimplemented" or
// "unauthenticated" is skipped by live searches. Those answers will not change
// between one search and the next, and without this every search would pay for them.
const downBackoff = 30 * time.Second

// fullCompletion is Search.min_completion for a release that is 100% complete, in
// hundredths of a percent.
const fullCompletion = 10000

// Searcher answers the meta half of a search from every enabled network.
//
// A config reload changes it in place (Reconfigure), so the eD2K runtime, the Meta
// API and the admin page keep the one pointer they were given at start. Everything a
// reload can change sits behind state, and a search loads it once.
type Searcher struct {
	state atomic.Pointer[searcherState]

	// mu serialises Start, its stop function and Reconfigure, and guards the fields
	// below it.
	mu        sync.Mutex
	cfg       config.MetaSearchConfig
	clientFor func(network string, c config.MetaNetworkConfig) metav1connect.MetaIngestClient
	// runCtx is the context Start runs the sources on, nil before Start and after its
	// stop, so a source a reload adds is started only while the searcher runs.
	runCtx context.Context
	// nextGen numbers the sources built, so a cache key never mixes a network's
	// answers from before and after its daemon changed.
	nextGen uint64

	// infoInterval is how often each daemon's GetInfo is polled.
	infoInterval time.Duration
	// catalog caches MetaApi.Search chunks; nil until EnableCatalog.
	catalog        *Cache[Chunk]
	catalogTimeout time.Duration
}

// searcherState is what a reload replaces as a whole.
type searcherState struct {
	sources []*source
	cache   *Cache[[]storage.File]
	// udpSlots bounds live calls made for UDP searches; see config.udpMaxConcurrent.
	udpSlots chan struct{}
	// torrentPrefix is the torrent network's name prefix, which a BitTorrent row
	// carries whichever daemon sent it.
	torrentPrefix string
}

// source is one network: its daemon client, its feed and its limits. The client,
// the feed and the counters are fixed for the source's life; a reload that changes
// how the daemon is reached builds a new source, and one that changes only a limit
// swaps settings.
type source struct {
	network string
	// native marks a network whose rows are real eD2K files (Kad) rather than
	// pseudo-hash rows: every client gets them in an eD2K search, whether or not it
	// reads meta tags. MetaApi.Search serves them like any other network's.
	native bool
	// mixed marks a network whose rows are of several kinds (web): its native
	// rows go to every client like Kad's, and the rest only to a client that asked
	// for meta rows.
	mixed  bool
	url    string
	gen    uint64
	conn   connKey
	client metav1connect.MetaIngestClient
	feed   *Feed

	settings atomic.Pointer[sourceSettings]
	// stop halts the poller and the feed that start began; guarded by Searcher.mu.
	stop func()

	// downUntil is a unix-nano deadline before which live calls are skipped.
	downUntil atomic.Int64
	// liveOK is the unix-nano time the daemon last answered a Search, 0 for never.
	liveOK atomic.Int64

	counters sourceCounters
	daemon   daemonInfo
}

// sourceSettings are the limits of one network that a reload applies in place.
type sourceSettings struct {
	prefix        string
	countInStatus bool
	live          bool
	onlyAvailable bool
	timeout       time.Duration
	udpTimeout    time.Duration
	maxResults    int
	maxUDPResults int
	cache         *Cache[[]storage.File]
}

// connKey is what reaches a network's daemon. A source is kept across a reload only
// while it is unchanged.
type connKey struct {
	url   string
	token string
	feed  config.MetaFeedConfig
}

// New builds a searcher for every enabled network in cfg, connecting to each daemon
// over HTTP. Nothing is contacted until Start or the first Search.
func New(cfg config.MetaSearchConfig) *Searcher {
	return NewWithClients(cfg, func(network string, c config.MetaNetworkConfig) metav1connect.MetaIngestClient {
		return NewClient(c.URL, c.Token)
	})
}

// NewWithClients is New with the daemon clients supplied by the caller, which is how
// tests put an in-process daemon behind a searcher.
func NewWithClients(cfg config.MetaSearchConfig, clientFor func(network string, c config.MetaNetworkConfig) metav1connect.MetaIngestClient) *Searcher {
	s := &Searcher{clientFor: clientFor, infoInterval: defaultInfoInterval}
	state, _, _ := s.buildState(cfg, nil)
	s.cfg = cfg
	s.state.Store(state)
	return s
}

// Start opens every configured feed subscription and starts polling each daemon's
// GetInfo for the dashboard and the status file count. The returned function stops
// them and waits for their goroutines to finish.
func (s *Searcher) Start(ctx context.Context) (stop func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	s.runCtx = ctx
	for _, src := range s.state.Load().sources {
		src.start(ctx, s.infoInterval)
	}
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		cancel()
		for _, src := range s.state.Load().sources {
			src.halt()
		}
		s.runCtx = nil
	}
}

// Reconfigure applies a reloaded metaSearch section. A network whose daemon address,
// token and feed settings are unchanged keeps its client, feed and counters and takes
// the new limits; one that changed is rebuilt, a disabled one is stopped and a newly
// enabled one is started. A search already running finishes on the old state.
func (s *Searcher) Reconfigure(cfg config.MetaSearchConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, added, removed := s.buildState(cfg, s.state.Load())
	s.cfg = cfg
	s.state.Store(next)
	for _, src := range removed {
		src.halt()
	}
	if s.runCtx != nil {
		for _, src := range added {
			src.start(s.runCtx, s.infoInterval)
		}
	}
}

// Networks lists the enabled networks, for the startup log.
func (s *Searcher) Networks() []string {
	sources := s.sources()
	out := make([]string, 0, len(sources))
	for _, src := range sources {
		out = append(out, src.network)
	}
	return out
}

// ErrNetworkDisabled is FetchMetaFile's answer for a network that is not enabled.
var ErrNetworkDisabled = errors.New("meta: network not enabled")

// FetchMetaFile asks the network's daemon for the .torrent or .nzb of one release,
// by the catalog_id its rows carry. The caller bounds the call with ctx and checks
// the bytes against the row's meta hash; the daemon's own identity check is not
// asked for, since the server does not keep identities.
func (s *Searcher) FetchMetaFile(ctx context.Context, network, catalogID string) (*metav1.MetaFile, error) {
	for _, src := range s.sources() {
		if src.network == network {
			return src.client.FetchMetaFile(ctx, &metav1.FetchMetaFileRequest{CatalogId: catalogID})
		}
	}
	return nil, ErrNetworkDisabled
}

// HoldingNetwork is the network whose feed holds catalogID, "" when none does.
// The metafile fetcher asks it first for a kind two networks serve.
func (s *Searcher) HoldingNetwork(catalogID string) string {
	for _, src := range s.sources() {
		if src.feed != nil && src.feed.Holds(catalogID) {
			return src.network
		}
	}
	return ""
}

// Search returns the meta rows for one eD2K search, every network queried in
// parallel. Each network contributes its feed matches first, then — when the feed
// did not fill its quota — live Search results obtained within that network's
// deadline. A slow or unreachable daemon costs at most its deadline and contributes
// nothing; it never fails the search.
//
// udp selects the UDP limits: a shorter deadline, a smaller row cap, and a live call
// only while a udpMaxConcurrent slot is free.
//
// nativeOnly asks for native rows alone, for a requester that cannot act on a
// torrent, Usenet or web row: the Kad network's, and the eD2K files a web page
// offered. The torrent and Usenet daemons are then not called at all.
//
// A web row of a release another network sent too — the same catalog_id, which for a
// torrent is its info hash — is dropped: torrent-crawler's and Kad's rows know
// their sources, a web page's do not. An eD2K file both send is left to
// mergeMetaResults, which keeps the first by hash, and Kad answers first.
func (s *Searcher) Search(ctx context.Context, expr *storage.SearchExpr, udp, nativeOnly bool) []storage.File {
	st := s.state.Load()
	if expr == nil || len(st.sources) == 0 {
		return nil
	}
	q, hasTerms := BuildQuery(expr)

	results := make([][]storage.File, len(st.sources))
	settings := make([]*sourceSettings, len(st.sources))
	var wg sync.WaitGroup
	for i, src := range st.sources {
		settings[i] = src.settings.Load()
		if nativeOnly && !src.native && !src.mixed {
			continue
		}
		wg.Add(1)
		go func(i int, src *source) {
			defer wg.Done()
			results[i] = src.search(ctx, expr, q, hasTerms, udp, st.udpSlots, settings[i])
		}(i, src)
	}
	wg.Wait()

	sent := map[string]struct{}{}
	for i, rows := range results {
		if st.sources[i].mixed {
			continue
		}
		for _, row := range rows {
			if row.Meta != nil {
				sent[row.Meta.CatalogID] = struct{}{}
			}
		}
	}

	var out []storage.File
	for i, rows := range results {
		src := st.sources[i]
		served := 0
		for _, row := range rows {
			if src.mixed {
				if nativeOnly && !row.Meta.Native() {
					continue
				}
				if _, dup := sent[row.Meta.CatalogID]; dup {
					continue
				}
			}
			row.Name = st.prefixFor(src, settings[i], row) + row.Name
			if src.network == NetworkWeb && row.Meta.Native() {
				// a copy: the cache shares Meta
				m := *row.Meta
				m.Network = storage.MetaNetworkWeb
				row.Meta = &m
			}
			out = append(out, row)
			served++
		}
		src.counters.rowsServed.Add(uint64(served))
	}
	return out
}

// sources are the enabled networks as of now.
func (s *Searcher) sources() []*source {
	return s.state.Load().sources
}

// buildState is the state cfg asks for. old is the state in effect, nil at
// construction: a source whose connection cfg leaves unchanged is taken from it with
// new settings. added are the sources built, removed the ones of old not kept.
// Called with s.mu held, or before s is shared; s.cfg is still the old config.
func (s *Searcher) buildState(cfg config.MetaSearchConfig, old *searcherState) (state *searcherState, added, removed []*source) {
	state = &searcherState{torrentPrefix: cfg.Torrent.NamePrefixOrDefault(config.DefaultTorrentNamePrefix)}
	switch {
	case old != nil && cfg.Cache == s.cfg.Cache:
		state.cache = old.cache
	case cfg.Cache.Enabled:
		state.cache = NewCache(cfg.Cache.MaxEntries, cfg.Cache.MaxRowsPerEntry, time.Duration(cfg.Cache.TTLSeconds)*time.Second)
	}
	if old != nil && cfg.UDPMaxConcurrent == s.cfg.UDPMaxConcurrent {
		state.udpSlots = old.udpSlots
	} else {
		state.udpSlots = make(chan struct{}, max(cfg.UDPMaxConcurrent, 1))
	}

	previous := map[string]*source{}
	if old != nil {
		for _, src := range old.sources {
			previous[src.network] = src
		}
	}
	for _, n := range []struct {
		name   string
		cfg    config.MetaNetworkConfig
		prefix string
		native bool
	}{
		// Answer order: Kad rows are real eD2K files, so they come before the
		// pseudo-hash rows and are the last meta rows a result ceiling cuts.
		{NetworkKad, cfg.Kad, config.DefaultKadNamePrefix, true},
		{NetworkTorrent, cfg.Torrent, config.DefaultTorrentNamePrefix, false},
		{NetworkUsenet, cfg.Usenet, config.DefaultUsenetNamePrefix, false},
		{NetworkWeb, cfg.Web, config.DefaultWebNamePrefix, false},
	} {
		if !n.cfg.Enabled {
			continue
		}
		conn := connKey{url: n.cfg.URL, token: n.cfg.Token, feed: n.cfg.Feed}
		src, kept := previous[n.name]
		if kept && src.conn == conn {
			delete(previous, n.name)
		} else {
			s.nextGen++
			src = &source{
				network: n.name,
				native:  n.native,
				mixed:   n.name == NetworkWeb,
				url:     n.cfg.URL,
				gen:     s.nextGen,
				conn:    conn,
				client:  s.clientFor(n.name, n.cfg),
			}
			if n.cfg.Feed.Enabled {
				src.feed = NewFeed(n.name, src.client, n.cfg.Feed.MaxRows,
					time.Duration(n.cfg.Feed.ReconnectMinSeconds)*time.Second,
					time.Duration(n.cfg.Feed.ReconnectMaxSeconds)*time.Second)
			}
			added = append(added, src)
		}
		src.settings.Store(&sourceSettings{
			prefix:        n.cfg.NamePrefixOrDefault(n.prefix),
			countInStatus: n.cfg.CountInServerStatus,
			live:          n.cfg.LiveSearchOrDefault(),
			onlyAvailable: n.cfg.OnlyAvailable,
			timeout:       time.Duration(n.cfg.SearchTimeoutMs) * time.Millisecond,
			udpTimeout:    time.Duration(n.cfg.UDPSearchTimeoutMs) * time.Millisecond,
			maxResults:    n.cfg.MaxResults,
			maxUDPResults: n.cfg.MaxUDPResults,
			cache:         state.cache,
		})
		state.sources = append(state.sources, src)
	}
	for _, src := range previous {
		removed = append(removed, src)
	}
	return state, added, removed
}

// prefixFor is the name prefix of one row: its network's, except for a torrent
// of a mixed network (web), which is prefixed as a torrent. An eD2K file a web
// page offered keeps the web prefix, as every network prefixes its rows.
func (st *searcherState) prefixFor(src *source, set *sourceSettings, row storage.File) string {
	if !src.mixed || row.Meta == nil {
		return set.prefix
	}
	switch metahash.Kind(row.Meta.Kind) {
	case metahash.KindBTV1, metahash.KindBTV2:
		return st.torrentPrefix
	default:
		return set.prefix
	}
}

// start runs the source's GetInfo poller and its feed until halt or until parent
// ends.
func (src *source) start(parent context.Context, interval time.Duration) {
	ctx, cancel := context.WithCancel(parent)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		src.pollInfo(ctx, interval)
	}()
	if src.feed != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			src.feed.Run(ctx)
		}()
	}
	src.stop = func() {
		cancel()
		wg.Wait()
	}
}

// halt stops what start began and waits for it. Safe on a source never started.
func (src *source) halt() {
	if src.stop != nil {
		src.stop()
		src.stop = nil
	}
}

func (src *source) search(ctx context.Context, expr *storage.SearchExpr, q Query, hasTerms, udp bool, udpSlots chan struct{}, set *sourceSettings) []storage.File {
	limit, timeout := set.maxResults, set.timeout
	if udp {
		limit, timeout = set.maxUDPResults, set.udpTimeout
		src.counters.searchesUDP.Add(1)
	} else {
		src.counters.searchesTCP.Add(1)
	}

	var out []storage.File
	seen := map[string]struct{}{}
	add := func(rows []storage.File, filter bool) {
		if filter {
			rows = matchReleases(expr, rows)
		}
		for _, row := range rows {
			if len(out) >= limit {
				return
			}
			if set.onlyAvailable && !available(src.network, row) {
				continue
			}
			if _, dup := seen[string(row.Hash)]; dup {
				continue
			}
			seen[string(row.Hash)] = struct{}{}
			out = append(out, row)
		}
	}

	if src.feed != nil {
		// The feed's match is asked for more than limit when rows may be dropped as
		// unavailable, so a feed full of dead rows does not crowd out live ones.
		want := limit
		if set.onlyAvailable {
			want = limit * 4
		}
		add(src.feed.Match(expr, q.Terms, want), false)
	}
	if len(out) >= limit || !set.live || !hasTerms || src.isDown() {
		return out
	}
	if udp {
		select {
		case udpSlots <- struct{}{}:
			defer func() { <-udpSlots }()
		default:
			src.counters.udpSkipped.Add(1)
			logging.Debugf("meta search %s: udp live slots exhausted, answering from feed/cache only", src.network)
			if set.cache != nil {
				add(src.cachedOnly(q, set), true)
			}
			return out
		}
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rows, err := src.fetch(ctx, q, set)
	if err != nil {
		if isTimeout(err) {
			src.counters.liveTimeouts.Add(1)
		} else {
			src.counters.liveErrors.Add(1)
		}
		src.noteError(err)
	}
	add(rows, true)
	return out
}

// fetch runs the live Search, through the cache when one is configured. The request
// always asks for maxResults releases, TCP and UDP alike, so both share one cache
// entry per query.
func (src *source) fetch(ctx context.Context, q Query, set *sourceSettings) ([]storage.File, error) {
	loaded := false
	load := func() ([]storage.File, error) {
		loaded = true
		src.counters.liveCalls.Add(1)
		resp, err := src.client.Search(ctx, src.request(q, set))
		if err != nil {
			return nil, err
		}
		src.noteLiveOK()
		rows := make([]storage.File, 0, len(resp.GetEntries()))
		for _, entry := range resp.GetEntries() {
			file, err := EntryToFile(entry)
			if err != nil {
				logging.Debugf("meta search %s: dropped row %q: %v", src.network, entry.GetCatalogId(), err)
				continue
			}
			rows = append(rows, file)
		}
		NameSubFiles(rows)
		return rows, nil
	}
	if set.cache == nil {
		return load()
	}
	rows, err := set.cache.Get(ctx, src.cacheKey(q, set), load)
	// A caller that shared another caller's in-flight load was answered without a
	// call of its own, so it counts as a hit like a stored entry does.
	switch {
	case loaded:
		src.counters.cacheMisses.Add(1)
	case err == nil:
		src.counters.cacheHits.Add(1)
	}
	return rows, err
}

// request is the live Search for q: the query's own constraints, plus the
// availability filter the network's onlyAvailable asks for — complete releases for
// Usenet, alive ones for every other network.
func (src *source) request(q Query, set *sourceSettings) *metav1.SearchRequest {
	req := q.Request(set.maxResults)
	if set.onlyAvailable {
		if src.network == NetworkUsenet {
			req.MinCompletion = fullCompletion
		} else {
			req.Alive = true
		}
	}
	return req
}

// cachedOnly returns a cache hit without ever calling the daemon.
func (src *source) cachedOnly(q Query, set *sourceSettings) []storage.File {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // a waiter on an in-flight load returns at once
	rows, err := set.cache.Get(ctx, src.cacheKey(q, set), func() ([]storage.File, error) {
		return nil, errNotCached
	})
	if err == nil {
		src.counters.cacheHits.Add(1)
	}
	return rows
}

// cacheKey names one live Search: the network's source (so a daemon a reload
// replaced never answers from its predecessor's entries), the parts of the request
// a reload can change, and the query.
func (src *source) cacheKey(q Query, set *sourceSettings) string {
	return src.network + "\x00" + strconv.FormatUint(src.gen, 10) + "\x00" +
		strconv.FormatBool(set.onlyAvailable) + "\x00" + strconv.Itoa(set.maxResults) + "\x00" + q.Key()
}

var errNotCached = errors.New("not cached")

func (src *source) isDown() bool {
	return time.Now().UnixNano() < src.downUntil.Load()
}

// noteLiveOK records that the daemon just answered a Search.
func (src *source) noteLiveOK() {
	src.liveOK.Store(time.Now().UnixNano())
}

// noteError logs a failed live call and, for an answer that will not change on the
// next search, skips the daemon for downBackoff.
func (src *source) noteError(err error) {
	if isTimeout(err) {
		logging.Debugf("meta search %s: no answer within the deadline", src.network)
		return
	}
	switch connect.CodeOf(err) {
	case connect.CodeUnavailable, connect.CodeUnimplemented, connect.CodeUnauthenticated:
		if !src.isDown() {
			logging.Warnf("meta search %s: %v; live search paused for %s", src.network, err, downBackoff)
		}
		src.downUntil.Store(time.Now().Add(downBackoff).UnixNano())
	default:
		logging.Warnf("meta search %s: %v", src.network, err)
	}
}

// isTimeout reports whether a live call ended at its deadline rather than failing.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, errNotCached) {
		return true
	}
	switch connect.CodeOf(err) {
	case connect.CodeDeadlineExceeded, connect.CodeCanceled:
		return true
	}
	return false
}

// matchReleases keeps the rows of a daemon answer that match expr, release by
// release in the daemon's ranking order; see matchRelease.
func matchReleases(expr *storage.SearchExpr, rows []storage.File) []storage.File {
	var order []string
	groups := map[string][]storage.File{}
	for _, row := range rows {
		id := row.Meta.CatalogID
		if _, ok := groups[id]; !ok {
			order = append(order, id)
		}
		groups[id] = append(groups[id], row)
	}
	var out []storage.File
	for _, id := range order {
		out = append(out, matchRelease(expr, groups[id])...)
	}
	return out
}

// matchRelease keeps the rows of one release that match expr. When the whole-set
// row matches, it alone stands for the release, so that a season pack found by its
// own name does not fill the answer with every episode. Otherwise the file rows are
// matched by their "Release - path" names (NameSubFiles), which is what makes a
// file found through its path or a term of the release's name show up.
func matchRelease(expr *storage.SearchExpr, rows []storage.File) []storage.File {
	for _, row := range rows {
		if isWholeSet(row) && storage.MatchSearchExpr(expr, row) {
			return []storage.File{row}
		}
	}
	var out []storage.File
	for _, row := range rows {
		if !isWholeSet(row) && storage.MatchSearchExpr(expr, row) {
			out = append(out, row)
		}
	}
	return out
}
