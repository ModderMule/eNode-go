// Package meta merges torrent and Usenet releases into eD2K search answers. The rows
// come from catalogue daemons (torrent-crawler, usenet-crawler) that serve the
// enode.meta.v1 MetaIngest service defined in github.com/ModderMule/enodemeta.
//
// Everything that depends on the contract module or on connect lives here; the ed2k
// package sees only a Search method returning storage.File rows. See
// docs/meta-search.md.
package meta

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"enode/config"
	"enode/logging"
	"enode/storage"

	"connectrpc.com/connect/v2"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
)

// Network names, as used in config keys and log lines.
const (
	NetworkTorrent = "torrent"
	NetworkUsenet  = "usenet"
)

// downBackoff is how long a daemon that answered "unavailable", "unimplemented" or
// "unauthenticated" is skipped by live searches. Those answers will not change
// between one search and the next, and without this every search would pay for them.
const downBackoff = 30 * time.Second

// Searcher answers the meta half of a search from every enabled network.
type Searcher struct {
	sources []*source
	// udpSlots bounds live calls made for UDP searches; see config.udpMaxConcurrent.
	udpSlots chan struct{}
}

// source is one network: its daemon client, its feed and its limits.
type source struct {
	network       string
	prefix        string
	client        metav1connect.MetaIngestClient
	live          bool
	timeout       time.Duration
	udpTimeout    time.Duration
	maxResults    int
	maxUDPResults int
	feed          *Feed
	cache         *Cache
	// downUntil is a unix-nano deadline before which live calls are skipped.
	downUntil atomic.Int64
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
	s := &Searcher{udpSlots: make(chan struct{}, max(cfg.UDPMaxConcurrent, 1))}
	var cache *Cache
	if cfg.Cache.Enabled {
		cache = NewCache(cfg.Cache.MaxEntries, cfg.Cache.MaxRowsPerEntry, time.Duration(cfg.Cache.TTLSeconds)*time.Second)
	}
	for _, n := range []struct {
		name   string
		cfg    config.MetaNetworkConfig
		prefix string
	}{
		{NetworkTorrent, cfg.Torrent, config.DefaultTorrentNamePrefix},
		{NetworkUsenet, cfg.Usenet, config.DefaultUsenetNamePrefix},
	} {
		if !n.cfg.Enabled {
			continue
		}
		src := &source{
			network:       n.name,
			prefix:        n.cfg.NamePrefixOrDefault(n.prefix),
			client:        clientFor(n.name, n.cfg),
			live:          n.cfg.LiveSearchOrDefault(),
			timeout:       time.Duration(n.cfg.SearchTimeoutMs) * time.Millisecond,
			udpTimeout:    time.Duration(n.cfg.UDPSearchTimeoutMs) * time.Millisecond,
			maxResults:    n.cfg.MaxResults,
			maxUDPResults: n.cfg.MaxUDPResults,
			cache:         cache,
		}
		if n.cfg.Feed.Enabled {
			src.feed = NewFeed(n.name, src.client, n.cfg.Feed.MaxRows,
				time.Duration(n.cfg.Feed.ReconnectMinSeconds)*time.Second,
				time.Duration(n.cfg.Feed.ReconnectMaxSeconds)*time.Second)
		}
		s.sources = append(s.sources, src)
	}
	return s
}

// Start opens every configured feed subscription. The returned function stops them
// and waits for their goroutines to finish.
func (s *Searcher) Start(ctx context.Context) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	for _, src := range s.sources {
		if src.feed == nil {
			continue
		}
		wg.Add(1)
		go func(f *Feed) {
			defer wg.Done()
			f.Run(ctx)
		}(src.feed)
	}
	return func() {
		cancel()
		wg.Wait()
	}
}

// Networks lists the enabled networks, for the startup log.
func (s *Searcher) Networks() []string {
	out := make([]string, 0, len(s.sources))
	for _, src := range s.sources {
		out = append(out, src.network)
	}
	return out
}

// Search returns the meta rows for one eD2K search, every network queried in
// parallel. Each network contributes its feed matches first, then — when the feed
// did not fill its quota — live Search results obtained within that network's
// deadline. A slow or unreachable daemon costs at most its deadline and contributes
// nothing; it never fails the search.
//
// udp selects the UDP limits: a shorter deadline, a smaller row cap, and a live call
// only while a udpMaxConcurrent slot is free.
func (s *Searcher) Search(ctx context.Context, expr *storage.SearchExpr, udp bool) []storage.File {
	if expr == nil || len(s.sources) == 0 {
		return nil
	}
	q, hasTerms := BuildQuery(expr)

	results := make([][]storage.File, len(s.sources))
	var wg sync.WaitGroup
	for i, src := range s.sources {
		wg.Add(1)
		go func(i int, src *source) {
			defer wg.Done()
			results[i] = src.search(ctx, expr, q, hasTerms, udp, s.udpSlots)
		}(i, src)
	}
	wg.Wait()

	var out []storage.File
	for i, rows := range results {
		prefix := s.sources[i].prefix
		for _, row := range rows {
			row.Name = prefix + row.Name
			out = append(out, row)
		}
	}
	return out
}

func (src *source) search(ctx context.Context, expr *storage.SearchExpr, q Query, hasTerms, udp bool, udpSlots chan struct{}) []storage.File {
	limit, timeout := src.maxResults, src.timeout
	if udp {
		limit, timeout = src.maxUDPResults, src.udpTimeout
	}

	var out []storage.File
	seen := map[string]struct{}{}
	add := func(rows []storage.File, filter bool) {
		for _, row := range rows {
			if len(out) >= limit {
				return
			}
			if filter && !storage.MatchSearchExpr(expr, row) {
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
		add(src.feed.Match(expr, q.Terms, limit), false)
	}
	if len(out) >= limit || !src.live || !hasTerms || src.isDown() {
		return out
	}
	if udp {
		select {
		case udpSlots <- struct{}{}:
			defer func() { <-udpSlots }()
		default:
			logging.Debugf("meta search %s: udp live slots exhausted, answering from feed/cache only", src.network)
			if src.cache != nil {
				add(src.cachedOnly(q), true)
			}
			return out
		}
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rows, err := src.fetch(ctx, q)
	if err != nil {
		src.noteError(err)
	}
	add(rows, true)
	return out
}

// fetch runs the live Search, through the cache when one is configured. The request
// always asks for maxResults releases, TCP and UDP alike, so both share one cache
// entry per query.
func (src *source) fetch(ctx context.Context, q Query) ([]storage.File, error) {
	load := func() ([]storage.File, error) {
		resp, err := src.client.Search(ctx, q.Request(src.maxResults))
		if err != nil {
			return nil, err
		}
		rows := make([]storage.File, 0, len(resp.GetEntries()))
		for _, entry := range resp.GetEntries() {
			file, err := EntryToFile(entry)
			if err != nil {
				logging.Debugf("meta search %s: dropped row %q: %v", src.network, entry.GetCatalogId(), err)
				continue
			}
			rows = append(rows, file)
		}
		return rows, nil
	}
	if src.cache == nil {
		return load()
	}
	return src.cache.Get(ctx, src.cacheKey(q), load)
}

// cachedOnly returns a cache hit without ever calling the daemon.
func (src *source) cachedOnly(q Query) []storage.File {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // a waiter on an in-flight load returns at once
	rows, _ := src.cache.Get(ctx, src.cacheKey(q), func() ([]storage.File, error) {
		return nil, errNotCached
	})
	return rows
}

func (src *source) cacheKey(q Query) string {
	return src.network + "\x00" + q.Key()
}

var errNotCached = errors.New("not cached")

func (src *source) isDown() bool {
	return time.Now().UnixNano() < src.downUntil.Load()
}

// noteError logs a failed live call and, for an answer that will not change on the
// next search, skips the daemon for downBackoff.
func (src *source) noteError(err error) {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, errNotCached) {
		logging.Debugf("meta search %s: no answer within the deadline", src.network)
		return
	}
	switch connect.CodeOf(err) {
	case connect.CodeDeadlineExceeded, connect.CodeCanceled:
		logging.Debugf("meta search %s: no answer within the deadline", src.network)
	case connect.CodeUnavailable, connect.CodeUnimplemented, connect.CodeUnauthenticated:
		if !src.isDown() {
			logging.Warnf("meta search %s: %v; live search paused for %s", src.network, err, downBackoff)
		}
		src.downUntil.Store(time.Now().Add(downBackoff).UnixNano())
	default:
		logging.Warnf("meta search %s: %v", src.network, err)
	}
}
