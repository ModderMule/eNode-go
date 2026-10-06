package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"enode/admin"
	"enode/config"
	"enode/ed2k"
	"enode/logging"
	"enode/meta"
	"enode/netfilter"
	"enode/serverlink"
	"enode/storage"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
)

// serverSearchRuntime is the server-to-server search service: the listener other
// servers call, and the searcher that calls them. It is built before the eD2K
// runtime, so the gossip description reply can advertise it, and attached to the
// runtime once that exists. See docs/server-search.md.
type serverSearchRuntime struct {
	cfg      config.ServerSearchConfig
	server   *serverlink.Server
	svc      *serverlink.Service
	searcher *serverlink.Searcher
	advert   ed2k.ServerSearchAdvert
	url      string

	// runtime and filter arrive after the service is built; until then nobody is a
	// verified server and nothing is blocked. The listener only starts afterwards.
	runtime atomic.Pointer[ed2k.ServerRuntime]
	filter  atomic.Pointer[netfilter.Filter]
}

// buildServerSearch builds the service when serverSearch.enabled is on, or returns nil.
func buildServerSearch(cfg config.Config, engine storage.Engine, advertisedIP string) (*serverSearchRuntime, error) {
	c := cfg.ServerSearch
	if !c.Enabled {
		return nil, nil
	}
	rt := &serverSearchRuntime{cfg: c}

	var tokens []string
	var peers []serverlink.ClientConfig
	for _, p := range c.Peers {
		if p.Token != "" {
			tokens = append(tokens, p.Token)
		}
		if p.URL != "" {
			peers = append(peers, serverlink.ClientConfig{URL: p.URL, Token: p.Token, Fingerprint: p.Fingerprint})
		}
	}

	svcCfg := serverlink.ServiceConfig{
		Name: func() string {
			if runtime := rt.runtime.Load(); runtime != nil {
				return runtime.PublicStatus().Name
			}
			return cfg.Name
		},
		Search:            c.ServeSearch(),
		Browse:            c.ServeBrowse(),
		MaxSearchLimit:    c.Serve.MaxSearchLimit,
		MaxBrowseLimit:    c.Serve.MaxBrowseLimit,
		BrowseMinInterval: time.Duration(c.Serve.BrowseMinIntervalSeconds) * time.Second,
		CacheEntries:      c.Serve.Cache.MaxEntries,
		CacheTTL:          time.Duration(c.Serve.Cache.TTLSeconds) * time.Second,
		PerIPPerMinute:    c.Serve.RateLimit.PerIPPerMinute,
		PerPeerPerMinute:  c.Serve.RateLimit.PerPeerPerMinute,
		TrustForwardedFor: c.TrustForwardedFor,
		Tokens:            tokens,
		Blocked: func(ip net.IP) bool {
			blocked, _ := rt.filter.Load().Blocked(ip)
			return blocked
		},
	}
	if c.GossipMode() {
		svcCfg.Verified = func(ip net.IP) bool {
			runtime := rt.runtime.Load()
			return runtime != nil && runtime.IsGossipServer(ip)
		}
	}
	rt.svc = serverlink.NewService(svcCfg, engine)

	server, err := serverlink.NewServer(serverlink.ServerConfig{
		Listen: c.Listen, CertFile: c.TLS.CertFile, KeyFile: c.TLS.KeyFile,
	}, rt.svc)
	if err != nil {
		return nil, err
	}
	rt.server = server
	rt.url = metaAPIURL(c.AdvertiseURL, c.Listen, c.TLSEnabled(), advertisedIP)
	if c.GossipMode() {
		if rt.url == "" {
			logging.Warnf("server search: no advertised server IP and no serverSearch.advertiseURL, so other servers are not told where the service is")
		} else {
			rt.advert = ed2k.ServerSearchAdvert{URL: rt.url, Fingerprint: server.Fingerprint()}
		}
	}

	if c.Consumes() {
		searchCfg := serverlink.SearcherConfig{
			Peers:        peers,
			Live:         c.Search.Enabled,
			Timeout:      time.Duration(c.Search.TimeoutMs) * time.Millisecond,
			MaxResults:   c.Search.MaxResults,
			CacheEntries: c.Search.Cache.MaxEntries,
			CacheTTL:     time.Duration(c.Search.Cache.TTLSeconds) * time.Second,
			Mirror:       c.Mirror.Enabled,
			Interval:     time.Duration(c.Mirror.IntervalMinutes) * time.Minute,
			MaxFiles:     c.Mirror.MaxFiles,
			PageSize:     c.Mirror.PageSize,
			Stale:        time.Duration(c.Mirror.StaleHours) * time.Hour,
		}
		if c.GossipMode() {
			searchCfg.Discover = rt.discover
		}
		rt.searcher = serverlink.NewSearcher(searchCfg)
	}
	return rt, nil
}

// attach gives the service the eD2K runtime, which knows the gossip-verified
// servers, and the access filter. Called before start.
func (rt *serverSearchRuntime) attach(runtime *ed2k.ServerRuntime, filter *netfilter.Filter) {
	rt.runtime.Store(runtime)
	rt.filter.Store(filter)
}

// start binds the listener and starts the searcher. The returned function stops both.
func (rt *serverSearchRuntime) start(ctx context.Context) (func(), error) {
	if err := rt.server.Start(); err != nil {
		return nil, err
	}
	stopSearcher := func() {}
	if rt.searcher != nil {
		stopSearcher = rt.searcher.Start(ctx)
	}
	c := rt.cfg
	logging.Infof("server search: listening on %s mode=%s serve search=%t browse=%t; asks peers: search=%t mirror=%t (%d configured)",
		rt.server.Addr(), c.Mode, c.ServeSearch(), c.ServeBrowse(), c.Search.Enabled, c.Mirror.Enabled, len(c.Peers))
	if fp := rt.server.Fingerprint(); fp != "" {
		logging.Infof("server search: certificate fingerprint %s (give it to peers as serverSearch.peers[].fingerprint)", fp)
	}
	if rt.advert.URL != "" {
		logging.Infof("server search: advertised to other servers as %s", rt.advert.URL)
	}
	return func() {
		stopSearcher()
		rt.server.Close()
	}, nil
}

// peerSearcher is the searcher that asks the other servers. Nil-receiver safe:
// nil when the service is off or asks nobody.
func (rt *serverSearchRuntime) peerSearcher() *serverlink.Searcher {
	if rt == nil {
		return nil
	}
	return rt.searcher
}

// advertisement is the gossip view. Nil-receiver safe: zero when off.
func (rt *serverSearchRuntime) advertisement() ed2k.ServerSearchAdvert {
	if rt == nil {
		return ed2k.ServerSearchAdvert{}
	}
	return rt.advert
}

// adminStats is the dashboard's view of the service. Nil-receiver safe: nil when off.
func (rt *serverSearchRuntime) adminStats() *admin.ServerSearchStats {
	if rt == nil {
		return nil
	}
	ss := rt.svc.Stats()
	out := &admin.ServerSearchStats{
		Mode:           rt.cfg.Mode,
		URL:            rt.url,
		Fingerprint:    rt.server.Fingerprint(),
		ServeSearch:    rt.cfg.ServeSearch(),
		ServeBrowse:    rt.cfg.ServeBrowse(),
		InfoCalls:      ss.InfoCalls.Load(),
		Searches:       ss.Searches.Load(),
		Browses:        ss.Browses.Load(),
		FilesServed:    ss.FilesServed.Load(),
		Resets:         ss.Resets.Load(),
		RateLimited:    ss.RateLimited.Load(),
		AuthFailures:   ss.AuthFailures.Load(),
		LiveSearch:     rt.cfg.Search.Enabled,
		Mirror:         rt.cfg.Mirror.Enabled,
		MirrorMaxFiles: rt.cfg.Mirror.MaxFiles,
		Peers:          []admin.ServerSearchPeerStats{},
	}
	if rt.searcher == nil {
		return out
	}
	out.MirrorFiles = rt.searcher.MirrorFiles()
	for _, p := range rt.searcher.Stats() {
		mirrorAt := ""
		if !p.MirrorAt.IsZero() {
			mirrorAt = p.MirrorAt.UTC().Format(time.RFC3339)
		}
		out.Peers = append(out.Peers, admin.ServerSearchPeerStats{
			URL: p.URL, Static: p.Static, Name: p.Name, Files: p.Files, Down: p.Down, LastError: p.LastError,
			Mirrored: p.Mirrored, MirrorFiles: p.MirrorFiles, MirrorAt: mirrorAt, MirrorTrimmed: p.MirrorTrimmed,
			Walks: p.Walks, WalkErrors: p.WalkErrors, Resets: p.Resets,
			LiveCalls: p.LiveCalls, LiveErrors: p.LiveErrors, LiveTimeouts: p.LiveTimeouts, RowsServed: p.RowsServed,
		})
	}
	return out
}

// discover lists the servers gossip says offer the service. Each is dialled at
// the address gossip verified, whatever host its URL names: the URL is the peer's
// own claim, and following it elsewhere would let any server point this one at a
// third party.
func (rt *serverSearchRuntime) discover() []serverlink.ClientConfig {
	runtime := rt.runtime.Load()
	if runtime == nil {
		return nil
	}
	var out []serverlink.ClientConfig
	for _, p := range runtime.GossipSearchPeers() {
		out = append(out, serverlink.ClientConfig{
			URL:         p.ServerSearch.URL,
			Fingerprint: p.ServerSearch.Fingerprint,
			DialIP:      p.Addr.IP,
		})
	}
	return out
}

// combinedSearcher is what the eD2K runtime asks for rows beyond its own files:
// the catalogue daemons and the other servers, at once. Either may be nil.
type combinedSearcher struct {
	meta    ed2k.MetaSearcher
	servers *serverlink.Searcher
}

// newCombinedSearcher returns the searcher to attach to the runtime, or nil when
// there is neither a catalogue daemon nor a server to ask. With only one of them
// it is still the wrapper: a nil *meta.Searcher must not be attached as a non-nil
// interface.
func newCombinedSearcher(metaSearcher ed2k.MetaSearcher, servers *serverlink.Searcher) ed2k.MetaSearcher {
	if metaSearcher == nil && servers == nil {
		return nil
	}
	if servers == nil {
		return metaSearcher
	}
	return &combinedSearcher{meta: metaSearcher, servers: servers}
}

// Search asks both at once. The catalogue rows come first, as before; another
// server's files follow. Those are real eD2K files, so every client gets them,
// whether or not it asked for torrent and Usenet rows.
func (c *combinedSearcher) Search(ctx context.Context, expr *storage.SearchExpr, udp, nativeOnly bool) []storage.File {
	var wg sync.WaitGroup
	var metaRows, serverRows []storage.File
	if c.meta != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			metaRows = c.meta.Search(ctx, expr, udp, nativeOnly)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverRows = c.servers.Search(ctx, expr, udp)
	}()
	wg.Wait()
	return append(metaRows, serverRows...)
}

// AdvertisedFiles leaves other servers' files out: they are theirs to count.
func (c *combinedSearcher) AdvertisedFiles() int {
	if c.meta == nil {
		return 0
	}
	return c.meta.AdvertisedFiles()
}

func (c *combinedSearcher) NetworkUsers(network string) int {
	if c.meta == nil {
		return 0
	}
	return c.meta.NetworkUsers(network)
}

// combinedCatalog is what MetaApi.Search pages through: the catalogue daemons'
// networks and the servers network. Either half may be nil.
type combinedCatalog struct {
	meta    *meta.Searcher
	servers *serverlink.Searcher
}

// CatalogNetworks lists the networks either half answers.
func (c *combinedCatalog) CatalogNetworks() []string {
	var out []string
	if c.meta != nil {
		out = c.meta.CatalogNetworks()
	}
	if c.servers.CatalogEnabled() {
		out = append(out, serverlink.NetworkServers)
	}
	return out
}

// SearchCatalog asks whichever half has the network.
func (c *combinedCatalog) SearchCatalog(ctx context.Context, network string, req *metav1.SearchRequest, chunk int) (meta.Chunk, error) {
	if network == serverlink.NetworkServers {
		if !c.servers.CatalogEnabled() {
			return meta.Chunk{}, meta.ErrCatalogOff
		}
		return c.servers.SearchCatalog(ctx, req, chunk)
	}
	if c.meta == nil {
		return meta.Chunk{}, meta.ErrCatalogOff
	}
	return c.meta.SearchCatalog(ctx, network, req, chunk)
}

// warnServerSearch logs what an operator should know about the configuration.
func warnServerSearch(cfg config.Config) {
	c := cfg.ServerSearch
	if !c.Enabled {
		return
	}
	if c.GossipMode() && !c.TLSEnabled() {
		logging.Warnf("serverSearch.mode gossip without serverSearch.tls: the catalogue is served to any verified server in clear text")
	}
	if c.Consumes() && len(c.Peers) == 0 && !c.GossipMode() {
		logging.Warnf("serverSearch asks peers (search or mirror on) but serverSearch.peers is empty and mode is not gossip: there is nobody to ask")
	}
	if c.Mirror.Enabled {
		logging.Infof("server search: mirror on, up to %s files, walked every %d min",
			fmt.Sprint(c.Mirror.MaxFiles), c.Mirror.IntervalMinutes)
	}
}
