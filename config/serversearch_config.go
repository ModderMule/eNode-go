package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Server search modes: who may call the service.
const (
	// ServerSearchModeAllowlist admits only the servers listed under peers, each
	// by its token.
	ServerSearchModeAllowlist = "allowlist"
	// ServerSearchModeGossip also admits any server the gossip peer table has
	// verified, without a token, and advertises the service to them.
	ServerSearchModeGossip = "gossip"
)

// ServerSearchConfig is the server-to-server search service: other eD2K servers
// search and browse this server's own file catalogue, and this server theirs.
// Off unless Enabled. No client is identified to another server: an answer
// carries files and counts, never a source. See docs/server-search.md.
type ServerSearchConfig struct {
	Enabled bool `yaml:"enabled"`
	// Mode is ServerSearchModeAllowlist (the default) or ServerSearchModeGossip.
	Mode string `yaml:"mode"`
	// Listen is the service's own listener.
	Listen string `yaml:"listen"`
	// AdvertiseURL is the base URL other servers reach the listener on. Empty
	// derives it from the advertised address and the listener's port. Only sent
	// in gossip mode.
	AdvertiseURL string `yaml:"advertiseURL"`
	// AllowInsecureAuth lets tokens cross an unencrypted connection, for a
	// listener behind a TLS proxy and for peers on a private network.
	AllowInsecureAuth bool `yaml:"allowInsecureAuth"`
	// TrustForwardedFor takes the caller's address from X-Forwarded-For. Only
	// behind a proxy that sets it: gossip mode admits a caller by its address.
	TrustForwardedFor bool                   `yaml:"trustForwardedFor"`
	TLS               ServerSearchTLSConfig  `yaml:"tls"`
	Serve             ServerSearchServe      `yaml:"serve"`
	Peers             []ServerSearchPeer     `yaml:"peers"`
	Search            ServerSearchLiveConfig `yaml:"search"`
	Mirror            ServerSearchMirror     `yaml:"mirror"`
}

// ServerSearchTLSConfig serves the listener over TLS. In gossip mode the
// certificate's fingerprint is advertised, so a self-signed one is enough.
type ServerSearchTLSConfig struct {
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

// ServerSearchServe is what this server answers for other servers.
type ServerSearchServe struct {
	// Search and Browse are *bool, defaulting on: enabling the service serves both.
	Search *bool `yaml:"search"`
	Browse *bool `yaml:"browse"`
	// MaxSearchLimit and MaxBrowseLimit cap the files in one answer.
	MaxSearchLimit int `yaml:"maxSearchLimit"`
	MaxBrowseLimit int `yaml:"maxBrowseLimit"`
	// BrowseMinIntervalSeconds is the pause asked of a server between two
	// browse calls. 0 asks for none.
	BrowseMinIntervalSeconds int `yaml:"browseMinIntervalSeconds"`
	// Cache holds search answers so that paging one is stable.
	Cache     MetaAPISearchCacheConfig    `yaml:"cache"`
	RateLimit ServerSearchRateLimitConfig `yaml:"rateLimit"`
}

// ServerSearchRateLimitConfig caps calls per minute; 0 disables a limit. PerIP
// counts every caller by address before it is identified, PerPeer an admitted
// server.
type ServerSearchRateLimitConfig struct {
	PerIPPerMinute   int `yaml:"perIPPerMinute"`
	PerPeerPerMinute int `yaml:"perPeerPerMinute"`
}

// ServerSearchPeer is one server this one exchanges searches with. The token is
// shared by both operators and serves both directions: it is sent to URL, and a
// caller presenting it is this peer.
type ServerSearchPeer struct {
	// URL is the peer's service base URL. Empty lists a peer that may call but
	// is never called.
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
	// Fingerprint pins the peer's certificate, "sha256/<base64>" of its SPKI,
	// for a peer without a certificate a CA signed.
	Fingerprint string `yaml:"fingerprint"`
}

// ServerSearchLiveConfig asks the peers on a client's search and adds their
// files to the answer.
type ServerSearchLiveConfig struct {
	Enabled bool `yaml:"enabled"`
	// TimeoutMs bounds one peer's answer; a slower peer is left out.
	TimeoutMs int `yaml:"timeoutMs"`
	// MaxResults caps the files taken from one peer for one search.
	MaxResults int                      `yaml:"maxResults"`
	Cache      MetaAPISearchCacheConfig `yaml:"cache"`
}

// ServerSearchMirror keeps a copy of each peer's catalogue in memory by browsing
// it, so that a search is answered without calling the peer.
type ServerSearchMirror struct {
	Enabled bool `yaml:"enabled"`
	// IntervalMinutes is the pause between two walks of one peer.
	IntervalMinutes int `yaml:"intervalMinutes"`
	// MaxFiles caps the mirror across all peers.
	MaxFiles int `yaml:"maxFiles"`
	// PageSize is the files asked for per browse call.
	PageSize int `yaml:"pageSize"`
	// StaleHours drops a peer's files when no walk of it completed for this long.
	StaleHours int `yaml:"staleHours"`
}

// ServeSearch reports whether other servers may search, defaulting to true.
func (c ServerSearchConfig) ServeSearch() bool { return boolOrDefault(c.Serve.Search, true) }

// ServeBrowse reports whether other servers may browse, defaulting to true.
func (c ServerSearchConfig) ServeBrowse() bool { return boolOrDefault(c.Serve.Browse, true) }

// TLSEnabled reports whether the listener serves TLS.
func (c ServerSearchConfig) TLSEnabled() bool { return c.TLS.CertFile != "" && c.TLS.KeyFile != "" }

// GossipMode reports whether gossip-verified servers are admitted and told
// where the service is.
func (c ServerSearchConfig) GossipMode() bool { return c.Mode == ServerSearchModeGossip }

// Consumes reports whether this server calls its peers at all.
func (c ServerSearchConfig) Consumes() bool {
	return c.Enabled && (c.Search.Enabled || c.Mirror.Enabled)
}

// ApplyServerSearchDefaults returns c with the defaults Load would fill in, or the
// error Load would report. For callers that build the section without a file.
func ApplyServerSearchDefaults(c ServerSearchConfig, gossipEnabled bool) (ServerSearchConfig, error) {
	err := setServerSearchDefaults(&c, gossipEnabled)
	return c, err
}

// DefaultServerSearchListen is the service's default listener.
const DefaultServerSearchListen = "0.0.0.0:4673"

// Server search limits. maxServerBrowseLimit keeps a page well under a megabyte.
const (
	maxServerSearchLimit = 1000
	maxServerBrowseLimit = 2000
)

func setServerSearchDefaults(c *ServerSearchConfig, gossipEnabled bool) error {
	if c.Mode == "" {
		c.Mode = ServerSearchModeAllowlist
	}
	if c.Listen == "" {
		c.Listen = DefaultServerSearchListen
	}
	s := &c.Serve
	if s.MaxSearchLimit <= 0 {
		s.MaxSearchLimit = 200
	}
	if s.MaxBrowseLimit <= 0 {
		s.MaxBrowseLimit = 1000
	}
	if s.Cache.MaxEntries <= 0 {
		s.Cache.MaxEntries = 500
	}
	if s.Cache.TTLSeconds <= 0 {
		s.Cache.TTLSeconds = 300
	}
	if c.Search.TimeoutMs <= 0 {
		c.Search.TimeoutMs = 1500
	}
	if c.Search.MaxResults <= 0 {
		c.Search.MaxResults = 50
	}
	if c.Search.Cache.MaxEntries <= 0 {
		c.Search.Cache.MaxEntries = 1000
	}
	if c.Search.Cache.TTLSeconds <= 0 {
		c.Search.Cache.TTLSeconds = 300
	}
	m := &c.Mirror
	if m.IntervalMinutes <= 0 {
		m.IntervalMinutes = 60
	}
	if m.MaxFiles <= 0 {
		m.MaxFiles = 500000
	}
	if m.PageSize <= 0 {
		m.PageSize = 1000
	}
	if m.StaleHours <= 0 {
		m.StaleHours = 24
	}
	switch {
	case s.RateLimit.PerIPPerMinute < 0 || s.RateLimit.PerPeerPerMinute < 0:
		return fmt.Errorf("serverSearch.serve.rateLimit values must not be negative; 0 disables a limit")
	case s.BrowseMinIntervalSeconds < 0:
		return fmt.Errorf("serverSearch.serve.browseMinIntervalSeconds must not be negative")
	case s.MaxSearchLimit > maxServerSearchLimit:
		return fmt.Errorf("serverSearch.serve.maxSearchLimit (%d) exceeds %d", s.MaxSearchLimit, maxServerSearchLimit)
	case s.MaxBrowseLimit > maxServerBrowseLimit:
		return fmt.Errorf("serverSearch.serve.maxBrowseLimit (%d) exceeds %d", s.MaxBrowseLimit, maxServerBrowseLimit)
	case c.Search.MaxResults > maxMetaResults:
		return fmt.Errorf("serverSearch.search.maxResults (%d) exceeds %d", c.Search.MaxResults, maxMetaResults)
	case m.PageSize > maxServerBrowseLimit:
		return fmt.Errorf("serverSearch.mirror.pageSize (%d) exceeds %d", m.PageSize, maxServerBrowseLimit)
	}
	if !c.Enabled {
		return nil
	}
	if c.Mode != ServerSearchModeAllowlist && c.Mode != ServerSearchModeGossip {
		return fmt.Errorf("serverSearch.mode %q is invalid: use %q or %q", c.Mode, ServerSearchModeAllowlist, ServerSearchModeGossip)
	}
	if c.GossipMode() && !gossipEnabled {
		return fmt.Errorf("serverSearch.mode %q needs gossip.enabled: it admits the servers gossip has verified", ServerSearchModeGossip)
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("serverSearch.listen %q is invalid: use host:port: %w", c.Listen, err)
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return fmt.Errorf("serverSearch.tls needs both certFile and keyFile, or neither")
	}
	if c.AdvertiseURL != "" && !isHTTPURL(c.AdvertiseURL) {
		return fmt.Errorf("serverSearch.advertiseURL %q is invalid: use http(s)://host[:port]", c.AdvertiseURL)
	}
	c.AdvertiseURL = strings.TrimRight(c.AdvertiseURL, "/")
	return validateServerSearchPeers(c, isLoopbackHost(host))
}

// validateServerSearchPeers checks the peer list, and that no token would cross
// the network in clear text in either direction.
func validateServerSearchPeers(c *ServerSearchConfig, loopbackListener bool) error {
	tokens := map[string]int{}
	for i := range c.Peers {
		p := &c.Peers[i]
		key := fmt.Sprintf("serverSearch.peers[%d]", i)
		p.URL = strings.TrimRight(strings.TrimSpace(p.URL), "/")
		p.Token = strings.TrimSpace(p.Token)
		p.Fingerprint = strings.TrimSpace(p.Fingerprint)
		if p.URL == "" && p.Token == "" {
			return fmt.Errorf("%s needs a url, a token, or both", key)
		}
		if p.Token == "" && !c.GossipMode() {
			return fmt.Errorf("%s has no token: mode %q admits and calls a peer by its token", key, ServerSearchModeAllowlist)
		}
		if p.Fingerprint != "" && !strings.HasPrefix(p.Fingerprint, "sha256/") {
			return fmt.Errorf("%s.fingerprint %q is invalid: use sha256/<base64>, as the peer's log prints it", key, p.Fingerprint)
		}
		if p.Token != "" {
			if other, dup := tokens[p.Token]; dup {
				return fmt.Errorf("%s shares its token with serverSearch.peers[%d]: a token says which peer is calling", key, other)
			}
			tokens[p.Token] = i
		}
		if p.URL == "" {
			continue
		}
		u, err := url.Parse(p.URL)
		if err != nil || !isHTTPURL(p.URL) {
			return fmt.Errorf("%s.url %q is invalid: use http(s)://host[:port]", key, p.URL)
		}
		if p.Fingerprint != "" && u.Scheme != "https" {
			return fmt.Errorf("%s.fingerprint pins a certificate, but its url is not https", key)
		}
		if p.Token != "" && u.Scheme != "https" && !isLoopbackHost(u.Hostname()) && !c.AllowInsecureAuth {
			return fmt.Errorf("%s would send its token to %s in clear text: use https, or allowInsecureAuth: true on a private network", key, p.URL)
		}
	}
	if len(tokens) > 0 && !c.TLSEnabled() && !loopbackListener && !c.AllowInsecureAuth {
		return fmt.Errorf("serverSearch needs serverSearch.tls, or allowInsecureAuth: true when a TLS proxy terminates in front: peers' tokens would otherwise reach %s in clear text", c.Listen)
	}
	return nil
}

// isLoopbackHost reports whether host is the loopback interface.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
