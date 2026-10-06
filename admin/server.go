// Package admin serves a small, self-contained HTTP status dashboard for a
// running eNode server. It depends only on the Go standard library: the page is
// rendered with html/template and the live figures are polled from a JSON
// endpoint by inline vanilla JavaScript.
//
// The package is deliberately decoupled from the ed2k and config packages — the
// caller supplies the unchanging server facts (StaticInfo) and a snapshot
// function for the live counters — so it stays a pure HTTP/render layer with no
// import cycle. The template renders only static data; every dynamic value is
// fetched from /stats.json by the page script, so those follow one update path.
package admin

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"enode/internal/ratelimit"
	"enode/logging"
)

// Config is the listener configuration for the dashboard.
type Config struct {
	BindIP string
	Port   uint16
	// Username and Password are the Basic-auth credentials a non-loopback client
	// needs. Empty means such a client sees the status page only (see auth.go).
	Username string
	Password string
}

// StaticInfo holds the server facts that do not change while the process runs.
// It is captured once and rendered into the page by the template; the dynamic
// counters travel separately in LiveStats.
type StaticInfo struct {
	Name        string
	Description string
	Version     string
	Engine      string

	// AdvertisedIP and AdvertisedIPv6 are the addresses clients are told
	// (OP_SERVERIDENT, CT_MOD_SVR_IP_V6); empty when unresolved.
	AdvertisedIP   string
	AdvertisedIPv6 string

	TCPPort    uint16
	TCPPortObf uint16
	UDPPort    uint16
	UDPPortObf uint16
	NATPort    uint16

	Crypt             bool
	IPv6              bool
	NAT               bool
	ServerIndependent bool

	// Accounts is set by SetAccounts: the Meta API has accounts to manage.
	Accounts bool
	// Reload is set by SetReloader: the page offers the "Reload config" button.
	Reload bool
}

// LiveStats holds the figures that change over the life of the server. It is
// produced fresh per request by the snapshot function and served as JSON to the
// page's polling script — it is never baked into the rendered HTML.
//
// Servers is what a client would actually be sent in OP_SERVERLIST, which is not the
// same as the number of configured peers once gossip is running. The Gossip* and
// Filter* fields are zero when the corresponding subsystem is off, and the caller's
// snapshot function is expected to read them from nil-safe accessors, so "disabled" and
// "enabled but idle" both render as 0 rather than needing a tri-state.
type LiveStats struct {
	Clients       int    `json:"clients"`
	Files         int    `json:"files"`
	LowIDs        int    `json:"lowIDs"`
	Servers       int    `json:"servers"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
	Time          string `json:"time"`

	// Server-to-server gossip. Known counts every peer in the table whatever its state;
	// Verified counts the subset advertisable to clients, which excludes parked peers;
	// Parked counts those retired after maxFailures consecutive failed rounds; Admitted
	// is a monotonic total of entries ever accepted from a peer list.
	GossipKnown    int    `json:"gossipKnown"`
	GossipVerified int    `json:"gossipVerified"`
	GossipParked   int    `json:"gossipParked"`
	GossipAdmitted uint64 `json:"gossipAdmitted"`
	// Monotonic totals of what gossip refused, by reason: an unusable address, our own
	// address, a current or recent client, a full table, a list from a sender we never
	// handshook with, and a gossip frame that arrived unobfuscated.
	GossipRejectedBad         uint64 `json:"gossipRejectedBad"`
	GossipRejectedSelf        uint64 `json:"gossipRejectedSelf"`
	GossipRejectedClient      uint64 `json:"gossipRejectedClient"`
	GossipRejectedFull        uint64 `json:"gossipRejectedFull"`
	GossipRejectedUnsolicited uint64 `json:"gossipRejectedUnsolicited"`
	GossipRejectedPlaintext   uint64 `json:"gossipRejectedPlaintext"`

	// Access filters, counted per layer: addresses refused by the ipfilter range list
	// and by the GeoIP country deny-list respectively.
	FilterBlockedIP  int64 `json:"filterBlockedIP"`
	FilterBlockedGeo int64 `json:"filterBlockedGeo"`

	// Torrent/Usenet/Kad meta search. Files above is the eD2K count alone; AdvertisedFiles
	// is the total clients are sent in the server status, which adds the networks set
	// to countInServerStatus. Meta is empty when meta search is off.
	AdvertisedFiles  int                `json:"advertisedFiles"`
	MetaCacheEntries int                `json:"metaCacheEntries"`
	Meta             []MetaNetworkStats `json:"meta"`

	// MetaAPI is the client-facing Meta API; nil when it is off.
	MetaAPI *MetaAPIStats `json:"metaApi"`

	// ServerSearch is the server-to-server search service; nil when it is off.
	ServerSearch *ServerSearchStats `json:"serverSearch"`

	// Update is the last successful GitHub release check (updatecheck.go); nil when
	// the check is off or has not succeeded yet.
	Update *UpdateInfo `json:"update"`
}

// MetaAPIStats are the Meta API's figures (docs/meta-api.md). Accounts counts are
// zero in public mode.
type MetaAPIStats struct {
	// AuthMode is "public" or "account".
	AuthMode string `json:"authMode"`
	GRPCURL  string `json:"grpcUrl"`
	HTTPURL  string `json:"httpUrl"`

	Served         int64 `json:"served"`
	CacheHits      int64 `json:"cacheHits"`
	CacheBytes     int64 `json:"cacheBytes"`
	NotFound       int64 `json:"notFound"`
	VerifyFailed   int64 `json:"verifyFailed"`
	UpstreamErrors int64 `json:"upstreamErrors"`
	RateLimited    int64 `json:"rateLimited"`
	AuthFailures   int64 `json:"authFailures"`
	Logins         int64 `json:"logins"`

	// Search is "off", "public" or "account" (needs an active account).
	Search             string `json:"search"`
	Searches           int64  `json:"searches"`
	SearchCacheEntries int    `json:"searchCacheEntries"`

	AccountsPending  int `json:"accountsPending"`
	AccountsActive   int `json:"accountsActive"`
	AccountsExpired  int `json:"accountsExpired"`
	AccountsDisabled int `json:"accountsDisabled"`
}

// ServerSearchStats are the server-to-server search figures (docs/server-search.md):
// what this server answered for others, and what it knows of its peers.
type ServerSearchStats struct {
	// Mode is "allowlist" or "gossip".
	Mode        string `json:"mode"`
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
	ServeSearch bool   `json:"serveSearch"`
	ServeBrowse bool   `json:"serveBrowse"`

	InfoCalls    int64 `json:"infoCalls"`
	Searches     int64 `json:"searches"`
	Browses      int64 `json:"browses"`
	FilesServed  int64 `json:"filesServed"`
	Resets       int64 `json:"resets"`
	RateLimited  int64 `json:"rateLimited"`
	AuthFailures int64 `json:"authFailures"`

	// LiveSearch and Mirror say what this server asks of its peers.
	LiveSearch     bool `json:"liveSearch"`
	Mirror         bool `json:"mirror"`
	MirrorFiles    int  `json:"mirrorFiles"`
	MirrorMaxFiles int  `json:"mirrorMaxFiles"`

	Peers []ServerSearchPeerStats `json:"peers"`
}

// ServerSearchPeerStats is one server this one searches. Name is the peer's own
// string and LastError may quote it, so the page inserts both as text.
type ServerSearchPeerStats struct {
	URL string `json:"url"`
	// Static is a configured peer; false is one gossip advertised.
	Static    bool   `json:"static"`
	Name      string `json:"name"`
	Files     uint64 `json:"files"`
	Down      bool   `json:"down"`
	LastError string `json:"lastError"`

	Mirrored      bool   `json:"mirrored"`
	MirrorFiles   int    `json:"mirrorFiles"`
	MirrorAt      string `json:"mirrorAt"`
	MirrorTrimmed bool   `json:"mirrorTrimmed"`
	Walks         int64  `json:"walks"`
	WalkErrors    int64  `json:"walkErrors"`
	Resets        int64  `json:"resets"`

	LiveCalls    int64 `json:"liveCalls"`
	LiveErrors   int64 `json:"liveErrors"`
	LiveTimeouts int64 `json:"liveTimeouts"`
	RowsServed   int64 `json:"rowsServed"`
}

// MetaNetworkStats is one torrent, Usenet or Kad network's figures: the meta.NetworkStats
// fields the page shows. The caller maps one to the other so this package keeps no
// dependency on the meta package.
type MetaNetworkStats struct {
	Network             string `json:"network"`
	URL                 string `json:"url"`
	LiveSearch          bool   `json:"liveSearch"`
	FeedEnabled         bool   `json:"feedEnabled"`
	CountInServerStatus bool   `json:"countInServerStatus"`

	// Reachable is whether the last GetInfo poll succeeded. The daemon figures are
	// from the last successful poll, InfoAt (RFC 3339, "" before the first one).
	Reachable bool   `json:"reachable"`
	LastError string `json:"lastError"`
	InfoAt    string `json:"infoAt"`
	// Down is whether live searches are paused after an unavailable, unimplemented
	// or unauthenticated answer.
	Down bool `json:"down"`
	// StatsStale is whether the last GetInfo poll failed although the daemon answered
	// a search within the last two polls: it is up, only its figures are old. LiveOKAt
	// is when it last answered one (RFC 3339, "" for never).
	StatsStale bool   `json:"statsStale"`
	LiveOKAt   string `json:"liveOkAt"`

	Daemon          string `json:"daemon"`
	Version         string `json:"version"`
	SearchAvailable bool   `json:"searchAvailable"`
	Catalogued      uint64 `json:"catalogued"`
	Published       uint64 `json:"published"`
	Files           uint64 `json:"files"`
	LastSeq         uint64 `json:"lastSeq"`

	// NetworkUsers and NetworkUsersExperimental are the daemon's two estimates of the
	// users of its whole network, and NetworkFiles of that network's files; 0 is no
	// estimate. statsBoost.kadUsers and torrentUsers add the first to the users.
	NetworkUsers             uint64 `json:"networkUsers"`
	NetworkUsersExperimental uint64 `json:"networkUsersExperimental"`
	NetworkFiles             uint64 `json:"networkFiles"`

	FeedReleases int    `json:"feedReleases"`
	FeedRows     int    `json:"feedRows"`
	FeedCursor   uint64 `json:"feedCursor"`
	FeedCaughtUp bool   `json:"feedCaughtUp"`

	SearchesTCP  uint64 `json:"searchesTCP"`
	SearchesUDP  uint64 `json:"searchesUDP"`
	RowsServed   uint64 `json:"rowsServed"`
	LiveCalls    uint64 `json:"liveCalls"`
	LiveErrors   uint64 `json:"liveErrors"`
	LiveTimeouts uint64 `json:"liveTimeouts"`
	CacheHits    uint64 `json:"cacheHits"`
	CacheMisses  uint64 `json:"cacheMisses"`
	UDPSkipped   uint64 `json:"udpSkipped"`
	// CatalogCalls, CatalogErrors and CatalogCacheHits are MetaApi.Search's daemon
	// calls, failed chunk loads and cached chunks served.
	CatalogCalls     uint64 `json:"catalogCalls"`
	CatalogErrors    uint64 `json:"catalogErrors"`
	CatalogCacheHits uint64 `json:"catalogCacheHits"`

	// Counted is what this network adds to AdvertisedFiles.
	Counted int `json:"counted"`
}

// Server is the admin dashboard HTTP server.
type Server struct {
	// mu guards cfg's credentials, static and reload, which a config reload replaces
	// while requests are being served.
	mu        sync.RWMutex
	cfg       Config
	static    StaticInfo
	reload    func() (ReloadResult, error)
	snapshot  func() LiveStats
	accounts  AccountAdmin
	authLimit *ratelimit.Limiter
	http      *http.Server
	ln        net.Listener
}

// New builds a dashboard server. static holds the unchanging server facts;
// snapshot returns the current live figures each time it is called (once per
// /stats.json request).
//
// A loopback client always gets in. A non-loopback one needs cfg.Username and
// cfg.Password when they are set, and without them sees the status page only; see
// auth.go.
func New(cfg Config, static StaticInfo, snapshot func() LiveStats) *Server {
	// Non-loopback requests only: bounds password guessing, and leaves room for the
	// page polling /stats.json every 5 s.
	s := &Server{cfg: cfg, static: static, snapshot: snapshot, authLimit: ratelimit.New(120)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stats.json", s.guard(false, s.handleStats))
	mux.HandleFunc("GET /accounts", s.guard(true, s.handleAccountsPage))
	mux.HandleFunc("GET /api/accounts", s.guard(true, s.handleAccountList))
	mux.HandleFunc("GET /api/accounts/{id}", s.guard(true, s.handleAccountDetail))
	mux.HandleFunc("POST /api/accounts/{id}/{action}", s.guard(true, s.handleAccountAction))
	mux.HandleFunc("POST /api/reload-config", s.guard(true, s.handleReloadConfig))
	mux.HandleFunc("/", s.guard(false, s.handleIndex))
	s.http = &http.Server{
		Handler: mux,
		// A dashboard reachable off-box (if the operator widens BindIP) should not
		// be trivially held open by a slow-header client.
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// Start binds the listener synchronously — so a bind failure is returned to the
// caller before it logs a URL — then serves in the background.
func (s *Server) Start() error {
	addr := net.JoinHostPort(s.cfg.BindIP, strconv.Itoa(int(s.cfg.Port)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	go func() {
		if err := s.http.Serve(ln); err != nil && err != http.ErrServerClosed {
			logging.Warnf("admin dashboard serve error: %v", err)
		}
	}()
	return nil
}

// Close stops the server and releases the listener.
func (s *Server) Close() error {
	if s.http == nil {
		return nil
	}
	return s.http.Close()
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// The catch-all mux pattern "/" matches every unmatched path; only the exact
	// root is the dashboard, everything else is a 404.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.Execute(w, s.staticInfo()); err != nil {
		logging.Warnf("admin dashboard render error: %v", err)
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(s.snapshot()); err != nil {
		logging.Warnf("admin dashboard stats encode error: %v", err)
	}
}
