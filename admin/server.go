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
	"time"

	"enode/logging"
)

// Config is the listener configuration for the dashboard.
type Config struct {
	BindIP string
	Port   uint16
}

// StaticInfo holds the server facts that do not change while the process runs.
// It is captured once and rendered into the page by the template; the dynamic
// counters travel separately in LiveStats.
type StaticInfo struct {
	Name        string
	Description string
	Version     string
	Engine      string

	TCPPort    uint16
	TCPPortObf uint16
	UDPPort    uint16
	UDPPortObf uint16
	NATPort    uint16

	Crypt             bool
	IPv6              bool
	NAT               bool
	ServerIndependent bool
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
	// Verified counts the subset advertisable to clients; Parked counts those retired
	// after maxFailures consecutive failed rounds; Admitted is a monotonic total of
	// entries ever accepted from a peer list.
	GossipKnown    int    `json:"gossipKnown"`
	GossipVerified int    `json:"gossipVerified"`
	GossipParked   int    `json:"gossipParked"`
	GossipAdmitted uint64 `json:"gossipAdmitted"`

	// Access filters, counted per layer: addresses refused by the ipfilter range list
	// and by the GeoIP country deny-list respectively.
	FilterBlockedIP  int64 `json:"filterBlockedIP"`
	FilterBlockedGeo int64 `json:"filterBlockedGeo"`
}

// Server is the admin dashboard HTTP server.
type Server struct {
	cfg      Config
	static   StaticInfo
	snapshot func() LiveStats
	http     *http.Server
	ln       net.Listener
}

// New builds a dashboard server. static holds the unchanging server facts;
// snapshot returns the current live figures each time it is called (once per
// /stats.json request).
//
// ToDo: the dashboard has no authentication — it relies on the localhost-only
// default bind. Before documenting a non-loopback bind as supported, add an
// optional token/basic-auth gate so an operator can expose it safely.
func New(cfg Config, static StaticInfo, snapshot func() LiveStats) *Server {
	s := &Server{cfg: cfg, static: static, snapshot: snapshot}
	mux := http.NewServeMux()
	mux.HandleFunc("/stats.json", s.handleStats)
	mux.HandleFunc("/", s.handleIndex)
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
	if err := pageTemplate.Execute(w, s.static); err != nil {
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
