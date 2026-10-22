// Package ed3k runs an ed3k index node (Protocol.md §11) beside the eD2K server:
// INDEX without ROUTER, so it never dials, holds no routing table, stores SOURCE,
// KEYWORD and NOTE records for every target, relays Punch messages for the
// leaves that reserve a slot, and answers ReachTest with ok = false. Its records
// live in the server's storage engine (storage.Ed3kStore).
//
// The transport is QUIC over the obfuscating socket of package obfs, with
// RFC 7250 Ed25519 keys (packages transport, internal/ed3k/itls and iquic).
package ed3k

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"enode/ed3k/ed3kpb"
	"enode/ed3k/ident"
	"enode/ed3k/index"
	"enode/ed3k/obfs"
	"enode/ed3k/token"
	"enode/ed3k/transport"
	quic "enode/internal/ed3k/iquic"
	"enode/logging"
	"enode/storage"
)

// Capability bits of Protocol.md §2 that this node sets or reads.
const (
	CapRouter = 1 << 0
	CapRelay  = 1 << 1
	CapIndex  = 1 << 2
	CapED2K   = 1 << 6
)

// Timeouts of Protocol.md §4.1 and §5.5.
const (
	helloTimeout   = 30 * time.Second // the peer's Hello on stream 0
	requestTimeout = 30 * time.Second // a request that has not arrived whole is reset
	sweepEvery     = time.Minute
	// keepEvery is how often the kept sources of live connections are renewed
	// (index.Keep pushes them 30 min ahead).
	keepEvery = 15 * time.Minute
)

// Config is what a Node needs.
type Config struct {
	// Key is the node's identity.
	Key ed25519.PrivateKey
	// Conn is the UDP socket, already bound (the caller binds it so that it
	// survives a handover). Listen is used when Conn is nil.
	Conn   *net.UDPConn
	Listen netip.AddrPort
	// Network is the name of a test or closed network; empty for the public one.
	Network string
	// Advertise4 and Advertise6 are the endpoints in the node's link and Hello.
	Advertise4, Advertise6 netip.AddrPort
	Agent, Nick            string
	// Store holds the records.
	Store  storage.Ed3kStore
	Limits storage.Ed3kLimits
	Budget Budget
	Relay  RelayLimits
	// RequestsPerMinute bounds KadRequests per host group, kind and operation.
	RequestsPerMinute int
	// Reject refuses records whose file name or note matches (content filters).
	Reject func(string) bool
	// StrictRecordFields refuses KEYWORD and NOTE records that also carry a
	// record field of an extension (spec question E of the 2026-10-22 audit).
	StrictRecordFields bool
}

// Budget bounds the connections a node accepts (§4.6, widened for INDEX).
type Budget struct {
	MaxConns        int // all connections
	PerHost         int // open connections per host group
	PerSite         int // open connections per site
	NewPerHostMin   int // new connections per host group and minute
	NewPerNodeIDMin int // new connections per node ID and minute; beyond: a 24 h ban
}

// RelayLimits bounds the relay service (§9.4, widened for INDEX).
type RelayLimits struct {
	Leaves  int // reservations in all
	PerHost int
	PerSite int
}

// Defaults for an index node.
var (
	DefaultBudget = Budget{MaxConns: 50000, PerHost: 256, PerSite: 1024, NewPerHostMin: 120, NewPerNodeIDMin: 10}
	DefaultRelay  = RelayLimits{Leaves: 1024, PerHost: 8, PerSite: 32}
)

// Stats is a snapshot for the admin page.
type Stats struct {
	Connections  int
	Accepted     uint64
	Refused      uint64 // budget, bans, missing Hello
	Exchanges    uint64
	RelayLeaves  int
	Punches      uint64
	PunchFailed  uint64
	Index        index.Stats
	ObfsDropped  uint64
	ObfsProbes   uint64
	ObfsHeld     uint64
	BridgeListed uint64
}

// Node is a running index node.
type Node struct {
	cfg   Config
	id    ident.NodeID
	named bool
	idx   *index.Index
	pc    *obfs.Conn
	ln    *quic.Listener

	mu       sync.Mutex
	sessions map[*quic.Conn]*session
	budget   *budget
	relay    *relay
	bridge   *bridge

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	accepted, refused, exchanges, punches, punchFailed atomic.Uint64
}

// New checks the configuration; Start brings the node up.
func New(cfg Config) (*Node, error) {
	if len(cfg.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("ed3k: no node key")
	}
	if cfg.Store == nil {
		return nil, errors.New("ed3k: no record store")
	}
	if err := token.CheckTables(); err != nil {
		return nil, err
	}
	if len(cfg.Network) > 32 {
		return nil, errors.New("ed3k: network name above 32 bytes")
	}
	if cfg.Budget == (Budget{}) {
		cfg.Budget = DefaultBudget
	}
	if cfg.Relay == (RelayLimits{}) {
		cfg.Relay = DefaultRelay
	}
	if cfg.Agent == "" {
		cfg.Agent = "eNode-go"
	}
	n := &Node{
		cfg:      cfg,
		id:       ident.NodeIDOf(cfg.Key.Public().(ed25519.PublicKey)),
		named:    cfg.Network != "",
		sessions: map[*quic.Conn]*session{},
	}
	n.idx = index.New(index.Config{Store: cfg.Store, Limits: cfg.Limits, Named: n.named,
		RequestsPerMinute: cfg.RequestsPerMinute, Reject: cfg.Reject, StrictRecordFields: cfg.StrictRecordFields})
	n.budget = newBudget(cfg.Budget, n.named)
	n.relay = newRelay(cfg.Relay, n.named)
	n.bridge = newBridge(cfg.Store)
	return n, nil
}

// ID is the node ID.
func (n *Node) ID() ident.NodeID { return n.id }

// Link is the node's ed3k:node link, as advertised to eD2K clients (ST_ED3K).
func (n *Node) Link() ident.NodeLink {
	return ident.NodeLink{ID: n.id, EP4: n.cfg.Advertise4, EP6: n.cfg.Advertise6}
}

// LocalAddr is the bound socket's address.
func (n *Node) LocalAddr() net.Addr { return n.pc.LocalAddr() }

// Start binds (when no socket was given), listens and starts the sweeper.
func (n *Node) Start(ctx context.Context) error {
	udp := n.cfg.Conn
	if udp == nil {
		var err error
		udp, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(n.cfg.Listen))
		if err != nil {
			return fmt.Errorf("ed3k: listen %v: %w", n.cfg.Listen, err)
		}
	}
	_ = udp.SetReadBuffer(4 << 20)
	_ = udp.SetWriteBuffer(4 << 20)
	// No connection outlives the process, also not across a handover: what an
	// earlier run kept for its connections goes at the end of its lifetime (§11).
	rctx, cancel := context.WithTimeout(ctx, time.Minute)
	err := n.idx.ReleaseAll(rctx, n.connPrefix())
	cancel()
	if err != nil {
		logging.Warnf("ed3k: releasing the sources kept by an earlier run: %v", err)
	}
	n.pc = obfs.NewServer(udp, obfs.NetID(n.cfg.Network), n.id.Obf())
	tlsConf, err := transport.ServerTLS(n.cfg.Key)
	if err != nil {
		n.pc.Close()
		return err
	}
	qc := transport.QUICConfig(transport.IdleIndex)
	qc.OnPathSwitch = n.onPathSwitch
	n.ln, err = quic.Listen(n.pc, tlsConf, qc)
	if err != nil {
		n.pc.Close()
		return err
	}
	n.ctx, n.cancel = context.WithCancel(ctx)
	n.wg.Add(2)
	go n.acceptLoop()
	go n.sweepLoop()
	logging.Infof("ed3k: index node %s listening on %v (%s)", n.id, n.pc.LocalAddr(), n.Link())
	return nil
}

// Close closes every connection and the socket.
func (n *Node) Close() error {
	if n.cancel == nil {
		return nil
	}
	n.cancel()
	n.mu.Lock()
	for c := range n.sessions {
		c.CloseWithError(transport.CodeClosed, "shutting down")
	}
	n.mu.Unlock()
	err := n.ln.Close()
	n.pc.Close()
	n.wg.Wait()
	return err
}

// Stats returns the counters.
func (n *Node) Stats() Stats {
	n.mu.Lock()
	conns := len(n.sessions)
	n.mu.Unlock()
	st := Stats{
		Connections: conns, Accepted: n.accepted.Load(), Refused: n.refused.Load(),
		Exchanges: n.exchanges.Load(), RelayLeaves: n.relay.count(), Punches: n.punches.Load(),
		PunchFailed: n.punchFailed.Load(), Index: n.idx.Stats(), BridgeListed: n.bridge.listed.Load(),
	}
	if n.pc != nil {
		st.ObfsDropped, st.ObfsProbes, st.ObfsHeld = n.pc.Dropped.Load(), n.pc.Probes.Load(), n.pc.Held.Load()
	}
	return st
}

// StoreStats counts the records held.
func (n *Node) StoreStats(ctx context.Context) (storage.Ed3kStats, error) {
	return n.cfg.Store.Ed3kStats(ctx, time.Now())
}

func (n *Node) acceptLoop() {
	defer n.wg.Done()
	for {
		c, err := n.ln.Accept(n.ctx)
		if err != nil {
			if n.ctx.Err() == nil {
				logging.Warnf("ed3k: accept: %v", err)
			}
			return
		}
		n.admit(c)
	}
}

// admit applies the connection budget to a completed handshake and starts the
// session (§4.6).
func (n *Node) admit(c *quic.Conn) {
	pub, err := transport.PeerKey(c.ConnectionState().TLS)
	if err != nil {
		c.CloseWithError(transport.CodeNoKey, "")
		n.refused.Add(1)
		return
	}
	id := ident.NodeIDOf(pub)
	remote, ok := addrPort(c.RemoteAddr())
	if !ok {
		c.CloseWithError(transport.CodeProtocol, "")
		return
	}
	code, refuse, banned := n.budget.admit(id, remote.Addr(), time.Now())
	if banned {
		n.closeNode(id, code)
	}
	if refuse {
		c.CloseWithError(code, "")
		n.refused.Add(1)
		return
	}
	s := newSession(n, c, id, pub)
	n.mu.Lock()
	n.sessions[c] = s
	n.mu.Unlock()
	// The handshake completed, so QUIC validated the client's address.
	s.track(c.RemoteAddr())
	n.accepted.Add(1)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		s.serve()
		n.mu.Lock()
		delete(n.sessions, c)
		n.mu.Unlock()
		n.budget.leave(remote.Addr())
	}()
}

// sweepLoop expires records every minute and renews the kept sources of live
// connections every hour.
func (n *Node) sweepLoop() {
	defer n.wg.Done()
	sweep := time.NewTicker(sweepEvery)
	keep := time.NewTicker(keepEvery)
	defer sweep.Stop()
	defer keep.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case now := <-sweep.C:
			ctx, cancel := context.WithTimeout(n.ctx, 5*time.Minute)
			if _, err := n.cfg.Store.ExpireEd3k(ctx, now); err != nil {
				logging.Warnf("ed3k: expiring records: %v", err)
			}
			cancel()
			n.budget.sweep(now)
		case <-keep.C:
			n.mu.Lock()
			var keepers []*session
			for _, s := range n.sessions {
				if s.storedSources.Load() {
					keepers = append(keepers, s)
				}
			}
			n.mu.Unlock()
			for _, s := range keepers {
				if err := n.idx.Keep(n.ctx, s.connID); err != nil {
					logging.Warnf("ed3k: keeping sources of %s: %v", s.id, err)
				}
			}
		}
	}
}

// closeNode closes every open connection of a node ID that was just banned
// (§4.6).
func (n *Node) closeNode(id ident.NodeID, code quic.ApplicationErrorCode) {
	n.mu.Lock()
	var conns []*quic.Conn
	for c, s := range n.sessions {
		if s.id == id {
			conns = append(conns, c)
		}
	}
	n.mu.Unlock()
	for _, c := range conns {
		c.CloseWithError(code, "banned")
	}
}

// onPathSwitch follows a client's migration: QUIC validated the new address,
// and the obfuscation layer lifts its amplification limit there (§4.4).
func (n *Node) onPathSwitch(c *quic.Conn, addr net.Addr) {
	n.mu.Lock()
	s := n.sessions[c]
	n.mu.Unlock()
	if s != nil {
		s.track(addr)
	}
}

// connPrefix starts the name of every connection of this node in the store,
// so that a later run can release what this one kept.
func (n *Node) connPrefix() string { return n.id.String()[:8] + "-" }

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	u, ok := a.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := u.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// helloFor is this node's Hello to a peer at remote.
func (n *Node) helloFor(remote netip.AddrPort) *ed3kpb.Hello {
	caps := uint64(CapIndex | CapED2K)
	if n.relay.hasRoom() {
		caps |= CapRelay
	}
	h := &ed3kpb.Hello{Caps: caps, Agent: clip(n.cfg.Agent, 64), Observed: ident.EncodeEndpoint(remote),
		Nat: 1, Nick: clip(n.cfg.Nick, 64)}
	if n.cfg.Advertise4.IsValid() {
		h.Ep4 = ident.EncodeEndpoint(n.cfg.Advertise4)
	}
	if n.cfg.Advertise6.IsValid() {
		h.Ep6 = ident.EncodeEndpoint(n.cfg.Advertise6)
	}
	return h
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xc0 == 0x80 {
		n--
	}
	return s[:n]
}
