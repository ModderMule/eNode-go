package ed2k

import (
	"net"
	"sort"
	"sync"
	"time"

	"enode/logging"
)

// Server-to-server gossip: the peer table, its admission state machine, and the merge
// policy. The wire codec is in gossipoperations.go and the outbound loop in
// gossipclient.go. See docs/server-gossip.md.
//
// The table lives here rather than behind storage.Engine deliberately. MySQLEngine and
// MongoDBEngine implement AddServer/ServersAll as bare slice appends with no mutex
// (storage/engine_mysql.go, storage/engine_mongodb.go) — safe today only because
// seedServers() is their single caller and runs before any listener binds. Gossip
// writes from the UDP worker pool, so routing it through Engine would introduce a data
// race in two of the three engines. GossipHandler carries its own lock instead, and
// the client-facing OP_SERVERLIST merges the two sources at send time.

// peerState is a peer's position in the admission sequence. Advancing past peerKeyed
// requires the peer to answer a frame we encrypted with the ServerKey it issued for our
// address, which is what eserver requires before it will list a peer or echo it to third
// parties. See advertisableState for where the admission bar sits and why.
type peerState uint8

const (
	// peerSeen means we know an address but have proved nothing about it. Reached by a
	// plaintext 0xA0, or by an entry harvested from someone else's list.
	peerSeen peerState = iota
	// peerKeyed means the obfuscated bootstrap ping came back and we hold the peer's
	// ServerKey, so we can now talk to it on the obfuscated channel.
	peerKeyed
	// peerDescribed means it answered OP_SERVERDESCREQ, obfuscated, with a usable
	// name/description. This is the admission bar — see advertisableState.
	peerDescribed
	// peerVerified means it *also* answered an obfuscated list request. Strictly better
	// evidence than peerDescribed, but not required to advertise a peer.
	peerVerified
)

// advertisableState is the lowest state at which a peer may be advertised to clients and
// echoed to other servers.
//
// peerDescribed, not peerVerified, and that is a correction from real interop. Requiring a
// list reply looked right on paper but is unsatisfiable in practice: a peer with an empty
// peer table — the first two servers in any new mesh, or a lone eserver — has no 0xA1 to
// send, so it would stay unadvertisable forever and the mesh could never bootstrap.
// Verified against eserver 17.14: it answers our obfuscated 0xA2 with its name and
// description but sends no list, and its own admission test is exactly that reply
// ("Adding server %s:%d name=%s desc=%s").
//
// The security property is unaffected. Reaching peerDescribed already required the peer to
// answer a frame we encrypted with the ServerKey *it* issued for our address, which is the
// thing a client masquerading as a server cannot do (§7.1.7). The list reply only adds
// evidence that it has peers, which says nothing about whether it is a server.
const advertisableState = peerDescribed

func (s peerState) String() string {
	switch s {
	case peerSeen:
		return "seen"
	case peerKeyed:
		return "keyed"
	case peerDescribed:
		return "described"
	case peerVerified:
		return "verified"
	}
	return "unknown"
}

// PeerServer is one known server. Values learned from the peer itself (ServerKey, the
// obfuscation ports, name) are only ever written from a frame that arrived from that
// peer's own address, never from a third party's list.
type PeerServer struct {
	Addr PeerAddr
	Name string
	Desc string

	// ServerKey is the key WE must use to talk to this peer, read from its extended
	// 0x97 at +36. The peer derives it from its own secret plus our IP and expects it
	// echoed back, so it is opaque to us — see deriveUDPKey for the same property on
	// the client-facing side.
	ServerKey uint32
	// UDPPortObf and TCPPortObf are the peer's advertised obfuscation ports, from the
	// same reply. UDPPortObf is where phase 3 sends; zero means "fall back to +14".
	UDPPortObf uint16
	TCPPortObf uint16
	UDPFlags   uint32

	// OurChallenge is the random_part we used for this peer's phase-2 bootstrap ping. Its
	// reply is RC4-keyed on exactly this value, so it must survive until the reply
	// arrives.
	OurChallenge uint32
	// PlainChallenge is the separate 0x55AA-prefixed challenge sent with the phase-1
	// plain 0x96.
	//
	// Kept apart from OurChallenge because both are outstanding at once: a round sends the
	// plain probe and the obfuscated ping back to back, and the two replies arrive
	// independently on different sockets. Sharing one field meant phase 2 overwrote phase
	// 1's value, and every plain 0x97 was then rejected as "sent a bad challenge" —
	// observed against the real eserver.
	PlainChallenge uint32
	// RefererIP is who told us about this peer, matching eserver's IP_referer console
	// column. Kept for diagnostics: it is how a run of bogus entries is traced back to
	// the peer injecting them.
	RefererIP net.IP

	State        peerState
	Users        uint32
	Files        uint32
	LastSeen     time.Time
	LastVerified time.Time
	// Failures counts consecutive rounds that produced no inbound frame. At
	// maxFailures the peer is parked (see Parked).
	Failures int
}

// Parked reports whether the peer has failed too many consecutive rounds to keep
// contacting. A parked peer is retained rather than deleted so that an inbound frame
// from it can revive it — a server that was down for an afternoon should not have to be
// rediscovered.
func (p *PeerServer) Parked(maxFailures int) bool {
	return maxFailures > 0 && p.Failures >= maxFailures
}

// GossipConfig is what the handler needs from config.GossipConfig, restated here so
// the ed2k package does not import config (which imports storage, which would make the
// dependency direction awkward).
type GossipConfig struct {
	// SelfIPv4 and SelfPort identify us, for the self-rejection rule and for the
	// address announced in 0xA0.
	SelfIPv4 net.IP
	SelfPort uint16
	// SelfIPv6 is our public IPv6, if any, also self-rejected.
	SelfIPv6 net.IP
	// Name and Desc answer a peer's OP_SERVERDESCREQ.
	Name string
	Desc string
	// MaxServers caps the table. MaxFailures parks a peer.
	MaxServers  int
	MaxFailures int
	// AllowPrivatePeers permits LAN/loopback peers — eMule's FilterLANIPs, inverted.
	AllowPrivatePeers bool
	// PublishIPv6 enables the 0xa7/0xa8 extension.
	PublishIPv6 bool
	// UDPPortObf and TCPPortObf are our own advertised ports, echoed in our 0x97.
	UDPPortObf uint16
	TCPPortObf uint16
}

// recentClientWindow is how long an IP that was a connected client stays untrusted as
// a peer. It catches the case the Rust implementation documents: an mldonkey that
// registered itself with real seeds, disconnected from us, and then comes back inside
// someone else's 0xA1. Without the window it would be admitted as a server the moment
// its session closed.
const recentClientWindow = 30 * time.Minute

// GossipHandler owns the peer table and every decision about what enters it.
type GossipHandler struct {
	mu    sync.RWMutex
	cfg   GossipConfig
	peers map[string]*PeerServer

	// clientIPs tracks addresses that are, or recently were, connected clients. A
	// client is not a server: admitting one would publish an address that answers no
	// server protocol, and it is the standard way a peer list gets poisoned.
	clientIPs map[string]time.Time

	// localIPs are our own bind addresses, so a peer echoing our address back is
	// recognised as us even when it is not the configured advertised IP. Re-ingesting
	// those is what recreates the phantom self-entries the reference implementation
	// kept fighting.
	localIPs map[string]struct{}

	// stats are cumulative counters for the admin surface and the logs.
	stats GossipStats
}

// GossipStats is a snapshot of what gossip has done. Counters only ever increase.
type GossipStats struct {
	Known        int
	Verified     int
	Parked       int
	Admitted     uint64
	RejectedSelf uint64
	RejectedBad  uint64
	RejectedFull uint64
	RejectedPeer uint64
	// RejectedUnsolicited counts lists from a sender we never handshook with, the case
	// eserver logs as "received a servlist from unknown server".
	RejectedUnsolicited uint64
	// RejectedPlaintext counts gossip opcodes that arrived unobfuscated, which eserver
	// logs as "ignore non obfuscated OP_SERVER_LIST_REQ/_RES".
	RejectedPlaintext uint64
}

// NewGossipHandler builds a handler. Seeds are entered at peerSeen so the first round
// contacts them; they earn peerVerified the same way any other peer does, because a
// seed we cannot complete a handshake with is not a peer worth advertising.
func NewGossipHandler(cfg GossipConfig, seeds []PeerAddr) *GossipHandler {
	g := &GossipHandler{
		cfg:       cfg,
		peers:     make(map[string]*PeerServer),
		clientIPs: make(map[string]time.Time),
		localIPs:  make(map[string]struct{}),
	}
	for _, s := range seeds {
		if s.IP == nil || s.Port == 0 {
			continue
		}
		key := s.String()
		g.peers[key] = &PeerServer{Addr: s, State: peerSeen}
	}
	return g
}

// AddLocalIP registers one of our own addresses for self-rejection. Called for each
// bind address and for the advertised IP.
func (g *GossipHandler) AddLocalIP(ip net.IP) {
	if g == nil || ip == nil || ip.IsUnspecified() {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.localIPs[NormalizeIP(ip).String()] = struct{}{}
}

// NoteClient records that an address is a connected client, so it cannot be admitted
// as a peer for recentClientWindow after it disconnects. Called from the TCP accept
// path; cheap enough to run per connection (one map write under a lock held for the
// duration of that write only).
func (g *GossipHandler) NoteClient(ip net.IP) {
	if g == nil || ip == nil {
		return
	}
	key := NormalizeIP(ip).String()
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.clientIPs[key] = now
	// Opportunistic expiry, so the map cannot grow without bound on a busy server. Only
	// swept when it is large enough for the scan to be worth it.
	if len(g.clientIPs) > 4096 {
		cutoff := now.Add(-recentClientWindow)
		for k, seen := range g.clientIPs {
			if seen.Before(cutoff) {
				delete(g.clientIPs, k)
			}
		}
	}
}

// Verified returns the peers that may be advertised to clients and echoed to other
// servers, newest-verified first so a truncated list carries the freshest entries.
func (g *GossipHandler) Verified() []PeerAddr {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*PeerServer, 0, len(g.peers))
	for _, p := range g.peers {
		if p.State >= advertisableState {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastVerified.After(out[j].LastVerified) })
	addrs := make([]PeerAddr, 0, len(out))
	for _, p := range out {
		addrs = append(addrs, p.Addr)
	}
	return addrs
}

// VerifiedEntries returns verified peers as server.met entries, for persistence.
func (g *GossipHandler) VerifiedEntries() []ServerMetEntry {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]ServerMetEntry, 0, len(g.peers))
	for _, p := range g.peers {
		if p.State < advertisableState {
			continue
		}
		out = append(out, ServerMetEntry{
			IP: p.Addr.IP, Port: p.Addr.Port, Name: p.Name, Description: p.Desc,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.String() < out[j].IP.String() })
	return out
}

// Stats returns a snapshot with the live table sizes filled in.
func (g *GossipHandler) Stats() GossipStats {
	if g == nil {
		return GossipStats{}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	s := g.stats
	s.Known = len(g.peers)
	for _, p := range g.peers {
		if p.State >= advertisableState {
			s.Verified++
		}
		if p.Parked(g.cfg.MaxFailures) {
			s.Parked++
		}
	}
	return s
}

// Snapshot returns copies of every peer, for the admin surface. Copies rather than
// pointers so a reader cannot observe the table mutating underneath it.
func (g *GossipHandler) Snapshot() []PeerServer {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]PeerServer, 0, len(g.peers))
	for _, p := range g.peers {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.String() < out[j].Addr.String() })
	return out
}

// MergePeerList admits entries harvested from a peer's 0xA1/0xA8, applying the full
// policy. Returns how many were admitted.
//
// from is the sender's address — the peer that served the list. obfuscated reports
// whether the frame arrived on the obfuscated channel. Both matter: an unobfuscated
// list is refused outright (eserver: "ignore non obfuscated OP_SERVER_LIST_RES"), and a
// list from a sender we have not handshaken with is refused too ("received a servlist
// from unknown server %s:%d"). Together those two rules are what stop anyone who can
// send a UDP packet from injecting peers.
func (g *GossipHandler) MergePeerList(from net.IP, entries []PeerAddr, obfuscated bool) int {
	if g == nil {
		return 0
	}
	if !obfuscated {
		g.mu.Lock()
		g.stats.RejectedPlaintext++
		g.mu.Unlock()
		logging.Debugf("gossip: ignoring non-obfuscated peer list from %s (%d entries)", from, len(entries))
		return 0
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// The sender must be a peer we have at least keyed, i.e. one that answered our
	// bootstrap ping. peerSeen is not enough: anyone can be at peerSeen simply by
	// appearing in someone else's list.
	if !g.senderIsKnownLocked(from) {
		g.stats.RejectedUnsolicited++
		logging.Debugf("gossip: received a peer list from unknown server %s, dropping %d entries",
			from, len(entries))
		return 0
	}

	admitted := 0
	for _, e := range entries {
		if g.admitLocked(e, from) {
			admitted++
		}
	}
	if admitted > 0 {
		logging.Debugf("gossip: merged %d/%d peer(s) from %s (table=%d)",
			admitted, len(entries), from, len(g.peers))
	}
	return admitted
}

// NoteRegistration handles an inbound OP_SERVER_LIST_REQ (0xA0): a peer announcing
// itself. The announced port is used, but the *observed source IP* always wins over
// the announced address — a sender cannot register a third party.
//
// obfuscated gates verification, not admission. A plaintext 0xA0 is recorded as a hint
// (peerSeen) so the outbound loop will probe the sender, but it can never promote a
// peer, because completing the obfuscated round-trip is the only thing that proves the
// sender holds a ServerKey we issued.
//
// The challenge in the 0xA0 payload is deliberately ignored. It is *not* the challenge a
// peer expects echoed in a 0x97: eserver keeps a separate per-peer ping challenge and
// rejects anything else with "server %s:%d sent a bad challenge %x instead of %x" —
// measured, having tried exactly that. The only correct echo is the one the inbound-ping
// handler sends back in direct reply, which is where it belongs.
func (g *GossipHandler) NoteRegistration(from net.IP, announcedPort uint16, obfuscated bool) {
	if g == nil || from == nil {
		return
	}
	addr := PeerAddr{IP: NormalizeIP(from), Port: announcedPort}

	g.mu.Lock()
	defer g.mu.Unlock()

	if !obfuscated {
		g.stats.RejectedPlaintext++
		logging.Debugf("gossip: non-obfuscated OP_SERVER_LIST_REQ from %s, recording as a hint only", from)
	}
	if !g.admitLocked(addr, nil) {
		return
	}
	p := g.peers[addr.String()]
	if p == nil {
		return
	}
	p.LastSeen = time.Now()
	p.Failures = 0
	if obfuscated {
		// Holding a ServerKey we derived for this peer's IP is the proof. Reaching us
		// obfuscated at all means it does.
		g.promoteLocked(p, peerVerified)
	}
}

// NoteStatRes records what a peer's OP_GLOBSERVSTATRES told us and advances it to
// peerKeyed once we hold a ServerKey.
//
// challengeMatches must be the caller's verdict on whether the reply echoed the
// challenge we sent. A reply that does not match is dropped: it is either a stale
// datagram or a spoof, and adopting a ServerKey from it would make every later
// obfuscated frame undecryptable at the far end.
func (g *GossipHandler) NoteStatRes(from net.IP, fields StatResFields, challengeMatches bool) {
	if g == nil || from == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	p := g.findByIPLocked(from)
	if p == nil {
		logging.Debugf("gossip: received a pong from unknown server %s, ignoring", from)
		return
	}
	if !challengeMatches {
		logging.Debugf("gossip: %s sent a bad challenge 0x%08x instead of 0x%08x or 0x%08x",
			p.Addr, fields.Challenge, p.OurChallenge, p.PlainChallenge)
		return
	}
	p.LastSeen = time.Now()
	p.Failures = 0
	p.Users, p.Files = fields.Users, fields.Files
	if !fields.Extended {
		// Lugdunum answers a *plain* 0x96 with the short form, which carries no
		// ServerKey. Normal, not an error — the obfuscated channel is where the key
		// comes from — so the peer stays at peerSeen and the next round pings it there.
		logging.Debugf("gossip: %s answered with the short stat form, no ServerKey yet", p.Addr)
		return
	}
	p.ServerKey = fields.ServerKey
	p.UDPPortObf = fields.UDPPortObf
	p.TCPPortObf = fields.TCPPortObf
	p.UDPFlags = fields.UDPFlags
	g.promoteLocked(p, peerKeyed)
	logging.Debugf("gossip: cinfo from %s ServerKey=0x%08x UDPobf=%d TCPobf=%d flags=0x%08x",
		p.Addr, fields.ServerKey, fields.UDPPortObf, fields.TCPPortObf, fields.UDPFlags)
}

// NoteDescription records a peer's name/description reply and advances it to
// peerDescribed. A reply failing the sanity check leaves the peer where it is, matching
// eserver's "received a bad name:desc reply from server %s:%d (bad name)/(bad desc)".
func (g *GossipHandler) NoteDescription(from net.IP, name, desc string) bool {
	if g == nil || from == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	p := g.findByIPLocked(from)
	if p == nil {
		logging.Debugf("gossip: received a name:desc reply from unknown server %s", from)
		return false
	}
	if !validServerName(name) {
		logging.Debugf("gossip: received a bad name:desc reply from server %s (bad name)", p.Addr)
		return false
	}
	if !validServerDesc(desc) {
		logging.Debugf("gossip: received a bad name:desc reply from server %s (bad desc)", p.Addr)
		return false
	}
	updating := p.Name != ""
	p.Name, p.Desc = name, desc
	p.LastSeen = time.Now()
	p.Failures = 0
	g.promoteLocked(p, peerDescribed)
	if updating {
		logging.Infof("gossip: updating server %s name=%q desc=%q", p.Addr, name, desc)
	} else {
		logging.Infof("gossip: adding server %s name=%q desc=%q", p.Addr, name, desc)
	}
	return true
}

// NoteVerified marks a peer as having completed the obfuscated list exchange, the last
// step before it may be advertised.
func (g *GossipHandler) NoteVerified(from net.IP) {
	if g == nil || from == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if p := g.findByIPLocked(from); p != nil {
		p.LastSeen = time.Now()
		p.Failures = 0
		g.promoteLocked(p, peerVerified)
	}
}

// SetOurChallenge records the random_part used for a peer's phase-2 bootstrap ping, so the
// reply can be decrypted and its echoed challenge checked.
func (g *GossipHandler) SetOurChallenge(addr PeerAddr, challenge uint32) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if p := g.peers[addr.String()]; p != nil {
		p.OurChallenge = challenge
	}
}

// SetPlainChallenge records the challenge sent with the phase-1 plain 0x96. Separate from
// SetOurChallenge because both probes are outstanding simultaneously.
func (g *GossipHandler) SetPlainChallenge(addr PeerAddr, challenge uint32) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if p := g.peers[addr.String()]; p != nil {
		p.PlainChallenge = challenge
	}
}

// PingChallengeFor returns the outstanding phase-2 ping challenge for a source address, if
// any. The receive path needs it to decrypt that peer's obf-ping reply, which is keyed on
// the challenge rather than on any ServerKey.
func (g *GossipHandler) PingChallengeFor(ip net.IP) (uint32, bool) {
	if g == nil || ip == nil {
		return 0, false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	p := g.findByIPLocked(ip)
	if p == nil || p.OurChallenge == 0 {
		return 0, false
	}
	return p.OurChallenge, true
}

// PeerByIP returns a copy of the peer at an address, for the receive path which knows
// only the source IP.
func (g *GossipHandler) PeerByIP(ip net.IP) (PeerServer, bool) {
	if g == nil || ip == nil {
		return PeerServer{}, false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	p := g.findByIPLocked(ip)
	if p == nil {
		return PeerServer{}, false
	}
	return *p, true
}

// Contactable returns copies of the peers the outbound loop should work on this round:
// everything not parked. Copies so the loop can send without holding the lock.
func (g *GossipHandler) Contactable() []PeerServer {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]PeerServer, 0, len(g.peers))
	for _, p := range g.peers {
		if p.Parked(g.cfg.MaxFailures) {
			continue
		}
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.String() < out[j].Addr.String() })
	return out
}

// NoteRoundFailure increments the failure counter for peers that produced nothing this
// round. Called by the loop after a round elapses.
func (g *GossipHandler) NoteRoundFailure(addr PeerAddr) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.peers[addr.String()]
	if p == nil {
		return
	}
	p.Failures++
	if p.Parked(g.cfg.MaxFailures) {
		logging.Debugf("gossip: parking %s after %d consecutive failures", p.Addr, p.Failures)
	}
}

// Config returns the handler's configuration, for the outbound loop.
func (g *GossipHandler) Config() GossipConfig {
	if g == nil {
		return GossipConfig{}
	}
	return g.cfg
}

// admitLocked applies the merge policy to one address and inserts it at peerSeen if it
// passes. An address already in the table is accepted without re-checking, so a peer
// that was admitted before an operator's ipfilter changed is not silently dropped
// mid-handshake; the periodic round will fail it out instead.
//
// Rejection reasons, in the order they are cheapest to test:
//
//   - malformed, or an address/port eMule's IsGoodServerEntry refuses (private,
//     loopback, multicast, reserved, port 0) unless AllowPrivatePeers
//   - it is us, by advertised address or by any local bind address
//   - it is, or recently was, a connected client
//   - the table is full
func (g *GossipHandler) admitLocked(addr PeerAddr, referer net.IP) bool {
	if addr.IP == nil || addr.Port == 0 {
		g.stats.RejectedBad++
		return false
	}
	addr.IP = NormalizeIP(addr.IP)
	key := addr.String()
	if _, exists := g.peers[key]; exists {
		return true
	}

	if !IsGoodServerEntry(addr.IP, addr.Port, false, g.cfg.AllowPrivatePeers) {
		g.stats.RejectedBad++
		logging.Debugf("gossip: refusing %s: not a usable server address", key)
		return false
	}
	if g.isSelfLocked(addr) {
		g.stats.RejectedSelf++
		logging.Debugf("gossip: refusing %s: that is us", key)
		return false
	}
	if seen, ok := g.clientIPs[addr.IP.String()]; ok && time.Since(seen) < recentClientWindow {
		g.stats.RejectedPeer++
		logging.Debugf("gossip: refusing %s: it is a client, not a server (last seen %s ago)",
			key, time.Since(seen).Round(time.Second))
		return false
	}
	if g.cfg.MaxServers > 0 && len(g.peers) >= g.cfg.MaxServers {
		g.stats.RejectedFull++
		logging.Debugf("gossip: refusing %s: table is full (%d)", key, len(g.peers))
		return false
	}

	g.peers[key] = &PeerServer{Addr: addr, State: peerSeen, RefererIP: referer, LastSeen: time.Now()}
	g.stats.Admitted++
	return true
}

// isSelfLocked reports whether an address is one of ours. Checked against the
// advertised endpoint *and* every bind address, because a peer echoes back whatever it
// observed — which on a multi-homed or NATed host need not be the advertised IP. The
// port is not compared: a second server of ours on another port is still not a peer to
// gossip with, and admitting it would have us handshake with ourselves.
func (g *GossipHandler) isSelfLocked(addr PeerAddr) bool {
	ip := addr.IP.String()
	if g.cfg.SelfIPv4 != nil && NormalizeIP(g.cfg.SelfIPv4).String() == ip {
		return true
	}
	if g.cfg.SelfIPv6 != nil && NormalizeIP(g.cfg.SelfIPv6).String() == ip {
		return true
	}
	_, ok := g.localIPs[ip]
	return ok
}

// senderIsKnownLocked reports whether we have at least exchanged a bootstrap ping with
// this address, which is the bar for trusting a peer list from it.
func (g *GossipHandler) senderIsKnownLocked(ip net.IP) bool {
	p := g.findByIPLocked(ip)
	return p != nil && p.State >= peerKeyed
}

// findByIPLocked locates a peer by IP alone. The receive path knows only the source
// address, and a peer's source port for gossip is its obfuscated port rather than the
// eD2K port it is keyed on, so the lookup cannot use the full endpoint.
//
// One server per IP is assumed. Two eD2K servers behind one address is possible in
// principle but the protocol gives us no way to tell their datagrams apart, and eserver
// has the same limitation.
func (g *GossipHandler) findByIPLocked(ip net.IP) *PeerServer {
	want := NormalizeIP(ip).String()
	for _, p := range g.peers {
		if p.Addr.IP.String() == want {
			return p
		}
	}
	return nil
}

// promoteLocked advances a peer's state, never regressing it. Monotonic because the
// phases complete out of order in practice — a peer may answer our description probe
// before its list reply arrives — and a later-arriving earlier phase must not undo
// progress.
func (g *GossipHandler) promoteLocked(p *PeerServer, to peerState) {
	if to > p.State {
		logging.Debugf("gossip: %s %s -> %s", p.Addr, p.State, to)
		p.State = to
	}
	// Stamped on reaching the admission bar, not only the top state, because Verified()
	// sorts on it — a peer at peerDescribed with a zero timestamp would always sort last
	// and be the first dropped when a list is truncated to 255.
	if to >= advertisableState {
		p.LastVerified = time.Now()
	}
}

// validServerName screens a peer's advertised name, as eserver does before adding it.
// A name is required, bounded, and must not contain control characters — it reaches
// logs, the admin page and other servers' lists, so an unbounded or control-laden
// string from an unauthenticated source is not something to store.
func validServerName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	return !hasControlChars(name)
}

// validServerDesc screens the description. Empty is allowed — plenty of real servers
// set no description — but the same length and control-character limits apply.
func validServerDesc(desc string) bool {
	if len(desc) > 512 {
		return false
	}
	return !hasControlChars(desc)
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
