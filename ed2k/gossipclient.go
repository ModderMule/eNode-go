package ed2k

import (
	"net"
	"sync"
	"time"

	"enode/logging"
)

// The outbound half of gossip: one round per interval, four phases per peer.
//
// Every frame is a fire-and-forget write through one of the *listener* sockets, never
// a freshly dialled one. That is not a stylistic choice — it is the constraint the
// original binary enforces. eserver checks the source port of an obfuscated frame
// against the portUDPobf the sender advertises and skips the peer when they disagree
// ("continue because portUDPobf(%d) != sin_port(%d)"). A socket from net.Dial would
// carry an ephemeral source port, so the peer would either ignore us or record that
// ephemeral port as our server port — which is where the reference implementation's
// "phantom clones on port 36258" came from.
//
// Because the writes are fire-and-forget, nothing here waits for a reply. The inbound
// handlers advance the state machine when the answers arrive, and the next round acts
// on whatever state the peer has reached. That makes the loop a plain scheduler with no
// per-peer goroutine, no timeouts and no pending-request bookkeeping.

// UDPWriter is the subset of *net.UDPConn the loop needs. An interface so a test can
// capture frames without binding a socket.
type UDPWriter interface {
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
}

// GossipClientConfig wires the loop to its two sockets and its cadence.
type GossipClientConfig struct {
	// Main is the plaintext eD2K UDP listener (P+4). Phase 1 leaves from here so the
	// peer's plaintext reply lands on the socket that handles plaintext.
	Main UDPWriter
	// Gossip is the obfuscated server-to-server listener (P+14). Phases 2-4 leave from
	// here, and its bound port is what we advertise as portUDPOBF — see the note above
	// on why that must match.
	Gossip UDPWriter
	// MainPort and GossipPort are those sockets' bound ports, used to compute a peer's
	// destination ports from its eD2K port.
	MainPort   uint16
	GossipPort uint16
	// Interval is how often a round runs.
	Interval time.Duration
}

// Lugdunum's port offsets from a server's eD2K TCP port. Defaults, not invariants:
// portUDPOBF and portOtherServers are donkey.ini parameters, so a peer may have moved
// them. These are only used until the peer tells us otherwise in its 0x97 — see
// gossipDestPorts.
const (
	// peerMainUDPOffset is where plaintext server-to-server and client queries go.
	peerMainUDPOffset = 4
	// peerObfPingOffset is the bootstrap ping port. eMule hardwires this offset for its
	// very first obfuscated ping (srchybrid/ServerList.cpp:294), before it has learned
	// anything about the peer, so it is the one offset that can be assumed.
	peerObfPingOffset = 12
	// peerGossipOffset is eserver's portUDPOBF default, used only when the peer has not
	// advertised its own.
	peerGossipOffset = 14
)

// StartGossipClient runs rounds until stop is closed, and returns a function that
// stops it. The first round runs immediately rather than after one interval: a server
// that has just started has an empty peer table and no reason to wait 150 seconds
// before populating it.
func (g *GossipHandler) StartGossipClient(cfg GossipClientConfig) (stop func()) {
	if g == nil {
		return func() {}
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = 150 * time.Second
	}
	done := make(chan struct{})
	go func() {
		g.RunRound(cfg)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				g.RunRound(cfg)
			case <-done:
				return
			}
		}
	}()
	// sync.Once rather than a bool: main.go registers this with defer alongside several
	// other shutdown hooks, and a double close(done) panics. A plain flag would also
	// race if a signal handler and the defer both fired.
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

// RunRound contacts every non-parked peer once. Exported so a test can drive a single
// round deterministically instead of waiting on a ticker.
func (g *GossipHandler) RunRound(cfg GossipClientConfig) {
	if g == nil {
		return
	}
	peers := g.Contactable()
	if len(peers) == 0 {
		return
	}
	for _, p := range peers {
		g.contactPeer(cfg, p)
	}
	logging.Debugf("gossip: round contacted %d peer(s), %d verified", len(peers), len(g.Verified()))
}

// contactPeer sends whatever the peer's current state calls for.
//
// Phase 1 runs for a peer we have not keyed yet; phases 3 and 4 need the ServerKey that
// phase 2's reply carries. The bootstrap ping (phase 2) is sent on *every* round even
// for an already-keyed peer: a peer rotates its ServerKey when our observed address
// changes (eMule's CServer::GetServerKeyUDP returns 0 in that case,
// srchybrid/Server.cpp:279-291), so re-pinging is how a key stays fresh.
func (g *GossipHandler) contactPeer(cfg GossipClientConfig, p PeerServer) {
	if p.State < peerKeyed {
		g.sendPhase1(cfg, p)
	}
	g.sendPhase2(cfg, p)
	if p.State >= peerKeyed && p.ServerKey != 0 {
		g.sendPhase3(cfg, p)
		g.sendPhase4(cfg, p)
	}
	// Counted as a failure now and cleared by any inbound frame from this peer. A round
	// that produces an answer therefore never accumulates, while a peer that has gone
	// away climbs to maxFailures and parks.
	g.NoteRoundFailure(p.Addr)
}

// sendPhase1 is the plaintext bootstrap: "here I am" plus a status probe, from our main
// UDP socket to the peer's.
//
// The 0x96 challenge follows eMule's convention, uChallenge = 0x55AA0000 +
// GetRandomUInt16() (srchybrid/ServerList.cpp:306). Note what that marker does *not*
// do: it does not select the extended reply. Measured against eserver 17.14, a plain
// 0x96 carrying a 0x55AA-prefixed challenge comes back as 32 bytes of payload with no
// ServerKey — the extended form only ever arrives on the obfuscated channel, which is
// why phase 2 exists at all and why phase 1 alone can never key a peer.
func (g *GossipHandler) sendPhase1(cfg GossipClientConfig, p PeerServer) {
	if cfg.Main == nil || g.cfg.SelfIPv4 == nil {
		// With no routable IPv4 of our own there is nothing truthful to put in 0xA0's
		// address field, so registration is skipped; the peer can still learn about us
		// from our obfuscated frames.
		return
	}
	dst := &net.UDPAddr{IP: p.Addr.IP, Port: int(p.Addr.Port) + peerMainUDPOffset}
	challenge := 0x55AA0000 | uint32(Rand(0xffff))

	if pkt, err := BuildServerListReqPacket(g.cfg.SelfIPv4, g.cfg.SelfPort, challenge); err == nil {
		g.writeTo(cfg.Main, dst, pkt.Bytes(), "phase1 0xA0", p)
	}
	if pkt, err := MakeUDPPacket(PrED2K, []PacketItem{
		{Type: TypeUint8, Value: OpGlobServStatReq},
		{Type: TypeUint32, Value: challenge},
	}); err == nil {
		// Recorded separately from the phase-2 ping challenge: both probes are outstanding
		// at once and their replies arrive independently, so one field cannot hold both.
		g.SetPlainChallenge(p.Addr, challenge)
		g.writeTo(cfg.Main, dst, pkt.Bytes(), "phase1 0x96", p)
	}
}

// sendPhase2 is the obfuscated bootstrap ping: a raw, unencrypted challenge to the
// peer's +12 port, from our gossip socket.
//
// Unencrypted because we hold no key for this peer yet — obtaining one is the point.
// eMule is explicit ("we don't encrypt raw packets (!)", srchybrid/UDPSocket.cpp:762).
// The reply is obfuscated and RC4-keyed on the challenge we just sent, which is why the
// challenge is recorded before the write rather than after.
//
// Sent to +12 rather than the peer's advertised portUDPOBF because +12 is the bootstrap
// port by definition: it is where eMule sends its first obfuscated ping before it has
// learned anything (ServerList.cpp:294), and the one offset a peer cannot have moved
// without becoming unreachable to stock clients too.
func (g *GossipHandler) sendPhase2(cfg GossipClientConfig, p PeerServer) {
	if cfg.Gossip == nil {
		return
	}
	packet, challenge, err := BuildObfPingRequest()
	if err != nil {
		logging.Debugf("gossip: cannot build a bootstrap ping for %s: %v", p.Addr, err)
		return
	}
	g.SetOurChallenge(p.Addr, challenge)
	dst := &net.UDPAddr{IP: p.Addr.IP, Port: int(p.Addr.Port) + peerObfPingOffset}
	g.writeTo(cfg.Gossip, dst, packet, "phase2 obf-ping", p)
}

// sendPhase3 is the obfuscated gossip exchange, from our gossip socket to the peer's
// advertised portUDPOBF.
//
// Every frame is wrapped with the peer's own ServerKey and the client->server direction
// byte, which is what proves to the peer that we hold a key it issued for our address —
// something a client masquerading as a server cannot obtain. Reaching the peer
// obfuscated is the whole trust mechanism; a plaintext 0xA0 would be logged and dropped
// ("ignore non obfuscated OP_SERVER_LIST_REQ").
//
// No unsolicited 0x97 is sent here, and that is a correction from interop rather than an
// omission. A peer keeps its own per-peer ping challenge and rejects any 0x97 that does not
// echo it — eserver logs "server %s:%d sent a bad challenge %x instead of %x", which is
// exactly what an unsolicited echo produced, because the challenge from its 0xA0
// registration is a different value from the one its ping carries. Worse, the rejection
// resets its ping bookkeeping for us ("reseting sping server %s:%d"), so we never became a
// "working" server and never entered its server.met.
//
// The peer gets everything it needs — our obfuscation ports and the ServerKey it must use —
// from our direct reply to its own ping, which the inbound UDP handler already sends with
// the correct challenge echoed. That is the only path that can be correct, since only the
// reply knows which challenge was asked.
func (g *GossipHandler) sendPhase3(cfg GossipClientConfig, p PeerServer) {
	if cfg.Gossip == nil {
		return
	}
	dst := &net.UDPAddr{IP: p.Addr.IP, Port: int(gossipDestPort(p))}
	crypt := NewUDPCrypt(true, p.ServerKey)

	if g.cfg.SelfIPv4 != nil {
		if pkt, err := BuildServerListReqPacket(g.cfg.SelfIPv4, g.cfg.SelfPort, p.OurChallenge); err == nil {
			g.writeObf(cfg.Gossip, dst, crypt, pkt.Bytes(), "phase3 0xA0", p)
		}
	}
	if pkt, err := BuildServerListReq2Packet(); err == nil {
		g.writeObf(cfg.Gossip, dst, crypt, pkt.Bytes(), "phase3 0xA4", p)
	}
	// Only ask for v6 peers from a peer that advertised IPv6 support. A stock eserver
	// would log 0xA7 as an unknown opcode; there is no value in making it do that.
	if g.cfg.PublishIPv6 && p.UDPFlags&FlagIPv6 != 0 {
		if pkt, err := BuildServerListReqIPv6Packet(); err == nil {
			g.writeObf(cfg.Gossip, dst, crypt, pkt.Bytes(), "phase3 0xA7", p)
		}
	}
}

// sendPhase4 probes the peer's name and description, obfuscated on the gossip socket.
//
// This is the admission test the earlier reconstruction of the protocol missed
// entirely. eserver sends OP_SERVERDESCREQ to a candidate and only records it after a
// well-formed reply — its strings are servdescreply(), "received a bad name:desc reply
// from server %s:%d (bad name)/(bad desc)", and then "Adding server %s:%d name=%s
// desc=%s". A peer that answers everything else but has no usable name is not admitted.
//
// The extended form (challenge + tags) is sent rather than the bare request: our own
// handler discriminates on payload length, and a peer that only understands the old
// form answers with the old one anyway, which NoteDescription accepts either way.
func (g *GossipHandler) sendPhase4(cfg GossipClientConfig, p PeerServer) {
	if cfg.Gossip == nil {
		return
	}
	dst := &net.UDPAddr{IP: p.Addr.IP, Port: int(gossipDestPort(p))}
	crypt := NewUDPCrypt(true, p.ServerKey)
	pkt, err := MakeUDPPacket(PrED2K, []PacketItem{
		{Type: TypeUint8, Value: OpServerDescReq},
		{Type: TypeUint32, Value: p.OurChallenge},
	})
	if err != nil {
		return
	}
	g.writeObf(cfg.Gossip, dst, crypt, pkt.Bytes(), "phase4 0xA2", p)
}

// writeTo sends a plaintext frame.
func (g *GossipHandler) writeTo(w UDPWriter, dst *net.UDPAddr, data []byte, what string, p PeerServer) {
	if w == nil {
		return
	}
	if _, err := w.WriteToUDP(data, dst); err != nil {
		logging.Debugf("gossip: %s to %s failed: %v", what, dst, err)
		return
	}
	LogUDPRaw("gossip", "send", dst.String(), data)
	logging.Debugf("gossip: sent %s to %s (peer %s state=%s)", what, dst, p.Addr, p.State)
}

// writeObf wraps a frame in the peer's ServerKey and sends it.
//
// The envelope is eMule's CEncryptedDatagramSocket server-UDP format, unchanged — the
// same UDPCrypt used for the client-facing obfuscated listener. Two things differ from
// that case, and both matter:
//
//   - the key input is the ServerKey the *peer* published to us, not deriveUDPKey over
//     our own secret. That single substitution is the whole of what "Lugdunum
//     server-to-server obfuscation" amounts to.
//   - the direction byte is the client->server one (EncryptAsClient, 0x6B), because
//     here we are the sender addressing a peer rather than a server answering a client.
//     Using Encrypt (0xA5) produces something the peer cannot decrypt, and it fails
//     silently — the peer just sees junk that misses its magic check.
func (g *GossipHandler) writeObf(w UDPWriter, dst *net.UDPAddr, crypt *UDPCrypt, plain []byte, what string, p PeerServer) {
	if w == nil {
		return
	}
	g.writeTo(w, dst, crypt.EncryptAsClient(plain), what, p)
}

// gossipDestPort resolves where phase 3 and 4 frames go.
//
// The peer's advertised portUDPOBF wins whenever it has told us one, because
// portUDPOBF is a donkey.ini parameter and a peer that moved it is unreachable at the
// default. Only when nothing has been advertised does the +14 default apply.
func gossipDestPort(p PeerServer) uint16 {
	if p.UDPPortObf != 0 {
		return p.UDPPortObf
	}
	return p.Addr.Port + peerGossipOffset
}
