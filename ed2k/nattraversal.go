package ed2k

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"enode/logging"
)

const (
	DefaultNATTraversalPort = 2004
	defaultNATRegistryTTL   = 90 * time.Second
	defaultNATCleanupEvery  = 10 * time.Second
	// natWakeMaxPending caps the targets waiting on a wake at once. Beyond it a SYNC2
	// for an unregistered target fails at once, as without the wake.
	natWakeMaxPending = 4096
	// natWakeMaxWaiters caps the requesters waiting on one target.
	natWakeMaxWaiters = 4
)

// natWakeTimeout is how long a SYNC2 waits for a woken target's REGISTER before the
// requester gets OP_NAT_FAILED 0x01. ed2k-server's extension waits 3 s too. A variable
// so tests can shorten it.
var natWakeTimeout = 3 * time.Second

// natWakeIPv6Grace is how long a wait that asked for IPv6 holds on after the target's
// IPv4 REGISTER arrived first, so the pairing can still be IPv6. A variable for tests.
var natWakeIPv6Grace = 500 * time.Millisecond

// OP_NAT_WAKE family bits: which families the woken target should REGISTER over.
const (
	NatWakeIPv4 byte = 0x01
	NatWakeIPv6 byte = 0x02
)

// OP_NAT_FAILED reason codes (payload byte 0).
const (
	natFailReasonNotRegistered        uint8 = 0x01 // the target hash is not registered
	natFailReasonNoCommonFamily       uint8 = 0x02 // src and dst share no address family
	natFailReasonRendezvousRestricted uint8 = 0x03 // server-independent off and a peer is not logged in here
)

type NATTraversalConfig struct {
	Enabled                bool
	Port                   uint16
	RegistrationTTLSeconds int
}

// natCandidate is one reachable endpoint of a client, per address family. A
// dual-stack client accumulates both a v4 and a v6 candidate under one hash; each
// keeps its own lastSeen so a stale candidate is expired before it can be handed to
// a peer as a punch target. It is the snapshot form get() hands out; the registry
// itself stores natSlot.
type natCandidate struct {
	addr     *net.UDPAddr
	lastSeen time.Time
	sock     uint8 // natSlot.sock
}

type natClientEntry struct {
	hash    [16]byte
	v4      *natCandidate // nil until the client registers over IPv4
	v6      *natCandidate // nil until the client registers over IPv6
	version uint8
}

// natEndpoint is a UDP endpoint in a fixed-size, comparable form, so it can key the
// keepalive index. The IP is in its 16-byte form: IPv4 as v4-mapped, which is also how
// a dual-stack socket reports it, so both spellings of one IPv4 meet on the same key.
type natEndpoint struct {
	ip   [16]byte
	port uint16
}

// natSlot is one stored candidate. seen is the handler tick (natTick) of the last
// REGISTER or keepalive; 0 means the slot is empty, and a slot older than the TTL is
// treated as empty before the sweep removes it (see liveSlot). Values, not pointers, and
// a 32-bit tick rather than a time.Time: an entry costs no allocations of its own, which
// pays for the index.
type natSlot struct {
	ep natEndpoint
	// sock is the server socket that REGISTER or keepalive arrived on: 1 + its index in
	// NATTraversalHandler.socks, 0 when unknown. A forward to this candidate leaves from
	// that socket, the one its NAT mapping is open to. Fits in ep's padding, costs nothing.
	sock uint8
	seen uint32
}

type natStoredEntry struct {
	v4, v6  natSlot
	version uint8
}

type natOutbound struct {
	to     *net.UDPAddr
	packet []byte
	// via, when set, is the socket this datagram leaves from instead of the one the
	// current datagram arrived on: a SYNC to a requester that is waiting on a wake goes
	// out through the socket its own SYNC2 came in on, which its NAT mapping expects.
	via UDPReplyConn
	// forward marks the SYNC to the target of a pairing: it leaves from the target's
	// own socket (sock, see natSlot.sock) and, over IPv6, from the announced IPv6.
	forward bool
	sock    uint8
}

// natWakeWaiter is one requester whose SYNC2 is waiting on a woken target.
type natWakeWaiter struct {
	hash    [16]byte
	connAck [4]byte
	remote  *net.UDPAddr
	conn    UDPReplyConn
}

// natWakePending is a target that was sent OP_NAT_WAKE and has not registered yet.
type natWakePending struct {
	families byte
	waiters  []natWakeWaiter
	timer    *time.Timer
	// graced is set once the target's IPv4 arrived and the timer was cut to
	// natWakeIPv6Grace, waiting for its IPv6.
	graced bool
}

type NATTraversalHandler struct {
	mu  sync.RWMutex
	ttl time.Duration
	// epoch is when the handler was made; natSlot.seen counts milliseconds from it.
	epoch   time.Time
	entries map[[16]byte]natStoredEntry
	// byAddr indexes every stored candidate by its endpoint, so a keepalive, which
	// carries no hash, finds its entry in one lookup instead of a scan of the registry.
	// Every write to a slot's endpoint goes through setSlot/clearSlot, which keep it
	// in step.
	byAddr              map[natEndpoint][16]byte
	announceIPv4        uint32
	announceIPv6        [16]byte
	announcePort        uint16
	announcePortByLocal map[uint16]uint16
	ipv6Enabled         bool
	// serverIndependent, when true (default), pairs any two registered hashes
	// regardless of eD2K login — cross-server / serverless rendezvous. When false,
	// isLocalMember gates SYNC2 to hashes currently logged into this server.
	serverIndependent bool
	isLocalMember     func(hash [16]byte) bool
	// sessionTouch, when set, is called with a user hash whose PR_NAT keepalive just
	// arrived, so the eD2K TCP session for that user can have its idle deadline extended.
	// A hook rather than a direct dependency because NATTraversalHandler must stay usable
	// without a ServerRuntime — the natsim tools and most of its tests do exactly that.
	sessionTouch func(hash [16]byte)
	// sessionAddrs, when set, reports the addresses of the eD2K session logged in here
	// under a user hash (local=false when there is none). REGISTER for such a hash is
	// accepted only from those addresses; see registerAllowed.
	sessionAddrs func(hash [16]byte) (v4, v6 net.IP, local bool)
	// sessionWake, when set, sends OP_NAT_WAKE to the session logged in here under a
	// user hash, asking it to REGISTER over the given families. It reports false when
	// there is no such session or it did not announce SrvCapNatWake.
	sessionWake func(hash [16]byte, families byte) bool
	// pending holds targets that were woken and have not registered yet. Only attempts
	// in flight are in it, for at most natWakeTimeout each.
	pending map[[16]byte]*natWakePending
	// socks are the server sockets PR_NAT arrived on (natSlot.sock - 1 indexes it),
	// without arrival-address pin, learned by local port. A handful: 2004, udp.port,
	// the obfuscated and the gossip port.
	socks      []UDPReplyConn
	sockByPort map[uint16]uint8
}

// SetSessionAddrs registers the lookup registerAllowed binds a REGISTER to. Mirrors
// SetSessionTouch: the runtime supplies it, and it is optional.
func (h *NATTraversalHandler) SetSessionAddrs(fn func(hash [16]byte) (v4, v6 net.IP, local bool)) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessionAddrs = fn
}

// SetSessionTouch registers the callback invoked when a PR_NAT keepalive identifies a
// user. Mirrors SetLocalMembership: the runtime supplies it, and it is optional.
func (h *NATTraversalHandler) SetSessionTouch(fn func(hash [16]byte)) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessionTouch = fn
}

// touchSession invokes the callback outside the handler's lock.
//
// Outside deliberately: the callback reaches into ServerRuntime to find a session and set
// a socket deadline, and holding the NAT lock across that would couple two independent
// lock orders — the classic way to acquire a deadlock later.
func (h *NATTraversalHandler) touchSession(hash [16]byte) {
	h.mu.RLock()
	fn := h.sessionTouch
	h.mu.RUnlock()
	if fn != nil {
		fn(hash)
	}
}

func NewNATTraversalHandler(registrationTTL time.Duration) *NATTraversalHandler {
	if registrationTTL <= 0 {
		registrationTTL = defaultNATRegistryTTL
	}
	return &NATTraversalHandler{
		ttl:                 registrationTTL,
		epoch:               time.Now(),
		entries:             map[[16]byte]natStoredEntry{},
		byAddr:              map[natEndpoint][16]byte{},
		pending:             map[[16]byte]*natWakePending{},
		announcePortByLocal: map[uint16]uint16{},
		sockByPort:          map[uint16]uint8{},
		// Default to the historical open behaviour: pair any registered pair. main.go
		// overrides this from natTraversal.serverIndependent.
		serverIndependent: true,
	}
}

// ConfigureRegisterEndpointFromConfig stores dynIp/address hints used by HandlePacket.
// Priority is dynIp first, then address.
func (h *NATTraversalHandler) ConfigureRegisterEndpointFromConfig(dynIP, address string, port uint16) {
	if h == nil {
		return
	}
	ip := dynIP
	if ip == "" {
		ip = address
	}
	h.SetRegisterEndpoint(ip, port)
}

// SetRegisterEndpoint sets the endpoint returned in OP_NAT_REGISTER ACK.
// If ip is empty/invalid, handler falls back to local socket address.
func (h *NATTraversalHandler) SetRegisterEndpoint(ip string, port uint16) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.announceIPv4 = 0
	h.announcePort = 0
	if parsed := net.ParseIP(ip); parsed != nil {
		h.announceIPv4 = ipv4ToUint32(parsed)
	}
	if port != 0 {
		h.announcePort = port
	}
}

// SetRegisterEndpointForLocalPort overrides the OP_NAT_REGISTER ACK port
// based on the local listener port which received the registration packet.
func (h *NATTraversalHandler) SetRegisterEndpointForLocalPort(localPort uint16, announcePort uint16) {
	if h == nil || localPort == 0 || announcePort == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.announcePortByLocal == nil {
		h.announcePortByLocal = map[uint16]uint16{}
	}
	h.announcePortByLocal[localPort] = announcePort
}

// SetRegisterEndpointV6 sets the server's public IPv6 returned in the
// OP_NAT_REGISTER_IPV6 ack to a client that registered over IPv6. An all-zero value
// (empty or wrong-length input) leaves it unset; the ack then carries zeros and the
// client keeps using the address it dialed. See docs/ipv6-client-implementation-spec.md §9.
func (h *NATTraversalHandler) SetRegisterEndpointV6(ipv6 []byte) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.announceIPv6 = [16]byte{}
	if len(ipv6) == 16 {
		copy(h.announceIPv6[:], ipv6)
	}
}

// SetIPv6Enabled toggles dual-stack hole-punching. When false (the default) the
// handler declines PR_NAT datagrams that arrive over IPv6, exactly as before v6
// support was added; when true a v6 datagram is registered into the client's IPv6
// candidate slot and paired the same way as IPv4.
func (h *NATTraversalHandler) SetIPv6Enabled(enabled bool) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ipv6Enabled = enabled
}

func (h *NATTraversalHandler) isIPv6Enabled() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ipv6Enabled
}

// SetServerIndependent toggles cross-server / serverless rendezvous. When true (the
// default) SYNC2 pairs any two registered hashes; when false pairing is restricted to
// hashes SetLocalMembership reports as logged into this server, and a non-local peer
// gets OP_NAT_FAILED reason 0x03. See docs/ipv6-client-implementation-spec.md §9.
func (h *NATTraversalHandler) SetServerIndependent(enabled bool) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.serverIndependent = enabled
}

// SetLocalMembership installs the predicate used, when server-independent rendezvous
// is off, to decide whether a user hash is currently logged into this server. A nil
// predicate makes the restricted mode refuse every pairing (fail closed).
func (h *NATTraversalHandler) SetLocalMembership(member func(hash [16]byte) bool) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.isLocalMember = member
}

// rendezvousGate returns the current server-independent flag and the membership
// predicate under a single read lock, so handleSync2 sees a consistent pair.
func (h *NATTraversalHandler) rendezvousGate() (bool, func(hash [16]byte) bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.serverIndependent, h.isLocalMember
}

// HandlePacket answers one PR_NAT datagram. PR_NAT is plaintext on every listener:
// the caller hands it the datagram as it arrived, before any eD2K deobfuscation, and
// every reply and forward goes out in plaintext. An obfuscated reply could not be read
// by the client, and a forward encrypted with the requester's key not by the target.
func (h *NATTraversalHandler) HandlePacket(data []byte, remote *net.UDPAddr, conn UDPReplyConn) {
	if len(data) == 0 || remote == nil || conn == nil {
		return
	}
	if data[0] == PrNat {
		LogNATRaw("nat", "recv", remote.String(), data)
	}
	localPort := uint16(0)
	if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && localAddr != nil && localAddr.Port > 0 {
		localPort = uint16(localAddr.Port)
	}
	h.send(conn, conn, remote, h.processPacketFrom(data, remote, localPort, conn))
}

func (h *NATTraversalHandler) StartCleanup(interval time.Duration) func() {
	if interval <= 0 {
		interval = defaultNATCleanupEvery
	}
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				h.cleanup()
			case <-stop:
				return
			}
		}
	}()
	return func() { close(stop) }
}

func (h *NATTraversalHandler) processPacket(data []byte, remote *net.UDPAddr, localPort uint16) []natOutbound {
	return h.processPacketFrom(data, remote, localPort, nil)
}

// processPacketFrom is processPacket with the socket the datagram arrived on, which a
// SYNC2 waiting on a wake keeps for its later answer. conn may be nil (tests): the
// answer to a wait that times out is then dropped.
func (h *NATTraversalHandler) processPacketFrom(data []byte, remote *net.UDPAddr, localPort uint16, conn UDPReplyConn) []natOutbound {
	if len(data) == 0 || remote == nil {
		return nil
	}
	sock := h.socketIndex(conn, localPort)
	if len(data) == 1 {
		hash, matched := h.touchByAddr(remote, sock)
		logging.Debugf(
			"[module=nat] dir=recv, remote=%s, opcode=KEEPALIVE(1-byte), value=0x%02x, matched=%t",
			remote.String(), data[0], matched,
		)
		if matched {
			// The 1-byte keepalive counts as session liveness too, exactly as the full
			// OP_NATKEEPALIVE does — a client using the short form is no less alive.
			h.touchSession(hash)
			return []natOutbound{{
				to:     cloneUDPAddr(remote),
				packet: encodeNATPacket(OpNatPing, nil),
			}}
		}
		return nil
	}
	if data[0] != PrNat {
		return nil
	}
	opcode, payload, ok := decodeNATPacket(data)
	if !ok {
		return nil
	}
	// PR_NAT hole-punching is dual-stack when v6 is enabled: a datagram that arrives
	// over IPv6 is registered into the client's IPv6 candidate slot and paired the
	// same way as IPv4 (see docs/ipv6-client-implementation-spec.md §9). When v6-NAT
	// is disabled we keep the legacy behaviour and decline the datagram so no v6
	// endpoint is ever stored — otherwise buildNATSyncPacket would serialise it as
	// 0.0.0.0 and silently poison a v4 pairing.
	if remoteIsIPv6(remote) && !h.isIPv6Enabled() {
		logging.Debugf(
			"[module=nat] dir=recv, remote=%s, opcode=%s, declined=ipv6-disabled",
			remote.String(), natOpcodeLabel(opcode),
		)
		return nil
	}
	switch opcode {
	case OpNatRegister:
		return h.handleRegister(remote, payload, localPort, sock, false)
	case OpNatRegisterEx:
		return h.handleRegister(remote, payload, localPort, sock, true)
	case OpNatKeepAlive:
		hash, matched := h.touchByAddr(remote, sock)
		logging.Debugf(
			"[module=nat] dir=recv, remote=%s, opcode=%s, payloadLen=%d, matched=%t",
			remote.String(), natOpcodeLabel(OpNatKeepAlive), len(payload), matched,
		)
		if matched {
			// A keepalive proves the client is alive, so it also counts as liveness for its
			// eD2K TCP session. Without this a share-only LowID client — one that publishes
			// files, keeps its PR_NAT registration fresh, but sends no TCP traffic for hours
			// — is reaped by the TCP read deadline (disconnectTimeout, 3600 s by default)
			// and all of its sources vanish, even though it is plainly reachable.
			h.touchSession(hash)
			return []natOutbound{{
				to:     cloneUDPAddr(remote),
				packet: encodeNATPacket(OpNatPing, nil),
			}}
		}
		return nil
	case OpNatSync2:
		return h.handleSync2(remote, payload, conn, sock)
	default:
		return nil
	}
}

func (h *NATTraversalHandler) handleRegister(remote *net.UDPAddr, payload []byte, localPort uint16, sock uint8, isEx bool) []natOutbound {
	if len(payload) < 16 {
		return nil
	}
	var hash [16]byte
	copy(hash[:], payload[:16])
	version := uint8(0)
	if isEx && len(payload) >= 17 {
		version = payload[16]
	}
	if ok, reason := h.registerAllowed(hash, remote); !ok {
		logging.Debugf("[module=nat] dir=recv, remote=%s, opcode=%s, hash=%x, declined=%s",
			remote.String(), natOpcodeLabel(OpNatRegister), hash[:], reason)
		return nil
	}
	h.upsert(hash, remote, version, sock)
	// A woken target's REGISTER completes the SYNC2s waiting on it, after the ack.
	paired := h.completeWake(hash, remote)

	h.mu.RLock()
	port := h.announcePort
	if p, ok := h.announcePortByLocal[localPort]; ok && p != 0 {
		port = p
	}
	ipv4 := h.announceIPv4
	ipv6 := h.announceIPv6
	v6Enabled := h.ipv6Enabled
	h.mu.RUnlock()

	// A v6 registrant gets the widened OP_NAT_REGISTER_IPV6 ack carrying the server's
	// public IPv6; the port is the same family-independent value the v4 ack uses.
	if v6Enabled && remoteIsIPv6(remote) {
		resp := make([]byte, 18)
		binary.BigEndian.PutUint16(resp[0:2], port)
		copy(resp[2:18], ipv6[:])
		return append([]natOutbound{{
			to:     cloneUDPAddr(remote),
			packet: encodeNATPacket(OpNatRegisterIPv6, resp),
		}}, paired...)
	}

	resp := make([]byte, 6)
	binary.BigEndian.PutUint16(resp[0:2], port)
	binary.BigEndian.PutUint32(resp[2:6], ipv4)
	return append([]natOutbound{{
		to:     cloneUDPAddr(remote),
		packet: encodeNATPacket(OpNatRegister, resp),
	}}, paired...)
}

func (h *NATTraversalHandler) handleSync2(remote *net.UDPAddr, payload []byte, conn UDPReplyConn, sock uint8) []natOutbound {
	if len(payload) < 36 {
		return nil
	}
	var srcHash [16]byte
	var dstHash [16]byte
	var connAck [4]byte
	copy(srcHash[:], payload[0:16])
	copy(connAck[:], payload[16:20])
	copy(dstHash[:], payload[20:36])

	// Auto-register the requester's candidate for the family this SYNC2 arrived on
	// when that slot is empty, preserving the classic "SYNC2 implies register"
	// robustness. upsert with version 0 keeps any version an earlier REGISTER_EX set.
	src, srcFound := h.get(srcHash)
	if !srcFound || familySlot(src, remote) == nil {
		if ok, _ := h.registerAllowed(srcHash, remote); ok {
			h.upsert(srcHash, remote, 0, sock)
			src, _ = h.get(srcHash)
		}
	}
	dst, dstOK := h.get(dstHash)
	v6Enabled := h.isIPv6Enabled()
	logging.Debugf(
		"[module=nat] dir=recv, remote=%s, opcode=%s, srcHash=%x, srcFound=%t, src(v4=%s,v6=%s), dstHash=%x, dstFound=%t, dst(v4=%s,v6=%s), registrySize=%d, ttlSec=%d",
		remote.String(),
		natOpcodeLabel(OpNatSync2),
		srcHash[:], srcFound, formatCandidate(src.v4), formatCandidate(src.v6),
		dstHash[:], dstOK, formatCandidate(dst.v4), formatCandidate(dst.v6),
		h.entryCount(),
		int(h.ttl/time.Second),
	)
	if !dstOK {
		// No live registration (none, or every candidate past the TTL): a target logged in here that asked for it is woken over
		// TCP instead, and the answer comes when it registers (or after natWakeTimeout).
		if h.wakeTarget(src, dstHash, connAck, remote, conn) {
			return nil
		}
		return []natOutbound{h.natFailed(remote, dstHash, natFailReasonNotRegistered)}
	}

	// Server-independent gate (family-agnostic, applied before family selection):
	// when off, only pair hashes currently logged into this server. A nil predicate
	// fails closed. When on (default) the check is skipped, keeping the open path
	// free of any login coupling.
	if serverIndependent, member := h.rendezvousGate(); !serverIndependent {
		srcLocal := member != nil && member(srcHash)
		dstLocal := member != nil && member(dstHash)
		if !srcLocal || !dstLocal {
			logging.Debugf(
				"[module=nat] dir=recv, remote=%s, opcode=%s, restricted=server-independent-off, srcLocal=%t, dstLocal=%t",
				remote.String(), natOpcodeLabel(OpNatSync2), srcLocal, dstLocal,
			)
			return []natOutbound{h.natFailed(remote, dstHash, natFailReasonRendezvousRestricted)}
		}
	}

	if out := pairOutbound(src, dst, connAck[:], v6Enabled); out != nil {
		return out
	}
	// Registered, but not in a family the requester has: a wake asks for the rest.
	if h.wakeTarget(src, dstHash, connAck, remote, conn) {
		return nil
	}
	return []natOutbound{h.natFailed(remote, dstHash, natFailReasonNoCommonFamily)}
}

// pairOutbound builds the two SYNCs that introduce src and dst on a family both have,
// preferring IPv6, or returns nil when they share none. Both endpoints must share a
// family: the two firewalled peers punch directly at each other. [0] answers src, [1]
// is the forward to dst, sent from dst's own socket.
func pairOutbound(src, dst natClientEntry, connAck []byte, v6Enabled bool) []natOutbound {
	switch {
	case v6Enabled && src.v6 != nil && dst.v6 != nil:
		return []natOutbound{
			{
				to:     cloneUDPAddr(src.v6.addr),
				packet: buildNATSyncPacketV6(dst.v6.addr, dst.hash, connAck, dst.version),
			},
			{
				to:      cloneUDPAddr(dst.v6.addr),
				packet:  buildNATSyncPacketV6(src.v6.addr, src.hash, connAck, src.version),
				forward: true,
				sock:    dst.v6.sock,
			},
		}
	case src.v4 != nil && dst.v4 != nil:
		return []natOutbound{
			{
				to:     cloneUDPAddr(src.v4.addr),
				packet: buildNATSyncPacket(dst.v4.addr, dst.hash, connAck, dst.version, src.version),
			},
			{
				to:      cloneUDPAddr(dst.v4.addr),
				packet:  buildNATSyncPacket(src.v4.addr, src.hash, connAck, src.version, dst.version),
				forward: true,
				sock:    dst.v4.sock,
			},
		}
	default:
		return nil
	}
}

func buildNATSyncPacket(peer *net.UDPAddr, peerHash [16]byte, connAck []byte, peerVersion uint8, receiverVersion uint8) []byte {
	payloadSize := 26
	opcode := OpNatSync
	if receiverVersion > 0 {
		opcode = OpNatSyncEx
		payloadSize = 27
	}
	payload := make([]byte, payloadSize)
	if peer != nil {
		binary.BigEndian.PutUint32(payload[0:4], ipv4ToUint32(peer.IP))
		binary.BigEndian.PutUint16(payload[4:6], uint16(peer.Port))
	}
	copy(payload[6:22], peerHash[:])
	copy(payload[22:26], connAck)
	if opcode == OpNatSyncEx {
		payload[26] = peerVersion
	}
	return encodeNATPacket(opcode, payload)
}

// buildNATSyncPacketV6 builds the 39-byte OP_NAT_SYNC_IPV6 relayed to one peer with
// the other peer's public IPv6 endpoint: [ipv6:16][port:2 BE][hash:16][connAck:4]
// [version:1]. Unlike the v4 SYNC there is no EX split — the peer version is always
// present (0 when the peer registered without a version). See §9 of the spec.
func buildNATSyncPacketV6(peer *net.UDPAddr, peerHash [16]byte, connAck []byte, peerVersion uint8) []byte {
	payload := make([]byte, 39)
	if peer != nil {
		if b, ok := IPv6Bytes(peer.IP); ok {
			copy(payload[0:16], b[:])
		}
		binary.BigEndian.PutUint16(payload[16:18], uint16(peer.Port))
	}
	copy(payload[18:34], peerHash[:])
	copy(payload[34:38], connAck)
	payload[38] = peerVersion
	return encodeNATPacket(OpNatSyncIPv6, payload)
}

// natFailed builds an OP_NAT_FAILED outbound to remote: [reason:1][targetHash:16].
func (h *NATTraversalHandler) natFailed(remote *net.UDPAddr, targetHash [16]byte, reason uint8) natOutbound {
	failed := make([]byte, 17)
	failed[0] = reason
	copy(failed[1:], targetHash[:])
	logging.Debugf(
		"[module=nat] dir=send, remote=%s, opcode=%s, reasonCode=0x%02x, targetHash=%x, registry=%s",
		formatUDPAddr(remote), natOpcodeLabel(OpNatFailed), reason, targetHash[:], h.registrySummary(8),
	)
	return natOutbound{
		to:     cloneUDPAddr(remote),
		packet: encodeNATPacket(OpNatFailed, failed),
	}
}

// registerAllowed decides whether remote may become hash's candidate. A user hash is
// public (every OP_HELLO and source list carries it), so an unchecked REGISTER let
// anyone point a victim's candidate at themselves: SYNC2 then sent the victim's peers
// there, and the victim's own keepalives stopped matching while the attacker's kept
// its stale TCP session alive.
//
//   - Logged in here: the REGISTER must come from that session's address — the IPv4
//     exactly, or the IPv6's /64 (privacy addresses rotate within it). A session with
//     no address in the datagram's family falls to the next rule.
//   - Otherwise (server-independent rendezvous): a live candidate is not replaced
//     from a different IP until it expires; the same IP may change port, as a NAT
//     rebinding does.
func (h *NATTraversalHandler) registerAllowed(hash [16]byte, remote *net.UDPAddr) (bool, string) {
	h.mu.RLock()
	lookup := h.sessionAddrs
	h.mu.RUnlock()
	if lookup != nil {
		if v4, v6, local := lookup(hash); local {
			switch {
			case remoteIsIPv6(remote) && v6 != nil:
				if !sameIPv6Prefix64(v6, remote.IP) {
					return false, "not-session-address"
				}
				return true, ""
			case !remoteIsIPv6(remote) && v4 != nil:
				if !v4.Equal(remote.IP) {
					return false, "not-session-address"
				}
				return true, ""
			}
		}
	}
	// get hands out live candidates only, so an expired one never pins.
	entry, ok := h.get(hash)
	if !ok {
		return true, ""
	}
	if c := familySlot(entry, remote); c != nil && !c.addr.IP.Equal(remote.IP) {
		return false, "pinned-to-other-address"
	}
	return true, ""
}

// sameIPv6Prefix64 reports whether two IPv6 addresses share their /64.
func sameIPv6Prefix64(a, b net.IP) bool {
	a16, b16 := a.To16(), b.To16()
	return a16 != nil && b16 != nil && a.To4() == nil && b.To4() == nil && net.IP(a16[:8]).Equal(net.IP(b16[:8]))
}

func (h *NATTraversalHandler) upsert(hash [16]byte, remote *net.UDPAddr, version uint8, sock uint8) {
	h.mu.Lock()
	defer h.mu.Unlock()
	entry := h.entries[hash] // zero value when absent; preserves the other family slot
	if version > 0 {
		entry.version = version
	}
	h.setSlotLocked(hash, &entry, remoteIsIPv6(remote), natEndpointOf(remote), sock, h.tick())
	h.entries[hash] = entry
}

// touchByAddr refreshes the candidate matching a source address and reports whether one
// was found, along with the user hash it belongs to. One index lookup: a keepalive used
// to scan the whole registry under the write lock, which grew with the square of the
// number of registered clients.
//
// The hash is returned so a keepalive can also count as liveness for that user's eD2K TCP
// session — see SetSessionTouch. Without it the caller has proof the client is alive but
// no way to say which client.
//
// A candidate past the TTL does not match even before the sweep removes it: the client
// gets no PING and re-registers. sock is the socket the keepalive arrived on.
func (h *NATTraversalHandler) touchByAddr(remote *net.UDPAddr, sock uint8) (hash [16]byte, matched bool) {
	ep := natEndpointOf(remote)
	h.mu.Lock()
	defer h.mu.Unlock()
	owner, ok := h.byAddr[ep]
	if !ok {
		return hash, false
	}
	entry, ok := h.entries[owner]
	if !ok {
		return hash, false
	}
	slot := entry.slot(remoteIsIPv6(remote))
	now := h.tick()
	if !h.liveSlot(*slot, now) || slot.ep != ep {
		return hash, false
	}
	slot.seen = now
	slot.sock = sock
	h.entries[owner] = entry
	return owner, true
}

// get returns a snapshot of the entry's live candidates, built fresh, so the caller
// holds stable values after the lock is released. It reports false when there is none:
// a candidate past the TTL is gone for pairing even before the sweep removes it.
func (h *NATTraversalHandler) get(hash [16]byte) (natClientEntry, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	v, ok := h.entries[hash]
	if !ok {
		return natClientEntry{}, false
	}
	snap := h.snapshot(v, hash, h.tick(), time.Now())
	if snap.v4 == nil && snap.v6 == nil {
		return natClientEntry{}, false
	}
	return snap, true
}

func (h *NATTraversalHandler) cleanup() {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.tick()
	for k, entry := range h.entries {
		if entry.v4.seen != 0 && !h.liveSlot(entry.v4, now) {
			h.clearSlotLocked(k, &entry, false)
		}
		if entry.v6.seen != 0 && !h.liveSlot(entry.v6, now) {
			h.clearSlotLocked(k, &entry, true)
		}
		if entry.v4.seen == 0 && entry.v6.seen == 0 {
			delete(h.entries, k)
		} else {
			h.entries[k] = entry
		}
	}
}

func (h *NATTraversalHandler) entryCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.entries)
}

// candidateCount reports how many address families (0, 1 or 2) the given hash has a
// live endpoint for. Used by tests to assert the dual-stack registry.
func (h *NATTraversalHandler) candidateCount(hash [16]byte) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	entry, ok := h.entries[hash]
	if !ok {
		return 0
	}
	n := 0
	now := h.tick()
	if h.liveSlot(entry.v4, now) {
		n++
	}
	if h.liveSlot(entry.v6, now) {
		n++
	}
	return n
}

// familySlot returns the entry's candidate for the address family of remote.
func familySlot(entry natClientEntry, remote *net.UDPAddr) *natCandidate {
	if remoteIsIPv6(remote) {
		return entry.v6
	}
	return entry.v4
}

// announcedIPv6 returns the IPv6 sent in the v6 REGISTER ack, or nil when unset.
func (h *NATTraversalHandler) announcedIPv6() net.IP {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.announceIPv6 == ([16]byte{}) {
		return nil
	}
	return net.IP(append([]byte(nil), h.announceIPv6[:]...))
}

func sameEndpoint(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.IP.Equal(b.IP) && a.Port == b.Port
}

func (h *NATTraversalHandler) registrySummary(limit int) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.entries) == 0 {
		return "[]"
	}
	if limit <= 0 {
		limit = len(h.entries)
	}
	var b strings.Builder
	b.WriteString("[")
	i := 0
	for hash, entry := range h.entries {
		if i > 0 {
			b.WriteString("; ")
		}
		snap := h.snapshot(entry, hash, h.tick(), time.Now())
		b.WriteString(fmt.Sprintf("hash=%x v4=%s v6=%s", hash[:], formatCandidate(snap.v4), formatCandidate(snap.v6)))
		i++
		if i >= limit {
			if len(h.entries) > limit {
				b.WriteString("; ...")
			}
			break
		}
	}
	b.WriteString("]")
	return b.String()
}

func formatUDPAddr(addr *net.UDPAddr) string {
	if addr == nil {
		return "-"
	}
	return addr.String()
}

func formatCandidate(c *natCandidate) string {
	if c == nil {
		return "-"
	}
	return formatUDPAddr(c.addr)
}

func encodeNATPacket(opcode uint8, payload []byte) []byte {
	out := make([]byte, 6+len(payload))
	out[0] = PrNat
	binary.LittleEndian.PutUint32(out[1:5], uint32(len(payload)+1))
	out[5] = opcode
	copy(out[6:], payload)
	return out
}

func decodeNATPacket(raw []byte) (uint8, []byte, bool) {
	if len(raw) < 6 || raw[0] != PrNat {
		return 0, nil, false
	}
	sizeWithOpcode := binary.LittleEndian.Uint32(raw[1:5])
	if sizeWithOpcode == 0 {
		return 0, nil, false
	}
	packetEnd := int(sizeWithOpcode) + 5
	if packetEnd > len(raw) {
		return 0, nil, false
	}
	opcode := raw[5]
	payload := append([]byte(nil), raw[6:packetEnd]...)
	return opcode, payload, true
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	ip := append(net.IP(nil), addr.IP...)
	return &net.UDPAddr{IP: ip, Port: addr.Port, Zone: addr.Zone}
}

// ipv4ToUint32 packs an IPv4 address big-endian for the NAT wire format. It
// returns 0 for a non-IPv4 address, but processPacket already declines every v6
// datagram (remoteIsIPv6) before an endpoint can reach here, so the 0 fallback is
// defence-in-depth rather than a reachable path.
func ipv4ToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}

func natOpcodeLabel(opcode uint8) string {
	switch opcode {
	case OpNatRegisterEx:
		return "OP_NATREGISTER_EX(0xe3)"
	case OpNatRegister:
		return "OP_NATREGISTER(0xe4)"
	case OpNatSync2:
		return "OP_NATSYNC2(0xe9)"
	case OpNatSync:
		return "OP_NATSYNC(0xe1)"
	case OpNatSyncEx:
		return "OP_NATSYNC_EX(0xe7)"
	case OpNatFailed:
		return "OP_NATFAILED(0xe5)"
	case OpNatKeepAlive:
		return "OP_NATKEEPALIVE(0xe6)"
	case OpNatPing:
		return "OP_NATPING(0xe2)"
	case OpNatReping:
		return "OP_NATREPING(0xe8)"
	case OpNatData:
		return "OP_NATDATA(0xea)"
	case OpNatAck:
		return "OP_NATACK(0xeb)"
	case OpNatRst:
		return "OP_NATRST(0xef)"
	case OpNatRegisterIPv6:
		return "OP_NATREGISTER_IPV6(0xec)"
	case OpNatSyncIPv6:
		return "OP_NATSYNC_IPV6(0xed)"
	default:
		return fmt.Sprintf("0x%02x", opcode)
	}
}

func formatNATPayload(opcode uint8, payload []byte) string {
	switch opcode {
	case OpNatRegisterEx:
		if len(payload) >= 17 {
			return fmt.Sprintf("hash=%x version=%d", payload[:16], payload[16])
		}
		return fmt.Sprintf("payloadLen=%d hex=%s", len(payload), hex.EncodeToString(payload))
	case OpNatRegister:
		if len(payload) >= 16 {
			out := fmt.Sprintf("hash=%x", payload[:16])
			if len(payload) > 16 {
				out += fmt.Sprintf(" extraLen=%d extraHex=%s", len(payload)-16, hex.EncodeToString(payload[16:]))
			}
			return out
		}
		if len(payload) == 6 {
			port := binary.BigEndian.Uint16(payload[0:2])
			ipv4 := binary.BigEndian.Uint32(payload[2:6])
			return fmt.Sprintf("serverPort=%d serverIP=%d serverIPv4=%s", port, ipv4, uint32ToIPv4BE(ipv4))
		}
		return fmt.Sprintf("payloadLen=%d hex=%s", len(payload), hex.EncodeToString(payload))
	case OpNatSync2:
		if len(payload) >= 36 {
			return fmt.Sprintf("srcHash=%x connAck=%x dstHash=%x", payload[0:16], payload[16:20], payload[20:36])
		}
	case OpNatSync:
		if len(payload) >= 26 {
			ipv4 := binary.BigEndian.Uint32(payload[0:4])
			port := binary.BigEndian.Uint16(payload[4:6])
			return fmt.Sprintf("peerIP=%d peerIPv4=%s peerPort=%d peerHash=%x connAck=%x",
				ipv4, uint32ToIPv4BE(ipv4), port, payload[6:22], payload[22:26])
		}
	case OpNatSyncEx:
		if len(payload) >= 27 {
			ipv4 := binary.BigEndian.Uint32(payload[0:4])
			port := binary.BigEndian.Uint16(payload[4:6])
			version := payload[26]
			return fmt.Sprintf("peerIP=%d peerIPv4=%s peerPort=%d peerHash=%x connAck=%x version=%d",
				ipv4, uint32ToIPv4BE(ipv4), port, payload[6:22], payload[22:26], version)
		}
	case OpNatFailed:
		if len(payload) >= 17 {
			return fmt.Sprintf("reason=0x%02x targetHash=%x", payload[0], payload[1:17])
		}
	case OpNatRegisterIPv6:
		if len(payload) >= 18 {
			port := binary.BigEndian.Uint16(payload[0:2])
			return fmt.Sprintf("serverPort=%d serverIPv6=%s", port, net.IP(payload[2:18]).String())
		}
	case OpNatSyncIPv6:
		if len(payload) >= 39 {
			port := binary.BigEndian.Uint16(payload[16:18])
			return fmt.Sprintf("peerIPv6=%s peerPort=%d peerHash=%x connAck=%x version=%d",
				net.IP(payload[0:16]).String(), port, payload[18:34], payload[34:38], payload[38])
		}
	case OpNatKeepAlive:
		return fmt.Sprintf("payloadLen=%d", len(payload))
	}
	previewLen := len(payload)
	if previewLen > 64 {
		previewLen = 64
	}
	return fmt.Sprintf("payloadLen=%d previewHex=%s", len(payload), hex.EncodeToString(payload[:previewLen]))
}

func uint32ToIPv4BE(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// natEndpointOf converts a UDP address to its index key. The zone is dropped: a
// rendezvous candidate is a public address, never a link-local one.
func natEndpointOf(addr *net.UDPAddr) natEndpoint {
	var ep natEndpoint
	if addr == nil {
		return ep
	}
	if ip16 := addr.IP.To16(); ip16 != nil {
		copy(ep.ip[:], ip16)
	}
	ep.port = uint16(addr.Port)
	return ep
}

// udpAddr converts the key back, with an IPv4 in its 4-byte form.
func (ep natEndpoint) udpAddr() *net.UDPAddr {
	ip := net.IP(append([]byte(nil), ep.ip[:]...))
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return &net.UDPAddr{IP: ip, Port: int(ep.port)}
}

// slot returns the entry's slot for one family.
func (e *natStoredEntry) slot(v6 bool) *natSlot {
	if v6 {
		return &e.v6
	}
	return &e.v4
}

// snapshot builds the natClientEntry form handed out by get, live slots only. nowTick
// and now are the same instant as a tick and as a time.
func (h *NATTraversalHandler) snapshot(e natStoredEntry, hash [16]byte, nowTick uint32, now time.Time) natClientEntry {
	out := natClientEntry{hash: hash, version: e.version}
	if h.liveSlot(e.v4, nowTick) {
		out.v4 = &natCandidate{addr: e.v4.ep.udpAddr(), lastSeen: now.Add(-natAge(nowTick, e.v4.seen)), sock: e.v4.sock}
	}
	if h.liveSlot(e.v6, nowTick) {
		out.v6 = &natCandidate{addr: e.v6.ep.udpAddr(), lastSeen: now.Add(-natAge(nowTick, e.v6.seen)), sock: e.v6.sock}
	}
	return out
}

// liveSlot reports whether a slot holds a candidate younger than the TTL. Every reader
// goes through it, so a candidate expires at the TTL, not at the next sweep.
func (h *NATTraversalHandler) liveSlot(s natSlot, nowTick uint32) bool {
	return s.seen != 0 && natAge(nowTick, s.seen) < h.ttl
}

// tick is the current time as natSlot.seen counts it: milliseconds since the handler
// was made, never 0 (the empty slot). It wraps after 49 days; natAge is modular, and a
// candidate lives one TTL, so the wrap is harmless.
func (h *NATTraversalHandler) tick() uint32 {
	t := uint32(time.Since(h.epoch) / time.Millisecond)
	if t == 0 {
		t = 1
	}
	return t
}

// natAge is how long ago seen was, given the current tick.
func natAge(now, seen uint32) time.Duration {
	return time.Duration(now-seen) * time.Millisecond
}

// setSlotLocked stores ep as hash's candidate for one family and keeps byAddr in step.
// The caller holds h.mu and writes entry back to h.entries.
//
// An endpoint is one socket, so it belongs to one hash. When another hash holds it,
// that older registration is stale (a client that restarted with a new hash on the same
// port) and its slot is cleared: otherwise its keepalives would refresh the wrong entry.
func (h *NATTraversalHandler) setSlotLocked(hash [16]byte, entry *natStoredEntry, v6 bool, ep natEndpoint, sock uint8, now uint32) {
	slot := entry.slot(v6)
	if slot.seen != 0 && slot.ep != ep && h.byAddr[slot.ep] == hash {
		delete(h.byAddr, slot.ep)
	}
	if owner, ok := h.byAddr[ep]; ok && owner != hash {
		if other, ok := h.entries[owner]; ok {
			if os := other.slot(v6); os.ep == ep {
				*os = natSlot{}
			}
			if other.v4.seen == 0 && other.v6.seen == 0 {
				delete(h.entries, owner)
			} else {
				h.entries[owner] = other
			}
		}
	}
	slot.ep = ep
	slot.sock = sock
	slot.seen = now
	h.byAddr[ep] = hash
}

// clearSlotLocked empties one family slot of hash's entry and drops its index entry.
// The caller holds h.mu and writes entry back.
func (h *NATTraversalHandler) clearSlotLocked(hash [16]byte, entry *natStoredEntry, v6 bool) {
	slot := entry.slot(v6)
	if h.byAddr[slot.ep] == hash {
		delete(h.byAddr, slot.ep)
	}
	*slot = natSlot{}
}

// send writes processPacket's answers, all in plaintext; the immediate path, completeWake
// (through it) and expireWake all go through here. conn is the socket the current
// datagram arrived on and remote its sender (both nil for expireWake).
//   - via set: a requester waiting on a wake, from the reply conn of its own SYNC2.
//   - back to the sender, or any other answer: from conn, pinned to the arrival address.
//   - a forward to the target of a pairing: from the socket the target last REGISTERed
//     or kept alive on (fallback when unknown) and, over IPv6, from the IPv6 we announce
//     in the REGISTER ack — the arrival address is the one the *requester* used.
func (h *NATTraversalHandler) send(conn, fallback UDPReplyConn, remote *net.UDPAddr, outs []natOutbound) {
	var forwardSrc net.IP // resolved on first use; most datagrams only answer the sender
	for _, out := range outs {
		if out.to == nil || len(out.packet) == 0 {
			continue
		}
		switch {
		case out.via != nil:
			LogNATRaw("nat", "send", out.to.String(), out.packet)
			_, _ = out.via.WriteToUDP(out.packet, out.to)
		case !out.forward || sameEndpoint(out.to, remote):
			if conn == nil {
				continue
			}
			LogNATRaw("nat", "send", out.to.String(), out.packet)
			_, _ = conn.WriteToUDP(out.packet, out.to)
		default:
			c := h.socketConn(out.sock)
			if c == nil {
				c = fallback
			}
			if c == nil {
				continue
			}
			if forwardSrc == nil {
				forwardSrc = h.announcedIPv6()
			}
			LogNATRaw("nat", "send", out.to.String(), out.packet)
			_, _ = WriteToUDPFrom(c, out.packet, out.to, forwardSrc)
		}
	}
}

// socketIndex returns conn's natSlot.sock value, learning the socket on first sight. It
// is keyed by local port; a socket replaced on the same port replaces the entry. 0 when
// conn is nil, its port unknown, or the table full.
func (h *NATTraversalHandler) socketIndex(conn UDPReplyConn, localPort uint16) uint8 {
	if conn == nil || localPort == 0 {
		return 0
	}
	listener := replyConnListener(conn)
	h.mu.RLock()
	idx, ok := h.sockByPort[localPort]
	same := ok && (listener == nil || replyConnListener(h.socks[idx-1]) == listener)
	h.mu.RUnlock()
	if same {
		return idx
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if idx, ok := h.sockByPort[localPort]; ok {
		h.socks[idx-1] = baseReplyConn(conn)
		return idx
	}
	if len(h.socks) >= 255 {
		return 0
	}
	h.socks = append(h.socks, baseReplyConn(conn))
	idx = uint8(len(h.socks))
	h.sockByPort[localPort] = idx
	return idx
}

// socketConn returns the socket a natSlot.sock value names, or nil for 0.
func (h *NATTraversalHandler) socketConn(sock uint8) UDPReplyConn {
	if sock == 0 {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if int(sock) > len(h.socks) {
		return nil
	}
	return h.socks[sock-1]
}
