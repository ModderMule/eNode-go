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
	defaultNATRegistryTTL   = 30 * time.Second
	defaultNATCleanupEvery  = 10 * time.Second
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
// a peer as a punch target.
type natCandidate struct {
	addr     *net.UDPAddr
	lastSeen time.Time
}

type natClientEntry struct {
	hash    [16]byte
	v4      *natCandidate // nil until the client registers over IPv4
	v6      *natCandidate // nil until the client registers over IPv6
	version uint8
}

type natOutbound struct {
	to     *net.UDPAddr
	packet []byte
}

type NATTraversalHandler struct {
	mu                  sync.RWMutex
	ttl                 time.Duration
	entries             map[[16]byte]natClientEntry
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
		entries:             map[[16]byte]natClientEntry{},
		announcePortByLocal: map[uint16]uint16{},
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

func (h *NATTraversalHandler) HandlePacket(data []byte, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt) {
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
	for _, out := range h.processPacket(data, remote, localPort) {
		target := ""
		if out.to != nil {
			target = out.to.String()
		}
		if len(out.packet) > 0 && out.packet[0] == PrNat {
			LogNATRaw("nat", "send", target, out.packet)
		}
		wire := out.packet
		if crypt != nil && crypt.Status == CsEncrypting {
			wire = crypt.Encrypt(out.packet)
		}
		_, _ = conn.WriteToUDP(wire, out.to)
	}
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
	if len(data) == 0 || remote == nil {
		return nil
	}
	if len(data) == 1 {
		hash, matched := h.touchByAddr(remote)
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
		return h.handleRegister(remote, payload, localPort, false)
	case OpNatRegisterEx:
		return h.handleRegister(remote, payload, localPort, true)
	case OpNatKeepAlive:
		hash, matched := h.touchByAddr(remote)
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
		return h.handleSync2(remote, payload)
	default:
		return nil
	}
}

func (h *NATTraversalHandler) handleRegister(remote *net.UDPAddr, payload []byte, localPort uint16, isEx bool) []natOutbound {
	if len(payload) < 16 {
		return nil
	}
	var hash [16]byte
	copy(hash[:], payload[:16])
	version := uint8(0)
	if isEx && len(payload) >= 17 {
		version = payload[16]
	}
	h.upsert(hash, remote, version)

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
		return []natOutbound{{
			to:     cloneUDPAddr(remote),
			packet: encodeNATPacket(OpNatRegisterIPv6, resp),
		}}
	}

	resp := make([]byte, 6)
	binary.BigEndian.PutUint16(resp[0:2], port)
	binary.BigEndian.PutUint32(resp[2:6], ipv4)
	return []natOutbound{{
		to:     cloneUDPAddr(remote),
		packet: encodeNATPacket(OpNatRegister, resp),
	}}
}

func (h *NATTraversalHandler) handleSync2(remote *net.UDPAddr, payload []byte) []natOutbound {
	if len(payload) < 36 {
		return nil
	}
	var srcHash [16]byte
	var dstHash [16]byte
	copy(srcHash[:], payload[0:16])
	connAck := append([]byte(nil), payload[16:20]...)
	copy(dstHash[:], payload[20:36])

	// Auto-register the requester's candidate for the family this SYNC2 arrived on
	// when that slot is empty, preserving the classic "SYNC2 implies register"
	// robustness. upsert with version 0 keeps any version an earlier REGISTER_EX set.
	src, srcFound := h.get(srcHash)
	if !srcFound || familySlot(src, remote) == nil {
		h.upsert(srcHash, remote, 0)
		src, _ = h.get(srcHash)
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

	// Pair on a family both peers can reach, preferring IPv6. Both endpoints must
	// share a family — the two firewalled peers punch directly at each other.
	switch {
	case v6Enabled && src.v6 != nil && dst.v6 != nil:
		return []natOutbound{
			{
				to:     cloneUDPAddr(src.v6.addr),
				packet: buildNATSyncPacketV6(dst.v6.addr, dst.hash, connAck, dst.version),
			},
			{
				to:     cloneUDPAddr(dst.v6.addr),
				packet: buildNATSyncPacketV6(src.v6.addr, src.hash, connAck, src.version),
			},
		}
	case src.v4 != nil && dst.v4 != nil:
		return []natOutbound{
			{
				to:     cloneUDPAddr(src.v4.addr),
				packet: buildNATSyncPacket(dst.v4.addr, dst.hash, connAck, dst.version, src.version),
			},
			{
				to:     cloneUDPAddr(dst.v4.addr),
				packet: buildNATSyncPacket(src.v4.addr, src.hash, connAck, src.version, dst.version),
			},
		}
	default:
		return []natOutbound{h.natFailed(remote, dstHash, natFailReasonNoCommonFamily)}
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

func (h *NATTraversalHandler) upsert(hash [16]byte, remote *net.UDPAddr, version uint8) {
	h.mu.Lock()
	defer h.mu.Unlock()
	entry := h.entries[hash] // zero value when absent; preserves the other family slot
	entry.hash = hash
	if version > 0 {
		entry.version = version
	}
	cand := &natCandidate{addr: cloneUDPAddr(remote), lastSeen: time.Now()}
	if remoteIsIPv6(remote) {
		entry.v6 = cand
	} else {
		entry.v4 = cand
	}
	h.entries[hash] = entry
}

// touchByAddr refreshes the candidate matching a source address and reports whether one
// was found, along with the user hash it belongs to.
//
// The hash is returned so a keepalive can also count as liveness for that user's eD2K TCP
// session — see SetSessionTouch. Without it the caller has proof the client is alive but
// no way to say which client.
func (h *NATTraversalHandler) touchByAddr(remote *net.UDPAddr) (hash [16]byte, matched bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	for _, entry := range h.entries {
		// entry.v4/v6 are pointers shared with the map, so writing through them
		// refreshes the stored candidate directly.
		if entry.v4 != nil && sameEndpoint(entry.v4.addr, remote) {
			entry.v4.lastSeen = now
			return entry.hash, true
		}
		if entry.v6 != nil && sameEndpoint(entry.v6.addr, remote) {
			entry.v6.lastSeen = now
			return entry.hash, true
		}
	}
	return hash, false
}

// get returns a deep copy of the entry so the caller holds a stable snapshot after
// the lock is released — the map keeps live candidate pointers that touchByAddr and
// upsert mutate, and an alias would let a caller observe those changes.
func (h *NATTraversalHandler) get(hash [16]byte) (natClientEntry, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	v, ok := h.entries[hash]
	if !ok {
		return natClientEntry{}, false
	}
	return v.clone(), true
}

func (e natClientEntry) clone() natClientEntry {
	out := natClientEntry{hash: e.hash, version: e.version}
	if e.v4 != nil {
		c := natCandidate{addr: cloneUDPAddr(e.v4.addr), lastSeen: e.v4.lastSeen}
		out.v4 = &c
	}
	if e.v6 != nil {
		c := natCandidate{addr: cloneUDPAddr(e.v6.addr), lastSeen: e.v6.lastSeen}
		out.v6 = &c
	}
	return out
}

func (h *NATTraversalHandler) cleanup() {
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := time.Now().Add(-h.ttl)
	for k, entry := range h.entries {
		if entry.v4 != nil && entry.v4.lastSeen.Before(cutoff) {
			entry.v4 = nil
		}
		if entry.v6 != nil && entry.v6.lastSeen.Before(cutoff) {
			entry.v6 = nil
		}
		if entry.v4 == nil && entry.v6 == nil {
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
	if entry.v4 != nil {
		n++
	}
	if entry.v6 != nil {
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
		b.WriteString(fmt.Sprintf("hash=%x v4=%s v6=%s", hash[:], formatCandidate(entry.v4), formatCandidate(entry.v6)))
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
