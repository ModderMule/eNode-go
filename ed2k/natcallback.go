package ed2k

import (
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"time"

	"enode/internal/ratelimit"
	"enode/logging"
)

// Lugdunum eserver's LowID-to-LowID NAT callback, as NeoLoader, eMuleQt and
// ed2k-server 0.9.85 speak it. See docs/lugdunum-nat-callback.local.md.
//
// A LowID client A that wants to reach LowID client B sends an obfuscated UDP
// 0xa6 <B's ID><A's ID> to the server. The server tells B where A's datagram came
// from: over UDP 0xa7 when B itself sent a 0xa6 in the last 19 s (so its NAT has a
// mapping and the server knows the port), else over TCP 0x37 on B's session. The
// server relays nothing else.
//
// Memory: an idle session pays nothing. The capability is one bool in existing
// padding of tcpClient, and the 19 s window lives in natCallbackState, which only
// holds clients that sent a request in the last natCallbackWindow.

// natCallbackWindow is how long after its own 0xa6 a client is answered over UDP.
// Measured on eserver 17.15: 15 s still got UDP, 23 s got TCP; the eMuleQt design
// (and the doc) use 19 s.
const natCallbackWindow = 19 * time.Second

// natCallbackPerRequesterPerMinute caps 0xa6 requests per requester LowID. eMuleQt
// sends at most 9 per attempt, every 5 s; ed2k-server allows a burst of 10, then 1/s.
// Keyed by requester, not by address: behind a carrier-grade NAT many LowIDs share one
// IPv4, and a per-address budget would let a few of them silence the rest.
const natCallbackPerRequesterPerMinute = 60

// natCallbackNoticeFlagHash is OR-ed into the notice's crypt byte when the
// requester's user hash follows.
const natCallbackNoticeFlagHash byte = 0x80

// natCallbackState is the server-wide state of the callback: the per-IP limiter
// and the recent requesters. The zero value is ready to use.
type natCallbackState struct {
	mu        sync.Mutex
	limiter   *ratelimit.Limiter
	recent    map[uint32]natCallbackRecent
	lastSweep time.Time
}

// natCallbackRecent is a client that sent an accepted 0xa6: the address its
// datagram came from, which is where a UDP 0xa7 for it goes.
type natCallbackRecent struct {
	ipv4 uint32
	port uint16
	at   time.Time
}

// BuildNatCallbackNotice builds the notice body shared by UDP 0xa7 and TCP 0x37:
// <requester IP 4><requester UDP port 2 LE><requester ID 4><crypt flags 1>[<hash 16>].
// The IP is in the same packed form as an ed2k ID (first octet in the low byte).
// The hash is appended, and 0x80 set in the flags, only when hash is 16 bytes.
func BuildNatCallbackNotice(requesterIPv4 uint32, requesterPort uint16, requesterID uint32, cryptFlags byte, hash []byte) []byte {
	body := make([]byte, 11, 27)
	binary.LittleEndian.PutUint32(body[0:4], requesterIPv4)
	binary.LittleEndian.PutUint16(body[4:6], requesterPort)
	binary.LittleEndian.PutUint32(body[6:10], requesterID)
	body[10] = cryptFlags & 0x07
	if len(hash) == 16 {
		body[10] |= natCallbackNoticeFlagHash
		body = append(body, hash...)
	}
	return body
}

// BuildNatCallbackRequestedPacket builds TCP 0x37 (OpNatCallbackRequested) with
// the BuildNatCallbackNotice body.
func BuildNatCallbackRequestedPacket(requesterIPv4 uint32, requesterPort uint16, requesterID uint32, cryptFlags byte, hash []byte) (*Buffer, error) {
	flags := cryptFlags & 0x07
	if len(hash) == 16 {
		flags |= natCallbackNoticeFlagHash
	}
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpNatCallbackRequested},
		{Type: TypeUint32, Value: requesterIPv4},
		{Type: TypeUint16, Value: requesterPort},
		{Type: TypeUint32, Value: requesterID},
		{Type: TypeUint8, Value: flags},
	}
	if len(hash) == 16 {
		pack = append(pack, PacketItem{Type: TypeHash, Value: hash})
	}
	return MakePacket(PrED2K, pack)
}

// NatCallbackCrypt applies eserver's rule for the notice's crypt byte, the same rule
// as OP_FOUNDSOURCES_OBFU. requester and target are CryptOptions bytes (0x01
// support, 0x02 request, 0x04 require). The byte is always the requester's bits.
// withHash reports that both sides support obfuscation and at least one requests
// it. ok is false when that does not hold and either side requires it: no notice
// is sent then. Checked against the live capture table in the doc.
func NatCallbackCrypt(requester, target byte) (flags byte, withHash, ok bool) {
	const support, request, require = 0x01, 0x02, 0x04
	flags = requester & 0x07
	withHash = requester&support != 0 && target&support != 0 &&
		(requester&request != 0 || target&request != 0)
	if !withHash && (requester&require != 0 || target&require != 0) {
		return flags, false, false
	}
	return flags, withHash, true
}

// natCallbackEnabled reports whether this server offers the callback. The advertised
// TCP flag is the switch, so the flag and the behaviour cannot disagree.
func (s *ServerRuntime) natCallbackEnabled() bool {
	return s.tcp().Flags&FlagNatCallback != 0
}

// udpNatCallbackRequest handles UDP 0xa6 <target ID 4><requester ID 4>. Every refusal
// is silent, as on eserver and ed2k-server: the requester never gets an answer of
// its own (it learns the target's endpoint only from the target's own 0xa6).
func (s *ServerRuntime) udpNatCallbackRequest(b *Buffer, remote *net.UDPAddr, conn UDPReplyConn, obfuscated bool, module string) {
	if !s.natCallbackEnabled() || !obfuscated {
		logging.Debugf("nat callback ignored remote=%s enabled=%t obfuscated=%t", remote, s.natCallbackEnabled(), obfuscated)
		return
	}
	srcIPv4, ok := IPv4ToUint32LE(NormalizeIP(remote.IP))
	if !ok || remote.Port <= 0 || remote.Port > 0xffff {
		return
	}
	targetID, err := b.GetUInt32LE()
	if err != nil {
		return
	}
	requesterID, err := b.GetUInt32LE()
	if err != nil {
		return
	}
	requester, ok := s.natCallbackPeer(requesterID)
	if !ok || requester.ipv4 != srcIPv4 {
		// The requester ID must be a LowID session logged in from this IPv4. That
		// binds the ID to an address, not to one client: clients behind the same
		// NAT can still request in each other's name, as on eserver.
		logging.Debugf("nat callback requester unknown remote=%s requester=%d", remote, requesterID)
		return
	}
	// After the requester check, so the limiter only ever holds buckets for real
	// sessions and a flood of made-up IDs cannot grow it.
	if !s.natCallback.allow(requesterID) {
		s.blocks.rateLimited.Add(1)
		logging.Debugf("nat callback rate limited remote=%s requester=%d", remote, requesterID)
		return
	}
	now := time.Now()
	s.natCallback.remember(requesterID, natCallbackRecent{ipv4: srcIPv4, port: uint16(remote.Port), at: now})

	if targetID == requesterID {
		return
	}
	target, ok := s.natCallbackPeer(targetID)
	if !ok || !target.natt {
		logging.Debugf("nat callback target not callback-capable remote=%s target=%d", remote, targetID)
		return
	}
	flags, withHash, ok := NatCallbackCrypt(requester.crypt, target.crypt)
	if !ok {
		logging.Debugf("nat callback crypt mismatch requester=%d target=%d", requesterID, targetID)
		return
	}
	var hash []byte
	if withHash {
		hash = requester.hash
	}
	if recent, ok := s.natCallback.recentFor(targetID, now); ok && recent.ipv4 == target.ipv4 {
		notice := BuildNatCallbackNotice(srcIPv4, uint16(remote.Port), requesterID, flags, hash)
		s.sendNatCallbackUDP(conn, recent, notice, module)
		return
	}
	if s.parking.Load() != nil {
		return
	}
	packet, err := BuildNatCallbackRequestedPacket(srcIPv4, uint16(remote.Port), requesterID, flags, hash)
	if err != nil {
		return
	}
	// Sent at once: eserver holds 0x37 up to 12 s to batch notices, which only
	// slows the callback down and would need a buffer per session.
	_ = target.client.writePacket(packet)
}

// natCallbackPeerView is what the callback reads from a session, copied under its lock.
type natCallbackPeerView struct {
	client *tcpClient
	ipv4   uint32
	crypt  byte
	natt   bool
	hash   []byte
}

// natCallbackPeer returns the logged-in LowID session holding id. Its IPv4 is the
// address the session connected from, or the one it reported for an IPv6 session.
func (s *ServerRuntime) natCallbackPeer(id uint32) (natCallbackPeerView, bool) {
	if id == 0 || HasHighID(id) || s.LowIDs == nil {
		return natCallbackPeerView{}, false
	}
	v, ok := s.LowIDs.Get(id)
	if !ok {
		return natCallbackPeerView{}, false
	}
	c, ok := v.(*tcpClient)
	if !ok {
		return natCallbackPeerView{}, false
	}
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	if !c.logged || !c.hasLowID || c.info.ID != id {
		return natCallbackPeerView{}, false
	}
	ipv4 := c.info.IPv4
	if p, ok := IPv4ToUint32LE(c.peerIP); ok {
		ipv4 = p
	}
	return natCallbackPeerView{
		client: c,
		ipv4:   ipv4,
		crypt:  c.info.CryptOptions,
		natt:   c.nattCapable,
		hash:   append([]byte(nil), c.info.Hash...),
	}, true
}

// sendNatCallbackUDP sends UDP 0xa7 to the address the target's own 0xa6 came from,
// obfuscated with the key this server gives that IP. The marker byte avoids every
// value a client UDP socket reads as eMule or Kad, because the notice arrives on the
// client socket the target sent its 0xa6 from.
func (s *ServerRuntime) sendNatCallbackUDP(conn UDPReplyConn, recent natCallbackRecent, notice []byte, module string) {
	ip := v4FromUint32(recent.ipv4)
	addr := &net.UDPAddr{IP: ip, Port: int(recent.port)}
	data := make([]byte, 0, 2+len(notice))
	data = append(data, PrED2K, OpNatCallbackRequestedUDP)
	data = append(data, notice...)
	LogUDPRaw(module, "send", addr.String(), data)
	crypt := NewUDPCrypt(true, deriveUDPKey(s.udpSecret(), ip))
	if _, err := conn.WriteToUDP(crypt.EncryptForClientSocket(data), addr); err != nil {
		logging.Debugf("nat callback udp notice failed remote=%s err=%v", addr, err)
	}
}

// lowIDParity is the LowID parity this session must get: odd when it set
// SrvCapNatTraversal on a server offering the callback, even otherwise, any when
// the server does not offer it.
func (c *tcpClient) lowIDParity() int {
	if !c.server.natCallbackEnabled() {
		return LowIDAnyParity
	}
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	if c.nattCapable {
		return LowIDOddParity
	}
	return LowIDEvenParity
}

// wantsLongIDChange reports whether OP_IDCHANGE gets Lugdunum's 24-byte form: the
// server offers the callback and the client set both crypt support and
// SrvCapNatTraversal. Lugdunum's 12-byte NAT-only form is not copied: it has no
// observed IP at offset 12, which a LowID client needs to learn its address.
func (c *tcpClient) wantsLongIDChange() bool {
	if !c.server.natCallbackEnabled() {
		return false
	}
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	return c.nattCapable && c.info.CryptOptions&0x01 != 0
}

// idChangeNatPorts fills the two extra words of the 24-byte OP_IDCHANGE.
func (c *tcpClient) idChangeNatPorts(id uint32) *IDChangeNatPorts {
	obf := c.server.udp().TCPPortObf
	if obf == 0 {
		obf = c.server.tcp().Port
	}
	clientPort := c.snapshotInfo().Port
	if !HasHighID(id) {
		if addr, ok := c.conn.RemoteAddr().(*net.TCPAddr); ok && addr.Port > 0 && addr.Port <= 0xffff {
			clientPort = uint16(addr.Port)
		}
	}
	return &IDChangeNatPorts{ObfuscationTCPPort: obf, ClientTCPPort: clientPort}
}

func (n *natCallbackState) allow(requesterID uint32) bool {
	n.mu.Lock()
	if n.limiter == nil {
		n.limiter = ratelimit.New(natCallbackPerRequesterPerMinute)
	}
	l := n.limiter
	n.mu.Unlock()
	return l.Allow(strconv.FormatUint(uint64(requesterID), 10))
}

// remember records an accepted request. Old entries are swept here, at most once
// per window, so no goroutine is needed and the map holds only recent requesters.
func (n *natCallbackState) remember(id uint32, r natCallbackRecent) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.recent == nil {
		n.recent = map[uint32]natCallbackRecent{}
	}
	if r.at.Sub(n.lastSweep) >= natCallbackWindow {
		for k, v := range n.recent {
			if r.at.Sub(v.at) > natCallbackWindow {
				delete(n.recent, k)
			}
		}
		n.lastSweep = r.at
	}
	n.recent[id] = r
}

func (n *natCallbackState) recentFor(id uint32, now time.Time) (natCallbackRecent, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, ok := n.recent[id]
	if !ok || now.Sub(r.at) > natCallbackWindow {
		return natCallbackRecent{}, false
	}
	return r, true
}
