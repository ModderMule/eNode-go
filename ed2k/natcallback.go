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
// Foreign callback (UDP flag 0x400000): a requester not logged in here sends 0xa6
// <B's ID><0>[<crypt>]. B is woken with TCP 0x37 (ID 0, no hash) and bursts UDP
// OpNatKeepalive; its source port goes to the requester in UDP 0xa7.
//
// Memory: an idle session pays nothing. The capability is one bool in existing
// padding of tcpClient, and the 19 s window lives in natCallbackState, which only
// holds clients that sent a request in the last natCallbackWindow. The hole-punch
// login bit is one more bool in that padding.

// natCallbackWindow is how long after its own 0xa6 a client is answered over UDP.
// Measured on eserver 17.15: 15 s still got UDP, 23 s got TCP; the eMuleQt design
// (and the doc) use 19 s.
const natCallbackWindow = 19 * time.Second

// natCallbackPerRequesterPerMinute caps 0xa6 requests per requester LowID. eMuleQt
// sends at most 9 per attempt, every 5 s; ed2k-server allows a burst of 10, then 1/s.
// Keyed by requester, not by address: behind a carrier-grade NAT many LowIDs share one
// IPv4, and a per-address budget would let a few of them silence the rest.
const natCallbackPerRequesterPerMinute = 60

// Foreign callback limits: per source address (IPv4, or IPv6 /64) and per target
// LowID. A requester repeats every 5 s up to 3 times.
const (
	natForeignPerAddressPerMinute = 20
	natForeignPerTargetPerMinute  = 10
	// natForeignMaxPerTarget caps pending requesters per target; the oldest goes.
	natForeignMaxPerTarget = 4
)

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

	// Foreign callback: requesters not logged in here, waiting for their target's
	// OpNatKeepalive, keyed by target LowID. Only requests of the last window.
	foreignAddr   *ratelimit.Limiter
	foreignTarget *ratelimit.Limiter
	foreign       map[uint32][]natForeignPending
	foreignSweep  time.Time
}

// natForeignPending is a foreign requester: where its 0xa6 came from, its crypt
// bits and the socket it reached, which the 0xa7 leaves from.
type natForeignPending struct {
	ipv4  uint32
	port  uint16
	crypt byte
	at    time.Time
	conn  UDPReplyConn
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
	if requesterID == 0 {
		s.udpForeignCallbackRequest(b, remote, conn, srcIPv4, targetID)
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

// foreignCallbackEnabled reports whether this server takes the foreign 0xa6
// (requester ID 0). The advertised UDP flag is the switch.
func (s *ServerRuntime) foreignCallbackEnabled() bool {
	return s.natCallbackEnabled() && s.udp().UDPFlags&FlagForeignCallback != 0
}

// udpForeignCallbackRequest handles 0xa6 <target ID 4><0 4>[<crypt 1>] from a client
// not logged in here. The obfuscation key is derived per source IP, so a decrypted
// request proves the requester's address. The target is woken with TCP 0x37
// (requester ID 0, no hash); the requester gets UDP 0xa7 once the target's
// OpNatKeepalive arrives. Every refusal is silent.
func (s *ServerRuntime) udpForeignCallbackRequest(b *Buffer, remote *net.UDPAddr, conn UDPReplyConn, srcIPv4, targetID uint32) {
	if !s.foreignCallbackEnabled() {
		return
	}
	// A client connected here uses the normal request with its own ID.
	if s.hasConnectionFrom(remote.IP) {
		logging.Debugf("foreign callback from a connected address ignored remote=%s", remote)
		return
	}
	var crypt byte
	if b.Remaining() > 0 {
		crypt, _ = b.GetUInt8()
	}
	if !s.natCallback.allowForeignAddress(addressKey(remote.IP)) {
		s.blocks.rateLimited.Add(1)
		logging.Debugf("foreign callback rate limited remote=%s", remote)
		return
	}
	target, ok := s.natCallbackPeer(targetID)
	if !ok || !target.natt || !target.holePunch {
		logging.Debugf("foreign callback target not capable remote=%s target=%d", remote, targetID)
		return
	}
	// After the target check, so made-up IDs cannot grow the limiter.
	if !s.natCallback.allowForeignTarget(targetID) {
		s.blocks.rateLimited.Add(1)
		logging.Debugf("foreign callback target rate limited remote=%s target=%d", remote, targetID)
		return
	}
	port := uint16(remote.Port)
	s.natCallback.addForeign(targetID, natForeignPending{ipv4: srcIPv4, port: port, crypt: crypt & 0x07, at: time.Now(), conn: conn})
	if s.parking.Load() != nil {
		return
	}
	packet, err := BuildNatCallbackRequestedPacket(srcIPv4, port, 0, crypt&0x07, nil)
	if err != nil {
		return
	}
	_ = target.client.writePacket(packet)
}

// udpNatKeepalive handles OpNatKeepalive <user hash 16>, accepted only obfuscated and
// from the IPv4 of the session logged in under that hash. Its source is the target's
// UDP endpoint: every foreign requester waiting for that LowID gets UDP 0xa7 with it.
// Without one pending it is a plain keepalive and ignored.
func (s *ServerRuntime) udpNatKeepalive(b *Buffer, remote *net.UDPAddr, obfuscated bool, module string) {
	if !obfuscated || !s.foreignCallbackEnabled() {
		return
	}
	srcIPv4, ok := IPv4ToUint32LE(NormalizeIP(remote.IP))
	if !ok || remote.Port <= 0 || remote.Port > 0xffff {
		return
	}
	hash := b.Get(16)
	if len(hash) != 16 {
		return
	}
	c := s.sessionByHash(hash)
	if c == nil {
		return
	}
	c.infoMu.RLock()
	id := c.info.ID
	c.infoMu.RUnlock()
	target, ok := s.natCallbackPeer(id)
	if !ok || target.client != c || target.ipv4 != srcIPv4 {
		logging.Debugf("nat keepalive not from the session remote=%s", remote)
		return
	}
	for _, p := range s.natCallback.takeForeign(id, time.Now()) {
		notice := BuildNatCallbackNotice(srcIPv4, uint16(remote.Port), id, target.crypt&0x07, nil)
		s.sendNatCallbackUDP(p.conn, natCallbackRecent{ipv4: p.ipv4, port: p.port}, notice, module)
	}
}

// hasConnectionFrom reports whether a TCP connection from ip's address is open here.
func (s *ServerRuntime) hasConnectionFrom(ip net.IP) bool {
	key := addressKey(NormalizeIP(ip))
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	return s.connsPerIP[key] > 0
}

// natCallbackPeerView is what the callback reads from a session, copied under its lock.
type natCallbackPeerView struct {
	client    *tcpClient
	ipv4      uint32
	crypt     byte
	natt      bool
	holePunch bool
	hash      []byte
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
		client:    c,
		ipv4:      ipv4,
		crypt:     c.info.CryptOptions,
		natt:      c.nattCapable,
		holePunch: c.holePunchExt,
		hash:      append([]byte(nil), c.info.Hash...),
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

func (n *natCallbackState) allowForeignAddress(key string) bool {
	n.mu.Lock()
	if n.foreignAddr == nil {
		n.foreignAddr = ratelimit.New(natForeignPerAddressPerMinute)
	}
	l := n.foreignAddr
	n.mu.Unlock()
	return l.Allow(key)
}

func (n *natCallbackState) allowForeignTarget(target uint32) bool {
	n.mu.Lock()
	if n.foreignTarget == nil {
		n.foreignTarget = ratelimit.New(natForeignPerTargetPerMinute)
	}
	l := n.foreignTarget
	n.mu.Unlock()
	return l.Allow(strconv.FormatUint(uint64(target), 10))
}

// addForeign records a foreign requester for target. The same requester (address
// and port) only refreshes its entry; past natForeignMaxPerTarget the oldest goes.
// Stale entries are swept at most once per window, as in remember.
func (n *natCallbackState) addForeign(target uint32, p natForeignPending) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.foreign == nil {
		n.foreign = map[uint32][]natForeignPending{}
	}
	if p.at.Sub(n.foreignSweep) >= natCallbackWindow {
		for k, list := range n.foreign {
			if list = liveForeign(list, p.at); len(list) == 0 {
				delete(n.foreign, k)
			} else {
				n.foreign[k] = list
			}
		}
		n.foreignSweep = p.at
	}
	list := n.foreign[target]
	for i, e := range list {
		if e.ipv4 == p.ipv4 && e.port == p.port {
			// Kept in arrival order, so the refreshed one moves to the end.
			list = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(list) >= natForeignMaxPerTarget {
		list = list[len(list)-natForeignMaxPerTarget+1:]
	}
	n.foreign[target] = append(list, p)
}

// takeForeign removes and returns the live requesters waiting for target.
func (n *natCallbackState) takeForeign(target uint32, now time.Time) []natForeignPending {
	n.mu.Lock()
	defer n.mu.Unlock()
	list, ok := n.foreign[target]
	if !ok {
		return nil
	}
	delete(n.foreign, target)
	return liveForeign(list, now)
}

// liveForeign drops entries older than natCallbackWindow, in place.
func liveForeign(list []natForeignPending, now time.Time) []natForeignPending {
	live := list[:0]
	for _, e := range list {
		if now.Sub(e.at) <= natCallbackWindow {
			live = append(live, e)
		}
	}
	return live
}
