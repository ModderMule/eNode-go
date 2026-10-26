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
// Foreign callback (UDP flag 0x100000): a requester not logged in here sends 0xa6
// <B's ID><0>[<crypt>]. B is woken with TCP 0x37 (ID 0, no hash) and bursts UDP
// OpNatKeepalive; its source port goes to the requester in UDP 0xa7, always with B's
// hash. No keepalive within 3 s: the 0xa7 carries B's last known UDP port instead.
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

// Foreign callback limits, as ed2k-server. A requester repeats every 5 s up to 3
// times. The per-address rate is config (UDPRuntimeConfig.ForeignPerMinute/Burst).
const (
	natForeignPerTargetPerMinute = 6
	// Distinct targets one source address (IPv4, or IPv6 /64) may name per window.
	natForeignMaxTargetsPerAddress = 60
	natForeignTargetWindow         = 10 * time.Minute
	// natForeignMaxPerTarget caps pending requesters per target; the oldest goes.
	natForeignMaxPerTarget = 4
	// natForeignFallback is how long a requester waits for the target's keepalive
	// before the 0xa7 goes out with the target's last known UDP port.
	natForeignFallback = 3 * time.Second
	// natKeepaliveTTL is how long a session's last obfuscated keepalive endpoint is
	// kept for that fallback.
	natKeepaliveTTL = 10 * time.Minute
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
	foreignAddr      *ratelimit.Limiter
	foreignAddrRate  int
	foreignAddrBurst int
	foreignTarget    *ratelimit.Limiter
	foreign          map[uint32]*natForeignWait
	foreignGen       uint64
	// foreignNamed is address key -> target LowID -> last request, for the
	// distinct-target cap.
	foreignNamed map[string]map[uint32]time.Time
	// keepalives is each LowID's last obfuscated OpNatKeepalive source.
	keepalives   map[uint32]natCallbackRecent
	foreignSweep time.Time
	// afterFunc arms the fallback timer; nil is time.AfterFunc. Tests replace it.
	afterFunc func(time.Duration, func())
}

// natForeignWait is a target's pending requesters. gen tells the fallback timer
// armed for this batch from one armed for an earlier, already answered batch.
type natForeignWait struct {
	list []natForeignPending
	gen  uint64
}

// natForeignPending is a foreign requester: where its 0xa6 came from, its crypt
// bits (cryptKnown when the 9th byte was sent) and the socket it reached, which
// the 0xa7 leaves from.
type natForeignPending struct {
	ipv4       uint32
	port       uint16
	crypt      byte
	cryptKnown bool
	at         time.Time
	conn       UDPReplyConn
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
		s.udpForeignCallbackRequest(b, remote, conn, srcIPv4, targetID, module)
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
// OpNatKeepalive arrives, or after natForeignFallback with the target's last known
// port. Every refusal is silent. IP-filtered sources never get here (UDPHandler).
func (s *ServerRuntime) udpForeignCallbackRequest(b *Buffer, remote *net.UDPAddr, conn UDPReplyConn, srcIPv4, targetID uint32, module string) {
	if !s.foreignCallbackEnabled() {
		return
	}
	// A client connected here uses the normal request with its own ID.
	if s.hasConnectionFrom(remote.IP) {
		logging.Debugf("foreign callback from a connected address ignored remote=%s", remote)
		return
	}
	var crypt byte
	cryptKnown := false
	if b.Remaining() > 0 {
		if c, err := b.GetUInt8(); err == nil {
			crypt, cryptKnown = c&0x07, true
		}
	}
	key := addressKey(remote.IP)
	s.observeUDPQuerier(key)
	cfg := s.udp()
	if !s.natCallback.allowForeignAddress(key, cfg.ForeignPerMinute, cfg.ForeignBurst) {
		s.blocks.rateLimited.Add(1)
		logging.Debugf("foreign callback rate limited remote=%s", remote)
		return
	}
	target, ok := s.natCallbackPeer(targetID)
	if !ok || !target.natt || !target.holePunch {
		logging.Debugf("foreign callback target not capable remote=%s target=%d", remote, targetID)
		return
	}
	// Same rule as the same-server path when the requester sent its bits; without
	// them the 0x37 says 0.
	var wakeFlags byte
	if cryptKnown {
		flags, _, ok := NatCallbackCrypt(crypt, target.crypt)
		if !ok {
			logging.Debugf("foreign callback crypt mismatch remote=%s target=%d", remote, targetID)
			return
		}
		wakeFlags = flags
	}
	now := time.Now()
	// After the target check, so made-up IDs cannot fill either.
	if !s.natCallback.allowForeignNamed(key, targetID, now) {
		s.blocks.rateLimited.Add(1)
		logging.Debugf("foreign callback too many targets remote=%s target=%d", remote, targetID)
		return
	}
	if !s.natCallback.allowForeignTarget(targetID) {
		s.blocks.rateLimited.Add(1)
		logging.Debugf("foreign callback target rate limited remote=%s target=%d", remote, targetID)
		return
	}
	port := uint16(remote.Port)
	logging.Debugf("foreign callback accepted remote=%s target=%d crypt=%d known=%t", remote, targetID, crypt, cryptKnown)
	gen, first := s.natCallback.addForeign(targetID, natForeignPending{
		ipv4: srcIPv4, port: port, crypt: crypt, cryptKnown: cryptKnown, at: now, conn: conn,
	})
	if first {
		s.natCallback.after(natForeignFallback, func() { s.foreignFallback(targetID, gen, module) })
	}
	if s.parking.Load() != nil {
		return
	}
	packet, err := BuildNatCallbackRequestedPacket(srcIPv4, port, 0, wakeFlags, nil)
	if err != nil {
		return
	}
	if err := target.client.writePacket(packet); err == nil {
		logging.Debugf("foreign callback 0x37 sent target=%d requester=%s flags=%d", targetID, remote, wakeFlags)
	}
}

// udpNatKeepalive handles OpNatKeepalive <user hash 16>, accepted only obfuscated and
// from the IPv4 of the session logged in under that hash. Its source is the target's
// UDP endpoint: every foreign requester waiting for that LowID gets UDP 0xa7 with it.
// The endpoint is also kept for the 3 s fallback of later requests.
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
	now := time.Now()
	endpoint := natCallbackRecent{ipv4: srcIPv4, port: uint16(remote.Port), at: now}
	s.natCallback.rememberKeepalive(id, endpoint)
	s.sendForeignNotices(target, id, endpoint, s.natCallback.takeForeign(id, now), "keepalive", module)
}

// foreignFallback runs natForeignFallback after a target's first pending request.
// Requesters still waiting get the 0xa7 with the target's last known UDP endpoint:
// its own recent 0xa6, else its last keepalive, either from its session IPv4. None
// known: nothing is sent.
func (s *ServerRuntime) foreignFallback(targetID uint32, gen uint64, module string) {
	now := time.Now()
	pending := s.natCallback.takeForeignGen(targetID, gen, now)
	if len(pending) == 0 {
		return
	}
	target, ok := s.natCallbackPeer(targetID)
	if !ok {
		return
	}
	endpoint, ok := s.natCallback.recentFor(targetID, now)
	if !ok || endpoint.ipv4 != target.ipv4 {
		endpoint, ok = s.natCallback.keepaliveFor(targetID, now)
	}
	if !ok || endpoint.ipv4 != target.ipv4 {
		logging.Debugf("foreign callback fallback without a target port target=%d requesters=%d", targetID, len(pending))
		return
	}
	s.sendForeignNotices(target, targetID, endpoint, pending, "fallback", module)
}

// sendForeignNotices sends each pending requester UDP 0xa7 with the target's
// endpoint. The crypt byte is the target's bits. The target's hash always follows
// (27 bytes, as ed2k-server 0.9.86): the requester dials and obfuscates its first
// QUIC Initial with it. 0x80 keeps Lugdunum's meaning, "use the crypt layer": set
// only when the requester sent its bits and both use the layer.
func (s *ServerRuntime) sendForeignNotices(target natCallbackPeerView, targetID uint32, endpoint natCallbackRecent, pending []natForeignPending, via, module string) {
	for _, p := range pending {
		flags := target.crypt & 0x07
		useCrypt := false
		if p.cryptKnown {
			f, withHash, ok := NatCallbackCrypt(target.crypt, p.crypt)
			if !ok {
				continue
			}
			flags, useCrypt = f, withHash
		}
		notice := BuildNatCallbackNotice(endpoint.ipv4, endpoint.port, targetID, flags, target.hash)
		if !useCrypt {
			notice[10] &^= natCallbackNoticeFlagHash
		}
		hash := notice[11:]
		dst := natCallbackRecent{ipv4: p.ipv4, port: p.port}
		s.sendNatCallbackUDP(p.conn, dst, notice, module)
		logging.Debugf("foreign callback 0xa7 sent requester=%s:%d target=%d port=%d hash=%t crypt=%t via=%s",
			v4FromUint32(p.ipv4), p.port, targetID, endpoint.port, len(hash) == 16, useCrypt, via)
	}
}

// observeUDPQuerier feeds the bot detector, which only observes.
func (s *ServerRuntime) observeUDPQuerier(key string) {
	if s.bots.record(key, s.udp().BotDetection) {
		s.blocks.bots.Add(1)
		logging.Warnf("udp querier looks automated source=%s (observed only, not blocked)", key)
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

// allowForeignAddress applies the per-address limit; a changed config is picked up
// on the next call.
func (n *natCallbackState) allowForeignAddress(key string, perMinute, burst int) bool {
	n.mu.Lock()
	if n.foreignAddr == nil {
		n.foreignAddr = ratelimit.NewBurst(perMinute, burst)
	} else if perMinute != n.foreignAddrRate || burst != n.foreignAddrBurst {
		n.foreignAddr.SetLimits(perMinute, burst)
	}
	n.foreignAddrRate, n.foreignAddrBurst = perMinute, burst
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

// allowForeignNamed caps the distinct targets one address names per
// natForeignTargetWindow. A target it named before does not count again.
func (n *natCallbackState) allowForeignNamed(key string, target uint32, now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sweepLocked(now)
	if n.foreignNamed == nil {
		n.foreignNamed = map[string]map[uint32]time.Time{}
	}
	named := n.foreignNamed[key]
	for id, at := range named {
		if now.Sub(at) > natForeignTargetWindow {
			delete(named, id)
		}
	}
	if _, ok := named[target]; !ok && len(named) >= natForeignMaxTargetsPerAddress {
		return false
	}
	if named == nil {
		named = map[uint32]time.Time{}
		n.foreignNamed[key] = named
	}
	named[target] = now
	return true
}

// rememberKeepalive keeps a session's last obfuscated keepalive source.
func (n *natCallbackState) rememberKeepalive(id uint32, r natCallbackRecent) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sweepLocked(r.at)
	if n.keepalives == nil {
		n.keepalives = map[uint32]natCallbackRecent{}
	}
	n.keepalives[id] = r
}

func (n *natCallbackState) keepaliveFor(id uint32, now time.Time) (natCallbackRecent, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, ok := n.keepalives[id]
	if !ok || now.Sub(r.at) > natKeepaliveTTL {
		return natCallbackRecent{}, false
	}
	return r, true
}

// after arms the fallback timer.
func (n *natCallbackState) after(d time.Duration, f func()) {
	n.mu.Lock()
	af := n.afterFunc
	n.mu.Unlock()
	if af == nil {
		time.AfterFunc(d, f)
		return
	}
	af(d, f)
}

// addForeign records a foreign requester for target. The same requester (address
// and port) only refreshes its entry; past natForeignMaxPerTarget the oldest goes.
// first reports that the target had none pending, and gen names that batch.
func (n *natCallbackState) addForeign(target uint32, p natForeignPending) (gen uint64, first bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sweepLocked(p.at)
	if n.foreign == nil {
		n.foreign = map[uint32]*natForeignWait{}
	}
	w := n.foreign[target]
	if w != nil {
		w.list = liveForeign(w.list, p.at)
	}
	if w == nil || len(w.list) == 0 {
		n.foreignGen++
		w = &natForeignWait{gen: n.foreignGen}
		n.foreign[target] = w
		first = true
	}
	list := w.list
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
	w.list = append(list, p)
	return w.gen, first
}

// takeForeign removes and returns the live requesters waiting for target.
func (n *natCallbackState) takeForeign(target uint32, now time.Time) []natForeignPending {
	n.mu.Lock()
	defer n.mu.Unlock()
	w, ok := n.foreign[target]
	if !ok {
		return nil
	}
	delete(n.foreign, target)
	return liveForeign(w.list, now)
}

// takeForeignGen is takeForeign for the fallback timer of batch gen: a later batch
// has its own timer.
func (n *natCallbackState) takeForeignGen(target uint32, gen uint64, now time.Time) []natForeignPending {
	n.mu.Lock()
	defer n.mu.Unlock()
	w, ok := n.foreign[target]
	if !ok || w.gen != gen {
		return nil
	}
	delete(n.foreign, target)
	return liveForeign(w.list, now)
}

// sweepLocked drops stale foreign state, at most once per window, so no goroutine is
// needed. Callers hold mu.
func (n *natCallbackState) sweepLocked(now time.Time) {
	if now.Sub(n.foreignSweep) < natCallbackWindow {
		return
	}
	n.foreignSweep = now
	for k, w := range n.foreign {
		if w.list = liveForeign(w.list, now); len(w.list) == 0 {
			delete(n.foreign, k)
		}
	}
	for key, named := range n.foreignNamed {
		for id, at := range named {
			if now.Sub(at) > natForeignTargetWindow {
				delete(named, id)
			}
		}
		if len(named) == 0 {
			delete(n.foreignNamed, key)
		}
	}
	for id, r := range n.keepalives {
		if now.Sub(r.at) > natKeepaliveTTL {
			delete(n.keepalives, id)
		}
	}
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
