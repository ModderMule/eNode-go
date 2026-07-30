package ed2k

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"enode/logging"
	"enode/storage"
)

type TCPRuntimeConfig struct {
	Name        string
	Description string
	// Address is the bind address, and may be the 0.0.0.0 wildcard.
	Address string
	// AdvertisedIP is the address published to clients in OP_SERVERIDENT. It is
	// separate from Address because the wildcard is a valid thing to bind but
	// encodes as IP 0, which tells a client nothing. Empty falls back to Address.
	AdvertisedIP         string
	Port                 uint16
	Flags                uint32
	Hash                 []byte
	MessageLogin         string
	MessageLowID         string
	ConnectionTimeout    time.Duration
	DisconnectTimeout    time.Duration
	ServerStatusInterval time.Duration
	// CounterCacheTTL bounds how stale the advertised client/file counts may be.
	// Zero uses defaultCounterCacheTTL.
	CounterCacheTTL time.Duration
	AllowLowIDs     bool
	SupportCrypt    bool
	// MinLowID and MaxLowID bound the LowID allocation range (tcp.minLowID /
	// tcp.maxLowID). Zero means "use the default", resolved in NewLowIDClients.
	MinLowID uint32
	MaxLowID uint32
	// IPv6 is the master switch: dual-stack accept, CT_MOD_IP_V6 parsing, the
	// SRV_*FLG_IPV6 advertisement, and CT_MOD_SVR_IP_V6. PublishV6Sources
	// additionally gates whether IPv6 sources are emitted (the sentinel and
	// tag-block formats) — a server can accept v6 clients without publishing them.
	// ProbeIPv6 verifies a client's advertised IPv6 is reachable before publishing;
	// when off, a known IPv6 is trusted as reachable. ServerIPv6 is the server's own
	// public IPv6 (16 bytes) for CT_MOD_SVR_IP_V6.
	IPv6             bool
	PublishV6Sources bool
	ProbeIPv6        bool
	ServerIPv6       []byte
	// NatRendezvousPort is advertised as the TagNatPort (0x9d) tag in OP_SERVERIDENT
	// when server-independent rendezvous is on. Zero omits the tag.
	NatRendezvousPort uint16
}

type UDPRuntimeConfig struct {
	Name        string
	Description string
	DynIP       string
	UDPFlags    uint32
	// GetSources and GetFiles gate the extended UDP opcodes. Previously they
	// existed only on UDPServerConfig, where BuildUDPFlags used them to *advertise*
	// support — so a server with getSources disabled cleared the flag and then
	// answered anyway. Conforming clients respect the advertised flag, so the
	// exposure was precisely to the abusive ones the option exists to stop.
	GetSources     bool
	GetFiles       bool
	UDPPortObf     uint16
	TCPPortObf     uint16
	UDPServerKey   uint32
	MaxConnections uint32
}

type ServerRuntime struct {
	TCP     TCPRuntimeConfig
	UDP     UDPRuntimeConfig
	Storage storage.Engine
	LowIDs  *LowIDClients
	NAT     *NATTraversalHandler
	// Gossip is the server-to-server peer table, or nil when gossip is disabled. Every
	// dispatch case that touches it is gated on nil, so a server with gossip off has
	// exactly its previous behaviour.
	Gossip *GossipHandler
	// Filter refuses blocked addresses before any parsing, or nil to filter nothing.
	Filter   AccessFilter
	counters *counterCache
	// sessionsMu guards sessionsByHash, which indexes logged-in connections by user hash
	// so a PR_NAT keepalive can extend the matching eD2K session's idle deadline. Keyed on
	// hash rather than ID because that is what the NAT registry knows; the LowIDs table is
	// keyed on the assigned ID and so cannot answer this lookup.
	sessionsMu     sync.RWMutex
	sessionsByHash map[[16]byte]*tcpClient
	// firewallProbe indirects the IPv4 dial-back so a test can drive both branches
	// of the login ID decision without a reachable listener, and can assert that
	// the decision short-circuits before dialling at all. nil selects the real
	// probe; nothing outside tests sets it.
	firewallProbe func(*tcpClient) bool
}

// ipv6Enabled reports whether IPv6 is on at all (dual-stack accept, CT_MOD_IP_V6
// parsing, advertisement). publishV6Sources reports whether IPv6 sources are
// emitted. Both the TCP and UDP handlers read these accessors rather than poking
// the TCP runtime config directly, so the two stacks share one source of truth.
func (s *ServerRuntime) ipv6Enabled() bool      { return s.TCP.IPv6 }
func (s *ServerRuntime) publishV6Sources() bool { return s.TCP.PublishV6Sources }

func NewServerRuntime(tcp TCPRuntimeConfig, udp UDPRuntimeConfig, store storage.Engine) *ServerRuntime {
	if tcp.ServerStatusInterval <= 0 {
		tcp.ServerStatusInterval = defaultServerStatusInterval
	}
	return &ServerRuntime{
		TCP:      tcp,
		UDP:      udp,
		Storage:  store,
		LowIDs:   NewLowIDClients(tcp.AllowLowIDs, tcp.MinLowID, tcp.MaxLowID),
		counters: newCounterCache(store, tcp.CounterCacheTTL),
	}
}

// AccessFilter decides whether a peer address may talk to this server at all. The
// interface is declared here rather than imported so the protocol package gains no
// dependency on the filter implementation (netfilter, which pulls in MaxMind) and so a
// test can substitute a stub.
//
// Blocked is called before any wire parsing on both transports, so implementations must
// be cheap and safe for concurrent use from every UDP worker and accept goroutine.
type AccessFilter interface {
	Blocked(ip net.IP) (bool, string)
}

// SetAccessFilter attaches the ipfilter/GeoIP layer. nil disables filtering, and both
// call sites are nil-guarded, so an unfiltered server pays one interface comparison.
func (s *ServerRuntime) SetAccessFilter(f AccessFilter) {
	s.Filter = f
}

// blockedPeer reports whether an address is refused, with a reason for the log.
func (s *ServerRuntime) blockedPeer(ip net.IP) (bool, string) {
	if s.Filter == nil || ip == nil {
		return false, ""
	}
	return s.Filter.Blocked(ip)
}

func (s *ServerRuntime) TCPHandler(enableCrypt bool) func(net.Conn) {
	return func(conn net.Conn) {
		// Filtered before newTCPClient, so a blocked address is closed without a byte
		// being read or a session goroutine, status ticker or crypt state being created.
		// Closing silently rather than sending OP_SERVERMESSAGE first is deliberate: the
		// reply would cost a round trip to an address we have already decided not to
		// serve, and it tells a scanner it found an eD2K server.
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			if blocked, reason := s.blockedPeer(NormalizeIP(tcpAddr.IP)); blocked {
				logging.Debugf("tcp connection refused remote=%s reason=%s", tcpAddr.IP, reason)
				_ = conn.Close()
				return
			}
		}
		// Record every accepted address so gossip can refuse to admit a client as a peer.
		// Placed after the filter so a blocked address is not tracked at all.
		if s.Gossip != nil {
			if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				s.Gossip.NoteClient(tcpAddr.IP)
			}
		}
		client := newTCPClient(s, conn, enableCrypt)
		client.run()
	}
}

// advertisedAddress is the address published to clients, falling back to the
// bind address when none was configured. Callers that need the *bind* address
// (probeClient's LocalAddr) must keep using TCP.Address.
func (s *ServerRuntime) advertisedAddress() string {
	if s.TCP.AdvertisedIP != "" {
		return s.TCP.AdvertisedIP
	}
	return s.TCP.Address
}

func (s *ServerRuntime) SetNATHandler(handler *NATTraversalHandler) {
	s.NAT = handler
	// Bridge PR_NAT keepalives to eD2K session liveness. Registered here rather than in
	// main.go so the wiring cannot be forgotten when a NAT handler is attached.
	handler.SetSessionTouch(s.TouchSessionByHash)
}

// registerSession indexes a logged-in connection by user hash. Called from handShake, so
// only a session that actually completed login can be found.
func (s *ServerRuntime) registerSession(hash []byte, client *tcpClient) {
	if len(hash) != 16 {
		return
	}
	var key [16]byte
	copy(key[:], hash)
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if s.sessionsByHash == nil {
		s.sessionsByHash = make(map[[16]byte]*tcpClient)
	}
	s.sessionsByHash[key] = client
}

// unregisterSession removes the index entry, but only when it still points at this
// connection.
//
// The identity check matters: a duplicate login is rejected rather than allowed
// (see handleLoginRequest), but a reconnect after a stale session finally times out can
// have the two overlap briefly. Deleting unconditionally would then let the departing
// session unregister the live one, and the live client would silently lose keepalive-based
// liveness for the rest of its session.
func (s *ServerRuntime) unregisterSession(hash []byte, client *tcpClient) {
	if len(hash) != 16 {
		return
	}
	var key [16]byte
	copy(key[:], hash)
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if s.sessionsByHash[key] == client {
		delete(s.sessionsByHash, key)
	}
}

// TouchSessionByHash extends the idle deadline of the eD2K session belonging to a user
// hash. Invoked when that user's PR_NAT keepalive arrives.
//
// This is what stops a share-only LowID client from being reaped: such a client publishes
// its files, keeps its PR_NAT registration fresh so it stays punchable, and then sends no
// TCP traffic at all. The read deadline (disconnectTimeout, 3600 s by default) would close
// it and drop every source it offered, even though the keepalives prove it is reachable.
//
// Refreshing lastSeen in the NAT registry alone was not enough — that governs whether the
// client can be *paired*, not whether its eD2K session survives.
func (s *ServerRuntime) TouchSessionByHash(hash [16]byte) {
	s.sessionsMu.RLock()
	client := s.sessionsByHash[hash]
	s.sessionsMu.RUnlock()
	if client == nil {
		return
	}
	client.touchDeadline()
}

// Counts returns the cached online-client and file totals — the same briefly
// cached reading that backs OP_SERVERSTATUS and OP_GLOBSERVSTATRES. Callers such
// as the admin dashboard read this rather than Storage.ClientsCount/FilesCount so
// that frequent polling cannot turn into a flood of COUNT(*) queries.
func (s *ServerRuntime) Counts() (clients, files int) {
	return s.counters.Counts()
}

// AdvertisedServerCount reports how many peer servers a client would receive in
// OP_SERVERLIST right now.
//
// The admin dashboard reads this rather than Storage.ServersCount(), which counts only
// the configured entries and so reports 0 for every peer gossip learns. Delegating to
// advertisableServers keeps one definition of "a peer we are willing to publish" — the
// count and the wire list cannot drift apart, including the deduplication between a
// configured seed and the same address arriving over gossip.
func (s *ServerRuntime) AdvertisedServerCount() int {
	return len(s.advertisableServers())
}

func (s *ServerRuntime) UDPHandler(enableCrypt bool) func([]byte, *net.UDPAddr, *net.UDPConn) {
	module := "udp"
	if enableCrypt {
		module = "udp-obfs"
	}
	return func(data []byte, remote *net.UDPAddr, conn *net.UDPConn) {
		if len(data) == 0 {
			return
		}
		// Filtered first, ahead of NewUDPCrypt and any decryption or parsing. A blocked
		// address therefore costs one binary search and nothing else — which is the whole
		// point on a socket that can be flooded.
		if blocked, reason := s.blockedPeer(NormalizeIP(remote.IP)); blocked {
			logging.Debugf("udp datagram dropped remote=%s len=%d reason=%s", remote, len(data), reason)
			return
		}
		// The obfuscation key is per-client, derived from the source IP (see
		// deriveUDPKey). Built per datagram, not once per listener: the handler
		// runs concurrently across a worker pool (udpserver.go), so a shared crypt
		// whose key varied per client would race. crypt.ServerKey is the key we
		// also advertise to this client at reply offset +36, so both directions
		// agree. On the plaintext listener the crypt does no crypto but still
		// carries the derived key for the stat reply to advertise.
		crypt := NewUDPCrypt(enableCrypt, deriveUDPKey(s.UDP.UDPServerKey, remote.IP))
		// Whether the datagram genuinely arrived obfuscated, recorded before Decrypt
		// replaces the buffer. This is not the same question as "which listener is this":
		// Decrypt deliberately passes a plaintext PR_ED2K frame straight through (so a
		// plaintext login on the obfuscated port still works, the H4 fix), and it also
		// returns the input unchanged when decryption fails. So a plaintext 0xA0 aimed at
		// the gossip port would otherwise be indistinguishable from a properly obfuscated
		// one — and for gossip that distinction *is* the authentication. A frame counts as
		// obfuscated only if the listener does crypto, the first byte was not a protocol
		// constant, and what came out is a well-formed eD2K frame.
		arrivedPlaintext := data[0] == PrED2K
		if crypt.Status == CsEncrypting {
			data = crypt.Decrypt(data)
		}
		// Neither of a *peer server's* two reply shapes can be read by the decrypt above,
		// so gossip needs two more attempts. Both key/direction pairs below were measured
		// against eserver 17.14 rather than inferred — see docs/server-gossip.md.
		if enableCrypt && !arrivedPlaintext && (len(data) == 0 || data[0] != PrED2K) && s.Gossip != nil {
			data = s.decryptPeerReply(data, remote.IP)
		}
		obfuscated := enableCrypt && !arrivedPlaintext && len(data) > 0 && data[0] == PrED2K
		if s.NAT != nil {
			if data[0] == PrNat || len(data) == 1 {
				s.NAT.HandlePacket(data, remote, conn, crypt)
				if data[0] == PrNat {
					return
				}
			}
		}
		LogUDPRaw(module, "recv", remote.String(), data)
		b := NewBufferFromBytes(data)
		protocol, err := b.GetUInt8()
		if err != nil {
			return
		}
		code, err := b.GetUInt8()
		if err != nil {
			return
		}
		if protocol != PrED2K {
			// Server-UDP crypt-ping: a client without our UDP key yet sends a raw
			// 32-bit challenge (+ up to 15 padding bytes) to the obfuscated port
			// before it can obfuscate anything. It fails the fixed-key Decrypt above
			// (no SYNC_SERVER), so `data` is still the raw bytes and its first byte
			// is not PR_ED2K. Answer with the stat reply keyed on the challenge so
			// the client learns our real UDP key. Only on the obfuscated listener,
			// where such a probe is expected. See docs/server-udp-crypt-ping.md.
			if enableCrypt && isCryptPing(data) {
				s.udpCryptPingReply(data, remote, conn, crypt.ServerKey, module)
				return
			}
			logging.Debugf("udp unsupported protocol remote=%s proto=0x%x", remote, protocol)
			return
		}
		// Gated per opcode, not by one shared switch: each is advertised by its
		// own flag, and the two below are deliberately ungated because they carry
		// no such flag — refusing them would make the server invisible in server
		// lists.
		switch code {
		case OpGlobGetSources:
			if !s.udpOpcodeEnabled(s.UDP.GetSources, code, remote) {
				return
			}
			s.udpGlobGetSources(b, remote, conn, crypt, module)
		case OpGlobGetSources2:
			if !s.udpOpcodeEnabled(s.UDP.GetSources, code, remote) {
				return
			}
			s.udpGlobGetSources2(b, remote, conn, crypt, module)
		case OpGlobGetSourcesIPv6:
			if !s.publishV6Sources() || !s.udpOpcodeEnabled(s.UDP.GetSources, code, remote) {
				return
			}
			s.udpGlobGetSourcesIPv6(b, remote, conn, crypt, module)
		case OpGlobServStatReq:
			s.udpGlobServStatReq(b, remote, conn, crypt, module)
		case OpServerDescReq:
			if len(data) < 6 {
				s.udpServDescResOld(remote, conn, crypt, module)
			} else {
				s.udpServDescRes(b, remote, conn, crypt, module)
			}
		case OpGlobSearchReq:
			if !s.udpOpcodeEnabled(s.UDP.GetFiles, code, remote) {
				return
			}
			s.udpGlobSearchReq(b, remote, conn, crypt, module)
		case OpGlobSearchReq3:
			if !s.udpOpcodeEnabled(s.UDP.GetFiles, code, remote) {
				return
			}
			s.udpGlobSearchReq3(b, remote, conn, crypt, module)

		// Server-to-server gossip, each gated on the handler being present so a server
		// with gossip disabled behaves exactly as before. The obfuscated flag is threaded
		// down rather than inferred from the listener — see where it is computed above.
		case OpServerListReq:
			if !s.gossipOpcodeEnabled(code, remote, false) {
				return
			}
			s.udpServerListReq(b, remote, conn, obfuscated, module)
		case OpServerListRes:
			if !s.gossipOpcodeEnabled(code, remote, false) {
				return
			}
			s.udpServerListRes(b, remote, false, obfuscated, module)
		case OpServerListReq2:
			if !s.gossipOpcodeEnabled(code, remote, false) {
				return
			}
			s.udpServerListReq2(remote, conn, false, obfuscated, module)
		case OpServerListReqIPv6:
			if !s.gossipOpcodeEnabled(code, remote, true) {
				return
			}
			s.udpServerListReq2(remote, conn, true, obfuscated, module)
		case OpServerListResIPv6:
			if !s.gossipOpcodeEnabled(code, remote, true) {
				return
			}
			s.udpServerListRes(b, remote, true, obfuscated, module)
		case OpGlobServStatRes:
			// A peer answering our probe. Clients never send this, so it is only ever
			// server-to-server traffic.
			if !s.gossipOpcodeEnabled(code, remote, false) {
				return
			}
			s.udpGlobServStatRes(b, remote, module)
		case OpServerDescRes:
			// A peer answering our name/description probe — the admission test.
			if !s.gossipOpcodeEnabled(code, remote, false) {
				return
			}
			s.udpServerDescRes(b, remote, module)
		default:
			logging.Debugf("udp unknown opcode remote=%s opcode=0x%x", remote, code)
		}
	}
}

// gossipOpcodeEnabled gates a gossip opcode on the handler being attached, and on the
// IPv6 extension being on for the 0xa7/0xa8 pair. Mirrors udpOpcodeEnabled: the decision
// and its log line live in one place rather than being repeated at each case.
func (s *ServerRuntime) gossipOpcodeEnabled(code uint8, remote *net.UDPAddr, needIPv6 bool) bool {
	if s.Gossip == nil {
		logging.Debugf("udp gossip opcode ignored, gossip disabled remote=%s opcode=0x%x", remote, code)
		return false
	}
	if needIPv6 && !s.Gossip.Config().PublishIPv6 {
		logging.Debugf("udp gossip opcode ignored, publishIPv6 off remote=%s opcode=0x%x", remote, code)
		return false
	}
	return true
}

type tcpClient struct {
	server     *ServerRuntime
	conn       net.Conn
	packet     *Packet
	crypt      *TCPCrypt
	module     string
	writeMu    sync.Mutex
	closeMu    sync.Mutex
	remoteHost string
	statusStop chan struct{}

	// peerIP is the connecting address, family-normalised (mapped v4 collapsed to
	// plain IPv4). connectedV6 is true when the session itself is IPv6 — one of the
	// two signals that make it safe to send this client IPv6 sources (the other is
	// a CT_MOD_IP_V6 tag in login). Both are set once at construction / login and
	// then only read.
	peerIP      net.IP
	connectedV6 bool
	// ipv6Capable is set at login to connectedV6 || the client sent a CT_MOD_IP_V6
	// tag. Only read by this connection's own request handlers, so it needs no
	// lock. It gates whether this session may receive IPv6 sentinel sources.
	ipv6Capable bool

	// infoMu guards info, logged and hasLowID. The connection's own goroutine
	// writes them during login, but two other goroutines read them: the periodic
	// status ticker (logged) and any peer handling OP_CALLBACKREQUEST, which
	// reaches this client through the shared LowIDs table.
	infoMu   sync.RWMutex
	info     storage.ClientInfo
	logged   bool
	hasLowID bool

	// pendingResults holds the tail of a search whose first page has been sent, so
	// OP_QUERY_MORE_RESULT can deliver the rest. Only this connection's own goroutine
	// touches them — search and the More request both arrive on this socket — so no lock
	// is needed, unlike the fields above which the status ticker and peer callbacks read.
	//
	// Held rather than re-queried because eMule's More request carries no payload at all
	// (srchybrid/SearchResultsWnd.cpp:1282): there is nothing to re-run the query from.
	// Bounded by storage.MaxSearchResults, so the memory a session can pin this way is
	// bounded too.
	pendingResults []storage.File

	closeReason string
}

// snapshotInfo returns a copy of the client's identity, safe to read from any
// goroutine. Hash is copied too: returning the slice header would let the caller
// alias a field the owning goroutine may still rewrite.
func (c *tcpClient) snapshotInfo() storage.ClientInfo {
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	info := c.info
	if info.Hash != nil {
		info.Hash = append([]byte(nil), info.Hash...)
	}
	return info
}

func (c *tcpClient) isLogged() bool {
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	return c.logged
}

// isV6Capable reports whether this session can parse the IPv6 wire forms (it
// connected over IPv6 or sent a CT_MOD_IP_V6 login tag). Unlike the same-goroutine
// direct reads of ipv6Capable in this connection's own handlers, the callback path
// reaches a target through the shared LowIDs table and reads it from another
// goroutine, so it goes through the infoMu lock the login writer now holds.
func (c *tcpClient) isV6Capable() bool {
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	return c.ipv6Capable
}

func newTCPClient(server *ServerRuntime, conn net.Conn, enableCrypt bool) *tcpClient {
	host := ""
	var peerIP net.IP
	if addr := conn.RemoteAddr(); addr != nil {
		host = splitHost(addr.String())
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			peerIP = NormalizeIP(tcpAddr.IP)
		}
	}
	// Take the address straight from net.Addr rather than re-parsing the host
	// string: on a dual-stack listener an IPv4 peer arrives as ::ffff:a.b.c.d,
	// which NormalizeIP collapses to plain IPv4, and a genuine v6 peer keeps its
	// 16 bytes. ipv4 is 0 for a v6-only peer (no HighID exists for it); connectedV6
	// records that the session itself is IPv6, one of the two v6-capability signals.
	ipv4, _ := IPv4ToUint32LE(peerIP)
	connectedV6 := false
	if _, ok := IPv6Bytes(peerIP); ok {
		connectedV6 = true
	}
	packet := NewPacket()
	var crypt *TCPCrypt
	if enableCrypt {
		crypt = NewTCPCrypt(packet, true)
	}
	enableTCPKeepAlive(conn, defaultTCPKeepAlivePeriod)
	return &tcpClient{
		server:      server,
		conn:        conn,
		packet:      packet,
		crypt:       crypt,
		module:      tcpModule(enableCrypt),
		hasLowID:    true,
		remoteHost:  host,
		peerIP:      peerIP,
		connectedV6: connectedV6,
		info: storage.ClientInfo{
			IPv4:  ipv4,
			ID:    0,
			Port:  0,
			LowID: true,
		},
	}
}

const defaultTCPKeepAlivePeriod = 2 * time.Minute
const defaultServerStatusInterval = 5 * time.Minute

func enableTCPKeepAlive(conn net.Conn, period time.Duration) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tcp.SetKeepAlive(true); err != nil {
		return
	}
	if period > 0 {
		_ = tcp.SetKeepAlivePeriod(period)
	}
}

func (c *tcpClient) run() {
	c.setCloseReason("read-loop-ended")
	defer func() {
		if c.statusStop != nil {
			close(c.statusStop)
		}
		c.infoMu.RLock()
		hadLowID, wasLogged := c.hasLowID, c.logged
		c.infoMu.RUnlock()
		info := c.snapshotInfo()
		if hadLowID {
			c.server.LowIDs.Remove(info.ID)
		}
		if wasLogged {
			c.server.unregisterSession(info.Hash, c)
			c.server.Storage.Disconnect(info)
		}
		_ = c.conn.Close()
		logging.Infof("tcp session closed remote=%s id=%d lowID=%t storeID=%d reason=%s",
			c.remoteHost, info.ID, info.LowID, info.StoreID, c.getCloseReason())
	}()

	buf := make([]byte, 4096)
	for {
		if c.server.TCP.DisconnectTimeout > 0 {
			_ = c.conn.SetReadDeadline(time.Now().Add(c.server.TCP.DisconnectTimeout))
		}
		n, err := c.conn.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.setCloseReason("peer-closed")
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				c.setCloseReason(fmt.Sprintf("read-timeout(%s)", c.server.TCP.DisconnectTimeout))
			} else {
				c.setCloseReason(fmt.Sprintf("read-error: %v", err))
			}
			return
		}
		if n == 0 {
			c.setCloseReason("read-zero")
			return
		}
		c.handleBytes(buf[:n])
	}
}

func (c *tcpClient) handleBytes(data []byte) {
	if c.crypt != nil {
		state := c.crypt.State()
		switch state {
		case CsUnknown, CsNegotiating:
			// Inspect the protocol byte before assuming obfuscation. A plaintext
			// client may legitimately connect to the obfuscated port; feeding its
			// login straight into negotiate() would consume the payload as
			// [marker][96-byte DH A][pad], derive keys from it, and wedge the
			// session. The original checks the protocol byte first for this
			// reason (eNode/ed2k/packet.js:105-129).
			if state == CsUnknown && len(data) > 0 && IsProtocol(data[0]) {
				logging.Debugf("tcp plaintext on obfuscated port remote=%s proto=0x%x", c.remoteHost, data[0])
				c.crypt.SetState(CsNone)
				break
			}
			rest, err := c.crypt.ProcessData(NewBufferFromBytes(data))
			if err != nil {
				// The stream is unrecoverable once negotiation fails: state stays
				// CsNegotiating and every later chunk fails the same way, so the
				// peer would linger until disconnectTimeout (3600s by default).
				logging.Warnf("tcp crypt error remote=%s err=%v", c.remoteHost, err)
				c.closeWithReason(fmt.Sprintf("crypt-handshake-failed: %v", err))
				return
			}
			if state == CsUnknown {
				if len(rest) > 0 {
					_ = c.writeRaw(rest)
				}
				return
			}
			if len(rest) == 0 {
				return
			}
			data = rest
		case CsEncrypting:
			data = c.crypt.Decrypt(data)
		}
	}
	c.processPacketData(data)
}

func (c *tcpClient) processPacketData(data []byte) {
	buf := NewBufferFromBytes(data)
	switch c.packet.Status {
	case PsNew:
		if err := c.packet.Init(buf); err != nil {
			// An oversized declaration is never legitimate and would otherwise
			// allocate the declared size, so drop the peer rather than resync.
			if errors.Is(err, ErrPacketTooLarge) {
				logging.Warnf("tcp packet too large remote=%s err=%v", c.remoteHost, err)
				c.closeWithReason("packet-too-large")
			}
			return
		}
	case PsWaitingData:
		c.packet.Append(buf.Get())
	default:
		return
	}

	if c.packet.Status != PsReady {
		return
	}

	c.handlePacket(c.packet)
	c.packet.Status = PsNew
	if c.packet.HasExcess && len(c.packet.Excess) > 0 {
		excess := append([]byte(nil), c.packet.Excess...)
		c.packet.HasExcess = false
		c.packet.Excess = nil
		c.processPacketData(excess)
	}
}

func (c *tcpClient) handlePacket(packet *Packet) {
	switch packet.Protocol {
	case PrED2K:
		LogTCPPacket(c.module, "recv", c.remoteHost, packet.Protocol, packet.Code, packet.Data.Bytes())
		c.handleED2K(packet.Code, packet.Data)
	case PrZlib:
		LogTCPPacket(c.module, "recv", c.remoteHost, packet.Protocol, packet.Code, packet.Data.Bytes())
		payload, err := InflateZlibPayload(packet.Data.Bytes())
		if err != nil {
			logging.Warnf("tcp zlib inflate failed remote=%s err=%v", c.remoteHost, err)
			// A compression ratio that overshoots the ceiling is a zlib bomb, not
			// a corrupt stream: drop the peer instead of waiting for the next one.
			if errors.Is(err, ErrInflatedTooLarge) {
				c.closeWithReason("zlib-bomb")
			}
			return
		}
		LogTCPPacket(c.module, "recv-decompressed", c.remoteHost, PrED2K, packet.Code, payload)
		c.handleED2K(packet.Code, NewBufferFromBytes(payload))
	default:
		LogTCPPacket(c.module, "recv", c.remoteHost, packet.Protocol, packet.Code, packet.Data.Bytes())
		logging.Debugf("tcp unsupported protocol remote=%s proto=0x%x", c.remoteHost, packet.Protocol)
	}
}

func (c *tcpClient) handleED2K(opcode uint8, data *Buffer) {
	data.Pos(0)
	switch opcode {
	case OpLoginRequest:
		c.handleLoginRequest(data)
	case OpOfferFiles:
		c.handleOfferFiles(data)
	case OpGetServerList:
		c.handleGetServerList()
	case OpGetSources:
		c.handleGetSources(data, false)
	case OpGetSourcesObfu:
		c.handleGetSources(data, true)
	case OpGetSourcesIPv6:
		// Unhandled (falls to the default log) unless we publish v6 sources, so a
		// disabled server behaves exactly as before for this opcode too.
		if c.server.publishV6Sources() {
			c.handleGetSourcesIPv6(data)
		} else {
			logging.Debugf("tcp unhandled opcode remote=%s opcode=0x%x (ipv6 publish off)", c.remoteHost, opcode)
		}
	case OpSearchRequest:
		c.handleSearchRequest(data)
	case OpQueryMoreResult:
		c.handleQueryMoreResult()
	case OpCallbackRequest:
		c.handleCallbackRequest(data)
	case OpDisconnect:
		// eMule sends this before closing. Acting on it releases the session, its LowID
		// and its storage row immediately instead of after the read loop notices the FIN —
		// and, more usefully, instead of after disconnectTimeout for a client whose socket
		// dies without one. Empty payload.
		c.closeWithReason("client-disconnect")
	default:
		logging.Debugf("tcp unhandled opcode remote=%s opcode=0x%x", c.remoteHost, opcode)
	}
}

func (c *tcpClient) handleLoginRequest(data *Buffer) {
	req, err := ParseLoginRequest(data)
	if err != nil {
		logging.Warnf("login request parse failed remote=%s err=%v", c.remoteHost, err)
		return
	}
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_LOGINREQUEST hash=%x id=%d port=%d tags=%s",
		c.remoteHost, req.Hash, req.ID, req.Port, formatNamedTags(req.Tags, 32))

	// One login per connection. OP_LOGINREQUEST is dispatched at any point in the
	// session, and a repeat used to overwrite c.info.ID while the previously
	// allocated LowID stayed in the table pointing at this client — the cleanup
	// path frees only the last one, so a socket looping logins drained the pool.
	if c.isLogged() {
		logging.Warnf("duplicate login on an established session remote=%s", c.remoteHost)
		c.closeWithReason("already-logged-in")
		return
	}

	// Reject the new connection when this user hash is already online, rather
	// than evicting the existing session. The hash is public — it is broadcast in
	// OP_HELLO and handed out in OP_FOUNDSOURCES_OBFU — so eviction let any peer
	// disconnect any user at will. The original rejects too
	// (eNode/ed2k/tcpoperations.js:233-243), and checks before the firewall probe
	// so a duplicate does not cost a dial-back.
	if len(req.Hash) == 16 && c.server.Storage.IsConnected(storage.ClientInfo{Hash: req.Hash}) {
		logging.Warnf("login rejected remote=%s hash=%x: already connected", c.remoteHost, req.Hash)
		c.sendServerMessage("Already connected from another session.")
		c.closeWithReason("duplicate-login")
		return
	}

	// Resolve the client's public IPv6 and its capability, but only when IPv6 is
	// enabled — otherwise the session behaves exactly as before, with no v6 parsed,
	// stored, or advertised. The address is the CT_MOD_IP_V6 tag when present (the
	// client's preferred public v6), else the connecting address if the session
	// itself is IPv6. ipv6Capable — used later to gate sentinel sources — is true
	// if either signal is present.
	var v6Bytes []byte
	var v6Capable bool
	if c.server.ipv6Enabled() {
		var sentV6Tag bool
		v6Bytes, sentV6Tag = loginIPv6(req.Tags)
		if v6Bytes == nil && c.connectedV6 {
			if pb, ok := IPv6Bytes(c.peerIP); ok && IsPublicIPv6(c.peerIP) {
				v6Bytes = append([]byte(nil), pb[:]...)
			}
		}
		v6Capable = c.connectedV6 || sentV6Tag
	}

	c.infoMu.Lock()
	c.info.Hash = req.Hash
	c.info.ID = req.ID
	c.info.Port = req.Port
	// Record the client's obfuscation capabilities so OP_FOUNDSOURCES_OBFU can
	// re-publish them per source. Absent tag → 0, i.e. no crypt advertised.
	c.info.CryptOptions = cryptOptionsFromLoginFlags(loginFlags(req.Tags))
	c.info.IPv6 = v6Bytes
	// ipv6Capable is read cross-goroutine by the callback path (isV6Capable), so it
	// is written under infoMu here rather than as a bare field assignment.
	c.ipv6Capable = v6Capable
	ipv4, port := c.info.IPv4, c.info.Port
	c.infoMu.Unlock()

	// Kick off the IPv6 reachability probe concurrently with the IPv4 firewall
	// probe below. The two are independent blocking dial-backs on the login path,
	// so running them serially doubled worst-case login latency for a dual-stack
	// client — the common eMuleAI case: connects over IPv4, advertises
	// CT_MOD_IP_V6. The probe reads only already-settled info (IPv6, Port), so it
	// races nothing. Only started when an actual dial is needed; a v6-connected or
	// probe-disabled client trusts the address as reachable.
	needV6Probe := c.v6ProbeRequired(len(v6Bytes))
	var v6ProbeResult chan bool
	if needV6Probe {
		v6ProbeResult = make(chan bool, 1)
		go func() { v6ProbeResult <- c.server.probeIPv6Reachable(c) }()
	}

	// A client whose observed IPv4 cannot be expressed as an ed2k HighID is forced
	// to LowID, and the pointless dial-back is skipped with it (|| short-circuits).
	// The ClientID field *is* the packed IPv4 with the first octet in the low byte,
	// so both 0.0.0.0 — a v6-only session, where isFirewalled would dial
	// 0.0.0.0:port — and any address ending in .0 land at or below 0x00ffffff,
	// which every client reads as a LowID. eMule states the rule from the client
	// side: "we now know the servers just give *.*.*.0 users a lowID"
	// (srchybrid/otherfunctions.h:448).
	//
	// Calling such a client a HighID would leave the server publishing it as
	// directly reachable while the client and every peer handed it as a source
	// treat it as a LowID — and since it was never registered in the LowID pool,
	// the callback they then send cannot be routed, so the source is reachable by
	// nobody.
	usableIPv4 := HasHighID(ipv4)
	firewalled := !usableIPv4 || c.server.isFirewalled(c)
	logging.Debugf("login decision remote=%s requestedID=%d usableIPv4=%t firewalled=%t hasIPv6=%t ipv6Capable=%t",
		c.remoteHost, req.ID, usableIPv4, firewalled, len(v6Bytes) == 16, c.ipv6Capable)
	if firewalled {
		c.infoMu.Lock()
		c.hasLowID = true
		c.info.LowID = true
		c.infoMu.Unlock()
		c.sendServerMessage(c.server.TCP.MessageLowID)

		// AddByAddress publishes this *tcpClient into a table other goroutines
		// read. The address+port seed only affects LowID distribution; keying on
		// the full connecting address rather than the 32-bit IPv4 keeps v6-only
		// clients (all of whom have ipv4 == 0) from colliding on one seed. The ID
		// that comes back is written under infoMu below, so a concurrent reader
		// sees either the old or the new value, never a torn one.
		id, ok := c.server.LowIDs.AddByAddress(c.peerIP, ipv4, port, c)
		if !ok {
			c.closeWithReason("lowid-pool-exhausted")
			return
		}
		c.infoMu.Lock()
		c.info.ID = id
		c.infoMu.Unlock()
	} else {
		c.infoMu.Lock()
		c.hasLowID = false
		c.info.LowID = false
		c.info.ID = c.info.IPv4
		c.infoMu.Unlock()
	}

	// Record the IPv6 reachability verdict, joining the concurrent probe if one was
	// started. A v6-connected or probe-disabled client trusts the address as
	// reachable (reachable stays true). The verdict is independent of the IPv4
	// firewall decision above.
	if c.server.publishV6Sources() && len(v6Bytes) == 16 {
		reachable := true
		if needV6Probe {
			reachable = <-v6ProbeResult
		}
		c.infoMu.Lock()
		c.info.IPv6Reachable = reachable
		c.infoMu.Unlock()
		logging.Debugf("ipv6 reachability remote=%s ipv6=%s reachable=%t connectedV6=%t",
			c.remoteHost, net.IP(v6Bytes).String(), reachable, c.connectedV6)
	}

	info := c.snapshotInfo()
	logging.Infof("login accepted remote=%s assignedID=%d lowID=%t port=%d ipv6Reachable=%t",
		c.remoteHost, info.ID, info.LowID, info.Port, info.IPv6Reachable)
	c.handShake()
}

func (c *tcpClient) handShake() {
	storeID, err := c.server.Storage.Connect(c.snapshotInfo())
	if err != nil {
		logging.Warnf("storage connect failed remote=%s err=%v", c.remoteHost, err)
		c.closeWithReason(fmt.Sprintf("storage-connect-failed: %v", err))
		return
	}
	c.infoMu.Lock()
	c.logged = true
	c.info.StoreID = storeID
	c.infoMu.Unlock()
	info := c.snapshotInfo()
	logging.Infof("login handshake complete remote=%s storeID=%d id=%d lowID=%t", c.remoteHost, info.StoreID, info.ID, info.LowID)

	// Indexed by user hash so a PR_NAT keepalive from this client can keep its session
	// alive. Removed in run()'s defer.
	c.server.registerSession(info.Hash, c)

	c.sendServerMessage(c.server.TCP.MessageLogin)
	c.sendServerMessage(fmt.Sprintf("server version %s (%s)", ENodeVersionStr, ENodeName))
	c.sendServerStatus()
	c.startPeriodicServerStatus()
	c.sendIDChange(info.ID)
	c.sendServerIdent()
}

// touchDeadline pushes the read deadline out by DisconnectTimeout, treating out-of-band
// activity (a PR_NAT keepalive) as if a byte had arrived on the socket.
//
// Called from the NAT UDP worker pool, not this connection's own goroutine, so it takes
// writeMu. That mutex already serialises socket operations against the status ticker and
// peer callbacks, and SetReadDeadline is exactly such an operation — the read loop's own
// SetReadDeadline is the one place it is touched without the lock, and that is safe
// because a deadline set slightly early only costs one extra loop iteration.
func (c *tcpClient) touchDeadline() {
	if c.server.TCP.DisconnectTimeout <= 0 {
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetReadDeadline(time.Now().Add(c.server.TCP.DisconnectTimeout))
}

func (c *tcpClient) setCloseReason(reason string) {
	if reason == "" {
		return
	}
	c.closeMu.Lock()
	if c.closeReason == "" || c.closeReason == "read-loop-ended" {
		c.closeReason = reason
	}
	c.closeMu.Unlock()
}

func (c *tcpClient) getCloseReason() string {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closeReason == "" {
		return "unknown"
	}
	return c.closeReason
}

func (c *tcpClient) closeWithReason(reason string) {
	c.setCloseReason(reason)
	_ = c.conn.Close()
}

func (c *tcpClient) startPeriodicServerStatus() {
	if c.statusStop != nil {
		return
	}
	interval := c.server.TCP.ServerStatusInterval
	if interval <= 0 {
		return
	}
	c.statusStop = make(chan struct{})
	go func(stop <-chan struct{}) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if c.isLogged() {
					c.sendServerStatus()
				}
			case <-stop:
				return
			}
		}
	}(c.statusStop)
}

func (c *tcpClient) handleOfferFiles(data *Buffer) {
	raw := append([]byte(nil), data.Bytes()...)
	records, err := data.GetFileList()
	if err != nil {
		previewLen := 96
		if len(raw) < previewLen {
			previewLen = len(raw)
		}
		previewHex := hex.EncodeToString(raw[:previewLen])
		logging.Warnf("offer files parse failed remote=%s payloadLen=%d previewHex=%s err=%v",
			c.remoteHost, len(raw), previewHex, err)
		return
	}
	const maxOfferFilesLog = 50
	logging.Debugf("offer files remote=%s count=%d payloadLen=%d", c.remoteHost, len(records), len(raw))
	// One snapshot for the whole batch: the identity cannot change mid-batch,
	// and taking it per file would lock once per offered file.
	info := c.snapshotInfo()
	for _, record := range records {
		file := fileFromRecord(record, info)
		c.server.Storage.AddFile(file, info)
	}
	limit := len(records)
	if limit > maxOfferFilesLog {
		limit = maxOfferFilesLog
	}
	for i := 0; i < limit; i++ {
		record := records[i]
		file := fileFromRecord(record, info)
		logging.Debugf("offer file remote=%s idx=%d hash=%x name=%q size=%d type=%q sourceID=%d sourcePort=%d",
			c.remoteHost, i, record.Hash, file.Name, file.Size, file.Type, info.ID, info.Port)
	}
	if len(records) > maxOfferFilesLog {
		logging.Debugf("offer files remote=%s truncated=%d", c.remoteHost, len(records)-maxOfferFilesLog)
	}
}

func (c *tcpClient) handleGetServerList() {
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_GETSERVERLIST payload=empty", c.remoteHost)
	c.sendServerList()
	c.sendServerIdent()
}

func (c *tcpClient) handleGetSources(data *Buffer, obfuscated bool) {
	hash, fileSize, ok := c.parseGetSources(data, opNameGetSources(obfuscated))
	if !ok {
		return
	}
	sources := c.server.Storage.GetSources(hash, fileSize)
	c.debugPayloadf("tcp payload parsed remote=%s opcode=%s sourcesFound=%d", c.remoteHost, opNameGetSources(obfuscated), len(sources))
	// A v6-capable session (connected over IPv6, or having sent CT_MOD_IP_V6) can
	// parse the sentinel, so IPv6-only sources are published to it inline. Every
	// other session gets the byte-identical classic layout. Sent even when empty,
	// matching the original's unconditional reply.
	format := FormatClassic
	if c.server.publishV6Sources() && c.ipv6Capable {
		format = FormatSentinel
	}
	c.sendFoundSources(hash, sources, obfuscated, format)
}

// handleGetSourcesIPv6 answers OP_GETSOURCES_IPV6 (0x24) with the richer
// tag-block format. Sending this opcode is itself the opt-in, so the reply is
// safe regardless of the sentinel-capability signals.
func (c *tcpClient) handleGetSourcesIPv6(data *Buffer) {
	hash, fileSize, ok := c.parseGetSources(data, "OP_GETSOURCES_IPV6")
	if !ok {
		return
	}
	sources := c.server.Storage.GetSources(hash, fileSize)
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_GETSOURCES_IPV6 sourcesFound=%d", c.remoteHost, len(sources))
	packet, err := BuildFoundSourcesIPv6Packet(hash, sources)
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

// parseGetSources reads the shared OP_GETSOURCES* payload: a 16-byte file hash
// and the file size (a zero uint32 signals a following uint64 for large files).
func (c *tcpClient) parseGetSources(data *Buffer, opName string) (hash []byte, fileSize uint64, ok bool) {
	hash = append([]byte(nil), data.Get(16)...)
	if len(hash) != 16 {
		logging.Warnf("get sources parse failed remote=%s opcode=%s err=invalid-hash-len", c.remoteHost, opName)
		return nil, 0, false
	}
	size, err := data.GetUInt32LE()
	if err != nil {
		logging.Warnf("get sources parse failed remote=%s opcode=%s err=%v", c.remoteHost, opName, err)
		return nil, 0, false
	}
	fileSize = uint64(size)
	if fileSize == 0 {
		v, err := data.GetUInt64LE()
		if err != nil {
			logging.Warnf("get sources parse failed remote=%s opcode=%s err=%v", c.remoteHost, opName, err)
			return nil, 0, false
		}
		fileSize = v
	}
	c.debugPayloadf("tcp payload parsed remote=%s opcode=%s hash=%x fileSize=%d", c.remoteHost, opName, hash, fileSize)
	return hash, fileSize, true
}

func (c *tcpClient) handleSearchRequest(data *Buffer) {
	expr, err := ParseSearchExpr(data)
	if err != nil {
		logging.Warnf("search request parse failed remote=%s err=%v", c.remoteHost, err)
		return
	}
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_SEARCHREQUEST expr=%s", c.remoteHost, formatSearchExpr(expr))
	files := c.server.Storage.FindBySearch(expr)
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_SEARCHREQUEST resultCount=%d", c.remoteHost, len(files))
	// A zero-result reply must still be sent. OP_SEARCHRESULT is the only packet
	// that reaches eMule's LocalEd2kSearchEnd, which is what cancels the 50 s
	// local-search timer — on silence the client sits in "Searching…" for the
	// full timeout and then gives up without ever showing "0 results".
	c.sendSearchPage(files)
}

// handleQueryMoreResult answers OP_QUERY_MORE_RESULT (0x21) with the next page of the
// last search. Empty payload — eMule's More button sends nothing but the opcode — so the
// remaining results have to have been kept from the original query.
//
// A request with nothing pending gets an empty result page rather than silence. Silence
// would leave the client's search UI waiting on its local timer, which is the same
// failure the zero-result reply above exists to avoid.
func (c *tcpClient) handleQueryMoreResult() {
	if len(c.pendingResults) == 0 {
		c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_QUERY_MORE_RESULT pending=0", c.remoteHost)
		c.sendSearchResult(nil, false)
		return
	}
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_QUERY_MORE_RESULT pending=%d",
		c.remoteHost, len(c.pendingResults))
	c.sendSearchPage(c.pendingResults)
}

// sendSearchPage sends the first storage.MaxSearchPage of files, keeps the remainder for
// OP_QUERY_MORE_RESULT, and sets the more-results flag accordingly.
func (c *tcpClient) sendSearchPage(files []storage.File) {
	page, rest := files, []storage.File(nil)
	if len(files) > storage.MaxSearchPage {
		page, rest = files[:storage.MaxSearchPage], files[storage.MaxSearchPage:]
	}
	// Assigned before the send so a write error cannot leave a stale page pending.
	c.pendingResults = rest
	c.sendSearchResult(page, len(rest) > 0)
}

func (c *tcpClient) handleCallbackRequest(data *Buffer) {
	lowID, err := data.GetUInt32LE()
	if err != nil {
		logging.Warnf("callback request parse failed remote=%s err=%v", c.remoteHost, err)
		return
	}
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_CALLBACKREQUEST lowID=%d", c.remoteHost, lowID)
	v, ok := c.server.LowIDs.Get(lowID)
	if !ok {
		c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_CALLBACKREQUEST lowID=%d result=not-found", c.remoteHost, lowID)
		c.sendCallbackFailed()
		return
	}
	target, ok := v.(*tcpClient)
	if !ok {
		c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_CALLBACKREQUEST lowID=%d result=invalid-target-type", c.remoteHost, lowID)
		c.sendCallbackFailed()
		return
	}
	// target belongs to another connection's goroutine, so its identity is read
	// through the snapshot accessor rather than directly.
	targetInfo := target.snapshotInfo()
	self := c.snapshotInfo()
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_CALLBACKREQUEST lowID=%d targetIPv4=%d targetPort=%d",
		c.remoteHost, lowID, targetInfo.IPv4, targetInfo.Port)

	// Pick the callback family from the requester's reachability, as two separate
	// checks. Classic IPv4 is preferred when the requester has a HighID (a routable
	// IPv4). When it does not — LowID over IPv4, or v6-only (IPv4 == 0) — but it has
	// a reachable public IPv6 and the target can parse the IPv6 opcode, send the
	// IPv6 callback so the target calls back over IPv6. Otherwise the callback fails
	// cleanly instead of pointing the target at 0.0.0.0 or a firewalled IPv4.
	switch {
	case !self.LowID && self.IPv4 != 0:
		c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_CALLBACKREQUEST lowID=%d family=ipv4 callbackIPv4=%d callbackPort=%d",
			c.remoteHost, lowID, self.IPv4, self.Port)
		err = target.sendCallbackRequested(self.IPv4, self.Port)
	case c.server.publishV6Sources() && len(self.IPv6) == 16 && self.IPv6Reachable && target.isV6Capable():
		c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_CALLBACKREQUEST lowID=%d family=ipv6 callbackIPv6=%s callbackPort=%d",
			c.remoteHost, lowID, net.IP(self.IPv6).String(), self.Port)
		err = target.sendCallbackRequestedIPv6(self.IPv6, self.Port)
	default:
		c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_CALLBACKREQUEST lowID=%d result=unreachable",
			c.remoteHost, lowID)
		c.sendCallbackFailed()
		return
	}
	if err != nil {
		c.sendCallbackFailed()
	}
}

func (c *tcpClient) sendFoundSources(hash []byte, sources []storage.Source, obfuscated bool, format SourceFormat) {
	var (
		packet *Buffer
		err    error
	)
	switch {
	case format == FormatSentinel:
		packet, err = BuildFoundSourcesSentinelPacket(hash, sources, obfuscated)
	case obfuscated:
		packet, err = BuildFoundSourcesObfuPacket(hash, sources)
	default:
		packet, err = BuildFoundSourcesPacket(hash, sources)
	}
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendSearchResult(files []storage.File, moreAvailable bool) {
	packet, err := BuildSearchResultPacket(files, moreAvailable)
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendServerList() {
	servers := c.server.advertisableServers()
	// Append the IPv6 peer-server block under the same switch that gates every
	// other outbound v6 wire extension (the source sentinel, the 0x26 callback).
	packet, err := BuildServerListPacket(servers, c.server.publishV6Sources())
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

// advertisableServers is the peer list clients receive in OP_SERVERLIST: the operator's
// configured entries plus every peer gossip has verified.
//
// Configured entries are always included. An operator who names a peer has asserted it
// exists, and dropping it because a handshake has not completed yet would make the list
// empty for the first few minutes after every restart — and permanently empty for a
// server whose peers are all behind something that blocks the obfuscated ports.
//
// Gossip contributes verified peers only: an unverified entry is one we have proved
// nothing about, and publishing it to clients would spread addresses we cannot vouch
// for. With gossip disabled this returns exactly what it always did.
func (s *ServerRuntime) advertisableServers() []storage.Server {
	configured := s.Storage.ServersAll()
	if s.Gossip == nil {
		return configured
	}
	verified := s.Gossip.Verified()
	out := make([]storage.Server, 0, len(configured)+len(verified))
	seen := make(map[string]struct{}, len(configured)+len(verified))
	for _, sv := range configured {
		key := sv.IP + ":" + strconv.Itoa(int(sv.Port))
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, sv)
	}
	for _, p := range verified {
		// Keyed on the canonical string form of the parsed address so a configured
		// "1.2.3.4" and a gossiped 1.2.3.4 collapse rather than appearing twice.
		key := p.IP.String() + ":" + strconv.Itoa(int(p.Port))
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, storage.Server{IP: p.IP.String(), Port: p.Port})
	}
	return out
}

func (c *tcpClient) sendServerStatus() {
	clients, files := c.server.counters.Counts()
	packet, err := BuildServerStatusPacket(clients, files)
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendIDChange(id uint32) {
	// The observed IPv4 is taken from the accepted socket, never from anything the
	// client claimed in OP_LOGINREQUEST. It is what lets a LowID client learn its
	// own public IPv4 — see BuildIDChangePacket.
	packet, err := BuildIDChangePacket(id, c.server.TCP.Flags, c.server.TCP.Port, c.snapshotInfo().IPv4)
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendCallbackFailed() {
	packet, err := BuildCallbackFailedPacket()
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendServerIdent() {
	clientV6, v6Status := c.ipv6Reflection()
	packet, err := BuildServerIdentPacket(ServerConfig{
		Name:             c.server.TCP.Name,
		Description:      c.server.TCP.Description,
		Address:          c.server.advertisedAddress(),
		Hash:             c.server.TCP.Hash,
		TCPPort:          c.server.TCP.Port,
		TCPFlags:         c.server.TCP.Flags,
		IPv6:             c.server.TCP.ServerIPv6,
		NatPort:          c.server.TCP.NatRendezvousPort,
		ClientIPv6:       clientV6,
		ClientIPv6Status: v6Status,
	})
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendServerMessage(message string) {
	if message == "" {
		return
	}
	packet, err := BuildServerMessagePacket(message)
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendCallbackRequested(ipv4 uint32, port uint16) error {
	packet, err := BuildCallbackRequestedPacket(ipv4, port)
	if err != nil {
		return err
	}
	return c.writePacket(packet)
}

func (c *tcpClient) sendCallbackRequestedIPv6(ipv6 []byte, port uint16) error {
	packet, err := BuildCallbackRequestedIPv6Packet(ipv6, port)
	if err != nil {
		return err
	}
	return c.writePacket(packet)
}

func (c *tcpClient) writePacket(packet *Buffer) error {
	if packet == nil {
		return nil
	}
	return c.writeRaw(packet.Bytes())
}

func (c *tcpClient) writeRaw(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	LogTCPRaw(c.module, "send", c.remoteHost, data)
	c.logSendPayload(data)
	// writeRaw is reachable from goroutines other than this connection's own —
	// the status ticker and a peer's OP_CALLBACKREQUEST both land here — so the
	// state and the key must be read together, under the crypt lock.
	if c.crypt != nil {
		if key, encrypting := c.crypt.SendCipher(); encrypting {
			data = RC4Crypt(data, len(data), key)
		}
	}
	_, err := c.conn.Write(data)
	return err
}

func (c *tcpClient) debugPayloadf(format string, args ...any) {
	all := make([]any, 0, len(args)+1)
	all = append(all, c.module)
	all = append(all, args...)
	logging.Debugf("[module=%s] "+format, all...)
}

func (c *tcpClient) logSendPayload(raw []byte) {
	proto, _, opcode, payload, ok := parseTCPRaw(raw)
	if !ok {
		return
	}
	if proto == PrZlib {
		inflated, err := InflateZlibPayload(payload)
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send protocol=PR_ZLIB opcode=%s err=%v",
				c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send protocol=PR_ZLIB opcode=%s compressedPayloadLen=%d decompressedPayloadLen=%d",
			c.remoteHost, opcodeLabel(opcode), len(payload), len(inflated))
		c.logSendPayloadByOpcode(opcode, inflated)
		return
	}
	c.logSendPayloadByOpcode(opcode, payload)
}

func (c *tcpClient) logSendPayloadByOpcode(opcode uint8, payload []byte) {
	b := NewBufferFromBytes(payload)
	switch opcode {
	case OpServerMessage:
		msg, err := b.GetString()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s message=%q", c.remoteHost, opcodeLabel(opcode), msg)
	case OpServerStatus:
		users, err := b.GetUInt32LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		files, err := b.GetUInt32LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s users=%d files=%d", c.remoteHost, opcodeLabel(opcode), users, files)
	case OpIDChange:
		id, err := b.GetUInt32LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		flags, err := b.GetUInt32LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s id=%d flags=%d", c.remoteHost, opcodeLabel(opcode), id, flags)
	case OpServerList:
		count, err := b.GetUInt8()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		entries := make([]string, 0, count)
		limit := int(count)
		if limit > 20 {
			limit = 20
		}
		for i := 0; i < int(count); i++ {
			ipv4, err := b.GetUInt32LE()
			if err != nil {
				logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
				return
			}
			port, err := b.GetUInt16LE()
			if err != nil {
				logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
				return
			}
			if i < limit {
				entries = append(entries, fmt.Sprintf("{ip=%d,port=%d}", ipv4, port))
			}
		}
		if int(count) > limit {
			entries = append(entries, fmt.Sprintf("...+%d", int(count)-limit))
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s serverCount=%d servers=[%s]",
			c.remoteHost, opcodeLabel(opcode), count, strings.Join(entries, ", "))
	case OpServerIdent:
		hash := b.Get(16)
		if len(hash) != 16 {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=invalid-hash-len", c.remoteHost, opcodeLabel(opcode))
			return
		}
		ipv4, err := b.GetUInt32LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		port, err := b.GetUInt16LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		tags, err := b.GetTags()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s hash=%x ip=%d port=%d tags=%s",
			c.remoteHost, opcodeLabel(opcode), hash, ipv4, port, formatNamedTags(tags, 24))
	case OpFoundSources:
		hash, count, entries, err := parseFoundSourcesPayload(payload, false, 20)
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s fileHash=%x sourceCount=%d payloadLen=%d sources=%s",
			c.remoteHost, opcodeLabel(opcode), hash, count, len(payload), entries)
	case OpFoundSourcesObfu:
		hash, count, entries, err := parseFoundSourcesPayload(payload, true, 20)
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s fileHash=%x sourceCount=%d payloadLen=%d sources=%s",
			c.remoteHost, opcodeLabel(opcode), hash, count, len(payload), entries)
	case OpSearchResult:
		files, err := b.GetFileList()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s resultCount=%d files=%s",
			c.remoteHost, opcodeLabel(opcode), len(files), formatFileRecordsForLog(files, 5))
	case OpCallbackReqd:
		ipv4, err := b.GetUInt32LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		port, err := b.GetUInt16LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s targetIP=%d targetPort=%d",
			c.remoteHost, opcodeLabel(opcode), ipv4, port)
	case OpCallbackReqdIPv6:
		ipv6 := b.Get(16)
		if len(ipv6) != 16 {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=short-ipv6", c.remoteHost, opcodeLabel(opcode))
			return
		}
		port, err := b.GetUInt16LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s targetIPv6=%s targetPort=%d",
			c.remoteHost, opcodeLabel(opcode), net.IP(ipv6).String(), port)
	case OpCallbackFailed:
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s payload=empty", c.remoteHost, opcodeLabel(opcode))
	default:
		previewLen := len(payload)
		if previewLen > 128 {
			previewLen = 128
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s payloadLen=%d previewHex=%s",
			c.remoteHost, opcodeLabel(opcode), len(payload), hex.EncodeToString(payload[:previewLen]))
	}
}

func parseFoundSourcesPayload(payload []byte, withObfu bool, limit int) ([]byte, int, string, error) {
	b := NewBufferFromBytes(payload)
	hash := b.Get(16)
	if len(hash) != 16 {
		return nil, 0, "", fmt.Errorf("invalid-hash-len")
	}
	count, err := b.GetUInt8()
	if err != nil {
		return nil, 0, "", err
	}
	if limit <= 0 {
		limit = 20
	}
	n := int(count)
	if n > limit {
		n = limit
	}
	parts := make([]string, 0, n+1)
	for i := 0; i < int(count); i++ {
		id, err := b.GetUInt32LE()
		if err != nil {
			return nil, 0, "", err
		}
		port, err := b.GetUInt16LE()
		if err != nil {
			return nil, 0, "", err
		}
		if withObfu {
			obf, err := b.GetUInt8()
			if err != nil {
				return nil, 0, "", err
			}
			if (obf & 0x80) != 0 {
				userHash := b.Get(16)
				if len(userHash) != 16 {
					return nil, 0, "", ErrOutOfBounds
				}
				if i < n {
					parts = append(parts, fmt.Sprintf("{id=%d,port=%d,obfSettings=0x%02x,userHash=%x}", id, port, obf, userHash))
				}
				continue
			}
			if i < n {
				parts = append(parts, fmt.Sprintf("{id=%d,port=%d,obfSettings=0x%02x}", id, port, obf))
			}
			continue
		}
		if i < n {
			parts = append(parts, fmt.Sprintf("{id=%d,port=%d}", id, port))
		}
	}
	if int(count) > n {
		parts = append(parts, fmt.Sprintf("...+%d", int(count)-n))
	}
	return hash, int(count), "[" + strings.Join(parts, ", ") + "]", nil
}

func formatFileRecordsForLog(files []FileRecord, limit int) string {
	if len(files) == 0 {
		return "[]"
	}
	if limit <= 0 {
		limit = 5
	}
	n := len(files)
	if n > limit {
		n = limit
	}
	parts := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		name, _ := files[i].Tags["name"].(string)
		parts = append(parts, fmt.Sprintf("{hash=%x,id=%d,port=%d,size=%d,name=%q}", files[i].Hash, files[i].ID, files[i].Port, files[i].Size, name))
	}
	if len(files) > n {
		parts = append(parts, fmt.Sprintf("...+%d", len(files)-n))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func opcodeLabel(opcode uint8) string {
	switch opcode {
	case OpServerMessage:
		return "OP_SERVERMESSAGE"
	case OpServerStatus:
		return "OP_SERVERSTATUS"
	case OpIDChange:
		return "OP_IDCHANGE"
	case OpServerList:
		return "OP_SERVERLIST"
	case OpServerIdent:
		return "OP_SERVERIDENT"
	case OpFoundSources:
		return "OP_FOUNDSOURCES"
	case OpFoundSourcesObfu:
		return "OP_FOUNDSOURCES_OBFU"
	case OpSearchResult:
		return "OP_SEARCHRESULT"
	case OpCallbackReqd:
		return "OP_CALLBACKREQD"
	case OpCallbackReqdIPv6:
		return "OP_CALLBACKREQUESTED_IPV6"
	case OpCallbackFailed:
		return "OP_CALLBACKFAILED"
	default:
		return fmt.Sprintf("0x%02x", opcode)
	}
}

func (s *ServerRuntime) isFirewalled(client *tcpClient) bool {
	if s.firewallProbe != nil {
		return s.firewallProbe(client)
	}
	return s.probeFirewalled(client)
}

func (s *ServerRuntime) probeFirewalled(client *tcpClient) bool {
	if client == nil {
		return true
	}
	if s.TCP.SupportCrypt {
		ok, err := s.probeClient(client, true, "tcp4", client.remoteHost)
		if err == nil && ok {
			return false
		}
	}
	ok, err := s.probeClient(client, false, "tcp4", client.remoteHost)
	return err != nil || !ok
}

// probeIPv6Reachable dials the client's advertised public IPv6 and completes a
// hello exchange, mirroring isFirewalled but over tcp6. The verdict is
// independent of the IPv4 firewall state: a client can be IPv4-firewalled and
// still directly reachable over IPv6 (or vice versa). Only a reachable IPv6 is
// published as a source, so an unreachable address does not cost every other peer
// a failed connection attempt.
func (s *ServerRuntime) probeIPv6Reachable(client *tcpClient) bool {
	if client == nil {
		return false
	}
	info := client.snapshotInfo()
	if len(info.IPv6) != 16 || info.Port == 0 {
		return false
	}
	host := net.IP(info.IPv6).String()
	if s.TCP.SupportCrypt {
		if ok, err := s.probeClient(client, true, "tcp6", host); err == nil && ok {
			return true
		}
	}
	ok, err := s.probeClient(client, false, "tcp6", host)
	return err == nil && ok
}

func (s *ServerRuntime) probeClient(client *tcpClient, enableCrypt bool, network, host string) (bool, error) {
	info := client.snapshotInfo()
	if info.Port == 0 {
		return false, fmt.Errorf("client port is 0")
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", info.Port))
	dialer := net.Dialer{Timeout: s.TCP.ConnectionTimeout}
	// Only bind a local source address whose family matches the dial network;
	// binding a v4 LocalAddr to a tcp6 dial (or vice versa) fails outright.
	if local := localBindForNetwork(network, s.TCP.Address); local != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: local}
	}
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	cli := NewClient(ClientConfig{
		EnableCrypt:       enableCrypt,
		Address:           s.TCP.Address,
		TCPPort:           s.TCP.Port,
		ConnectionTimeout: int(s.TCP.ConnectionTimeout / time.Millisecond),
		Hash:              s.TCP.Hash,
	})
	cli.Hash = client.snapshotInfo().Hash

	if enableCrypt {
		pad, err := RandBuf(Rand(0xff))
		if err != nil {
			return false, err
		}
		handshake, err := cli.BuildHandshake(RandProtocol(), RandUint32(), pad)
		if err != nil {
			return false, err
		}
		if err := writeWithDeadline(conn, handshake, s.TCP.ConnectionTimeout); err != nil {
			return false, err
		}
		if _, err := readHandshake(cli, conn, s.TCP.ConnectionTimeout); err != nil {
			return false, err
		}
	}

	hello, err := cli.BuildHelloPacket()
	if err != nil {
		return false, err
	}
	helloBytes := hello.Bytes()
	if enableCrypt && cli.CryptStatus == CsEncrypting {
		helloBytes = RC4Crypt(helloBytes, len(helloBytes), cli.SendKey)
	}
	if err := writeWithDeadline(conn, helloBytes, s.TCP.ConnectionTimeout); err != nil {
		return false, err
	}
	return readHelloAnswer(cli, conn, s.TCP.ConnectionTimeout)
}

func readHandshake(cli *Client, conn net.Conn, timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	data, done, err := cli.Decrypt(buf[:n])
	if err != nil {
		return nil, err
	}
	if !done {
		return nil, errors.New("handshake incomplete")
	}
	return data, nil
}

func readHelloAnswer(cli *Client, conn net.Conn, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	var buffer []byte
	buf := make([]byte, 4096)

	for {
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if err != nil {
			return false, err
		}
		data := buf[:n]
		if cli.CryptStatus == CsEncrypting {
			data, _, err = cli.Decrypt(data)
			if err != nil {
				return false, err
			}
		}
		buffer = append(buffer, data...)
		// The peer here is the client being probed: it chose the address we
		// dialed and it controls every byte coming back. Without this ceiling it
		// can declare a huge size, then dribble bytes until the deadline while
		// the loop below never completes a packet and this slice grows unbounded.
		if len(buffer) > maxHelloAnswerBytes {
			return false, fmt.Errorf("hello answer exceeded %d bytes", maxHelloAnswerBytes)
		}

		for {
			if len(buffer) < 6 {
				break
			}
			if buffer[0] != PrED2K {
				return false, fmt.Errorf("bad protocol 0x%x", buffer[0])
			}
			size := int(binary.LittleEndian.Uint32(buffer[1:5]))
			// Same ceiling Packet.Init applies on the inbound path; this reader
			// reimplements the framing and so needs it too.
			if size > 0 && size-1 > MaxTCPPacketSize {
				return false, fmt.Errorf("%w: declared=%d max=%d", ErrPacketTooLarge, size-1, MaxTCPPacketSize)
			}
			if size <= 0 || len(buffer) < 5+size {
				break
			}
			payload := buffer[5 : 5+size]
			opcode := payload[0]
			if opcode == OpHelloAnswer {
				p := NewBufferFromBytes(payload[1:])
				_, _ = ReadOpHelloAnswer(p)
				return true, nil
			}
			buffer = buffer[5+size:]
		}
	}
}

func writeWithDeadline(conn net.Conn, data []byte, timeout time.Duration) error {
	if timeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	}
	_, err := conn.Write(data)
	return err
}

func (s *ServerRuntime) udpGlobGetSources(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	// A query that arrived over IPv6 comes from a v6-capable sender, so IPv6-only
	// sources may ride the sentinel form. An IPv4 query gets the classic layout.
	format := s.udpSourceFormat(remote)
	for b.Pos()+16 <= len(b.Bytes()) {
		hash := append([]byte(nil), b.Get(16)...)
		if len(hash) != 16 {
			return
		}
		sources := s.Storage.GetSourcesByHash(hash)
		if len(sources) == 0 {
			continue
		}
		packet, err := buildGlobFoundSources(hash, sources, format)
		if err != nil {
			continue
		}
		_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
	}
}

func (s *ServerRuntime) udpGlobGetSources2(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	format := s.udpSourceFormat(remote)
	for b.Pos()+20 <= len(b.Bytes()) {
		hash := append([]byte(nil), b.Get(16)...)
		if len(hash) != 16 {
			return
		}
		size, err := b.GetUInt32LE()
		if err != nil {
			return
		}
		fileSize := uint64(size)
		if fileSize == 0 {
			v, err := b.GetUInt64LE()
			if err != nil {
				return
			}
			fileSize = v
		}
		sources := s.Storage.GetSources(hash, fileSize)
		if len(sources) == 0 {
			continue
		}
		packet, err := buildGlobFoundSources(hash, sources, format)
		if err != nil {
			continue
		}
		_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
	}
}

// udpGlobGetSourcesIPv6 answers OP_GLOBGETSOURCES_IPV6 (0xa5) with the tag-block
// format. Payload matches OP_GLOBGETSOURCES2 (repeated hash+size). Sending this
// opcode is the opt-in, so the extended reply is safe on any arrival family.
func (s *ServerRuntime) udpGlobGetSourcesIPv6(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	for b.Pos()+20 <= len(b.Bytes()) {
		hash := append([]byte(nil), b.Get(16)...)
		if len(hash) != 16 {
			return
		}
		size, err := b.GetUInt32LE()
		if err != nil {
			return
		}
		fileSize := uint64(size)
		if fileSize == 0 {
			v, err := b.GetUInt64LE()
			if err != nil {
				return
			}
			fileSize = v
		}
		sources := s.Storage.GetSources(hash, fileSize)
		if len(sources) == 0 {
			continue
		}
		packet, err := BuildGlobFoundSourcesIPv6Packet(hash, sources)
		if err != nil {
			continue
		}
		_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
	}
}

// udpSourceFormat picks the classic or sentinel layout for a UDP source reply.
// The sentinel is only used when IPv6 publication is enabled and the query
// arrived over IPv6, so a legacy IPv4 client can never receive it.
func (s *ServerRuntime) udpSourceFormat(remote *net.UDPAddr) SourceFormat {
	if s.publishV6Sources() && remoteIsIPv6(remote) {
		return FormatSentinel
	}
	return FormatClassic
}

// remoteIsIPv6 reports whether a UDP sender's address is a genuine IPv6 (not an
// IPv4-mapped form).
func remoteIsIPv6(remote *net.UDPAddr) bool {
	if remote == nil {
		return false
	}
	_, ok := IPv6Bytes(remote.IP)
	return ok
}

func (s *ServerRuntime) udpGlobServStatReq(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	challenge, err := b.GetUInt32LE()
	if err != nil {
		return
	}
	packet, err := s.buildStatRes(challenge, crypt.ServerKey, remote)
	if err != nil {
		return
	}
	_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
}

// buildStatRes builds the OP_GLOBSERVSTATRES reply for a challenge, shared by the
// plaintext stat request and the obfuscated crypt-ping bootstrap. udpKey is the
// per-client obfuscation key (deriveUDPKey), advertised at reply offset +36 so
// the client adopts it for its own obfuscated traffic. The counts are cached:
// both callers are unauthenticated and unthrottled, so serving them straight
// from the database made a status flood cost two full table scans per datagram.
//
// remote supplies the observed address reflected in the 4 trailing bytes — the field
// Lugdunum already sends and eMule discards. Taken from the socket, never from anything
// the requester claimed, which is the same rule OP_IDCHANGE's observed-IP field follows.
func (s *ServerRuntime) buildStatRes(challenge uint32, udpKey uint32, remote *net.UDPAddr) (*Buffer, error) {
	clients, files := s.counters.Counts()
	var observed net.IP
	if remote != nil {
		observed = NormalizeIP(remote.IP)
	}
	return BuildGlobServStatResPacket(challenge, UDPConfig{
		Name:           s.UDP.Name,
		Description:    s.UDP.Description,
		DynIP:          s.UDP.DynIP,
		UDPFlags:       s.UDP.UDPFlags,
		UDPPortObf:     s.UDP.UDPPortObf,
		TCPPortObf:     s.UDP.TCPPortObf,
		UDPServerKey:   udpKey,
		MaxConnections: s.UDP.MaxConnections,
		ObservedIP:     observed,
	}, clients, files, int(s.LowIDs.Count()))
}

// udpCryptPingReply answers a server-UDP crypt-ping (see the call site in
// UDPHandler). The client sent a raw 32-bit challenge to the obfuscated port
// before it holds our UDP key; it decrypts this reply with baseKey = challenge
// (magic MAGICVALUE_UDP_SERVERCLIENT 0xA5) and reads the real key at +36
// (srchybrid/UDPSocket.cpp:159-171,377-407). So the reply is encrypted keyed on
// the challenge — not the per-client key — and written straight to the socket
// rather than through udpSend, which would re-encrypt with the per-client key.
// udpKey is the per-client key (deriveUDPKey) the reply carries at +36 for the
// client to adopt afterward.
func (s *ServerRuntime) udpCryptPingReply(data []byte, remote *net.UDPAddr, conn *net.UDPConn, udpKey uint32, module string) {
	challenge, err := NewBufferFromBytes(data).GetUInt32LE()
	if err != nil || challenge == 0 {
		// eMule never sends a zero challenge (srchybrid/ServerList.cpp:280-281) and
		// checks challenge != 0 before decrypting the reply, so a zero-keyed reply
		// would be unusable — treat it as junk.
		return
	}
	packet, err := s.buildStatRes(challenge, udpKey, remote)
	if err != nil {
		return
	}
	reply := NewUDPCrypt(true, challenge).Encrypt(packet.Bytes())
	LogUDPRaw(module, "send", remote.String(), reply)
	_, _ = conn.WriteToUDP(reply, remote)
}

func (s *ServerRuntime) udpServDescResOld(remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	packet, err := BuildServerDescResOldPacket(s.UDP.Name, s.UDP.Description)
	if err != nil {
		return
	}
	_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
}

func (s *ServerRuntime) udpServDescRes(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	challenge, err := b.GetUInt32LE()
	if err != nil {
		return
	}
	packet, err := BuildServerDescResPacket(challenge, UDPConfig{
		Name:        s.UDP.Name,
		Description: s.UDP.Description,
		DynIP:       s.UDP.DynIP,
	})
	if err != nil {
		return
	}
	_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
}

func (s *ServerRuntime) udpGlobSearchReq(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	expr, err := ParseSearchExpr(b)
	if err != nil {
		return
	}
	files := s.Storage.FindBySearch(expr)
	if len(files) == 0 {
		return
	}
	packets, err := BuildGlobSearchResPackets(files)
	if err != nil {
		return
	}
	for _, packet := range packets {
		_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
	}
}

func (s *ServerRuntime) udpGlobSearchReq3(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	// GetTags aborts mid-loop on a malformed tag and Buffer has no rewind, so
	// discarding this error left the read pointer at an arbitrary offset inside
	// a half-consumed tag — and ParseSearchExpr then built a query out of tag
	// payload bytes. Bail instead; the tag block is mandatory for this opcode,
	// so a failure here means the datagram is not parseable.
	if _, err := b.GetTags(); err != nil {
		logging.Warnf("udp glob search tags decode failed remote=%s err=%v", remote, err)
		return
	}
	expr, err := ParseSearchExpr(b)
	if err != nil {
		return
	}
	files := s.Storage.FindBySearch(expr)
	if len(files) == 0 {
		return
	}
	packets, err := BuildGlobSearchResPackets(files)
	if err != nil {
		return
	}
	for _, packet := range packets {
		_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
	}
}

func udpSend(conn *net.UDPConn, remote *net.UDPAddr, data []byte, crypt *UDPCrypt, module string) error {
	LogUDPRaw(module, "send", remote.String(), data)
	if crypt != nil && crypt.Status == CsEncrypting {
		data = crypt.Encrypt(data)
	}
	_, err := conn.WriteToUDP(data, remote)
	return err
}

func fileFromRecord(record FileRecord, info storage.ClientInfo) storage.File {
	file := storage.File{
		Hash:       record.Hash,
		Size:       record.Size,
		SourceID:   info.ID,
		SourcePort: info.Port,
	}
	if v, ok := record.Tags["name"].(string); ok {
		file.Name = v
	}
	if v, ok := record.Tags["type"].(string); ok {
		file.Type = v
	}
	if v, ok := tagUint32(record.Tags, "sources"); ok {
		file.Sources = v
	}
	// storage.File.Completed is a per-source boolean on the way in (the engines
	// store it as sources.complete) and a per-file aggregate on the way out
	// (recomputed as SUM(complete)). Only the (id, port) sentinel says anything
	// about *this* source, so it is the only thing allowed to set it.
	//
	// The "completesources" tag is the client's count of OTHER complete sources
	// it knows of. Feeding it in here meant a client that had the whole file but
	// knew of no other complete copy — legal, and it sends completesources=0 —
	// had its own completeness discarded. Letting a client-supplied count reach
	// a boolean column also let it inflate files.completed for a file it does
	// not have, so the tag is advisory and deliberately ignored.
	if record.Complete {
		file.Completed = 1
	}
	if v, ok := record.Tags["title"].(string); ok {
		file.Title = v
	}
	if v, ok := record.Tags["artist"].(string); ok {
		file.Artist = v
	}
	if v, ok := record.Tags["album"].(string); ok {
		file.Album = v
	}
	if v, ok := tagUint32(record.Tags, "length"); ok {
		file.Runtime = v
	}
	if v, ok := tagUint32(record.Tags, "bitrate"); ok {
		file.Bitrate = v
	}
	if v, ok := record.Tags["codec"].(string); ok {
		file.Codec = v
	}
	if file.Type == "" && file.Name != "" {
		file.Type = GetFileType(file.Name)
	}
	return file
}

// udpOpcodeEnabled reports whether an extended UDP opcode may be served, and
// logs the refusal. Extended UDP is the cheapest amplification surface the
// server has — one small datagram can trigger a source lookup per hash — so a
// refusal is worth seeing in the log.
func (s *ServerRuntime) udpOpcodeEnabled(enabled bool, code uint8, remote *net.UDPAddr) bool {
	if enabled {
		return true
	}
	logging.Debugf("udp opcode disabled by config remote=%s opcode=0x%x", remote, code)
	return false
}

func splitHost(addr string) string {
	if strings.Contains(addr, ":") {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			return host
		}
	}
	return addr
}

func tcpModule(enableCrypt bool) string {
	if enableCrypt {
		return "tcp-obfs"
	}
	return "tcp"
}

func opNameGetSources(obfuscated bool) string {
	if obfuscated {
		return "OP_GETSOURCES_OBFU"
	}
	return "OP_GETSOURCES"
}

// cryptPingMaxLen bounds a server-UDP crypt-ping: eMule sends a 4-byte challenge
// plus up to 15 random padding bytes (srchybrid/ServerList.cpp:277).
const cryptPingMaxLen = 4 + 15

// isCryptPing reports whether an undecryptable datagram on the obfuscated UDP
// listener is short enough to be a raw crypt-ping challenge. Length is the only
// signal available — the challenge is random bytes with no framing — but a false
// positive only costs one stat-reply datagram, on par with the plaintext
// OP_GLOBSERVSTATREQ this server already answers unthrottled.
func isCryptPing(data []byte) bool {
	return len(data) >= 4 && len(data) <= cryptPingMaxLen
}

func formatNamedTags(tags []NamedTag, limit int) string {
	if len(tags) == 0 {
		return "[]"
	}
	if limit <= 0 {
		limit = 32
	}
	n := len(tags)
	if n > limit {
		n = limit
	}
	parts := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		parts = append(parts, fmt.Sprintf("%s=%v", tags[i].Name, tags[i].Value))
	}
	if len(tags) > n {
		parts = append(parts, fmt.Sprintf("...+%d", len(tags)-n))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func formatSearchExpr(expr *storage.SearchExpr) string {
	if expr == nil {
		return "<nil>"
	}
	switch expr.Kind {
	case storage.SearchText:
		return fmt.Sprintf("TEXT(%q)", expr.Text)
	case storage.SearchString:
		return fmt.Sprintf("STRING(tag=0x%x,val=%q)", expr.TagType, expr.ValueString)
	case storage.SearchUInt32:
		return fmt.Sprintf("U32(tag=0x%x,val=%d)", expr.TagType, expr.ValueUint)
	case storage.SearchUInt64:
		return fmt.Sprintf("U64(tag=0x%x,val=%d)", expr.TagType, expr.ValueUint)
	case storage.SearchAnd:
		return fmt.Sprintf("AND(%s,%s)", formatSearchExpr(expr.Left), formatSearchExpr(expr.Right))
	case storage.SearchOr:
		return fmt.Sprintf("OR(%s,%s)", formatSearchExpr(expr.Left), formatSearchExpr(expr.Right))
	case storage.SearchAndNot:
		return fmt.Sprintf("ANDNOT(%s,%s)", formatSearchExpr(expr.Left), formatSearchExpr(expr.Right))
	default:
		return fmt.Sprintf("UNKNOWN(kind=%d)", expr.Kind)
	}
}

// loginFlags returns the CT_SERVER_FLAGS capability bitmask (tag "flags",
// code 0x20) from an OP_LOGINREQUEST tag set, or 0 if the client sent none.
// eMule packs its zlib/unicode/large-file and crypt capabilities here
// (srchybrid/ServerConnect.cpp). Integer tags decode to uint64; truncating to
// uint32 keeps every real flag bit — saturating (as tagUint32 does for magnitude
// fields) would be wrong for a bitmask, setting bits the client never advertised.
func loginFlags(tags []NamedTag) uint32 {
	for _, t := range tags {
		if t.Name != "flags" {
			continue
		}
		if v, ok := t.Value.(uint64); ok {
			return uint32(v)
		}
		return 0
	}
	return 0
}

// localBindForNetwork returns the configured bind address as a source IP for an
// outbound probe, but only when its family matches the dial network and it is not
// a wildcard. A mismatched or wildcard bind returns nil so the dialer picks the
// source itself.
func localBindForNetwork(network, address string) net.IP {
	if address == "" || address == "0.0.0.0" || address == "::" {
		return nil
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return nil
	}
	isV4 := ip.To4() != nil
	switch network {
	case "tcp4":
		if isV4 {
			return ip
		}
	case "tcp6":
		if !isV4 {
			return ip
		}
	}
	return nil
}

// loginIPv6 extracts the client's public IPv6 from the CT_MOD_IP_V6 (0xae) login
// tag, which decodes as a 16-byte hash value (tag name "ipv6"). It returns the
// validated public address bytes (nil if absent or not globally routable) and a
// separate present flag: the *presence* of the tag — even with an unusable value
// — signals the client understands the IPv6 source formats, which is what gates
// sending it sentinel sources. eMuleAI ServerConnect.cpp:220-223.
func loginIPv6(tags []NamedTag) (addr []byte, present bool) {
	for _, t := range tags {
		if t.Name != "ipv6" {
			continue
		}
		present = true
		b, ok := t.Value.([]byte)
		if !ok || len(b) != 16 {
			return nil, true
		}
		if !IsPublicIPv6(net.IP(b)) {
			return nil, true
		}
		return append([]byte(nil), b...), true
	}
	return nil, false
}

// v6ProbeRequired reports whether the login path has to dial back to decide the
// client's IPv6 reachability rather than simply trusting the address: a session
// that arrived over IPv6 has proven the address by using it, and probing can be
// turned off outright. Shared with ipv6Reflection so the IPv6StatusProbed bit
// cannot drift away from what the login path actually did.
func (c *tcpClient) v6ProbeRequired(v6Len int) bool {
	return c.server.publishV6Sources() && v6Len == 16 && !c.connectedV6 && c.server.TCP.ProbeIPv6
}

// ipv6Reflection returns the two per-session IPv6 fields of OP_SERVERIDENT: the
// address the server observed this session on (CT_MOD_YOUR_IP) and the
// IPv6Status* bitfield summarising what it knows about the session's IPv6.
//
// The reflected address is only ever one the server *observed*, so it is emitted
// solely for a session that actually arrived over IPv6 — echoing back the
// CT_MOD_IP_V6 the client sent us would teach it nothing. That leaves the
// v4-connected dual-stack client, and the status bitfield is what serves it: it
// reports the dial-back verdict for the address that client advertised.
//
// Both are omitted for a server with IPv6 turned off, so such a server keeps
// emitting the pre-reflection packet byte for byte.
func (c *tcpClient) ipv6Reflection() (peerV6 []byte, status uint8) {
	if !c.server.ipv6Enabled() {
		return nil, 0
	}
	if c.connectedV6 && IsPublicIPv6(c.peerIP) {
		if b, ok := IPv6Bytes(c.peerIP); ok {
			peerV6 = append([]byte(nil), b[:]...)
		}
	}
	// The verdict only exists once login has settled it, and only when v6 source
	// publication is on — that is the code path that computes it. Pre-login (an
	// OP_GETSERVERLIST before OP_LOGINREQUEST also sends an ident) there is nothing
	// to report, and a zero bitfield omits the tag.
	if !c.server.publishV6Sources() || !c.isLogged() {
		return peerV6, 0
	}
	info := c.snapshotInfo()
	if len(info.IPv6) != 16 {
		return peerV6, 0
	}
	status = IPv6StatusHave
	if info.IPv6Reachable {
		status |= IPv6StatusReachable
	}
	if c.v6ProbeRequired(len(info.IPv6)) {
		status |= IPv6StatusProbed
	}
	return peerV6, status
}

// cryptOptionsFromLoginFlags maps the login capability bits to the per-source
// OP_FOUNDSOURCES_OBFU options byte: 0x01 supports, 0x02 requests, 0x04 requires
// obfuscation (srchybrid/ServerSocket.cpp:558-560).
func cryptOptionsFromLoginFlags(flags uint32) byte {
	var b byte
	if flags&FlagSupportCrypt != 0 {
		b |= 0x01
	}
	if flags&FlagRequestCrypt != 0 {
		b |= 0x02
	}
	if flags&FlagRequireCrypt != 0 {
		b |= 0x04
	}
	return b
}
