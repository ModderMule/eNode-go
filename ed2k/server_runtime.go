package ed2k

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"enode/ed3k/ident"
	"enode/internal/ratelimit"
	"enode/logging"
	"enode/storage"

	"github.com/ModderMule/enodemeta/metahash"
)

type TCPRuntimeConfig struct {
	Name        string
	Description string
	// Address is the bind address, and may be the 0.0.0.0 wildcard.
	Address string
	// AdvertisedIP is the address published to clients in OP_SERVERIDENT. It is
	// separate from Address because the wildcard is a valid thing to bind but
	// encodes as IP 0, which tells a client nothing. Empty falls back to Address.
	AdvertisedIP      string
	Port              uint16
	Flags             uint32
	Hash              []byte
	MessageLogin      string
	MessageLowID      string
	ConnectionTimeout time.Duration
	DisconnectTimeout time.Duration
	// LoginTimeout bounds the time from accept to a completed login, however the
	// bytes trickle in; zero leaves only DisconnectTimeout. MaxConnsPerIP caps
	// concurrent connections per address (IPv6 per /64); zero is unlimited.
	LoginTimeout         time.Duration
	MaxConnsPerIP        int
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
	// when FlagNatRendezvous or FlagNatWake is set. Zero omits the tag.
	NatRendezvousPort uint16
	// MetaAPI is advertised in OP_SERVERIDENT when the Meta API is on.
	MetaAPI MetaAPIAdvert
	// Ed3k is the ed3k:node link of the index node, advertised in OP_SERVERIDENT as
	// ST_ED3K when ed3k is on. Empty omits the tag.
	Ed3k string
	// SoftFileLimit and HardFileLimit cap what one session may publish. The soft
	// limit is how many distinct files it may source at once: a new file past it is
	// ignored and the client is warned once. The hard limit is how many records one
	// OP_OFFERFILES may declare: a packet that reaches it gets the client told why
	// and disconnected. Zero means unlimited. Both are enforced in
	// handleOfferFiles, and advertised through UDPRuntimeConfig so that a
	// client is held to the numbers it was given. See docs/server-client-communication.md.
	SoftFileLimit int
	HardFileLimit int
	// MoreResultsMax is how many rows of a search a session keeps after the first page
	// for OP_QUERY_MORE_RESULT; zero is defaultMoreResultsMax, negative turns paging off.
	// MoreResultsTTL is how long they are kept; zero is defaultMoreResultsTTL. See
	// config tcp.moreResults.
	MoreResultsMax int
	MoreResultsTTL time.Duration
	// RelatedSearch answers `related::HASH` searches; RelatedMinClients is how many
	// online users must share the searched files first (zero is
	// defaultRelatedMinClients). See config tcp.relatedSearch.
	RelatedSearch     bool
	RelatedMinClients int
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
	GetSources bool
	GetFiles   bool
	UDPPortObf uint16
	TCPPortObf uint16
	// UDPSecret derives each client's UDP obfuscation key (deriveUDPKey). When empty,
	// UDPServerKey stands in as a legacy 4-byte secret.
	UDPSecret      []byte
	UDPServerKey   uint32
	MaxConnections uint32
	// SoftFiles and HardFiles are the advertised halves of TCPRuntimeConfig's
	// SoftFileLimit / HardFileLimit — the same values, emitted at OP_GLOBSERVSTATRES
	// offsets +16/+20. main.go fills both from one config key each, so they cannot
	// drift apart.
	SoftFiles uint32
	HardFiles uint32
	// RateLimitPerIPPerMinute caps UDP searches and source requests per address
	// (IPv6 per /64); 0 is off. See config udp.rateLimitPerIPPerMinute.
	RateLimitPerIPPerMinute int
	// BotDetection is udp.botDetection: which UDP queriers are listed as bots.
	BotDetection BotDetectionConfig
	// ForeignPerMinute and ForeignBurst limit foreign callback requests per address
	// (natTraversal.foreignPerMinute / foreignBurst); ForeignPerMinute 0 is off.
	ForeignPerMinute int
	ForeignBurst     int
	// ServerSearch is advertised in the extended OP_SERVER_DESC_RES when
	// serverSearch.mode is "gossip". An empty URL omits the tags.
	ServerSearch ServerSearchAdvert
	// Ed3k is the index node's ed3k:node link for the extended OP_SERVER_DESC_RES
	// when ed3k is on. Empty omits the tag.
	Ed3k string
}

type ServerRuntime struct {
	// tcpCfg and udpCfg are the settings every connection and datagram reads. They are
	// immutable snapshots swapped whole by ApplyRuntimeConfig, so a config reload can
	// replace them while the listeners are live; read them through tcp() and udp().
	tcpCfg  atomic.Pointer[TCPRuntimeConfig]
	udpCfg  atomic.Pointer[UDPRuntimeConfig]
	Storage storage.Engine
	LowIDs  *LowIDClients
	NAT     *NATTraversalHandler
	// gossipHandler is the server-to-server peer table, or nil when gossip is disabled.
	// Every dispatch case that touches it is gated on nil, so a server with gossip off
	// has exactly its previous behaviour. Swapped by SetGossipHandler, which a config
	// reload may call with the listeners live; read it through gossip().
	gossipHandler atomic.Pointer[GossipHandler]
	// Filter refuses blocked addresses before any parsing, or nil to filter nothing.
	Filter AccessFilter
	// Content refuses files by hash list and keyword; nil when no content filter is
	// configured. See SetContentFilter.
	Content ContentFilter
	// Spam scores offered files and observes only; nil when spam detection is off.
	Spam     SpamObserver
	counters *counterCache
	// udpLimiter applies UDPRuntimeConfig.RateLimitPerIPPerMinute.
	udpLimiter *ratelimit.Limiter
	// connsPerIP counts open TCP connections per addressKey, for MaxConnsPerIP.
	connsMu    sync.Mutex
	connsPerIP map[string]int
	// sessionsMu guards sessionsByHash, which indexes logged-in connections by user hash
	// so a PR_NAT keepalive can extend the matching eD2K session's idle deadline. Keyed on
	// hash rather than ID because that is what the NAT registry knows; the LowIDs table is
	// keyed on the assigned ID and so cannot answer this lookup.
	sessionsMu     sync.RWMutex
	sessionsByHash map[[16]byte]*tcpClient
	// sessionsByEd3k indexes the same sessions by the ed3k node ID of their CT_ED3K
	// login tag, for the ed3k bridge (Ed3kPairing). Under sessionsMu.
	sessionsByEd3k map[[16]byte][]*tcpClient
	// firewallProbe indirects the IPv4 dial-back so a test can drive both branches
	// of the login ID decision without a reachable listener, and can assert that
	// the decision short-circuits before dialling at all. nil selects the real
	// probe; nothing outside tests sets it.
	firewallProbe func(*tcpClient) bool
	// ipv6Probe indirects the IPv6 reachability dial-back the same way, so a test
	// can drive a v6 login to either verdict without a dialable public IPv6. nil
	// selects the real probe; nothing outside tests sets it.
	ipv6Probe func(*tcpClient) bool
	// staleProbeWait bounds how long a duplicate login waits for the session it
	// collides with to die after probeStaleSession pokes it. Zero selects
	// staleSessionProbeWait; tests shorten it so a refused duplicate costs no time.
	staleProbeWait time.Duration
	// meta supplies torrent/Usenet/Kad/web rows merged into search answers, or nil when no
	// catalogue daemon is configured. Set once by SetMetaSearcher before the listeners
	// bind, then only read. metaAdvertiseLegacy sends them to clients that did not ask;
	// a config reload may flip it with the listeners live.
	meta                MetaSearcher
	metaAdvertiseLegacy atomic.Bool
	// boost is added to the counts in both status packets. Swapped by SetStatsBoost,
	// which a config reload may call with the listeners live. nil advertises real counts.
	boost atomic.Pointer[StatsBoost]
	// usersCeilingWarned is when warnUsersOverCeiling last logged, in Unix nanoseconds.
	usersCeilingWarned atomic.Int64
	// bots lists the UDP queriers that look automated; it observes and refuses nothing.
	bots *botDetector
	// blocks counts what the runtime itself refused, for the admin surface.
	blocks blockCounters
	// liveMu guards live, every TCP session with a running read loop, logged in or
	// not: what a handover has to park. sessionsByHash holds only logged-in ones.
	liveMu sync.Mutex
	live   map[*tcpClient]struct{}
	// parking is the handover round in progress, or nil. While it is set every
	// session parks at its next read; see ParkSessions.
	parking atomic.Pointer[parkRound]
	// natCallback is the state of Lugdunum's NAT callback (natcallback.go).
	natCallback natCallbackState
}

// ipv6Enabled reports whether IPv6 is on at all (dual-stack accept, CT_MOD_IP_V6
// parsing, advertisement). publishV6Sources reports whether IPv6 sources are
// emitted. Both the TCP and UDP handlers read these accessors rather than poking
// the TCP runtime config directly, so the two stacks share one source of truth.
func (s *ServerRuntime) ipv6Enabled() bool      { return s.tcp().IPv6 }
func (s *ServerRuntime) publishV6Sources() bool { return s.tcp().PublishV6Sources }

func NewServerRuntime(tcp TCPRuntimeConfig, udp UDPRuntimeConfig, store storage.Engine) *ServerRuntime {
	tcp.setDefaults()
	s := &ServerRuntime{
		Storage:  store,
		LowIDs:   NewLowIDClients(tcp.AllowLowIDs, tcp.MinLowID, tcp.MaxLowID),
		counters: newCounterCache(store, tcp.CounterCacheTTL),
		// A disabled limiter allows everything, so a zero config costs one branch.
		udpLimiter: ratelimit.New(udp.RateLimitPerIPPerMinute),
		bots:       newBotDetector(),
	}
	s.tcpCfg.Store(&tcp)
	s.udpCfg.Store(&udp)
	return s
}

// ApplyRuntimeConfig replaces the TCP and UDP settings while the server is running.
// Connections and datagrams already in flight finish on the snapshot they loaded; the
// next read sees the new one. The counter cache TTL and the UDP rate limit are handed on
// to the objects that hold them. The LowID range is consumed only at construction and
// is not affected.
func (s *ServerRuntime) ApplyRuntimeConfig(tcp TCPRuntimeConfig, udp UDPRuntimeConfig) {
	tcp.setDefaults()
	s.tcpCfg.Store(&tcp)
	s.udpCfg.Store(&udp)
	s.counters.setTTL(tcp.CounterCacheTTL)
	s.udpLimiter.SetRate(udp.RateLimitPerIPPerMinute)
}

// TCPConfig and UDPConfig return copies of the current settings.
func (s *ServerRuntime) TCPConfig() TCPRuntimeConfig { return *s.tcp() }
func (s *ServerRuntime) UDPConfig() UDPRuntimeConfig { return *s.udp() }

// tcp, udp and gossip load the current snapshots. The returned configs must not be
// modified; gossip() is nil when gossip is disabled.
func (s *ServerRuntime) tcp() *TCPRuntimeConfig { return s.tcpCfg.Load() }
func (s *ServerRuntime) udp() *UDPRuntimeConfig { return s.udpCfg.Load() }
func (s *ServerRuntime) gossip() *GossipHandler { return s.gossipHandler.Load() }

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
		if g := s.gossip(); g != nil {
			if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				g.NoteClient(tcpAddr.IP)
			}
		}
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			key := addressKey(NormalizeIP(tcpAddr.IP))
			if !s.acquireConnSlot(key) {
				s.blocks.connLimit.Add(1)
				logging.Debugf("tcp connection refused remote=%s reason=per-ip-limit(%d)", tcpAddr.IP, s.tcp().MaxConnsPerIP)
				_ = conn.Close()
				return
			}
			defer s.releaseConnSlot(key)
		}
		client := newTCPClient(s, conn, enableCrypt)
		s.trackSession(client)
		defer s.untrackSession(client)
		client.run()
	}
}

// acquireConnSlot counts a new connection from key, refusing it past MaxConnsPerIP.
func (s *ServerRuntime) acquireConnSlot(key string) bool {
	// Counted even while the limit is off: a config reload can turn the limit on with
	// connections already open, and their slots must be there to release.
	limit := s.tcp().MaxConnsPerIP
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if limit > 0 && s.connsPerIP[key] >= limit {
		return false
	}
	if s.connsPerIP == nil {
		s.connsPerIP = map[string]int{}
	}
	s.connsPerIP[key]++
	return true
}

// releaseConnSlot undoes acquireConnSlot when the connection ends.
func (s *ServerRuntime) releaseConnSlot(key string) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if s.connsPerIP[key] <= 1 {
		delete(s.connsPerIP, key)
		return
	}
	s.connsPerIP[key]--
}

// advertisedAddress is the address published to clients, falling back to the
// bind address when none was configured. Callers that need the *bind* address
// (probeClient's LocalAddr) must keep using tcp().Address.
func (s *ServerRuntime) advertisedAddress() string {
	cfg := s.tcp()
	if cfg.AdvertisedIP != "" {
		return cfg.AdvertisedIP
	}
	return cfg.Address
}

func (s *ServerRuntime) SetNATHandler(handler *NATTraversalHandler) {
	s.NAT = handler
	// Bridge PR_NAT keepalives to eD2K session liveness. Registered here rather than in
	// main.go so the wiring cannot be forgotten when a NAT handler is attached.
	handler.SetSessionTouch(s.TouchSessionByHash)
	handler.SetSessionAddrs(s.sessionAddrs)
	handler.SetSessionWake(s.wakeNatSession)
	// PR_NAT pairs only clients logged in here.
	handler.SetLocalMembership(func(h [16]byte) bool { return s.sessionByHash(h[:]) != nil })
}

// sessionAddrs reports the addresses of the session logged in under hash: the
// address it connected from, plus the IPv6 it announced when it connected over IPv4.
func (s *ServerRuntime) sessionAddrs(hash [16]byte) (v4, v6 net.IP, local bool) {
	c := s.sessionByHash(hash[:])
	if c == nil {
		return nil, nil, false
	}
	if c.connectedV6 {
		return nil, c.peerIP, true
	}
	if info := c.snapshotInfo(); len(info.IPv6) == 16 {
		v6 = net.IP(info.IPv6)
	}
	return c.peerIP.To4(), v6, true
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
	if id, ok := client.ed3kNodeID(); ok {
		if s.sessionsByEd3k == nil {
			s.sessionsByEd3k = make(map[[16]byte][]*tcpClient)
		}
		// Every live login that claims the node ID is kept, so a forged claim
		// from elsewhere sits beside the node's own login instead of replacing
		// it; Ed3kPairing picks by address and hash.
		list := s.sessionsByEd3k[id]
		if !slices.Contains(list, client) {
			if len(list) >= maxEd3kClaims {
				list = list[1:]
			}
			s.sessionsByEd3k[id] = append(list, client)
		}
	}
}

// unregisterSession removes the index entry, but only when it still points at this
// connection.
//
// The identity check matters: a duplicate login is rejected rather than allowed unless it
// comes from the live session's IP (see handleLoginRequest), and a reconnect after a stale
// session finally times out can have the two overlap briefly. Deleting unconditionally would then let the departing
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
	if id, ok := client.ed3kNodeID(); ok {
		list := slices.DeleteFunc(s.sessionsByEd3k[id], func(c *tcpClient) bool { return c == client })
		if len(list) == 0 {
			delete(s.sessionsByEd3k, id)
		} else {
			s.sessionsByEd3k[id] = list
		}
	}
}

// Ed3kPairing returns the user hash and crypt options of the eD2K session that
// may be paired with this ed3k node (spec docs/ed2k-tags.md §6): its CT_ED3K
// login tag named the node ID, it logged in with the user hash derived from that
// node ID (§14.2), and it comes from ipv4, the address observed on the node's
// ed3k connection. The tag is not authenticated, hence both checks.
func (s *ServerRuntime) Ed3kPairing(nodeID [16]byte, ipv4 net.IP) (hash [16]byte, crypt byte, ok bool) {
	if ipv4 = ipv4.To4(); ipv4 == nil {
		return hash, 0, false
	}
	want := ident.DerivedUserHash(nodeID)
	s.sessionsMu.RLock()
	list := slices.Clone(s.sessionsByEd3k[nodeID])
	s.sessionsMu.RUnlock()
	for i := len(list) - 1; i >= 0; i-- { // the newest login first
		c := list[i]
		if !c.peerIP.To4().Equal(ipv4) {
			continue
		}
		c.infoMu.Lock()
		match := len(c.info.Hash) == 16 && [16]byte(c.info.Hash) == want
		crypt = c.info.CryptOptions
		c.infoMu.Unlock()
		if match {
			return want, crypt, true
		}
	}
	return hash, 0, false
}

// ed3kNodeID is the session's CT_ED3K node ID.
func (c *tcpClient) ed3kNodeID() ([16]byte, bool) {
	var id [16]byte
	c.infoMu.Lock()
	defer c.infoMu.Unlock()
	if len(c.ed3kID) != 16 {
		return id, false
	}
	copy(id[:], c.ed3kID)
	return id, true
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

func (s *ServerRuntime) UDPHandler(enableCrypt bool) func([]byte, *net.UDPAddr, UDPReplyConn) {
	module := "udp"
	if enableCrypt {
		module = "udp-obfs"
	}
	return func(data []byte, remote *net.UDPAddr, conn UDPReplyConn) {
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
		// PR_NAT is plaintext on every listener, so it is taken on the raw bytes, before
		// any deobfuscation, and answered in plaintext. It used to be dispatched after
		// Decrypt with the listener's crypt, which on the obfuscated port encrypted the
		// reply (unreadable to the client) and the forward to the other peer (with the
		// requester's key). A datagram that only decrypts to 0xf1 is not PR_NAT.
		if s.NAT != nil && (data[0] == PrNat || len(data) == 1) {
			s.NAT.HandlePacket(data, remote, conn)
			return
		}
		// The obfuscation key is per-client, derived from the source IP (see
		// deriveUDPKey). Built per datagram, not once per listener: the handler
		// runs concurrently across a worker pool (udpserver.go), so a shared crypt
		// whose key varied per client would race. crypt.ServerKey is the key we
		// also advertise to this client at reply offset +36, so both directions
		// agree. On the plaintext listener the crypt does no crypto but still
		// carries the derived key for the stat reply to advertise.
		crypt := NewUDPCrypt(enableCrypt, deriveUDPKey(s.udpSecret(), remote.IP))
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
		if enableCrypt && !arrivedPlaintext && (len(data) == 0 || data[0] != PrED2K) && s.gossip() != nil {
			data = s.decryptPeerReply(data, remote.IP)
		}
		obfuscated := enableCrypt && !arrivedPlaintext && len(data) > 0 && data[0] == PrED2K
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
			if !s.udpOpcodeEnabled(s.udp().GetSources, code, remote) {
				return
			}
			s.udpGlobGetSources(b, remote, conn, crypt, module)
		case OpGlobGetSources2:
			if !s.udpOpcodeEnabled(s.udp().GetSources, code, remote) {
				return
			}
			s.udpGlobGetSources2(b, remote, conn, crypt, module)
		case OpGlobGetSourcesIPv6:
			if !s.tcp().IPv6 || !s.udpOpcodeEnabled(s.udp().GetSources, code, remote) {
				return
			}
			s.udpGlobGetSourcesIPv6(b, remote, conn, crypt, module)
		case OpGlobServStatReq:
			s.udpGlobServStatReq(b, remote, conn, crypt, module)
		// Lugdunum's NAT callback request. 0xa6 is also OpGlobFoundSourcesIPv6, but
		// that one only ever goes from this server to a client.
		case OpNatCallbackRequest:
			s.udpNatCallbackRequest(b, remote, conn, obfuscated, module)
		// A foreign callback target's keepalive burst after a TCP 0x37.
		case OpNatKeepalive:
			s.udpNatKeepalive(b, remote, obfuscated, module)
		case OpServerDescReq:
			if len(data) < 6 {
				s.udpServDescResOld(remote, conn, crypt, module)
			} else {
				s.udpServDescRes(b, remote, conn, crypt, module)
			}
		// 0x92 is 0x98 with a different client belief about the server: both carry
		// a bare search tree and no tag block (srchybrid/Opcodes.h:191,194). eMule
		// picks 0x92 when it thinks we do ext-get-files but not large files
		// (SearchExprParser.cpp:999-1000) — never true of the flags we advertise,
		// since BuildUDPFlags always sets FlagLargeFiles, but a stale or
		// third-party server.met entry can say it. 0x92 had no case here at all
		// and fell through to `default:`, so those clients got no reply of any
		// kind — a gap inherited from the Node original (udpoperations.js:32-35).
		case OpGlobSearchReq, OpGlobSearchReq2:
			if !s.udpOpcodeEnabled(s.udp().GetFiles, code, remote) {
				return
			}
			s.udpGlobSearchReq(b, remote, conn, crypt, module)
		case OpGlobSearchReq3:
			if !s.udpOpcodeEnabled(s.udp().GetFiles, code, remote) {
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
	g := s.gossip()
	if g == nil {
		logging.Debugf("udp gossip opcode ignored, gossip disabled remote=%s opcode=0x%x", remote, code)
		return false
	}
	if needIPv6 && !g.Config().PublishIPv6 {
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
	// writeTimeout bounds one write to the socket; see tcpWriteTimeout. Set once,
	// before the session's goroutines start.
	writeTimeout time.Duration

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
	// metaCapable is set at login when the client sent SrvCapMetaSearch in
	// CT_SERVER_FLAGS: it can act on torrent/Usenet/web rows. Written once on this
	// connection's goroutine before its first search, and read only by it.
	metaCapable bool
	// nattCapable is set at login when the Lugdunum NAT callback is on and the client
	// sent SrvCapNatTraversal (0x1000): it got an odd LowID and may be named as a
	// callback target. A UDP worker reads it through the LowIDs table, so it is
	// written and read under infoMu. It sits in the padding after metaCapable, so it
	// adds nothing to the size of a session.
	nattCapable bool
	// natWakeCapable is set at login when the PR_NAT wake-up is on and the client sent
	// SrvCapNatWake (0x200000): a SYNC2 for it may wake it with OpNatWake. Read by a
	// UDP worker through sessionsByHash, so written and read under infoMu. Also in the
	// padding, so a session stays the same size.
	natWakeCapable bool
	// holePunchExt is set at login when the foreign callback is on and the client sent
	// SrvCapHolePunchExt (0x100000): it bursts UDP OpNatKeepalive after a TCP 0x37, so
	// it may be a foreign callback target. Under infoMu; in the padding too.
	holePunchExt bool
	// ed3kID is the ed3k node ID the client sent as CT_ED3K at login, or nil. Read
	// and written under infoMu.
	ed3kID []byte

	// infoMu guards info, logged and hasLowID. The connection's own goroutine
	// writes them during login, but two other goroutines read them: the periodic
	// status ticker (logged) and any peer handling OP_CALLBACKREQUEST, which
	// reaches this client through the shared LowIDs table.
	infoMu   sync.RWMutex
	info     storage.ClientInfo
	logged   bool
	hasLowID bool
	// nick and software are what the client called itself at login, kept for the
	// admin client list only. Written once under infoMu.
	nick     string
	software string
	// mod is the CT_MOD_VERSION from the answer to a dial-back probe, so only a
	// client that answered one (a HighID, or a reachable IPv6) has it. Admin
	// display only, never persisted. Written under infoMu by the probes, the IPv6
	// one on its own goroutine.
	mod string
	// connectedAt is when the connection was accepted; set at construction.
	connectedAt time.Time

	// pendingResults holds the tail of a search whose first page has been sent, so
	// OP_QUERY_MORE_RESULT can deliver the rest. Search and the More request both arrive
	// on this socket, but the status ticker drops expired rows from its own goroutine,
	// hence the atomic pointer.
	//
	// Held rather than re-queried because eMule's More request carries no payload at all
	// (srchybrid/SearchResultsWnd.cpp:1282): there is nothing to re-run the query from.
	// Every session that searched holds these rows, which made them the largest
	// per-session cost on a busy server, so they are capped at MoreResultsMax rows, kept
	// in a copy of their own (not a slice pinning the whole result), and dropped after
	// MoreResultsTTL.
	pendingResults atomic.Pointer[pendingSearch]

	// headerBuf holds the start of a packet header that arrived without the rest of
	// its six bytes. TCP owes us no alignment between reads and packet boundaries, so
	// a burst of small pipelined packets crossing a read or MSS boundary splits a
	// header; dropping the fragment desynced the stream. Only this connection's own
	// goroutine touches it, so it needs no lock.
	headerBuf []byte

	// softLimitWarned keeps the soft-limit warning to one per session, and
	// hardLimitHit makes the offer handler inert once the session has been dropped.
	// Like pendingResults these are touched only by this connection's own goroutine —
	// offers arrive on this socket and nowhere else — so they need no lock.
	//
	// There is no count of offered files here. The soft limit is on the distinct
	// files the session sources now, and storage already keeps that set per session
	// to release its sources on disconnect, so handleOfferFiles asks storage
	// (Engine.OfferedCount, Engine.HasOffered) instead of keeping a second copy. A
	// counter of records sent, which this used to be, charged a re-offered file again
	// each time: a client republishing a finished download, or one whose share list
	// was reloaded, ran into the limit with far fewer files than it allows.
	softLimitWarned bool
	hardLimitHit    bool
	// banlistHits holds the distinct ban-list files this session has offered, and
	// banlistDropped latches the handler once that got the session dropped, as
	// hardLimitHit does. Nil until the first hit, which most sessions never have.
	// keywordHits is the same set for files refused by a keyword.
	banlistHits    map[[16]byte]struct{}
	keywordHits    map[[16]byte]struct{}
	banlistDropped bool
	// spamSession is the spam observer's state for this session; see SpamObserver.
	spamSession any

	// loginGateTripped makes requireLogin inert once it has dropped the session, for
	// exactly the reason hardLimitHit exists above: closeWithReason closes the socket
	// but does not stop dispatch of bytes that already arrived. Same-goroutine only,
	// like the counters above, so it needs no lock.
	loginGateTripped bool

	// releaseOnce makes releaseSession run exactly once. It has two callers: run()'s
	// defer, and a same-IP re-login that takes this session over (handleLoginRequest)
	// and must finish releasing it before the new session connects to storage.
	releaseOnce sync.Once
	// storeMu orders this session's storage writes against its release. A same-IP
	// re-login releases the session from the new session's goroutine, possibly
	// while this one is still inside handleOfferFiles; an AddFiles landing after
	// Storage.Disconnect would publish sources for a session that is gone.
	// released is set under storeMu, before Disconnect, and checked by addFiles.
	storeMu  sync.Mutex
	released bool
	// handedOff is set when the session has moved to a successor process: releasing
	// it then closes this process's copy of the socket and nothing else, since the
	// LowID, the hash index and the storage row all live on over there.
	handedOff atomic.Bool

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
		connectedAt:  time.Now(),
		server:       server,
		conn:         conn,
		packet:       packet,
		crypt:        crypt,
		module:       tcpModule(enableCrypt),
		hasLowID:     true,
		remoteHost:   host,
		writeTimeout: tcpWriteTimeout,
		peerIP:       peerIP,
		connectedV6:  connectedV6,
		info: storage.ClientInfo{
			IPv4:  ipv4,
			ID:    0,
			Port:  0,
			LowID: true,
		},
	}
}

const defaultTCPKeepAlivePeriod = 2 * time.Minute

// maxEd3kClaims is how many live logins per ed3k node ID the bridge index keeps;
// the oldest goes first.
const maxEd3kClaims = 8

// tcpWriteTimeout bounds one write to a client socket. A healthy client drains even
// a full 255-result search page in well under a second; one that has stopped reading
// for this long is not coming back. Each session carries its own copy, which a test
// can shorten without touching other sessions.
const tcpWriteTimeout = 30 * time.Second

const (
	// maxUDPGetSourcesHashes is how many files one UDP source request is answered
	// for. eMule packs at most 35 (DownloadQueue.cpp MAX_REQUESTS_PER_SERVER, and
	// fewer by its 510-byte payload limit); a 64 KB datagram holds ~4000, each
	// answered with up to 1.5 KB.
	maxUDPGetSourcesHashes = 35
	// maxUDPSearchResults caps a UDP search's answer. A one-letter query is ten
	// bytes and matched MaxSearchResults (1000) files, each its own datagram.
	maxUDPSearchResults = 100
)

// errHelloHashMismatch is a dial-back answered by a client other than the one probed.
var errHelloHashMismatch = errors.New("hello answer from another user hash")

const defaultServerStatusInterval = 5 * time.Minute

// Defaults of the "More" retention, matching config tcp.moreResults: two more pages,
// kept for five minutes.
const (
	defaultMoreResultsMax = 2 * storage.MaxSearchPage
	defaultMoreResultsTTL = 5 * time.Minute
)

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
		// statusStop stays here rather than in releaseSession: this goroutine is the
		// only one that writes it, while releaseSession may run on another's.
		if c.statusStop != nil {
			close(c.statusStop)
		}
		c.releaseSession()
	}()

	// The idle deadline below is pushed out by every read, so on its own a socket
	// that trickles a byte at a time never completes a login and is never reaped.
	// Until login, the deadline is also capped at accept + LoginTimeout.
	var loginDeadline time.Time
	if c.server.tcp().LoginTimeout > 0 {
		loginDeadline = time.Now().Add(c.server.tcp().LoginTimeout)
	}
	buf := make([]byte, 4096)
	for {
		// Checked before every read, so a session that was busy in a handler when a
		// handover began parks as soon as it is done. ParkSessions also keeps
		// interrupting the read itself, below.
		if round := c.server.parking.Load(); round != nil {
			if !c.park(round) {
				return
			}
			continue
		}
		var deadline time.Time
		if c.server.tcp().DisconnectTimeout > 0 {
			deadline = time.Now().Add(c.server.tcp().DisconnectTimeout)
		}
		preLogin := !loginDeadline.IsZero() && !c.isLogged()
		if preLogin && (deadline.IsZero() || loginDeadline.Before(deadline)) {
			deadline = loginDeadline
		}
		if !deadline.IsZero() {
			_ = c.conn.SetReadDeadline(deadline)
		}
		n, err := c.conn.Read(buf)
		if err != nil {
			if round := c.server.parking.Load(); round != nil && isTimeout(err) {
				if !c.park(round) {
					return
				}
				continue
			}
			if errors.Is(err, io.EOF) {
				c.setCloseReason("peer-closed")
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() && preLogin {
				c.setCloseReason(fmt.Sprintf("login-timeout(%s)", c.server.tcp().LoginTimeout))
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				c.setCloseReason(fmt.Sprintf("read-timeout(%s)", c.server.tcp().DisconnectTimeout))
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
			// Only the stream's first byte decides: a later piece of a split key
			// exchange may start with any value.
			if state == CsUnknown && len(data) > 0 && IsProtocol(data[0]) && c.crypt.Buffered() == 0 {
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
	if c.packet.Status == PsNew && len(c.headerBuf) > 0 {
		data = append(c.headerBuf, data...)
		c.headerBuf = nil
	}
	buf := NewBufferFromBytes(data)
	switch c.packet.Status {
	case PsNew:
		if len(data) == 0 {
			return
		}
		// Reject a bad protocol byte before waiting for the rest of the header:
		// the stream has lost its framing and nothing later can resync it.
		if !IsProtocol(data[0]) {
			logging.Warnf("tcp unknown protocol remote=%s proto=0x%x", c.remoteHost, data[0])
			c.closeWithReason("unknown-protocol")
			return
		}
		if len(data) < PacketHeaderSize {
			c.headerBuf = append([]byte(nil), data...)
			return
		}
		if !c.preLoginHeaderAllowed(data) {
			return
		}
		if err := c.packet.Init(buf); err != nil {
			// With a full header in hand every Init error is fatal: an oversized
			// declaration would allocate the declared size, and a zero size leaves
			// no way to find the next packet boundary.
			if errors.Is(err, ErrPacketTooLarge) {
				logging.Warnf("tcp packet too large remote=%s err=%v", c.remoteHost, err)
				c.closeWithReason("packet-too-large")
				return
			}
			logging.Warnf("tcp bad packet header remote=%s err=%v", c.remoteHost, err)
			c.closeWithReason(fmt.Sprintf("bad-packet-header: %v", err))
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
	c.packet.release()
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
	// Deny by default: everything that is not the opcode creating a session or the one
	// ending it needs an identity, and there is none before handShake. Written as an
	// exemption list rather than a list of gated opcodes so that an opcode added to the
	// switch below is gated unless someone deliberately exempts it — including the ones
	// that fall through to the default branch, since a pre-login client has no business
	// sending those either. See requireLogin.
	switch opcode {
	case OpLoginRequest, OpDisconnect:
	default:
		if !c.requireLogin(opcode) {
			return
		}
	}
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
		// SRVCAP_IPV6 is advertised whenever the server is dual-stack, so the request
		// is answered even with ipv6.publishSources off — in the IPv6 form, carrying
		// no addresses — rather than leaving the client waiting on silence.
		if c.server.tcp().IPv6 {
			c.handleGetSourcesIPv6(data)
		} else {
			logging.Debugf("tcp unhandled opcode remote=%s opcode=0x%x (ipv6 off)", c.remoteHost, opcode)
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

	// A publisher banned for offering ban-list files is refused before anything is
	// allocated for the session. Told why, or the client just sees a server that
	// drops it and retries forever.
	if c.server.Content != nil && c.server.Content.Banned(req.Hash, c.peerIP) {
		c.server.blocks.bannedLogins.Add(1)
		logging.Warnf("login rejected remote=%s hash=%x: banned by the content filter", c.remoteHost, req.Hash)
		c.sendServerMessage(msgBanned)
		c.closeWithReason("content-ban")
		return
	}

	// Reject the new connection when this user hash is already online, rather
	// than evicting the existing session. The hash is public — it is broadcast in
	// OP_HELLO and handed out in OP_FOUNDSOURCES_OBFU — so eviction let any peer
	// disconnect any user at will. The original rejects too
	// (eNode/ed2k/tcpoperations.js:233-243), and checks before the firewall probe
	// so a duplicate does not cost a dial-back.
	//
	// One exception: a re-login from the same IP as the live session replaces it.
	// eMule's smart-LowID retry abandons its connection without closing it
	// (srchybrid/ServerSocket.cpp:326-338) and reconnects before its own 25 s
	// CONSERVTIMEOUT reaps the socket, so a plain reject locks it out — the client
	// reads the close as "server full" and loops. Taking over needs the victim's
	// source IP, which a remote attacker does not have; only hosts sharing that IP,
	// such as CGNAT neighbours, could still use it. Lugdunum eserver 17.14 does not
	// do this — it refuses every further LowID login from the IP instead — see
	// docs/port-divergences.local.md, H1a.
	//
	// A second exception: a dual-stack client moving its session from IPv4 to IPv6
	// connects from the IPv6 its live IPv4 session advertised (CT_MOD_IP_V6), with
	// the same listen port. That address is the victim's own claim, so it proves the
	// same host as well as a same-IP match does. The old session stays up until this
	// login is accepted, so the client never goes offline — see handShake.
	//
	// Anything else first probes the live session (probeStaleSession): a client that
	// crashed and came back on another address family — its last session was IPv6,
	// the restart logs in over IPv4 — matches neither exception, and its dead session
	// would otherwise hold the hash until the idle timeout. Only a session whose
	// socket is dead goes, so the probe gives a remote attacker nothing.
	if len(req.Hash) == 16 && c.server.Storage.IsConnected(storage.ClientInfo{Hash: req.Hash}) {
		c.replaceSameIPSession(req.Hash)
		if c.dualStackHandoverFrom(req.Hash, req.Port) != nil {
			logging.Infof("login takes over ipv4 session after acceptance remote=%s hash=%x", c.remoteHost, req.Hash)
		} else if c.probeStaleSession(req.Hash); c.server.Storage.IsConnected(storage.ClientInfo{Hash: req.Hash}) {
			// Re-checked so a row with no local session behind it — a stale row in a
			// shared database — is still refused.
			logging.Warnf("login rejected remote=%s hash=%x: already connected", c.remoteHost, req.Hash)
			c.sendServerMessage("Already connected from another session.")
			c.closeWithReason("duplicate-login")
			return
		}
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
	c.metaCapable = loginFlags(req.Tags)&SrvCapMetaSearch != 0
	c.nattCapable = c.server.natCallbackEnabled() && loginFlags(req.Tags)&SrvCapNatTraversal != 0
	c.natWakeCapable = c.server.natWakeEnabled() && loginFlags(req.Tags)&SrvCapNatWake != 0
	c.holePunchExt = c.server.foreignCallbackEnabled() && loginFlags(req.Tags)&SrvCapHolePunchExt != 0
	c.nick, c.software = loginNick(req.Tags), loginSoftware(req.Tags)
	c.ed3kID = loginEd3k(req.Tags)
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
	// races nothing. Only started when an actual dial is needed; with probing
	// turned off the address is trusted as reachable.
	needV6Probe := c.v6ProbeRequired(len(v6Bytes))
	var v6ProbeResult chan bool
	if needV6Probe {
		v6ProbeResult = make(chan bool, 1)
		go func() { v6ProbeResult <- c.server.isIPv6Reachable(c) }()
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
		c.sendServerMessage(c.server.tcp().MessageLowID)

		// AddByAddress publishes this *tcpClient into a table other goroutines
		// read. The address+port seed only affects LowID distribution; keying on
		// the full connecting address rather than the 32-bit IPv4 keeps v6-only
		// clients (all of whom have ipv4 == 0) from colliding on one seed. The ID
		// that comes back is written under infoMu below, so a concurrent reader
		// sees either the old or the new value, never a torn one.
		id, ok := c.server.LowIDs.AddByAddress(c.peerIP, ipv4, port, c, c.lowIDParity())
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
	// started. With probing turned off the address is trusted as reachable
	// (reachable stays true). The verdict is independent of the IPv4 firewall
	// decision above.
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
	if !c.completeDualStackHandover() {
		return
	}
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

	c.sendServerMessage(c.server.tcp().MessageLogin)
	c.sendServerMessage("server version " + LoginVersionStr)
	c.sendServerStatus()
	c.startPeriodicServerStatus()
	c.sendIDChange(info.ID)
	c.sendServerIdent()
}

// touchDeadline pushes the read deadline out by DisconnectTimeout, treating out-of-band
// activity (a PR_NAT keepalive) as if a byte had arrived on the socket.
//
// Called from the NAT UDP worker pool, not this connection's own goroutine. It takes no
// lock: net.Conn deadline methods are safe for concurrent use, and taking writeMu here
// let a peer that stopped reading park a UDP worker behind its blocked write for every
// keepalive, until the pool ran dry. A race with the read loop's own SetReadDeadline
// only moves the deadline by the time between the two calls.
func (c *tcpClient) touchDeadline() {
	// A parked session's deadline belongs to ParkSessions; pushing it out would
	// leave the read loop blocked instead of parked.
	if c.server.tcp().DisconnectTimeout <= 0 || c.server.parking.Load() != nil {
		return
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(c.server.tcp().DisconnectTimeout))
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

// msgNotLoggedIn is sent before the drop, so the user learns why the session ended
// rather than seeing an unexplained close — the same reasoning as msgHardFileLimit.
//
// eserver has no counterpart string, but not because it refuses silently: its refusal
// vocabulary is large (eserver-17.14-strings.txt:20779-20810) and includes two
// protocol-violation lines whose register this copies (":20791-20792"). It has no
// "not logged in" line because a conforming client cannot produce the situation.
//
// "ERROR" is load-bearing, for the same reason as the file-limit messages: both client
// trees divert a message beginning with it to the error log rather than the server-info
// pane. ASCII only, deliberately — this session has had no OP_IDCHANGE, so the client
// has not been told SRV_TCPFLG_UNICODE and reads the text as ANSI.
const msgNotLoggedIn = "ERROR : You must log in before sending requests to this server."

// requireLogin reports whether a session may be served an opcode that needs an identity.
// When it may not, it explains, drops the session and returns false — the same shape as
// udpOpcodeEnabled, which likewise logs its own refusal.
//
// Everything but OP_LOGINREQUEST and OP_DISCONNECT goes through here, because before
// handShake runs there is no identity to serve anything against: handShake is the only
// place c.logged and c.info.StoreID are ever set, so snapshotInfo returns
// {ID: 0, Port: 0, Hash: nil, StoreID: 0}.
//
// OP_OFFERFILES is what made this urgent. Publishing under that identity is not merely
// useless, it is unreclaimable: sources dedupe on (ID, Port), so every pre-login offer
// from every socket collapses into one {0, 0} row per hash; run()'s teardown calls
// Storage.Disconnect only for a session that was logged in; and MemoryEngine.CleanupStale
// cannot expire a source at all, because Source carries no timestamp
// (storage/storage.go:193-216). Those rows are then served to real clients, which can do
// nothing with an address of 0:0, and they occupy slots in the 255-entry wire cap.
// MongoDB is the same story keyed on a nil client_hash, and also writes source_id: 0,
// source_port: 0 into the files document (storage/engine_mongodb.go:310-319). MySQL is
// the mild case: the source INSERT fails on the sources_ibfk_2 foreign key and returns
// before the counter refresh, leaving one error line per offered record and an orphan
// files row that CleanupStale reaps.
//
// A fourth consequence has since been closed at the storage layer rather than here: the
// memory engine used to key a file on its hash alone and overwrite the whole record, so
// any offer — anonymous or not — could rewrite the Size of a hash already in the index
// and blackhole every later source lookup for it. Files are keyed on (hash, size) now;
// see storage.fileMapKey.
//
// No conforming client is refused. Both reference trees send their first request only
// once login has completed: srchybrid/ServerConnect.cpp:227-228 calls SendListToServer
// from the CS_CONNECTED branch, and eMuleQt/src/core/files/SharedFileList.cpp:652-653
// returns early unless ServerConnect::isConnected(), whose flag is set at the single site
// ServerConnect.cpp:425, in the ServerConnState::Connected branch. Both send
// OP_GETSERVERLIST from that same post-login branch. A client that pipelines its login
// and its first request into one segment is fine too: dispatch is sequential on this
// connection's goroutine, and processPacketData recurses into packet.Excess only after
// handlePacket has returned, so the login is complete before the next opcode is read.
//
// The session is dropped rather than the packet ignored because nothing a pre-login
// socket can legitimately do needs any of these opcodes, and ignoring would leave it free
// to keep sending full frames — each one parsed in full, and zlib-inflated first if it
// arrived as PR_ZLIB — for the whole of DisconnectTimeout.
func (c *tcpClient) requireLogin(opcode uint8) bool {
	if c.isLogged() {
		return true
	}
	// closeWithReason only closes the socket; every packet already buffered behind the
	// offending one still reaches this function. Without the latch a segment packed with
	// 10-byte empty offers would produce a warning, an OP_SERVERMESSAGE and a redundant
	// Close for each. Same latch, same reason, as hardLimitHit.
	if c.loginGateTripped {
		return false
	}
	c.loginGateTripped = true
	logging.Warnf("tcp request before login remote=%s opcode=0x%x: closing", c.remoteHost, opcode)
	c.sendServerMessage(msgNotLoggedIn)
	c.closeWithReason("not-logged-in")
	return false
}

// maxPreLoginPacket is the largest payload accepted before login. A login request is
// a few hundred bytes.
const maxPreLoginPacket = 64 << 10

// preLoginHeaderAllowed judges a packet from its header alone before login, before
// anything is buffered for it: only a login or disconnect of plausible size may
// follow. requireLogin applies the same opcode rule after the fact; this spares
// buffering (up to MaxTCPPacketSize) and inflating what it would refuse anyway.
func (c *tcpClient) preLoginHeaderAllowed(header []byte) bool {
	if c.isLogged() {
		return true
	}
	if size := binary.LittleEndian.Uint32(header[1:5]); size > maxPreLoginPacket+1 {
		logging.Warnf("tcp oversized packet before login remote=%s size=%d: closing", c.remoteHost, size)
		c.closeWithReason("prelogin-packet-too-large")
		return false
	}
	if header[0] != PrEMule {
		if code := header[5]; code != OpLoginRequest && code != OpDisconnect {
			return c.requireLogin(code)
		}
	}
	return true
}

func (c *tcpClient) startPeriodicServerStatus() {
	if c.statusStop != nil {
		return
	}
	interval := c.server.tcp().ServerStatusInterval
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
				// Not while a handover is parking the session: a write now would move
				// the RC4 keystream past the state being handed over.
				if c.isLogged() && c.server.parking.Load() == nil {
					c.sendServerStatus()
				}
				c.dropExpiredResults(time.Now())
			case <-stop:
				return
			}
		}
	}(c.statusStop)
}

// msgSoftFileLimit is eserver's own wording, verbatim from
// lugdunum-eserver/docs/eserver-17.14-strings.txt:20786. The "WARNING" prefix is
// load-bearing rather than decorative: both client trees divert a server message
// starting with it to the warning log instead of the server-info pane
// (srchybrid/ServerSocket.cpp:195-201, eMuleQt/src/core/server/ServerConnect.cpp:1208-1210).
//
// msgHardFileLimit has no eserver counterpart — there is a MsgSOFTLIMIT keyword in the
// 17.14 strings but no MsgHARDLIMIT, because eserver drops silently and only bumps its
// `hardlimit` reject counter. Sending one is a deliberate divergence: the client cannot
// otherwise distinguish this from any other mid-session close, so the user has no way to
// learn why. "ERROR" for the same routing reason as above.
const (
	msgSoftFileLimit = "WARNING : This server accepts %d shares per client. Some of your shares are ignored."
	msgHardFileLimit = "ERROR : This server accepts at most %d shares per client. Closing the connection."
)

// handleOfferFiles registers the files a client publishes, enforcing files.hardLimit
// and files.softLimit (0 = unlimited).
//
// The hard limit is on one packet: an OP_OFFERFILES declaring that many records or
// more is refused whole and the session closed, which is what Lugdunum's "disconnects
// him (before receiving the whole list)" describes. Both client trees send at most
// 200 records per packet (srchybrid/SharedFileList.cpp:832-834,
// eMuleQt/src/core/files/SharedFileList.cpp:54,880), so only a broken or abusive
// client reaches it. It used to be the session's running total, which dropped an honest
// client sharing more than the limit every time it had republished that many,
// only for it to reconnect and start again.
//
// The soft limit is on the distinct files the session sources at once, which storage
// knows (Engine.OfferedCount). A file the session already sources is always accepted
// and costs nothing, so a re-offer keeps its name and complete flag current; a new
// file past the limit is skipped and the client warned once.
//
// The declared count is read before anything else, so a refused packet is neither
// parsed nor stored. A zlib packet has been inflated by then; MaxTCPPacketSize and the
// inflate cap bound that.
func (c *tcpClient) handleOfferFiles(data *Buffer) {
	// closeWithReason only closes the socket; it does not stop dispatch of bytes that
	// already arrived. processPacketData recurses into packet.Excess after handlePacket
	// returns, so a client that pipelines two offers in one segment reaches this again
	// after the drop — without this latch it would be sent a second message on a closed
	// socket and logged twice.
	if c.hardLimitHit || c.banlistDropped {
		return
	}
	softLimit, hardLimit := c.server.tcp().SoftFileLimit, c.server.tcp().HardFileLimit
	if declared, ok := declaredFileCount(data); ok && hardLimit > 0 && declared >= uint32(hardLimit) {
		id := c.snapshotInfo().ID
		c.hardLimitHit = true
		c.server.blocks.hardLimit.Add(1)
		logging.Warnf("offer files hard limit remote=%s id=%d declared=%d hardLimit=%d: closing",
			c.remoteHost, id, declared, hardLimit)
		c.sendServerMessage(fmt.Sprintf(msgHardFileLimit, hardLimit))
		c.closeWithReason("file-hard-limit")
		return
	}
	// data.Bytes() is the whole payload regardless of the read pointer (buffer.go:90-92),
	// and GetOfferedFiles below only advances that pointer: every write to b.data lives
	// in a Put* method, none of which it can reach, and each value it returns is copied
	// out — the hash through an explicit append, strings through GetString. So the
	// payload is still intact on the error path below. This used to snapshot the frame
	// into a copy first, duplicating the whole of every offer packet to serve one length
	// and a 96-byte hex preview.
	payloadLen := len(data.Bytes())
	records, err := data.GetOfferedFiles()
	if err != nil {
		previewHex := hex.EncodeToString(data.Bytes()[:min(payloadLen, 96)])
		logging.Warnf("offer files parse failed remote=%s payloadLen=%d previewHex=%s err=%v",
			c.remoteHost, payloadLen, previewHex, err)
		return
	}
	const maxOfferFilesLog = 50
	logging.Debugf("offer files remote=%s count=%d payloadLen=%d",
		c.remoteHost, len(records), payloadLen)
	if len(records) > maxOfferFilesLog {
		logging.Debugf("offer files remote=%s truncated=%d", c.remoteHost, len(records)-maxOfferFilesLog)
	}
	// One snapshot for the whole batch: the identity cannot change mid-batch,
	// and taking it per file would lock once per offered file.
	info := c.snapshotInfo()
	var zeroSize, metaHashes, contentRefused int
	// The whole packet is written in one AddFiles call. Storing record by record cost
	// a fixed set of round-trips per file, so a database outside the host turned one
	// 200-file offer into most of a minute of blocked read loop and held pool
	// connections every other session was waiting on.
	batch := make([]storage.File, 0, len(records))
	for i, record := range records {
		if record.Size == 0 {
			// No size tag at all, or one that did not decode as an integer
			// (FileRecord.SetTag). Such a record is unusable and permanent: a client
			// only ever asks for sources by (hash, size), and eMule discards a
			// zero-size search result outright (srchybrid/SearchList.cpp:355), so it
			// would sit in the index for good — searchable, never servable. eserver
			// has policed published sizes since 17.3 (kiten-20071012.txt:189-190).
			//
			// Dropped before the soft limit, so it is not charged against it: a
			// client is not penalised for a record the server refuses.
			zeroSize++
			continue
		}
		if metahash.RejectOfferedFile(record.Hash) {
			// A torrent/Usenet/web pseudo-hash (docs/meta-search.md). A stock client cannot
			// offer one — a pseudo-hash download never obtains a hashset, so it never
			// enters the shared-file map — but a modified client can, and the row it
			// advertises would then acquire "sources" that serve nothing. Dropped before
			// the soft limit, like a zero size.
			metaHashes++
			continue
		}
		if refused, banlist, keyword := c.server.checkOffer(record.Hash, recordName(record)); refused {
			// On a hash list or holding a filtered keyword. Dropped before the
			// soft limit like the two cases above, so a refused file is not charged
			// against it.
			contentRefused++
			reason, distinct := "", 0
			switch {
			case banlist && c.noteBanlistHit(record.Hash):
				reason, distinct = "ban list", len(c.banlistHits)
			case keyword && c.noteKeywordHit(record.Hash):
				reason, distinct = "keyword", len(c.keywordHits)
			}
			if reason != "" {
				// Nothing of this packet is stored: the session is going away and
				// its sources with it.
				c.banlistDropped = true
				c.server.Content.Ban(info.Hash, c.peerIP, fmt.Sprintf("offered %d %s files", distinct, reason))
				logging.Warnf("offer files %s remote=%s id=%d hash=%x distinct=%d: closing and banning",
					reason, c.remoteHost, info.ID, info.Hash, distinct)
				c.sendServerMessage(msgBanlisted)
				c.closeWithReason("banlist")
				return
			}
			continue
		}
		file := fileFromRecord(record, info)
		batch = append(batch, file)
		if i < maxOfferFilesLog {
			logging.Debugf("offer file remote=%s idx=%d hash=%x name=%q size=%d type=%q sourceID=%d sourcePort=%d",
				c.remoteHost, i, record.Hash, file.Name, file.Size, file.Type, info.ID, info.Port)
		}
	}
	// Before the soft limit: what a publisher offers says what its share is, whether
	// or not the server indexes all of it.
	if c.server.Spam != nil && len(batch) > 0 {
		c.spamSession = c.server.Spam.ObserveOffer(c.spamSession, info.Hash, c.peerIP, batch)
	}
	batch, skipped := c.withinSoftLimit(batch, info, softLimit)
	if skipped > 0 && !c.softLimitWarned {
		c.softLimitWarned = true
		logging.Warnf("offer files soft limit remote=%s id=%d softLimit=%d skipped=%d of=%d: ignoring excess",
			c.remoteHost, info.ID, softLimit, skipped, len(records))
		c.sendServerMessage(fmt.Sprintf(msgSoftFileLimit, softLimit))
	}
	if len(batch) > 0 {
		c.addFiles(batch, info)
	}
	// One line for the packet, never one per record: a packet may hold as many
	// records as the hard limit lets through.
	if contentRefused > 0 {
		logging.Infof("offer files content filter remote=%s id=%d refused=%d of=%d",
			c.remoteHost, info.ID, contentRefused, len(records))
	}
	if zeroSize > 0 {
		logging.Infof("offer files zero size remote=%s id=%d dropped=%d of=%d",
			c.remoteHost, info.ID, zeroSize, len(records))
	}
	if metaHashes > 0 {
		logging.Warnf("offer files meta hash remote=%s id=%d dropped=%d of=%d",
			c.remoteHost, info.ID, metaHashes, len(records))
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
	var sources []storage.Source
	if !c.server.withheldHash(hash) {
		sources = c.server.Storage.GetSources(hash, fileSize)
	}
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
	var sources []storage.Source
	if !c.server.withheldHash(hash) {
		sources = c.server.v6PublishableSources(c.server.Storage.GetSources(hash, fileSize))
	}
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
		// Answered with an empty page for the same reason a zero-result search is
		// (see below): silence leaves the client "Searching…" until its timeout.
		c.sendSearchPage(nil)
		return
	}
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_SEARCHREQUEST expr=%s", c.remoteHost, formatSearchExpr(expr))
	if c.server.queryBlocked(expr) {
		// Answered like any search with no match, and without asking the index or
		// the catalogue daemons.
		c.sendSearchPage(nil)
		return
	}
	if seeds, ok := storage.FindRelated(expr); ok {
		// Not merged with meta or mirrored rows: those have no users to relate.
		files := c.server.relatedSearch(expr, seeds)
		c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_SEARCHREQUEST related resultCount=%d", c.remoteHost, len(files))
		c.sendSearchPage(files)
		return
	}
	metaCh := c.server.startMetaSearch(expr, c.metaCapable, false)
	files := c.server.withholdFiles(mergeMetaResults(c.server.Storage.FindBySearch(expr), metaCh))
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
//
// Rows past MoreResultsTTL count as nothing pending: the client gets the empty final page.
func (c *tcpClient) handleQueryMoreResult() {
	c.dropExpiredResults(time.Now())
	kept := c.pendingResults.Load()
	if kept == nil || len(kept.rows) == 0 {
		c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_QUERY_MORE_RESULT pending=0", c.remoteHost)
		c.sendSearchResult(nil, false)
		return
	}
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_QUERY_MORE_RESULT pending=%d",
		c.remoteHost, len(kept.rows))
	// Filtered again: the pages were cut when the search ran, and a list can have
	// gained a hash since. The deadline stays the one of the search.
	c.sendSearchPageUntil(c.server.withholdFiles(kept.rows), kept.expires)
}

// sendSearchPage sends the first page of a new search's files; see sendSearchPageUntil.
func (c *tcpClient) sendSearchPage(files []storage.File) {
	c.sendSearchPageUntil(files, time.Now().Add(c.server.tcp().MoreResultsTTL))
}

// sendSearchPageUntil sends the first storage.MaxSearchPage of files, keeps at most
// MoreResultsMax of the remainder for OP_QUERY_MORE_RESULT until expires, and sets the
// more-results flag accordingly.
func (c *tcpClient) sendSearchPageUntil(files []storage.File, expires time.Time) {
	page, rest := files, []storage.File(nil)
	if len(files) > storage.MaxSearchPage {
		page, rest = files[:storage.MaxSearchPage], files[storage.MaxSearchPage:]
	}
	// Assigned before the send so a write error cannot leave a stale page pending.
	c.keepPendingResults(rest, expires)
	c.sendSearchResult(page, len(c.pendingRows()) > 0)
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
	// The LowID is registered before the target's login completes (the IPv6 probe and
	// storage connect come after), so a target can be found here before it is a
	// session anyone may reach.
	if !target.isLogged() {
		c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_CALLBACKREQUEST lowID=%d result=target-not-logged-in", c.remoteHost, lowID)
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
		err = target.sendCallbackRequested(self.IPv4, self.Port, self.CryptOptions, self.Hash)
	case c.server.publishV6Sources() && len(self.IPv6) == 16 && self.IPv6Reachable && target.isV6Capable() &&
		(len(targetInfo.IPv6) == 16 || target.connectedV6):
		// The target must have IPv6 itself to dial the requester: being able to parse
		// the opcode is not enough, and a v6 callback it cannot place fails silently.
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
	var verified []PeerAddr
	if g := s.gossip(); g != nil {
		verified = g.Verified()
	}

	out := make([]storage.Server, 0, len(configured)+len(verified))
	seen := make(map[string]struct{}, len(configured)+len(verified))
	// Both sides go through storage.ServerAddrKey, which canonicalizes the address
	// before comparing. Keying the configured entries on their raw config string
	// instead would let the same peer appear twice whenever the operator spelled an
	// IPv6 literal differently from the way gossip reports it ("2001:DB8::1" against
	// 2001:db8::1). Deduplication runs even with gossip disabled, because a repeated
	// entry under `servers:` is just as duplicated on the wire.
	add := func(sv storage.Server) {
		key := storage.ServerAddrKey(sv)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, sv)
	}

	for _, sv := range configured {
		add(sv)
	}
	for _, p := range verified {
		add(storage.Server{IP: p.IP.String(), Port: p.Port})
	}
	return out
}

func (c *tcpClient) sendServerStatus() {
	clients, files := c.server.counters.Counts()
	packet, err := BuildServerStatusPacket(c.server.advertisedUsers(clients), c.server.advertisedFiles(files))
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendIDChange(id uint32) {
	// The observed IPv4 is taken from the accepted socket, never from anything the
	// client claimed in OP_LOGINREQUEST. It is what lets a LowID client learn its
	// own public IPv4 — see BuildIDChangePacket. A private or loopback address
	// (LAN, hairpin NAT, docker bridge) is not that: eMule would adopt it as its
	// public IP, so a LowID gets 0, which clients skip. A HighID keeps it: there
	// it equals the ID, clients ignore it, and MFC debug builds assert on 0.
	observed := c.snapshotInfo().IPv4
	if IsLANIP(c.peerIP) && !HasHighID(id) {
		observed = 0
	}
	var natPorts *IDChangeNatPorts
	if c.wantsLongIDChange() {
		natPorts = c.idChangeNatPorts(id)
	}
	packet, err := BuildIDChangePacket(id, c.server.tcp().Flags, c.server.tcp().Port, observed, natPorts)
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
	cfg := c.server.tcp()
	packet, err := BuildServerIdentPacket(ServerConfig{
		Name:             cfg.Name,
		Description:      cfg.Description,
		Address:          c.server.advertisedAddress(),
		Hash:             cfg.Hash,
		TCPPort:          cfg.Port,
		TCPFlags:         cfg.Flags,
		IPv6:             cfg.ServerIPv6,
		NatPort:          cfg.NatRendezvousPort,
		ClientIPv6:       clientV6,
		ClientIPv6Status: v6Status,
		MetaAPI:          cfg.MetaAPI,
		Ed3k:             cfg.Ed3k,
	})
	if err != nil {
		logging.Warnf("tcp server ident not sent remote=%s err=%v", c.remoteHost, err)
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

func (c *tcpClient) sendCallbackRequested(ipv4 uint32, port uint16, cryptOptions byte, userHash []byte) error {
	packet, err := BuildCallbackRequestedPacket(ipv4, port, cryptOptions, userHash)
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
	// Bounded, because writeMu is held across the write and other goroutines take it
	// too: without a deadline a peer that stops reading blocks its own session forever
	// and every peer that sends it OP_CALLBACKREQUESTED along with it.
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	_, err := c.conn.Write(data)
	if err != nil {
		// A partial write leaves the peer mid-packet, and on an obfuscated session the
		// RC4 keystream has already advanced past bytes it never received. Neither can
		// be recovered, so drop the session; the read loop then releases it.
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			c.closeWithReason(fmt.Sprintf("write-timeout(%s)", c.writeTimeout))
		} else {
			c.closeWithReason(fmt.Sprintf("write-error: %v", err))
		}
	}
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
		parts = append(parts, fmt.Sprintf("{hash=%x,id=%d,port=%d,size=%d,name=%q}", files[i].Hash, files[i].ID, files[i].Port, files[i].Size, files[i].Name))
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
	if s.tcp().SupportCrypt {
		ok, err := s.probeClient(client, true, "tcp4", client.remoteHost)
		if err == nil && ok {
			return false
		}
	}
	ok, err := s.probeClient(client, false, "tcp4", client.remoteHost)
	return err != nil || !ok
}

// isIPv6Reachable returns the IPv6 dial-back verdict, through the test hook when
// one is set.
func (s *ServerRuntime) isIPv6Reachable(client *tcpClient) bool {
	if s.ipv6Probe != nil {
		return s.ipv6Probe(client)
	}
	return s.probeIPv6Reachable(client)
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
	if s.tcp().SupportCrypt {
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
	dialer := net.Dialer{Timeout: s.tcp().ConnectionTimeout}
	// Only bind a local source address whose family matches the dial network;
	// binding a v4 LocalAddr to a tcp6 dial (or vice versa) fails outright.
	if local := localBindForNetwork(network, s.tcp().Address); local != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: local}
	}
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	cli := NewClient(ClientConfig{
		EnableCrypt:       enableCrypt,
		Address:           s.tcp().Address,
		TCPPort:           s.tcp().Port,
		ConnectionTimeout: int(s.tcp().ConnectionTimeout / time.Millisecond),
		Hash:              s.tcp().Hash,
	})
	cli.Hash = client.snapshotInfo().Hash

	var leftover []byte
	if enableCrypt {
		pad, err := RandBuf(Rand(0xff))
		if err != nil {
			return false, err
		}
		handshake, err := cli.BuildHandshake(RandProtocol(), RandUint32(), pad)
		if err != nil {
			return false, err
		}
		if err := writeWithDeadline(conn, handshake, s.tcp().ConnectionTimeout); err != nil {
			return false, err
		}
		if leftover, err = readHandshake(cli, conn, s.tcp().ConnectionTimeout); err != nil {
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
	if err := writeWithDeadline(conn, helloBytes, s.tcp().ConnectionTimeout); err != nil {
		return false, err
	}
	answer, ok, err := readHelloAnswer(cli, conn, s.tcp().ConnectionTimeout, cli.Hash, leftover)
	// The probe is a client-to-client hello, the one place a client names its mod;
	// OP_LOGINREQUEST never carries CT_MOD_VERSION.
	if ok {
		if mod := helloModVersion(answer.Tags); mod != "" {
			client.infoMu.Lock()
			client.mod = mod
			client.infoMu.Unlock()
		}
	}
	return ok, err
}

// readHandshake reads the obfuscation handshake answer, however TCP splits it, and
// returns what followed it, decrypted.
func readHandshake(cli *Client, conn net.Conn, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		data, done, err := cli.Decrypt(buf[:n])
		if err != nil {
			return nil, err
		}
		if done {
			return data, nil
		}
	}
}

// readHelloAnswer waits for the probed client's OP_HELLOANSWER. It counts only when
// the answer carries wantHash, the user hash the client logged in with: another
// client on the same (CGNAT) IP answering that port must not earn this one a HighID.
// buffer holds bytes already read past the crypt handshake. The parsed answer is
// returned with ok, for the tags it carries.
func readHelloAnswer(cli *Client, conn net.Conn, timeout time.Duration, wantHash, buffer []byte) (HelloAnswer, bool, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 4096)

	for first := true; ; first = false {
		if !first || len(buffer) == 0 {
			_ = conn.SetReadDeadline(deadline)
			n, err := conn.Read(buf)
			if err != nil {
				return HelloAnswer{}, false, err
			}
			data := buf[:n]
			if cli.CryptStatus == CsEncrypting {
				data, _, err = cli.Decrypt(data)
				if err != nil {
					return HelloAnswer{}, false, err
				}
			}
			buffer = append(buffer, data...)
		}
		// The peer here is the client being probed: it chose the address we
		// dialed and it controls every byte coming back. Without this ceiling it
		// can declare a huge size, then dribble bytes until the deadline while
		// the loop below never completes a packet and this slice grows unbounded.
		if len(buffer) > maxHelloAnswerBytes {
			return HelloAnswer{}, false, fmt.Errorf("hello answer exceeded %d bytes", maxHelloAnswerBytes)
		}

		for {
			if len(buffer) < 6 {
				break
			}
			if buffer[0] != PrED2K {
				return HelloAnswer{}, false, fmt.Errorf("bad protocol 0x%x", buffer[0])
			}
			size := int(binary.LittleEndian.Uint32(buffer[1:5]))
			// Same ceiling Packet.Init applies on the inbound path; this reader
			// reimplements the framing and so needs it too.
			if size > 0 && size-1 > MaxTCPPacketSize {
				return HelloAnswer{}, false, fmt.Errorf("%w: declared=%d max=%d", ErrPacketTooLarge, size-1, MaxTCPPacketSize)
			}
			if size <= 0 || len(buffer) < 5+size {
				break
			}
			payload := buffer[5 : 5+size]
			opcode := payload[0]
			if opcode == OpHelloAnswer {
				// Only the hash matters here; a tag this parser rejects further on
				// does not make the peer any less reachable.
				answer, _ := ReadOpHelloAnswer(NewBufferFromBytes(payload[1:]))
				if !bytes.Equal(answer.Hash, wantHash) {
					return HelloAnswer{}, false, errHelloHashMismatch
				}
				return answer, true, nil
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

func (s *ServerRuntime) udpGlobGetSources(b *Buffer, remote *net.UDPAddr, conn UDPReplyConn, crypt *UDPCrypt, module string) {
	// A query that arrived over IPv6 comes from a v6-capable sender, so IPv6-only
	// sources may ride the sentinel form. An IPv4 query gets the classic layout.
	format := s.udpSourceFormat(remote)
	for n := 0; n < maxUDPGetSourcesHashes && b.Pos()+16 <= len(b.Bytes()); n++ {
		hash := append([]byte(nil), b.Get(16)...)
		if len(hash) != 16 {
			return
		}
		if s.withheldHash(hash) {
			continue
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

func (s *ServerRuntime) udpGlobGetSources2(b *Buffer, remote *net.UDPAddr, conn UDPReplyConn, crypt *UDPCrypt, module string) {
	format := s.udpSourceFormat(remote)
	for n := 0; n < maxUDPGetSourcesHashes && b.Pos()+20 <= len(b.Bytes()); n++ {
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
		if s.withheldHash(hash) {
			continue
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
func (s *ServerRuntime) udpGlobGetSourcesIPv6(b *Buffer, remote *net.UDPAddr, conn UDPReplyConn, crypt *UDPCrypt, module string) {
	for n := 0; n < maxUDPGetSourcesHashes && b.Pos()+20 <= len(b.Bytes()); n++ {
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
		if s.withheldHash(hash) {
			continue
		}
		sources := s.v6PublishableSources(s.Storage.GetSources(hash, fileSize))
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

func (s *ServerRuntime) udpGlobServStatReq(b *Buffer, remote *net.UDPAddr, conn UDPReplyConn, crypt *UDPCrypt, module string) {
	challenge, err := b.GetUInt32LE()
	if err != nil {
		return
	}
	// The payload always advertises the derived key; only the envelope key can differ.
	packet, err := s.buildStatRes(challenge, crypt.ServerKey, remote)
	if err != nil {
		return
	}
	_ = udpSend(conn, remote, packet.Bytes(), s.peerReplyCrypt(remote, crypt), module)
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
	cfg := s.udp()
	return BuildGlobServStatResPacket(challenge, UDPConfig{
		Name:           cfg.Name,
		Description:    cfg.Description,
		DynIP:          cfg.DynIP,
		UDPFlags:       cfg.UDPFlags,
		UDPPortObf:     cfg.UDPPortObf,
		TCPPortObf:     cfg.TCPPortObf,
		UDPServerKey:   udpKey,
		MaxConnections: cfg.MaxConnections,
		SoftFiles:      cfg.SoftFiles,
		HardFiles:      cfg.HardFiles,
		ObservedIP:     observed,
	}, s.advertisedUsers(clients), s.advertisedFiles(files), s.advertisedLowIDs(int(s.LowIDs.Count())))
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
func (s *ServerRuntime) udpCryptPingReply(data []byte, remote *net.UDPAddr, conn UDPReplyConn, udpKey uint32, module string) {
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
	s.gossip().NoteInboundPingChallenge(remote.IP, challenge)
	reply := NewUDPCrypt(true, challenge).Encrypt(packet.Bytes())
	LogUDPRaw(module, "send", remote.String(), reply)
	_, _ = conn.WriteToUDP(reply, remote)
}

func (s *ServerRuntime) udpServDescResOld(remote *net.UDPAddr, conn UDPReplyConn, crypt *UDPCrypt, module string) {
	packet, err := BuildServerDescResOldPacket(s.udp().Name, s.udp().Description)
	if err != nil {
		return
	}
	_ = udpSend(conn, remote, packet.Bytes(), s.peerReplyCrypt(remote, crypt), module)
}

func (s *ServerRuntime) udpServDescRes(b *Buffer, remote *net.UDPAddr, conn UDPReplyConn, crypt *UDPCrypt, module string) {
	challenge, err := b.GetUInt32LE()
	if err != nil {
		return
	}
	packet, err := BuildServerDescResPacket(challenge, UDPConfig{
		Name:         s.udp().Name,
		Description:  s.udp().Description,
		DynIP:        s.udp().DynIP,
		ServerSearch: s.udp().ServerSearch,
		Ed3k:         s.udp().Ed3k,
	})
	if err != nil {
		return
	}
	_ = udpSend(conn, remote, packet.Bytes(), s.peerReplyCrypt(remote, crypt), module)
}

func (s *ServerRuntime) udpGlobSearchReq(b *Buffer, remote *net.UDPAddr, conn UDPReplyConn, crypt *UDPCrypt, module string) {
	expr, err := ParseSearchExpr(b)
	if err != nil {
		return
	}
	// OP_GLOBSEARCHREQ and ...REQ2 carry no tag block, so the requester cannot have
	// asked for meta rows: it gets the pseudo-hash ones only when they go to every
	// client. Kad rows are plain eD2K files and it gets those regardless.
	// A related search is TCP only (see relatedsearch.go).
	if s.queryBlocked(expr) || isRelatedSearch(expr) {
		return
	}
	metaCh := s.startMetaSearch(expr, false, true)
	// Withheld before the cap, or refused rows would use up result slots.
	files := capUDPSearchResults(s.withholdFiles(mergeMetaResults(s.Storage.FindBySearch(expr), metaCh)))
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

func (s *ServerRuntime) udpGlobSearchReq3(b *Buffer, remote *net.UDPAddr, conn UDPReplyConn, crypt *UDPCrypt, module string) {
	// GetTags aborts mid-loop on a malformed tag and Buffer has no rewind, so
	// discarding this error left the read pointer at an arbitrary offset inside
	// a half-consumed tag — and ParseSearchExpr then built a query out of tag
	// payload bytes. Bail instead; the tag block is mandatory for this opcode,
	// so a failure here means the datagram is not parseable.
	tags, err := b.GetTags()
	if err != nil {
		logging.Warnf("udp glob search tags decode failed remote=%s err=%v", remote, err)
		return
	}
	expr, err := ParseSearchExpr(b)
	if err != nil {
		return
	}
	metaCapable := udpSearchFlags(tags)&SrvCapUDPMetaSearch != 0
	if s.queryBlocked(expr) || isRelatedSearch(expr) {
		return
	}
	metaCh := s.startMetaSearch(expr, metaCapable, true)
	files := capUDPSearchResults(s.withholdFiles(mergeMetaResults(s.Storage.FindBySearch(expr), metaCh)))
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

// peerReplyCrypt returns the crypt a server-protocol reply (0x97, 0xA3, 0xA1) to remote
// must be sent with. That is crypt, the per-address derived key, except when gossip
// shares the tcp+12 socket and remote is a peer server: a Lugdunum peer decrypts
// anything from that port with its last crypt-ping challenge instead, see
// GossipHandler.NoteInboundPingChallenge.
func (s *ServerRuntime) peerReplyCrypt(remote *net.UDPAddr, crypt *UDPCrypt) *UDPCrypt {
	if crypt == nil || crypt.Status != CsEncrypting {
		return crypt
	}
	if key, ok := s.gossip().ReplyKeyFor(remote.IP); ok {
		return NewUDPCrypt(true, key)
	}
	return crypt
}

func udpSend(conn UDPReplyConn, remote *net.UDPAddr, data []byte, crypt *UDPCrypt, module string) error {
	LogUDPRaw(module, "send", remote.String(), data)
	if crypt != nil && crypt.Status == CsEncrypting {
		data = crypt.Encrypt(data)
	}
	_, err := conn.WriteToUDP(data, remote)
	return err
}

func fileFromRecord(record FileRecord, info storage.ClientInfo) storage.File {
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
	file := storage.File{
		Hash:       record.Hash,
		Name:       record.Name,
		Size:       record.Size,
		Type:       record.Type,
		Sources:    record.Sources,
		Title:      record.Title,
		Artist:     record.Artist,
		Album:      record.Album,
		Runtime:    record.Length,
		Bitrate:    record.Bitrate,
		Codec:      record.Codec,
		SourceID:   info.ID,
		SourcePort: info.Port,
	}
	if record.Complete {
		file.Completed = 1
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
	if !enabled {
		logging.Debugf("udp opcode disabled by config remote=%s opcode=0x%x", remote, code)
		return false
	}
	// Every opcode gated here answers one small datagram with many: the source
	// address is spoofable, so without a per-address budget the server is an
	// amplifier aimed wherever an attacker likes.
	//
	// The bot detector sees the query first: the limiter would otherwise hide every
	// rate above its own budget from it.
	key := addressKey(remote.IP)
	s.observeUDPQuerier(key)
	if !s.udpLimiter.Allow(key) {
		s.blocks.rateLimited.Add(1)
		logging.Debugf("udp opcode rate limited remote=%s opcode=0x%x", remote, code)
		return false
	}
	return true
}

// addressKey is the per-address bucket for rate and connection limits: the IPv4
// address, or the /64 of an IPv6 one, which one subscriber usually holds whole.
func addressKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
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
	case storage.SearchHash:
		if expr.ValueUint == 0 {
			return fmt.Sprintf("HASH(%x)", expr.ValueString)
		}
		return fmt.Sprintf("HASH(%x,size=%d)", expr.ValueString, expr.ValueUint)
	case storage.SearchRelated:
		return fmt.Sprintf("RELATED(%d)", len(expr.Related))
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

// loginEd3k returns the client's ed3k node ID from the CT_ED3K (0xe3) login tag, a
// 16-byte hash (spec docs/ed2k-tags.md §2), or nil when absent or of another form.
func loginEd3k(tags []NamedTag) []byte {
	for _, t := range tags {
		if t.Name != "ed3k" {
			continue
		}
		if b, ok := t.Value.([]byte); ok && len(b) == 16 && t.Type == TypeHash {
			return append([]byte(nil), b...)
		}
		return nil
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
		// CT_MOD_IP_V6 is a HASH (ipv6-spec.md); a 16-byte BLOB or BSOB is not it.
		b, ok := t.Value.([]byte)
		if !ok || len(b) != 16 || t.Type != TypeHash {
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
// client's IPv6 reachability rather than simply trusting the address. This holds
// for a session that arrived over IPv6 too: an outbound connection proves only
// that the client can reach us. A stateful IPv6 firewall — the default on most
// home routers — still drops the unsolicited SYN a peer sends to the eD2K port,
// and the existing session opens no hole for it, since the dial-back targets the
// listen port from a fresh source port and so matches no tracked connection. Only
// turning probing off skips the dial. Shared with ipv6Reflection so the
// IPv6StatusProbed bit cannot drift away from what the login path actually did.
func (c *tcpClient) v6ProbeRequired(v6Len int) bool {
	return c.server.publishV6Sources() && v6Len == 16 && c.server.tcp().ProbeIPv6
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
	// publication is on — that is the code path that computes it. The isLogged check is
	// now belt and braces: the route it was written for, an OP_GETSERVERLIST arriving
	// before OP_LOGINREQUEST, is refused by the login gate in handleED2K, so the only
	// remaining caller is handShake, which sets c.logged before it sends the ident. Kept
	// because sendServerIdent must never emit a verdict the login path has not computed.
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

// sessionByHash returns the logged-in connection indexed under a user hash, or nil.
func (s *ServerRuntime) sessionByHash(hash []byte) *tcpClient {
	if len(hash) != 16 {
		return nil
	}
	var key [16]byte
	copy(key[:], hash)
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	return s.sessionsByHash[key]
}

// replaceSameIPSession closes and releases the live session for hash when it was opened
// from this connection's IP, so the caller's login can take its place. A session from any
// other address is left alone. Two connections without a known address never match.
//
// The release runs here, synchronously, rather than being left to the old read loop:
// MySQL keeps one clients.id per hash and MongoDB disconnects by hash, so an old
// Storage.Disconnect landing after the new Storage.Connect would mark the new session
// offline. releaseOnce then turns the old loop's own deferred release into a no-op.
func (c *tcpClient) replaceSameIPSession(hash []byte) {
	old := c.server.sessionByHash(hash)
	if old == nil || old == c || c.peerIP == nil || !old.peerIP.Equal(c.peerIP) {
		return
	}
	oldInfo := old.snapshotInfo()
	logging.Infof("login replaces stale session remote=%s hash=%x oldID=%d oldStoreID=%d",
		c.remoteHost, hash, oldInfo.ID, oldInfo.StoreID)
	old.closeWithReason("replaced-by-relogin")
	old.releaseSession()
}

// staleSessionProbeWait is how long a duplicate login waits for the session it
// collides with to fail the probe. A crashed client's host answers the probe with a
// TCP reset within one round trip, so this only has to cover a slow path.
const staleSessionProbeWait = 2 * time.Second

// staleSessionProbeTick is how often the wait re-checks whether the session is gone.
const staleSessionProbeTick = 20 * time.Millisecond

// probeStaleSession pokes the live local session for hash with an OP_SERVERSTATUS
// and waits up to staleProbeWait for it to be released. The packet is one a live
// client accepts at any time and acts on silently. A session whose client process
// is gone gets a TCP reset from the client's host instead, its read loop fails, and
// its release frees the hash for this login. A session whose path is dead entirely
// sends no reset and stays until TCP keepalive or the idle timeout reaps it.
//
// The caller re-checks storage afterwards. A hash with no local session behind it —
// a stale row in a shared database — is not probed and stays refused.
func (c *tcpClient) probeStaleSession(hash []byte) {
	old := c.server.sessionByHash(hash)
	if old == nil || old == c {
		return
	}
	wait := c.server.staleProbeWait
	if wait <= 0 {
		wait = staleSessionProbeWait
	}
	logging.Debugf("probing session held by duplicate login remote=%s hash=%x oldRemote=%s",
		c.remoteHost, hash, old.remoteHost)
	// A failed write closes the old socket itself (see writeRaw), so its read loop
	// releases it without waiting for the reset.
	old.sendServerStatus()
	deadline := time.Now().Add(wait)
	for c.server.sessionByHash(hash) == old {
		if !time.Now().Before(deadline) {
			return
		}
		time.Sleep(staleSessionProbeTick)
	}
	// releaseSession drops the hash index entry before the storage row, both under
	// storeMu; taking it once means the row is gone too when the caller re-checks.
	old.storeMu.Lock()
	old.storeMu.Unlock() //nolint:staticcheck // empty critical section waits out the release
	logging.Infof("duplicate login found the held session dead remote=%s hash=%x oldRemote=%s",
		c.remoteHost, hash, old.remoteHost)
}

// dualStackHandoverFrom returns the live IPv4 session for hash that this IPv6 login
// may take over: it advertised this connection's source address as its CT_MOD_IP_V6
// and the same listen port. Nil for anything else, which is then refused as usual.
func (c *tcpClient) dualStackHandoverFrom(hash []byte, port uint16) *tcpClient {
	if !c.connectedV6 || c.peerIP == nil {
		return nil
	}
	old := c.server.sessionByHash(hash)
	if old == nil || old == c || old.connectedV6 {
		return nil
	}
	info := old.snapshotInfo()
	if len(info.IPv6) != 16 || info.Port != port || !net.IP(info.IPv6).Equal(c.peerIP) {
		return nil
	}
	return old
}

// completeDualStackHandover releases the IPv4 session an accepted IPv6 login takes
// over, right before the new storage row is written: the old row must go first, as
// in replaceSameIPSession. Re-derived here rather than remembered from the login
// check, so a session costs no extra field. False when the hash is online from a
// session this login may not take over; it is then refused like any duplicate.
func (c *tcpClient) completeDualStackHandover() bool {
	info := c.snapshotInfo()
	if len(info.Hash) != 16 || !c.server.Storage.IsConnected(storage.ClientInfo{Hash: info.Hash}) {
		return true
	}
	if old := c.dualStackHandoverFrom(info.Hash, info.Port); old != nil {
		oldInfo := old.snapshotInfo()
		logging.Infof("ipv6 login replaces ipv4 session remote=%s hash=%x oldRemote=%s oldID=%d",
			c.remoteHost, info.Hash, old.remoteHost, oldInfo.ID)
		old.closeWithReason("replaced-by-ipv6-session")
		old.releaseSession()
	}
	if c.server.Storage.IsConnected(storage.ClientInfo{Hash: info.Hash}) {
		logging.Warnf("login rejected remote=%s hash=%x: already connected", c.remoteHost, info.Hash)
		c.sendServerMessage("Already connected from another session.")
		c.closeWithReason("duplicate-login")
		return false
	}
	return true
}

// releaseSession frees everything a session holds — its LowID, its hash index entry and
// its storage row — closes the socket and logs the close. Runs once however many callers
// reach it; see releaseOnce.
func (c *tcpClient) releaseSession() {
	c.releaseOnce.Do(func() {
		if c.handedOff.Load() {
			// The successor serves the session on its own copy of the socket; closing
			// this one sends the client nothing.
			_ = c.conn.Close()
			info := c.snapshotInfo()
			logging.Debugf("tcp session handed off remote=%s id=%d storeID=%d", c.remoteHost, info.ID, info.StoreID)
			return
		}
		c.infoMu.RLock()
		hadLowID, wasLogged := c.hasLowID, c.logged
		c.infoMu.RUnlock()
		info := c.snapshotInfo()
		if hadLowID {
			c.server.LowIDs.Remove(info.ID)
		}
		c.storeMu.Lock()
		c.released = true
		if wasLogged {
			c.server.unregisterSession(info.Hash, c)
			c.server.Storage.Disconnect(info)
		}
		c.storeMu.Unlock()
		_ = c.conn.Close()
		logging.Infof("tcp session closed remote=%s id=%d lowID=%t storeID=%d reason=%s",
			c.remoteHost, info.ID, info.LowID, info.StoreID, c.getCloseReason())
	})
}

// v6PublishableSources strips the IPv6 addresses from sources unless the server
// publishes them (ipv6.publishSources), leaving the classic IPv4 list in the IPv6
// reply form.
func (s *ServerRuntime) v6PublishableSources(sources []storage.Source) []storage.Source {
	if s.publishV6Sources() {
		return sources
	}
	out := make([]storage.Source, len(sources))
	for i, src := range sources {
		src.IPv6, src.IPv6Reachable = nil, false
		out[i] = src
	}
	return out
}

// addFiles publishes an offer batch unless the session has been released.
func (c *tcpClient) addFiles(batch []storage.File, info storage.ClientInfo) {
	c.storeMu.Lock()
	defer c.storeMu.Unlock()
	if c.released {
		return
	}
	c.server.Storage.AddFiles(batch, info)
}

// declaredFileCount peeks at the record count an OP_OFFERFILES payload starts with,
// without moving the read pointer.
func declaredFileCount(data *Buffer) (uint32, bool) {
	rest := data.Bytes()[data.Pos():]
	if len(rest) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(rest), true
}

// withinSoftLimit returns the files of one offer the soft limit lets through, in
// order, and how many it held back. A file the session already sources always
// passes; a new one passes while the session sources fewer than softLimit files.
//
// The common case is one cheap call: while everything offered fits under the limit
// even if all of it is new, nothing has to be told apart. Only a packet that could
// cross the limit asks storage which of its files are already there.
func (c *tcpClient) withinSoftLimit(batch []storage.File, info storage.ClientInfo, softLimit int) ([]storage.File, int) {
	if softLimit <= 0 || len(batch) == 0 {
		return batch, 0
	}
	have := c.server.Storage.OfferedCount(info)
	if have+len(batch) <= softLimit {
		return batch, 0
	}
	known := c.server.Storage.HasOffered(info, batch)
	type fileKey struct {
		hash [16]byte
		size uint64
	}
	// A file listed twice in one packet is one file: its first record takes the
	// budget and the rest ride on it.
	admitted := make(map[fileKey]struct{})
	room := softLimit - have
	kept, skipped := batch[:0], 0
	for i, file := range batch {
		key := fileKey{size: file.Size}
		copy(key.hash[:], file.Hash)
		_, again := admitted[key]
		switch {
		case again || (i < len(known) && known[i]):
		case room > 0:
			room--
			admitted[key] = struct{}{}
		default:
			skipped++
			continue
		}
		kept = append(kept, file)
	}
	return kept, skipped
}

// capUDPSearchResults trims a UDP search answer to maxUDPSearchResults files.
func capUDPSearchResults(files []storage.File) []storage.File {
	if len(files) > maxUDPSearchResults {
		return files[:maxUDPSearchResults]
	}
	return files
}

// udpSecret is the secret client UDP keys are derived from: UDPSecret, or the legacy
// UDPServerKey when none was loaded.
func (s *ServerRuntime) udpSecret() []byte {
	if len(s.udp().UDPSecret) > 0 {
		return s.udp().UDPSecret
	}
	return LegacyUDPSecret(s.udp().UDPServerKey)
}

// pendingSearch is the tail of a search kept for OP_QUERY_MORE_RESULT, and when it lapses.
type pendingSearch struct {
	rows    []storage.File
	expires time.Time
}

// setDefaults fills the zero values that mean "use the default".
func (t *TCPRuntimeConfig) setDefaults() {
	if t.ServerStatusInterval <= 0 {
		t.ServerStatusInterval = defaultServerStatusInterval
	}
	if t.MoreResultsMax == 0 {
		t.MoreResultsMax = defaultMoreResultsMax
	}
	if t.MoreResultsTTL <= 0 {
		t.MoreResultsTTL = defaultMoreResultsTTL
	}
	if t.RelatedMinClients <= 0 {
		t.RelatedMinClients = defaultRelatedMinClients
	}
}

// keepPendingResults keeps rows for OP_QUERY_MORE_RESULT until expires, capped at
// MoreResultsMax and copied so they do not pin the array of the whole result.
func (c *tcpClient) keepPendingResults(rows []storage.File, expires time.Time) {
	rows = rows[:min(len(rows), max(c.server.tcp().MoreResultsMax, 0))]
	if len(rows) == 0 {
		c.pendingResults.Store(nil)
		return
	}
	c.pendingResults.Store(&pendingSearch{rows: slices.Clone(rows), expires: expires})
}

// pendingRows returns the rows kept for OP_QUERY_MORE_RESULT, nil with none.
func (c *tcpClient) pendingRows() []storage.File {
	if p := c.pendingResults.Load(); p != nil {
		return p.rows
	}
	return nil
}

// dropExpiredResults drops the kept rows once their deadline has passed. Called by the
// session's status ticker, so an idle session frees them too, and by the More handler.
func (c *tcpClient) dropExpiredResults(now time.Time) {
	if p := c.pendingResults.Load(); p != nil && !now.Before(p.expires) {
		c.pendingResults.CompareAndSwap(p, nil)
	}
}
