package ed2k

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

// What the admin surface reads from, and does to, a running server. Everything here
// hands out copies, so a caller can hold a result without holding a lock.

// maxNickBytes caps the login nick kept per session; a client may send far more.
const maxNickBytes = 64

// maxModBytes caps the CT_MOD_VERSION kept per session. Real mod strings
// ("MorphXT v12.7") are far shorter.
const maxModBytes = 32

// ClientView is one logged-in session as the admin client list shows it.
type ClientView struct {
	Hash [16]byte
	// StoreID is the session's storage identity, for a per-client storage lookup.
	StoreID uint64
	// IP is the address the session connected from.
	IP   net.IP
	Port uint16
	ID   uint32
	// LowID reports whether the client was assigned a LowID.
	LowID bool
	// IPv6 is the address the client published, nil when it has none.
	IPv6          net.IP
	IPv6Capable   bool
	IPv6Reachable bool
	Nick          string
	Software      string
	ConnectedAt   time.Time
	// Ed3kID is the ed3k node ID of the CT_ED3K login tag, "" when none was sent.
	Ed3kID string
}

// PeerView is one gossip peer as the admin surface shows it. It carries nothing a
// peer's address was authenticated with: the server key and the challenges stay in
// the peer table.
type PeerView struct {
	IP   string
	Port uint16
	Name string
	Desc string
	// State is seen, keyed, described or verified.
	State        string
	Parked       bool
	Users        uint32
	Files        uint32
	Failures     int
	Referer      string
	ServerSearch bool
	LastSeen     time.Time
	LastVerified time.Time
}

// BlockStats counts what the runtime itself refused since it started. The access and
// content filters keep their own counters.
type BlockStats struct {
	// RateLimited is UDP searches and source requests over the per-address budget.
	RateLimited uint64
	// ConnLimit is TCP connections over tcp.maxConnectionsPerIP.
	ConnLimit uint64
	// BannedLogins is logins refused because the user hash or address is banned.
	BannedLogins uint64
	// HardLimit is OP_OFFERFILES packets refused for declaring files.hardLimit
	// records or more.
	HardLimit uint64
	// Bots is how many times the bot detector flagged an address.
	Bots uint64
}

// blockCounters backs BlockStats.
type blockCounters struct {
	rateLimited  atomic.Uint64
	connLimit    atomic.Uint64
	bannedLogins atomic.Uint64
	hardLimit    atomic.Uint64
	bots         atomic.Uint64
}

// ClientSnapshot returns every logged-in session.
func (s *ServerRuntime) ClientSnapshot() []ClientView {
	s.sessionsMu.RLock()
	clients := make([]*tcpClient, 0, len(s.sessionsByHash))
	for _, c := range s.sessionsByHash {
		clients = append(clients, c)
	}
	s.sessionsMu.RUnlock()

	out := make([]ClientView, 0, len(clients))
	for _, c := range clients {
		out = append(out, c.view())
	}
	return out
}

// DisconnectClient closes the session logged in under a user hash and reports whether
// there was one. The client may log in again at once; refusing that is what a ban is for.
func (s *ServerRuntime) DisconnectClient(hash []byte) bool {
	c := s.sessionByHash(hash)
	if c == nil {
		return false
	}
	c.closeWithReason("admin-disconnect")
	return true
}

// ClientSoftware names the software of the session logged in under a user hash, or ""
// when there is none.
func (s *ServerRuntime) ClientSoftware(hash []byte) string {
	c := s.sessionByHash(hash)
	if c == nil {
		return ""
	}
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	return softwareWithMod(c.software, c.mod)
}

// GossipEnabled reports whether a gossip peer table is attached.
func (s *ServerRuntime) GossipEnabled() bool {
	return s.gossip() != nil
}

// GossipPeers returns the gossip peer table; empty while gossip is disabled. Read
// through the runtime because a config reload can replace the handler.
func (s *ServerRuntime) GossipPeers() []PeerView {
	g := s.gossip()
	if g == nil {
		return nil
	}
	maxFailures := g.Config().MaxFailures
	peers := g.Snapshot()
	out := make([]PeerView, 0, len(peers))
	for i := range peers {
		p := &peers[i]
		view := PeerView{
			IP:           p.Addr.IP.String(),
			Port:         p.Addr.Port,
			Name:         p.Name,
			Desc:         p.Desc,
			State:        p.State.String(),
			Parked:       p.Parked(maxFailures),
			Users:        p.Users,
			Files:        p.Files,
			Failures:     p.Failures,
			ServerSearch: p.ServerSearch.URL != "",
			LastSeen:     p.LastSeen,
			LastVerified: p.LastVerified,
		}
		if p.RefererIP != nil {
			view.Referer = p.RefererIP.String()
		}
		out = append(out, view)
	}
	return out
}

// BlockStats returns the runtime's refusal counters.
func (s *ServerRuntime) BlockStats() BlockStats {
	return BlockStats{
		RateLimited:  s.blocks.rateLimited.Load(),
		ConnLimit:    s.blocks.connLimit.Load(),
		BannedLogins: s.blocks.bannedLogins.Load(),
		HardLimit:    s.blocks.hardLimit.Load(),
		Bots:         s.blocks.bots.Load(),
	}
}

// Bots returns the UDP queriers the bot detector has flagged, highest rate first.
func (s *ServerRuntime) Bots() []BotDetection {
	return s.bots.snapshot()
}

// view copies what the admin client list shows of this session.
func (c *tcpClient) view() ClientView {
	info := c.snapshotInfo()
	c.infoMu.RLock()
	nick, software, v6Capable := c.nick, softwareWithMod(c.software, c.mod), c.ipv6Capable
	ed3kID := ""
	if len(c.ed3kID) == 16 {
		ed3kID = hex.EncodeToString(c.ed3kID)
	}
	c.infoMu.RUnlock()

	view := ClientView{
		StoreID:       info.StoreID,
		IP:            c.peerIP,
		Port:          info.Port,
		ID:            info.ID,
		LowID:         info.LowID,
		IPv6Capable:   v6Capable,
		IPv6Reachable: info.IPv6Reachable,
		Nick:          nick,
		Software:      software,
		ConnectedAt:   c.connectedAt,
		Ed3kID:        ed3kID,
	}
	copy(view.Hash[:], info.Hash)
	if len(info.IPv6) == net.IPv6len {
		view.IPv6 = net.IP(info.IPv6)
	}
	return view
}

// loginNick is the CT_NAME a client sent at login, cut to maxNickBytes on a rune
// boundary.
func loginNick(tags []NamedTag) string {
	for _, t := range tags {
		if t.Name != "name" {
			continue
		}
		nick, _ := t.Value.(string)
		nick = strings.ToValidUTF8(nick, "")
		for len(nick) > maxNickBytes {
			_, size := utf8.DecodeLastRuneInString(nick)
			nick = nick[:len(nick)-size]
		}
		return nick
	}
	return ""
}

// loginSoftware names the client from CT_EMULE_VERSION, which packs the compatible
// client id above the version (srchybrid/ServerConnect.cpp:199-203): id<<24 |
// major<<17 | minor<<10 | update<<7. A login without the tag is an eDonkey client.
func loginSoftware(tags []NamedTag) string {
	for _, t := range tags {
		if t.Name != "muleversion" {
			continue
		}
		v, ok := t.Value.(uint64)
		if !ok {
			break
		}
		major, minor, update := (v>>17)&0x7f, (v>>10)&0x7f, (v>>7)&0x07
		// The ids are srchybrid/ClientStateDefs.h's EClientSoftware.
		switch id := (v >> 24) & 0xff; id {
		case 0:
			return fmt.Sprintf("eMule %d.%d%c", major, minor, 'a'+rune(update))
		case 1:
			return fmt.Sprintf("cDonkey %d.%d.%d", major, minor, update)
		case 2:
			return fmt.Sprintf("xMule %d.%d.%d", major, minor, update)
		case 3:
			return fmt.Sprintf("aMule %d.%d.%d", major, minor, update)
		case 4, 40:
			return fmt.Sprintf("Shareaza %d.%d.%d", major, minor, update)
		case 10:
			return fmt.Sprintf("MLDonkey %d.%d.%d", major, minor, update)
		case 20:
			return fmt.Sprintf("lphant %d.%d.%d", major, minor, update)
		default:
			return fmt.Sprintf("client %d (%d.%d.%d)", id, major, minor, update)
		}
	}
	return "eDonkey"
}

// helloModVersion is the CT_MOD_VERSION of a hello answer, or "" when it has none.
// eMuleQt reads a string tag as is and an integer one as its number
// (src/core/client/UpDownClient.cpp:991-995). The peer controls the bytes, so the
// value is cleaned for display: valid UTF-8, no control characters or the brackets
// it is shown in, trimmed, and cut to maxModBytes on a rune boundary.
func helloModVersion(tags map[string]any) string {
	var mod string
	switch v := tags["modversion"].(type) {
	case string:
		mod = v
	case uint64:
		mod = fmt.Sprint(v)
	default:
		return ""
	}
	mod = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '[' || r == ']' {
			return -1
		}
		return r
	}, strings.ToValidUTF8(mod, ""))
	mod = strings.TrimSpace(mod)
	for len(mod) > maxModBytes {
		_, size := utf8.DecodeLastRuneInString(mod)
		mod = mod[:len(mod)-size]
	}
	return strings.TrimSpace(mod)
}

// softwareWithMod shows a client's software with its mod the way eMuleQt does,
// "eMule 0.50a [MorphXT v12.7]" (UpDownClient::dbgGetFullClientSoftVer), and the
// software alone when there is no mod.
func softwareWithMod(software, mod string) string {
	if mod == "" {
		return software
	}
	return software + " [" + mod + "]"
}
