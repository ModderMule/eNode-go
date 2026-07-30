package storage

import (
	"net"
	"strconv"
	"strings"
)

// Peer-server list identity and deduplication, shared by all three engines.
//
// Every engine keeps its advertisable peer list as a plain []Server, and every
// one of them used to append without checking — so a repeated entry under
// `servers:` was published twice in OP_SERVERLIST. eMule's own list has always
// deduplicated on add (CServerList::AddServer, srchybrid/ServerList.cpp:202-240),
// and the rules below mirror it:
//
//   - Validity is checked before identity. A port of 0 is rejected outright, as
//     IsGoodServerIP does (srchybrid/ServerList.cpp:322-325).
//   - Identity is (address, TCP port). The original compares the address string —
//     the dynIP hostname when there is one, else the dotted quad
//     (srchybrid/Server.cpp:249-252) — and falls back to a packed-IP + port scan
//     for entries with a numeric address.
//   - On a duplicate the existing entry wins and the incoming one is discarded.
//     eMule additionally resets the existing entry's failure count; storage.Server
//     carries no such state (gossip tracks failures in its own peer table), so
//     "existing wins" reduces to "ignore the duplicate".
//   - Two entries on the same address with different ports stay distinct, by design.
//
// The single fallback we do not need is the dynIP branch: seedServers rejects
// anything that is not an IPv4 or public IPv6 literal before it ever reaches an
// engine (cmd/enode/main.go, ed2k.ClassifyServerIP), so the address always is the
// IP and the two lookups the original performs collapse into one.

// ServerAddrKey is the deduplication identity of a peer entry: canonical address
// plus TCP port. Named for the address rather than "ServerKey", which throughout
// this codebase means the eserver UDP obfuscation key and is a different thing
// entirely.
//
// A parsable literal is canonicalized through net.IP, so the same address written
// three ways — "2001:DB8::1", "2001:db8:0:0:0:0:0:1", "2001:db8::1" — yields one
// key. Anything else is lowercased and trimmed, matching the case-insensitive
// comparison the current C++ client uses (ServerList::findByAddress); the original
// MFC GetServerByAddress used a case-sensitive _tcscmp, which is a bug rather than
// a behaviour worth reproducing.
func ServerAddrKey(s Server) string {
	addr := strings.TrimSpace(s.IP)
	if ip := net.ParseIP(addr); ip != nil {
		addr = ip.String()
	} else {
		addr = strings.ToLower(addr)
	}
	// JoinHostPort rather than addr+":"+port so an IPv6 literal is bracketed and the
	// port is unambiguously the part after the final colon.
	return net.JoinHostPort(addr, strconv.Itoa(int(s.Port)))
}

// appendUniqueServer appends s to list unless an entry with the same
// ServerAddrKey is already present, and reports whether it was added.
//
// The scan is linear, as the reference implementation's is. That is fine here: the
// list is seeded once from config before any listener binds and is bounded by the
// operator's own file, not by gossip — the live peer table gossip maintains is a
// map in GossipHandler and never passes through here.
func appendUniqueServer(list []Server, s Server) ([]Server, bool) {
	if s.Port == 0 {
		return list, false
	}
	key := ServerAddrKey(s)
	for _, existing := range list {
		if ServerAddrKey(existing) == key {
			return list, false
		}
	}
	return append(list, s), true
}
