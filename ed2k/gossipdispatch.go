package ed2k

import (
	"net"

	"enode/logging"
	"enode/storage"
)

// Inbound gossip: the handlers the UDP dispatcher routes the 0xA0/0xA1/0xA4/0xA7/0xA8
// opcodes to, plus the 0x97 and 0xA3 replies that advance a peer's state.
//
// Every one of these is reachable by anyone who can send a datagram, so the obfuscated
// flag threaded in from the dispatcher is load-bearing rather than informational: it is
// what separates "a peer holding a ServerKey we issued" from "anyone at all".

// SetGossipHandler attaches the peer table. nil leaves gossip disabled, and every
// dispatch case is gated on it, so a server with gossip off behaves exactly as before.
func (s *ServerRuntime) SetGossipHandler(h *GossipHandler) {
	s.Gossip = h
}

// decryptPeerReply makes the two extra decryption attempts a reply from a *peer server*
// needs, returning the plaintext frame or the input unchanged.
//
// The ordinary receive path (UDPCrypt.Decrypt) reads a frame sent to us in the client role:
// keyed on the ServerKey we published to that address, direction 0x6B. A peer *answering*
// our gossip is in neither of those positions, and both of its shapes were determined by
// brute-forcing every plausible (key, direction) pair against eserver 17.14:
//
//  1. reply to a phase-3/4 frame — key = the peer's OWN published ServerKey, direction
//     0xA5. Measured: for a 0xA2 probe, only (peerServerKey, 0xA5) yielded a valid magic;
//     our derived key failed in both directions. So the key belongs to the relationship as
//     the peer defines it, and the direction byte alone says who is speaking. That is the
//     same opacity property deriveUDPKey documents for the client case, seen from the other
//     side.
//  2. reply to the phase-2 bootstrap ping — key = the challenge we sent, direction 0xA5.
//     No ServerKey exists yet at that point; obtaining one is the purpose of the exchange
//     (srchybrid/UDPSocket.cpp:159-171).
//
// Without these, both replies fell through to the crypt-ping heuristic or the
// unsupported-protocol log and were silently dropped — so a peer never got past phase 2
// and gossip could not complete against a real eserver.
func (s *ServerRuntime) decryptPeerReply(data []byte, from net.IP) []byte {
	if peer, ok := s.Gossip.PeerByIP(from); ok && peer.ServerKey != 0 {
		if reply := NewUDPCrypt(true, peer.ServerKey).DecryptFromServer(data); len(reply) > 0 && reply[0] == PrED2K {
			return reply
		}
	}
	if challenge, ok := s.Gossip.PingChallengeFor(from); ok {
		if reply := NewUDPCrypt(true, challenge).DecryptFromServer(data); len(reply) > 0 && reply[0] == PrED2K {
			return reply
		}
	}
	return data
}

// udpServerListReq handles OP_SERVER_LIST_REQ (0xA0): a peer registering itself. It is
// also an implicit list request — Lugdunum falls through to the 0xA4 path — so we answer
// with our list, but only over the obfuscated channel.
func (s *ServerRuntime) udpServerListReq(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, obfuscated bool, module string) {
	announcedIP, port, _, _, err := ParseServerListReq(b)
	if err != nil {
		logging.Debugf("[module=%s] malformed OP_SERVER_LIST_REQ from %s: %v", module, remote, err)
		return
	}
	// The observed source address wins over the announced one: otherwise a sender could
	// register a third party, which is the cheapest possible way to poison a peer list.
	// Only the port is taken from the payload, since a listening port cannot be observed.
	if !announcedIP.Equal(NormalizeIP(remote.IP)) {
		logging.Debugf("[module=%s] %s announced %s in OP_SERVER_LIST_REQ; using the observed address",
			module, remote, announcedIP)
	}
	// The payload's challenge is parsed but discarded: it is not the value a peer expects
	// echoed in a 0x97 (see NoteRegistration).
	s.Gossip.NoteRegistration(remote.IP, port, obfuscated)

	if obfuscated {
		s.sendPeerList(remote, conn, false, module)
	}
}

// udpServerListReq2 handles OP_SERVER_LIST_REQ2 (0xA4) and its IPv6 twin 0xA7: an
// explicit "send me your list".
//
// Answered only over the obfuscated channel. A plaintext request is dropped for the same
// reason eserver drops one: serving our peer table to an unauthenticated sender hands a
// scanner the whole mesh for the cost of one datagram.
func (s *ServerRuntime) udpServerListReq2(remote *net.UDPAddr, conn *net.UDPConn, wantIPv6, obfuscated bool, module string) {
	if !obfuscated {
		logging.Debugf("[module=%s] ignoring non-obfuscated peer-list request from %s", module, remote)
		return
	}
	s.sendPeerList(remote, conn, wantIPv6, module)
}

// udpServerListRes handles OP_SERVER_LIST_RES (0xA1) and OP_SERVER_LIST_RES_IPV6 (0xA8):
// a peer's list, to be merged under the full policy.
func (s *ServerRuntime) udpServerListRes(b *Buffer, remote *net.UDPAddr, isIPv6, obfuscated bool, module string) {
	var entries []PeerAddr
	var err error
	if isIPv6 {
		entries, err = ParseServerListResIPv6(b)
	} else {
		entries, err = ParseServerListRes(b)
	}
	if err != nil {
		// 0xA1 is overloaded — mldonkey clients emit it with an unrelated payload — so a
		// parse failure here is expected traffic rather than a peer misbehaving.
		logging.Debugf("[module=%s] unparseable peer list from %s: %v", module, remote, err)
		return
	}
	// Logged distinctly for the v6 extension because 0xA7/0xA8 are ours, not Lugdunum's:
	// no reference implementation exercises them, so the interop suite has to be able to
	// see that the exchange actually happened rather than infer it from a peer count.
	if isIPv6 {
		logging.Debugf("[module=%s] gossip: received an IPv6 peer list (0xA8) from %s with %d entr(ies)",
			module, remote, len(entries))
	}
	s.Gossip.MergePeerList(remote.IP, entries, obfuscated)
}

// udpGlobServStatRes handles an inbound 0x97 — a peer answering our probe.
//
// Only meaningful on an obfuscated socket, because that is the only channel Lugdunum
// puts a ServerKey on: measured against the real binary, a plain 0x96 comes back as a
// 32-byte payload with no key. A plaintext 0x97 is still recorded as a successful
// contact, since it does prove the peer is alive.
func (s *ServerRuntime) udpGlobServStatRes(b *Buffer, remote *net.UDPAddr, module string) {
	fields, err := ParseGlobServStatRes(b)
	if err != nil {
		logging.Debugf("[module=%s] malformed OP_GLOBSERVSTATRES from %s: %v", module, remote, err)
		return
	}
	peer, known := s.Gossip.PeerByIP(remote.IP)
	if !known {
		logging.Debugf("[module=%s] received a pong from unknown server %s chl=%x %d users, %d files",
			module, remote, fields.Challenge, fields.Users, fields.Files)
		return
	}
	// Either outstanding challenge is a valid match. A round fires the plain 0x96 and the
	// obfuscated ping back to back and their replies arrive independently on different
	// sockets, so requiring the phase-2 value alone would reject every plain 0x97 — and
	// requiring the phase-1 value alone would reject every keyed reply.
	matches := fields.Challenge == peer.OurChallenge ||
		(peer.PlainChallenge != 0 && fields.Challenge == peer.PlainChallenge)
	s.Gossip.NoteStatRes(remote.IP, fields, matches)
}

// udpServerDescRes handles an inbound 0xA3 — a peer answering our name/description
// probe. A valid reply is the admission test that promotes the peer; a malformed one
// leaves it where it is, matching eserver's "(bad name)"/"(bad desc)" rejections.
func (s *ServerRuntime) udpServerDescRes(b *Buffer, remote *net.UDPAddr, module string) {
	name, desc, err := ParseServerDescRes(b)
	if err != nil {
		logging.Debugf("[module=%s] malformed OP_SERVER_DESC_RES from %s: %v", module, remote, err)
		return
	}
	s.Gossip.NoteDescription(remote.IP, name, desc)
}

// sendPeerList answers a list request with our verified peers.
//
// Verified only. An unverified entry is one we have not completed a handshake with, so
// propagating it would spread addresses we cannot vouch for — precisely the behaviour
// that makes a stale peer list circulate around a mesh forever.
func (s *ServerRuntime) sendPeerList(remote *net.UDPAddr, conn *net.UDPConn, wantIPv6 bool, module string) {
	peers := s.Gossip.Verified()
	var packet *Buffer
	var err error
	if wantIPv6 {
		packet, err = BuildServerListResIPv6Packet(peers)
	} else {
		packet, err = BuildServerListResPacket(peers)
	}
	if err != nil {
		logging.Debugf("[module=%s] cannot build a peer list for %s: %v", module, remote, err)
		return
	}
	if wantIPv6 {
		logging.Debugf("[module=%s] gossip: answering an IPv6 peer list request (0xA7) from %s with %d peer(s)",
			module, remote, len(peers))
	}
	// Sent through the same crypt the peer used to reach us: it holds the ServerKey we
	// published for its address, so this is the key it will decrypt with. Direction 0xA5
	// here, since on this frame we are the server answering.
	crypt := NewUDPCrypt(true, deriveUDPKey(s.UDP.UDPServerKey, remote.IP))
	_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
}

// gossipSeedsFromServers converts configured peer entries into gossip seeds, skipping
// anything that is not a usable address. Shared by main.go and the server.met loader so
// both apply the same filter.
func GossipSeedsFromServers(servers []storage.Server) []PeerAddr {
	out := make([]PeerAddr, 0, len(servers))
	for _, sv := range servers {
		ip := net.ParseIP(sv.IP)
		if ip == nil || sv.Port == 0 {
			continue
		}
		out = append(out, PeerAddr{IP: NormalizeIP(ip), Port: sv.Port})
	}
	return out
}

// ParseServerDescRes decodes OP_SERVER_DESC_RES (0xA3) in either form.
//
// Two shapes exist and a peer chooses without announcing which:
//
//	old:      <name: uint16-prefixed string><desc: uint16-prefixed string>
//	extended: <challenge: uint32><tag block>   with ST_SERVERNAME / ST_DESCRIPTION
//
// The extended form is tried first and accepted only if it yields a name, because its
// failure modes are unambiguous: an old-form payload read as extended puts the two
// string-length bytes into the challenge and then reads a tag count from name bytes,
// which is essentially never a small plausible count. Trying the old form first would be
// worse — an extended payload's challenge can look like a valid short string length.
func ParseServerDescRes(b *Buffer) (name, desc string, err error) {
	start := b.Pos()

	if b.Remaining() >= 8 {
		if _, e := b.GetUInt32LE(); e == nil {
			if tags, e := b.GetTags(); e == nil {
				var gotName bool
				for _, t := range tags {
					s, ok := t.Value.(string)
					if !ok {
						continue
					}
					switch t.Name {
					case "name":
						name, gotName = s, true
					case "description":
						desc = s
					}
				}
				if gotName {
					return name, desc, nil
				}
			}
		}
	}

	// Fall back to the old form.
	b.Pos(start)
	name, err = b.GetString()
	if err != nil {
		return "", "", err
	}
	// A missing description is tolerated: plenty of servers set none, and the name alone
	// is what the admission test actually requires.
	desc, _ = b.GetString()
	return name, desc, nil
}
