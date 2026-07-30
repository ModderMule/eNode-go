package ed2k

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
)

// Wire codec for server-to-server gossip. See docs/server-gossip.md for the full
// exchange; this file is only the encoding.
//
// A note on IP byte order, because it reads ambiguously in every description of this
// protocol. The reference documents 0xA0/0xA1 addresses as "network order" while our
// OP_SERVERLIST builder writes them as a little-endian uint32 — and those are the same
// four bytes. For 1.2.3.4, network order is 01 02 03 04, and IPv4ToUint32LE gives
// 0x04030201, which serialises little-endian to 01 02 03 04. The two descriptions
// never disagree, so nothing here needs to choose between them; the raw 4 address
// bytes are written directly.

// PeerAddr is one gossiped server endpoint. Separate from storage.Server (which
// carries the IP as a string for the config and the client-facing OP_SERVERLIST)
// because every gossip decision — IsGoodIP, self-detection, family selection — is a
// net.IP operation, and round-tripping through a string to make them would lose the
// v4/v6 distinction the 0xA1 vs 0xA8 split depends on.
type PeerAddr struct {
	IP   net.IP
	Port uint16
}

// String renders the endpoint for logs and as the peer-table key.
func (p PeerAddr) String() string {
	return net.JoinHostPort(p.IP.String(), fmt.Sprint(p.Port))
}

// Errors returned by the parsers. All of them mean "drop this datagram": gossip is
// unauthenticated, so a malformed frame is far more likely to be a probe or an
// mldonkey client misusing the opcode than a peer worth repairing.
var (
	ErrGossipShort     = errors.New("gossip frame too short")
	ErrGossipTruncated = errors.New("gossip peer list truncated")
)

// maxGossipPeers is the most entries a single 0xA1/0xA8 frame can describe. The count
// is one byte, so this is a wire-format ceiling rather than a policy choice — the same
// constraint storage.MaxWireSources encodes for source lists.
const maxGossipPeers = 255

// obfPingMaxPad bounds the random padding on the bootstrap ping. eMule sends 0..14
// bytes after the 4-byte challenge (srchybrid/ServerList.cpp:275-294), keeping the
// whole datagram under the 19 bytes eserver accepts as a raw ping.
const obfPingMaxPad = 14

// BuildServerListReqPacket builds OP_SERVER_LIST_REQ (0xA0): "a server exists at
// ip:port, and send me your list".
//
// eMule's header documents the payload as <IP 4><PORT 2> (Opcodes.h:201), six bytes.
// Lugdunum's server-to-server form appends a 4-byte challenge, which is what lets the
// sender match a later 0x97 to this request. Both are emitted here — the challenge is
// additive trailing data that a peer expecting only six bytes ignores — and
// ParseServerListReq accepts either length.
func BuildServerListReqPacket(ip net.IP, tcpPort uint16, challenge uint32) (*Buffer, error) {
	v4 := ip.To4()
	if v4 == nil {
		// 0xA0 has no IPv6 form: the field is four bytes wide. A v6-only server
		// registers by being reachable, not by announcing an address it cannot encode.
		return nil, fmt.Errorf("OP_SERVER_LIST_REQ requires an IPv4 address, got %v", ip)
	}
	return MakeUDPPacket(PrED2K, []PacketItem{
		{Type: TypeUint8, Value: OpServerListReq},
		{Type: TypeUint32, Value: uint32FromV4(v4)},
		{Type: TypeUint16, Value: tcpPort},
		{Type: TypeUint32, Value: challenge},
	})
}

// ParseServerListReq decodes an OP_SERVER_LIST_REQ payload (positioned after the
// opcode). hasChallenge reports whether the sender used the 10-byte Lugdunum form.
//
// The announced port is returned as-is and deliberately not validated here: whether
// to trust it is the merge policy's decision, and it needs the announced value to log
// what it rejected.
func ParseServerListReq(b *Buffer) (ip net.IP, port uint16, challenge uint32, hasChallenge bool, err error) {
	raw := b.Get(4)
	if len(raw) != 4 {
		return nil, 0, 0, false, ErrGossipShort
	}
	ip = net.IP(append([]byte(nil), raw...))
	port, err = b.GetUInt16LE()
	if err != nil {
		return nil, 0, 0, false, ErrGossipShort
	}
	if b.Remaining() >= 4 {
		challenge, err = b.GetUInt32LE()
		if err != nil {
			return nil, 0, 0, false, ErrGossipShort
		}
		hasChallenge = true
	}
	return ip, port, challenge, hasChallenge, nil
}

// BuildServerListReq2Packet builds OP_SERVER_LIST_REQ2 (0xA4): the explicit "send me
// your list", with an empty payload.
func BuildServerListReq2Packet() (*Buffer, error) {
	return MakeUDPPacket(PrED2K, []PacketItem{{Type: TypeUint8, Value: OpServerListReq2}})
}

// BuildServerListReqIPv6Packet builds the eNode-go OP_SERVER_LIST_REQ_IPV6 (0xA7),
// the v6 analogue of 0xA4. Empty payload; only ever sent to a peer that advertised
// FlagIPv6, so a stock eserver never receives it.
func BuildServerListReqIPv6Packet() (*Buffer, error) {
	return MakeUDPPacket(PrED2K, []PacketItem{{Type: TypeUint8, Value: OpServerListReqIPv6}})
}

// BuildServerListResPacket builds OP_SERVER_LIST_RES (0xA1): <count 1> then count ×
// (<ip 4><port 2 LE>). IPv4 only, byte-identical to what a real eserver emits — v6
// peers travel in 0xA8 instead.
//
// Non-IPv4 entries are skipped rather than rejected, so a caller may pass a mixed
// list without pre-filtering. The slice is truncated to the count, never the reverse:
// a count byte that disagrees with the records that follow desynchronises the peer's
// parser for the rest of the datagram.
func BuildServerListResPacket(peers []PeerAddr) (*Buffer, error) {
	v4 := make([]PeerAddr, 0, len(peers))
	for _, p := range peers {
		if p.IP.To4() == nil {
			continue
		}
		if len(v4) == maxGossipPeers {
			break
		}
		v4 = append(v4, p)
	}
	pack := make([]PacketItem, 0, 2+2*len(v4))
	pack = append(pack,
		PacketItem{Type: TypeUint8, Value: OpServerListRes},
		PacketItem{Type: TypeUint8, Value: uint8(len(v4))},
	)
	for _, p := range v4 {
		pack = append(pack,
			PacketItem{Type: TypeUint32, Value: uint32FromV4(p.IP.To4())},
			PacketItem{Type: TypeUint16, Value: p.Port},
		)
	}
	return MakeUDPPacket(PrED2K, pack)
}

// ParseServerListRes decodes an OP_SERVER_LIST_RES payload (positioned after the
// opcode).
//
// Strict by design. 0xA1 is overloaded — mldonkey *clients* emit it with an unrelated
// payload — so a frame whose declared count does not match the bytes present is
// rejected outright rather than partially accepted. Parsing as many entries as happen
// to fit is exactly how a foreign payload becomes a list of garbage ip:port pairs
// that then propagate to every other server.
func ParseServerListRes(b *Buffer) ([]PeerAddr, error) {
	count, err := b.GetUInt8()
	if err != nil {
		return nil, ErrGossipShort
	}
	if b.Remaining() < int(count)*6 {
		return nil, ErrGossipTruncated
	}
	out := make([]PeerAddr, 0, count)
	for range int(count) {
		raw := b.Get(4)
		if len(raw) != 4 {
			return nil, ErrGossipTruncated
		}
		port, err := b.GetUInt16LE()
		if err != nil {
			return nil, ErrGossipTruncated
		}
		out = append(out, PeerAddr{IP: net.IP(append([]byte(nil), raw...)), Port: port})
	}
	return out, nil
}

// BuildServerListResIPv6Packet builds the eNode-go OP_SERVER_LIST_RES_IPV6 (0xA8):
// <count 1> then count × (<ipv6 16 network order><port 2 LE>).
//
// A separate opcode rather than a trailing block on 0xA1 so that 0xA1 stays exactly
// what eserver produces and consumes. Only IPv6 entries are carried; a v4 entry in
// the input is skipped, since it belongs in 0xA1.
func BuildServerListResIPv6Packet(peers []PeerAddr) (*Buffer, error) {
	v6 := make([]PeerAddr, 0, len(peers))
	for _, p := range peers {
		b, ok := IPv6Bytes(p.IP)
		if !ok {
			continue
		}
		if len(v6) == maxGossipPeers {
			break
		}
		v6 = append(v6, PeerAddr{IP: net.IP(b[:]), Port: p.Port})
	}
	pack := make([]PacketItem, 0, 2+2*len(v6))
	pack = append(pack,
		PacketItem{Type: TypeUint8, Value: OpServerListResIPv6},
		PacketItem{Type: TypeUint8, Value: uint8(len(v6))},
	)
	for _, p := range v6 {
		addr := append([]byte(nil), p.IP...) // copy: PutHash must not alias the loop value
		pack = append(pack,
			PacketItem{Type: TypeHash, Value: addr},
			PacketItem{Type: TypeUint16, Value: p.Port},
		)
	}
	return MakeUDPPacket(PrED2K, pack)
}

// ParseServerListResIPv6 decodes an OP_SERVER_LIST_RES_IPV6 payload, with the same
// strict count check as the v4 form.
func ParseServerListResIPv6(b *Buffer) ([]PeerAddr, error) {
	count, err := b.GetUInt8()
	if err != nil {
		return nil, ErrGossipShort
	}
	if b.Remaining() < int(count)*18 {
		return nil, ErrGossipTruncated
	}
	out := make([]PeerAddr, 0, count)
	for range int(count) {
		raw := b.Get(16)
		if len(raw) != 16 {
			return nil, ErrGossipTruncated
		}
		port, err := b.GetUInt16LE()
		if err != nil {
			return nil, ErrGossipTruncated
		}
		out = append(out, PeerAddr{IP: net.IP(append([]byte(nil), raw...)), Port: port})
	}
	return out, nil
}

// BuildObfPingRequest builds the raw obfuscated-bootstrap ping: a 4-byte challenge
// followed by 0..14 random padding bytes, sent **unencrypted**.
//
// Unencrypted is not an oversight, it is the protocol. The sender holds no ServerKey
// for this peer yet — obtaining one is the point of the exchange — so there is nothing
// to encrypt with. eMule is explicit about it: "we don't encrypt raw packets (!)"
// (srchybrid/UDPSocket.cpp:762). Only the *reply* is obfuscated, keyed on this
// challenge (UDPSocket.cpp:171).
//
// The first byte is forced away from the protocol constants. A receiver dispatches on
// byte 0, so a challenge that happened to begin 0xE3/0xD4/0xC5 would be misread as a
// plaintext eD2K frame instead of a raw ping. Returns the challenge actually used,
// which the caller must remember to decrypt the reply.
func BuildObfPingRequest() (packet []byte, challenge uint32, err error) {
	var buf [4 + obfPingMaxPad]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, 0, fmt.Errorf("gossip ping entropy: %w", err)
	}
	for IsProtocol(buf[0]) {
		// Redraw only the offending byte; the rest of the challenge stays random.
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, 0, fmt.Errorf("gossip ping entropy: %w", err)
		}
		buf[0] = b[0]
	}
	padLen := int(buf[4]) % (obfPingMaxPad + 1)
	packet = append([]byte(nil), buf[:4+padLen]...)

	// A zero challenge is unusable: eMule never sends one and checks challenge != 0
	// before decrypting a reply (srchybrid/ServerList.cpp:280-281), so a peer keying
	// on it would produce something we could not read back.
	challenge = uint32FromV4(packet[:4])
	if challenge == 0 {
		packet[0] |= 0x01
		if IsProtocol(packet[0]) {
			packet[0] ^= 0x80
		}
		challenge = uint32FromV4(packet[:4])
	}
	return packet, challenge, nil
}

// StatResFields is what a peer's extended OP_GLOBSERVSTATRES (0x97) tells us. The
// three fields gossip actually needs are UDPPortObf, TCPPortObf and ServerKey.
type StatResFields struct {
	Challenge  uint32
	Users      uint32
	Files      uint32
	MaxUsers   uint32
	SoftFiles  uint32
	HardFiles  uint32
	UDPFlags   uint32
	LowIDUsers uint32
	UDPPortObf uint16
	TCPPortObf uint16
	ServerKey  uint32
	// ObservedIP is the address the peer says it saw us on, from the 4 trailing bytes
	// Lugdunum appends and eMule ignores. nil when the reply is the shorter form.
	ObservedIP net.IP
	// Extended reports whether the reply carried the obfuscation ports and ServerKey
	// at all. Lugdunum answers a *plain* 0x96 with the short form — measured 32 bytes
	// of payload, ending at the UDP flags — and only the obfuscated channel gets the
	// full one, so a short reply is normal rather than an error.
	Extended bool
}

// ParseGlobServStatRes decodes a peer's 0x97 payload, positioned after the opcode.
//
// Layout, measured against eserver 17.14 and identical to what
// BuildGlobServStatResPacket emits:
//
//	+0   challenge(4)
//	+4   users(4) files(4) maxusers(4) softfiles(4) hardfiles(4)
//	+24  udpflags(4)
//	+28  lowidusers(4)
//	+32  portUDPOBF(2)
//	+34  portTCPOBF(2)
//	+36  ServerKey(4)
//	+40  observed client IP(4)   — Lugdunum sends it, eMule discards it
//
// These offsets are relative to the payload *after* the 2-byte UDP header, which is
// the same frame of reference eMule's own field list uses
// (srchybrid/UDPSocket.cpp:376-380, "portUDPOBF at 32, portTCPOBF at 34, ServerKey at
// 36") — so no adjustment is needed between the two. Worth stating because reading
// those offsets against the *whole datagram* instead shifts everything by two and
// yields plausible-looking garbage ports rather than a parse error.
func ParseGlobServStatRes(b *Buffer) (StatResFields, error) {
	var out StatResFields
	fields := []*uint32{
		&out.Challenge, &out.Users, &out.Files,
		&out.MaxUsers, &out.SoftFiles, &out.HardFiles,
		&out.UDPFlags, &out.LowIDUsers,
	}
	for i, dst := range fields {
		v, err := b.GetUInt32LE()
		if err != nil {
			// The first three are the minimum any 0x97 carries; anything shorter is
			// not a stat reply at all.
			if i < 3 {
				return out, ErrGossipShort
			}
			return out, nil
		}
		*dst = v
	}
	// Everything past the UDP flags and LowID count is the extended form. All three
	// fields arrive together or not at all, so they are read as a unit: accepting a
	// partial tail would hand the caller a zero ServerKey, which reads as "this peer
	// does not support obfuscation" rather than "we failed to parse it".
	if b.Remaining() < 8 {
		return out, nil
	}
	udpObf, err := b.GetUInt16LE()
	if err != nil {
		return out, nil
	}
	tcpObf, err := b.GetUInt16LE()
	if err != nil {
		return out, nil
	}
	key, err := b.GetUInt32LE()
	if err != nil {
		return out, nil
	}
	out.UDPPortObf, out.TCPPortObf, out.ServerKey = udpObf, tcpObf, key
	out.Extended = true

	// The 4 trailing bytes Lugdunum appends: the address it observed us on. eMule logs
	// them as "additional bytes" and discards them (UDPSocket.cpp:384-388).
	if raw := b.Get(4); len(raw) == 4 {
		out.ObservedIP = net.IP(append([]byte(nil), raw...))
	}
	return out, nil
}

// uint32FromV4 packs 4 address bytes into the eD2K uint32 convention, where the first
// octet is the low byte. Takes a raw 4-byte slice rather than a net.IP so it can also
// read the challenge out of the ping packet, which is the same little-endian read.
func uint32FromV4(v4 []byte) uint32 {
	if len(v4) < 4 {
		return 0
	}
	return uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24
}
