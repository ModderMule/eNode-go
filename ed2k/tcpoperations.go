package ed2k

import (
	"enode/storage"
)

const minZlibPayloadOnSend = 128

type ServerConfig struct {
	Name        string
	Description string
	Address     string
	Hash        []byte
	TCPPort     uint16
	TCPFlags    uint32
	// IPv6 is the server's own public IPv6 (16 network-order bytes), advertised as
	// a CT_MOD_SVR_IP_V6 (0xaf) hash tag in OP_SERVERIDENT. Empty omits the tag.
	IPv6 []byte
	// NatPort is the server's NAT-rendezvous UDP port, advertised as a TagNatPort
	// (0x9d) uint16 tag in OP_SERVERIDENT so a client learns where to REGISTER/SYNC2.
	// Zero omits the tag (feature off or NAT disabled).
	NatPort uint16
	// ClientIPv6 is the IPv6 the server observed *this* session arriving on (16
	// network-order bytes), reflected back as a CT_MOD_YOUR_IP (0xad) hash tag.
	// Unlike the fields above it is per-session, not per-server. Empty omits the tag.
	ClientIPv6 []byte
	// ClientIPv6Status is the IPv6Status* bitfield describing what the server knows
	// about this session's IPv6, sent as a TagIPv6Status (0xab) uint8 tag. Zero omits
	// the tag, which is also how "the server has no verdict" is expressed.
	ClientIPv6Status uint8
}

type LoginRequest struct {
	Hash []byte
	ID   uint32
	Port uint16
	Tags []NamedTag
}

func ParseLoginRequest(data *Buffer) (LoginRequest, error) {
	out := LoginRequest{}
	hash := data.Get(16)
	if len(hash) != 16 {
		return out, ErrOutOfBounds
	}
	out.Hash = append([]byte(nil), hash...)
	id, err := data.GetUInt32LE()
	if err != nil {
		return out, err
	}
	out.ID = id
	port, err := data.GetUInt16LE()
	if err != nil {
		return out, err
	}
	out.Port = port
	tags, err := data.GetTags()
	if err != nil {
		return out, err
	}
	out.Tags = tags
	return out, nil
}

// SourceFormat selects how a found-sources reply encodes each source.
type SourceFormat int

const (
	// FormatClassic is the standard OP_FOUNDSOURCES layout, byte-identical to the
	// pre-IPv6 output. Safe for every client.
	FormatClassic SourceFormat = iota
	// FormatSentinel is FormatClassic plus the eMuleAI 0xFFFFFFFF+16-byte sentinel
	// for sources whose only routable address is IPv6. It desyncs a client that
	// lacks the sentinel parser, so it may only be sent to a session known to carry
	// it (connected over IPv6 or having sent CT_MOD_IP_V6).
	FormatSentinel
)

func BuildFoundSourcesPacket(fileHash []byte, sources []storage.Source) (*Buffer, error) {
	return buildFoundSourcesPacketWithOpcode(OpFoundSources, fileHash, sources, false, FormatClassic)
}

func BuildFoundSourcesObfuPacket(fileHash []byte, sources []storage.Source) (*Buffer, error) {
	return buildFoundSourcesPacketWithOpcode(OpFoundSourcesObfu, fileHash, sources, true, FormatClassic)
}

// BuildFoundSourcesSentinelPacket builds an OP_FOUNDSOURCES(_OBFU) reply that
// encodes IPv6-only sources with the sentinel form. Caller must have verified the
// requesting session parses it.
func BuildFoundSourcesSentinelPacket(fileHash []byte, sources []storage.Source, obfu bool) (*Buffer, error) {
	opcode := OpFoundSources
	if obfu {
		opcode = OpFoundSourcesObfu
	}
	return buildFoundSourcesPacketWithOpcode(opcode, fileHash, sources, obfu, FormatSentinel)
}

// HasHighID reports whether an ed2k ClientID is a routable HighID (a packed
// public IPv4) rather than a LowID handle or the unset 0. A source with a HighID
// is directly reachable over IPv4, so it is never replaced by the IPv6 sentinel.
//
// Read the other way round, it is also the test for whether an observed IPv4 can
// be handed to a client *as* its ID: a HighID is the packed address with the first
// octet in the low byte, so any address ending in .0 packs to a value at or below
// 0x00ffffff and comes back out of a client as a LowID. eMule states the rule from
// the client side — "we now know the servers just give *.*.*.0 users a lowID"
// (srchybrid/otherfunctions.h:448) — and drops its own .0 handling because of it.
func HasHighID(id uint32) bool {
	return id != 0 && !isLowID(id)
}

// sentinelForSource reports whether a source should be published with the IPv6
// sentinel: it has a verified-reachable IPv6 and no routable IPv4 HighID, so its
// only usable address is the IPv6. This matches eMuleAI's rule ("UINT_MAX means
// HighID with IPv6 only should not be listed here"): a LowID or v6-only source
// with a reachable v6 is better delivered as a direct v6 than as an uncallable
// LowID, and a v6-only source has no other reachable form at all.
func sentinelForSource(src storage.Source) bool {
	return sourceHasReachableIPv6(src) && !HasHighID(src.ID)
}

func buildFoundSourcesPacketWithOpcode(opcode uint8, fileHash []byte, sources []storage.Source, withObfuSettings bool, format SourceFormat) (*Buffer, error) {
	// The count is a single byte, so truncate the slice rather than the count:
	// uint8(256) is 0, which tells the client there are no sources and leaves the
	// 256 records that follow to be parsed as the next packet.
	sources = capWireSources(sources)
	pack := []PacketItem{
		{Type: TypeUint8, Value: opcode},
		{Type: TypeHash, Value: fileHash},
		{Type: TypeUint8, Value: uint8(len(sources))},
	}
	for _, src := range sources {
		useSentinel := format == FormatSentinel && sentinelForSource(src)
		// The port is sent verbatim for LowID sources too. There is no 0xFFFF
		// sentinel in the ed2k protocol: eMule stores whatever arrives here
		// (UpDownClient.cpp assigns m_userPort before it even looks at LowID) and
		// then republishes it through source exchange, so a fabricated port
		// propagates to peers that never contacted this server. Worse, ClientList
		// and DeadSourceList key on (IP, port), so the same peer learned via
		// OP_FOUNDSOURCES and via source exchange would never deduplicate.
		id := src.ID
		if useSentinel {
			id = SentinelIPv6ID
		}
		pack = append(pack,
			PacketItem{Type: TypeUint32, Value: id},
			PacketItem{Type: TypeUint16, Value: src.Port},
		)
		if withObfuSettings {
			// OP_FOUNDSOURCES_OBFU carries one "obfuscation settings" byte per source:
			// bit 0x01 supports crypt, 0x02 requests, 0x04 requires (matching eMule's
			// CreateSrcInfoPacket: (requires<<2)|(requests<<1)|(supports<<0)), and 0x80
			// meaning a 16-byte user hash follows.
			//
			// The hash is tied to crypt capability, as eMule expects (PartFile.cpp
			// AddSources warns when a hash is present for a source that isn't crypt
			// capable): send it only when the source advertised at least one crypt bit.
			// A non-crypt source therefore gets 0x00 and no hash — the requester used
			// OP_GETSOURCES_OBFU but cannot reach that peer obfuscated anyway.
			obf := src.CryptOptions & 0x07
			if obf != 0 && len(src.UserHash) == 16 {
				obf |= 0x80
			}
			pack = append(pack, PacketItem{Type: TypeUint8, Value: obf})
			if obf&0x80 != 0 {
				pack = append(pack, PacketItem{Type: TypeHash, Value: src.UserHash})
			}
		}
		if useSentinel {
			// The 16-byte IPv6 comes last, after any obfuscation fields — matching
			// eMuleAI PartFile.cpp AddSources, which reads it only after the crypt
			// options and user hash for an _OBFU source.
			pack = append(pack, PacketItem{Type: TypeHash, Value: src.IPv6})
		}
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func isLowID(id uint32) bool {
	return id > 0 && id <= 0x00FFFFFF
}

func BuildSearchResultPacket(files []storage.File) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpSearchResult},
		{Type: TypeUint32, Value: uint32(len(files))},
	}
	for _, file := range files {
		AddFile(&pack, SharedFile{
			Name:       file.Name,
			Size:       file.Size,
			Type:       file.Type,
			Sources:    file.Sources,
			Completed:  file.Completed,
			Title:      file.Title,
			Artist:     file.Artist,
			Album:      file.Album,
			Runtime:    file.Runtime,
			Bitrate:    file.Bitrate,
			Codec:      file.Codec,
			Hash:       file.Hash,
			SourceID:   file.SourceID,
			SourcePort: file.SourcePort,
		})
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

// BuildServerListPacket builds OP_SERVERLIST (0x32). The classic block is
// <v4count:uint8> followed by v4count × <ip:uint32 LE><port:uint16 LE>. When
// includeV6 is set and at least one configured server has a public IPv6, a trailing
// block <v6count:uint8> + v6count × <ipv6:16 network-order><port:uint16 LE> is
// appended. That trailing block is safe for legacy clients: the classic count is
// self-terminating, so a v4-only parser stops after v4count entries and ignores the
// rest. With no v6 servers (or includeV6 false) the packet is byte-identical to the
// pre-IPv6 form. An unclassifiable entry is skipped, not fatal — a single bad IP no
// longer silences the whole list.
func BuildServerListPacket(servers []storage.Server, includeV6 bool) (*Buffer, error) {
	type v4Entry struct {
		ip   uint32
		port uint16
	}
	type v6Entry struct {
		ip   [16]byte
		port uint16
	}
	var v4 []v4Entry
	var v6 []v6Entry
	for _, s := range servers {
		ipv4, ipv6, fam := ClassifyServerIP(s.IP)
		switch fam {
		case 4:
			if len(v4) < storage.MaxWireSources {
				v4 = append(v4, v4Entry{ip: ipv4, port: s.Port})
			}
		case 6:
			if includeV6 && len(v6) < storage.MaxWireSources {
				v6 = append(v6, v6Entry{ip: ipv6, port: s.Port})
			}
		}
	}

	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerList},
		{Type: TypeUint8, Value: uint8(len(v4))},
	}
	for _, e := range v4 {
		pack = append(pack,
			PacketItem{Type: TypeUint32, Value: e.ip},
			PacketItem{Type: TypeUint16, Value: e.port},
		)
	}
	if includeV6 && len(v6) > 0 {
		pack = append(pack, PacketItem{Type: TypeUint8, Value: uint8(len(v6))})
		for _, e := range v6 {
			ip := e.ip // copy so the packet item does not alias the loop variable
			pack = append(pack,
				PacketItem{Type: TypeHash, Value: ip[:]},
				PacketItem{Type: TypeUint16, Value: e.port},
			)
		}
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

// ClassifyServerIP classifies a configured peer-server address for OP_SERVERLIST.
// It returns (packed LE uint32, _, 4) for an IPv4 address, (_, 16 network-order
// bytes, 6) for a globally routable IPv6 address, or (_, _, 0) for anything else
// (empty, loopback/link-local/ULA v6, or malformed). Built on IPv4ToInt32LE
// (misc.go) and ParsePublicIPv6 (address.go) so the wire builder and seedServers
// agree on which entries are advertisable.
func ClassifyServerIP(ip string) (v4 uint32, v6 [16]byte, fam int) {
	if n, err := IPv4ToInt32LE(ip); err == nil {
		return n, v6, 4
	}
	if b, ok := ParsePublicIPv6(ip); ok {
		return 0, b, 6
	}
	return 0, v6, 0
}

func BuildServerStatusPacket(clients, files int) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerStatus},
		{Type: TypeUint32, Value: uint32(clients)},
		{Type: TypeUint32, Value: uint32(files)},
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

// BuildIDChangePacket builds OP_IDCHANGE in eMule's full documented layout,
// <newID 4><serverFlags 4><primaryTCPPort 4><observedClientIPv4 4>
// (srchybrid/Opcodes.h:182). The last two words are what make the packet 16 bytes
// instead of 8; both are additive, since eMule only ever lower-bounds the size —
// flags at offset 4 need size >= 8, the observed IP at offset 12 needs size >= 16
// (ServerSocket.cpp:264,307), and nothing rejects a longer packet.
//
// observedClientIPv4 is the address the server saw the session arrive from, and it
// is the only public-IPv4 source a LowID client has: eMule feeds it straight to
// SetPublicIP() (ServerSocket.cpp:349-350). A HighID client gets the same value it
// already reads out of its ID, which is exactly what eMule asserts.
//
// primaryTCPPort is annotated "(unused)" in the reference and is ignored by both
// surveyed clients; it carries the server's own listening port to match the name.
func BuildIDChangePacket(id, tcpFlags uint32, primaryPort uint16, observedClientIPv4 uint32) (*Buffer, error) {
	// eMule zeroes a reported IP that looks like a LowID and ASSERTs on it
	// (ServerSocket.cpp:309-312), so send 0 rather than a value the client will
	// reject anyway. HasHighID also covers the v6-only session, whose IPv4 is 0
	// because it has no IPv4 to report.
	if !HasHighID(observedClientIPv4) {
		observedClientIPv4 = 0
	}
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpIDChange},
		{Type: TypeUint32, Value: id},
		{Type: TypeUint32, Value: tcpFlags},
		{Type: TypeUint32, Value: uint32(primaryPort)},
		{Type: TypeUint32, Value: observedClientIPv4},
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func BuildCallbackFailedPacket() (*Buffer, error) {
	pack := []PacketItem{{Type: TypeUint8, Value: OpCallbackFailed}}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func BuildServerIdentPacket(conf ServerConfig) (*Buffer, error) {
	ip, err := IPv4ToInt32LE(conf.Address)
	if err != nil {
		return nil, err
	}
	tags := []Tag{
		{Type: TypeString, Code: TagName, Data: conf.Name},
		{Type: TypeString, Code: TagDescription, Data: conf.Description},
	}
	// Advertise the server's own IPv6 as a hash tag. eMule's OP_SERVERIDENT tag
	// loop consumes unknown name-IDs and unknown trailing tags without
	// disconnecting, so this is backward-compatible; a v6-aware client reads it.
	if len(conf.IPv6) == 16 {
		tags = append(tags, Tag{Type: TypeHash, Code: TagModSvrIPv6, Data: conf.IPv6})
	}
	// Advertise the NAT-rendezvous UDP port so a client can REGISTER/SYNC2 for
	// server-independent hole-punching without assuming the default port. Same
	// backward-compatible tag loop as the IPv6 tag above — a legacy client ignores it.
	if conf.NatPort != 0 {
		tags = append(tags, Tag{Type: TypeUint16, Code: TagNatPort, Data: conf.NatPort})
	}
	// Per-session reflection tags, appended last so the packet a legacy session
	// receives stays byte-identical to the pre-reflection server. Both ride the same
	// backward-compatible tag loop: eMule dispatches on the tag *name* and skips the
	// ones it does not know, but it consumes the value by *type*, so these use
	// TAGTYPE_HASH and TAGTYPE_UINT8 — types the reference reads by fixed length
	// (packets.cpp:470-472,479-483) rather than a type it would fail to skip.
	if len(conf.ClientIPv6) == 16 {
		tags = append(tags, Tag{Type: TypeHash, Code: TagModYourIP, Data: conf.ClientIPv6})
	}
	if conf.ClientIPv6Status != 0 {
		tags = append(tags, Tag{Type: TypeUint8, Code: TagIPv6Status, Data: conf.ClientIPv6Status})
	}
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerIdent},
		{Type: TypeHash, Value: conf.Hash},
		{Type: TypeUint32, Value: ip},
		{Type: TypeUint16, Value: conf.TCPPort},
		{Type: TypeTags, Value: tags},
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func BuildServerMessagePacket(message string) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerMessage},
		{Type: TypeString, Value: message},
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func BuildCallbackRequestedPacket(ipv4 uint32, port uint16) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpCallbackReqd},
		{Type: TypeUint32, Value: ipv4},
		{Type: TypeUint16, Value: port},
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

// BuildCallbackRequestedIPv6Packet builds the OP_CALLBACKREQUESTED_IPV6 (0x26)
// packet the server sends to a firewalled callback target so it can call back to a
// requester over IPv6. It mirrors BuildCallbackRequestedPacket, replacing the
// uint32 IPv4 with the requester's 16-byte in6_addr (network byte order, emitted
// as a HASH just like the sentinel / CT_MOD_SVR_IP_V6 paths); no crypt trailer,
// matching the classic emitter above.
func BuildCallbackRequestedIPv6Packet(ipv6 []byte, port uint16) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpCallbackReqdIPv6},
		{Type: TypeHash, Value: ipv6},
		{Type: TypeUint16, Value: port},
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

// capWireSources truncates to what a single-byte count can describe. Applied at
// the wire layer as well as in the engines so the count and the record count
// cannot disagree, whichever engine supplied the slice.
func capWireSources(sources []storage.Source) []storage.Source {
	if len(sources) > storage.MaxWireSources {
		return sources[:storage.MaxWireSources]
	}
	return sources
}
