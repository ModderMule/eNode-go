package ed2k

import (
	"net"

	"enode/storage"
)

type UDPConfig struct {
	Name           string
	Description    string
	DynIP          string
	UDPFlags       uint32
	UDPPortObf     uint16
	TCPPortObf     uint16
	UDPServerKey   uint32
	MaxConnections uint32
	// SoftFiles and HardFiles are the per-client publish caps this server enforces,
	// advertised so a client sees the same numbers that are applied to it. Zero means
	// unlimited and is what a client reads as "no limit stated". See
	// BuildGlobServStatResPacket and docs/file-publish-limits.md.
	SoftFiles uint32
	HardFiles uint32
	// ObservedIP is the address the server saw this requester on, appended to the 0x97
	// reply as 4 trailing bytes. Nil omits the field entirely, which keeps the packet
	// byte-identical to the pre-reflection form for any caller that does not set it.
	// See BuildGlobServStatResPacket.
	ObservedIP net.IP
}

func BuildGlobSearchResPackets(files []storage.File) ([]*Buffer, error) {
	out := make([]*Buffer, 0, len(files))
	for _, file := range files {
		pack := []PacketItem{{Type: TypeUint8, Value: OpGlobSearchRes}}
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
		b, err := MakeUDPPacket(PrED2K, pack)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func BuildGlobFoundSourcesPacket(fileHash []byte, sources []storage.Source) (*Buffer, error) {
	return buildGlobFoundSources(fileHash, sources, FormatClassic)
}

// BuildGlobFoundSourcesSentinelPacket encodes IPv6-only sources with the sentinel
// form in the classic OP_GLOBFOUNDSOURCES datagram. Only safe when the query
// arrived over IPv6 (the sender is v6-capable by construction); a vanilla client's
// coalescing skip stride (count*(4+2)) would desync on the extra 16 bytes.
//
// This relies on the server emitting exactly one file block per datagram — the
// caller does so (one udpSend per hash), so the desync-prone multi-block skip is
// never exercised. Do not batch multiple hashes into one datagram with this form.
func BuildGlobFoundSourcesSentinelPacket(fileHash []byte, sources []storage.Source) (*Buffer, error) {
	return buildGlobFoundSources(fileHash, sources, FormatSentinel)
}

func buildGlobFoundSources(fileHash []byte, sources []storage.Source, format SourceFormat) (*Buffer, error) {
	// Single-byte count: truncate the slice, not the count. See capWireSources.
	sources = capWireSources(sources)
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpGlobFoundSources},
		{Type: TypeHash, Value: fileHash},
		{Type: TypeUint8, Value: uint8(len(sources))},
	}
	for _, src := range sources {
		id := src.ID
		useSentinel := format == FormatSentinel && sentinelForSource(src)
		if useSentinel {
			id = SentinelIPv6ID
		}
		pack = append(pack,
			PacketItem{Type: TypeUint32, Value: id},
			PacketItem{Type: TypeUint16, Value: src.Port},
		)
		if useSentinel {
			pack = append(pack, PacketItem{Type: TypeHash, Value: src.IPv6})
		}
	}
	return MakeUDPPacket(PrED2K, pack)
}

// BuildGlobServStatResPacket builds OP_GLOBSERVSTATRES (0x97). Payload offsets, counted
// from just after the opcode:
//
//	+0   challenge(4)
//	+4   users(4) files(4) maxusers(4) softfiles(4) hardfiles(4)
//	+24  udpflags(4)
//	+28  lowidusers(4)
//	+32  portUDPOBF(2)   — eMule reads these three at exactly these offsets,
//	+34  portTCPOBF(2)     srchybrid/UDPSocket.cpp:376-380
//	+36  ServerKey(4)
//	+40  observed client IPv4(4)   — appended only when cfg.ObservedIP is set
//
// softfiles/hardfiles at +16/+20 are per-client *publish* caps, not capacity figures:
// how many files one client may register here before the excess is ignored (soft) and
// before it is disconnected (hard). They come from files.softLimit / files.hardLimit and
// are the same numbers handleOfferFiles applies, so a client is never told one thing and
// held to another. eMule stores them as the server.met ST_SOFTFILES / ST_HARDFILES tags
// and clamps its per-packet offer count to the soft one; it ignores the hard one
// entirely. See docs/file-publish-limits.md.
//
// The trailing observed-IP field is what Lugdunum already sends: measured against
// eserver 17.14 the extended reply is 44 payload bytes and the last four carry the
// address the server saw the requester on (192.168.65.1 in the container). eMule does not
// parse them — it logs only "OP_GlobServStatRes contains %d additional bytes"
// (UDPSocket.cpp:384-388) and discards the tail — so this is additive and cannot break a
// stock client, while a client that learns to read +40 gets IPv4 address reflection from
// eserver and from us alike.
//
// Unlike Lugdunum we send the full extended form on both the plain and the obfuscated
// channel. eserver answers a plain 0x96 with the short 32-byte form and only gives ports
// and ServerKey over the obfuscated one; being more generous breaks nothing and saves a
// client the extra round trip.
func BuildGlobServStatResPacket(challenge uint32, cfg UDPConfig, clientsCount int, filesCount int, lowIDCount int) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpGlobServStatRes},
		{Type: TypeUint32, Value: challenge},
		{Type: TypeUint32, Value: uint32(clientsCount + 2000)},
		{Type: TypeUint32, Value: uint32(filesCount)},
		{Type: TypeUint32, Value: cfg.MaxConnections},
		{Type: TypeUint32, Value: cfg.SoftFiles},
		{Type: TypeUint32, Value: cfg.HardFiles},
		{Type: TypeUint32, Value: cfg.UDPFlags},
		{Type: TypeUint32, Value: uint32(lowIDCount + 1000)},
		{Type: TypeUint16, Value: cfg.UDPPortObf},
		{Type: TypeUint16, Value: cfg.TCPPortObf},
		{Type: TypeUint32, Value: cfg.UDPServerKey},
	}
	// Only IPv4 has a 4-byte form here. A v6 requester is told its observed address
	// through the CT_MOD_YOUR_IP tag in OP_SERVERIDENT instead, which is 16 bytes wide;
	// truncating a v6 address into this field would reflect something meaningless.
	if v4 := cfg.ObservedIP.To4(); v4 != nil {
		pack = append(pack, PacketItem{Type: TypeUint32, Value: uint32FromV4(v4)})
	}
	return MakeUDPPacket(PrED2K, pack)
}

func BuildServerDescResOldPacket(name, desc string) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerDescRes},
		{Type: TypeString, Value: name},
		{Type: TypeString, Value: desc},
	}
	return MakeUDPPacket(PrED2K, pack)
}

func BuildServerDescResPacket(challenge uint32, cfg UDPConfig) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerDescRes},
		{Type: TypeUint32, Value: challenge},
		{Type: TypeTags, Value: []Tag{
			{Type: TypeString, Code: TagName, Data: cfg.Name},
			{Type: TypeString, Code: TagDescription, Data: cfg.Description},
			{Type: TypeString, Code: TagDynIP, Data: cfg.DynIP},
			// String rather than uint32, and not ENodeVersionInt. Both forms reach the same
			// sscanf("%d.%d") in eserver, which admits a peer to its `working` set only at
			// 17.7 or above; the string form lets the part it ignores name us honestly,
			// since this reply answers clients as well as peer servers. See GossipVersionStr.
			{Type: TypeString, Code: TagVersion2, Data: GossipVersionStr},
			{Type: TypeString, Code: TagAuxPortsList, Data: ""},
		}},
	}
	return MakeUDPPacket(PrED2K, pack)
}
