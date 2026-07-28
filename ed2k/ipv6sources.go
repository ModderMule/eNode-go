package ed2k

import "enode/storage"

// IPv6 tag-block source format (eNode-go extension, §Format 2).
//
// This is the richer, opt-in reply to OP_GETSOURCES_IPV6 (0x24) /
// OP_GLOBGETSOURCES_IPV6 (0xa5). Per source it carries the classic id+port
// followed by a uint8-counted tag block, so IPv6 (and, later, other) attributes
// ride as tags rather than fixed fields. Unknown tags are skipped tolerantly by
// eMuleQt's parser, so the block is forward-compatible without another opcode.
//
// It is only ever sent in response to the matching request opcode, which a legacy
// client never emits — so there is no desync risk, unlike the sentinel form that
// rides inside classic OP_FOUNDSOURCES.

// BuildFoundSourcesIPv6Packet builds an OP_FOUNDSOURCES_IPV6 (0x25) TCP reply.
func BuildFoundSourcesIPv6Packet(fileHash []byte, sources []storage.Source) (*Buffer, error) {
	return buildFoundSourcesIPv6(OpFoundSourcesIPv6, false, fileHash, sources)
}

// BuildGlobFoundSourcesIPv6Packet builds an OP_GLOBFOUNDSOURCES_IPV6 (0xa6) UDP
// reply.
func BuildGlobFoundSourcesIPv6Packet(fileHash []byte, sources []storage.Source) (*Buffer, error) {
	return buildFoundSourcesIPv6(OpGlobFoundSourcesIPv6, true, fileHash, sources)
}

func buildFoundSourcesIPv6(opcode uint8, udp bool, fileHash []byte, sources []storage.Source) (*Buffer, error) {
	sources = capWireSources(sources)
	pack := []PacketItem{
		{Type: TypeUint8, Value: opcode},
		{Type: TypeHash, Value: fileHash},
		{Type: TypeUint8, Value: uint8(len(sources))},
	}
	// Each source is id(4) + port(2) + a uint8-counted tag list. A source with a
	// reachable IPv6 carries one CT_MOD_IP_V6 tag; if it has no routable IPv4
	// HighID its id is the 0xFFFFFFFF sentinel, so the address is the only way to
	// reach it. A source with no reachable IPv6 has an empty tag list, making the
	// block a strict superset of the classic list.
	for _, src := range sources {
		id := src.ID
		var tags []Tag
		if sourceHasReachableIPv6(src) {
			if !HasHighID(id) {
				id = SentinelIPv6ID
			}
			tags = []Tag{{Type: TypeHash, Code: TagModIPv6, Data: src.IPv6}}
		}
		pack = append(pack,
			PacketItem{Type: TypeUint32, Value: id},
			PacketItem{Type: TypeUint16, Value: src.Port},
			PacketItem{Type: itemTagsU8, Value: tags},
		)
	}
	if udp {
		return MakeUDPPacket(PrED2K, pack)
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func sourceHasReachableIPv6(src storage.Source) bool {
	return len(src.IPv6) == 16 && src.IPv6Reachable
}
