package ed2k

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"

	"enode/storage"
)

// ErrPacketTooLarge is returned when a peer declares a payload above
// MaxTCPPacketSize. Callers should drop the connection: no legitimate client
// sends one, and the declared size is allocated up front.
var ErrPacketTooLarge = errors.New("packet: declared size exceeds maximum")

// ErrInflatedTooLarge is returned when a PR_ZLIB payload expands past
// MaxTCPPacketSize. The wire-size check in Init bounds only the *compressed*
// declaration, and zlib reaches roughly 1032:1, so a conforming 2 MB packet
// still inflates to ~2 GB.
var ErrInflatedTooLarge = errors.New("packet: inflated payload exceeds maximum")

// ErrUnknownProtocol is returned by Init when the first header byte is not an
// ed2k protocol byte. The stream has lost its framing and cannot be resynced, so
// callers drop the connection, as eMule's CEMSocket does.
var ErrUnknownProtocol = errors.New("packet: unknown protocol byte")

// PacketHeaderSize is the fixed TCP header: protocol(1) + size(4) + opcode(1).
// Init needs all six bytes at once, so the caller buffers a shorter chunk.
const PacketHeaderSize = 6

type PacketItem struct {
	Type  uint8
	Value any
}

type SharedFile struct {
	Name       string
	Size       uint64
	Type       string
	Sources    uint32
	Completed  uint32
	Title      string
	Artist     string
	Album      string
	Runtime    uint32
	Bitrate    uint32
	Codec      string
	Hash       []byte
	SourceID   uint32
	SourcePort uint16
	// Meta adds the FT_META_* tags of a torrent/Usenet row; nil for an eD2K file.
	Meta *storage.MetaInfo
}

type Packet struct {
	Protocol  uint8
	Size      uint32
	Code      uint8
	Status    int
	Data      *Buffer
	HasExcess bool
	Excess    []byte
	// recv gathers the payload as it arrives; Data is set from it once complete.
	recv []byte
}

// packetInitialCap is what a packet's buffer starts at. It grows with the bytes that
// actually arrive: preallocating the declared size let each 6-byte header reserve up
// to MaxTCPPacketSize, before login and before a single payload byte.
const packetInitialCap = 64 << 10

func NewPacket() *Packet {
	return &Packet{
		Status: PsNew,
		Data:   NewBuffer(0),
	}
}

func itemSize(item PacketItem) (int, error) {
	switch item.Type {
	case TypeUint8:
		return 1, nil
	case TypeUint16:
		return 2, nil
	case TypeUint32:
		return 4, nil
	case TypeString:
		v, ok := item.Value.(string)
		if !ok {
			return 0, ErrUnsupportedTag
		}
		return 2 + len([]byte(v)), nil
	case TypeHash:
		return 16, nil
	case TypeTags:
		v, ok := item.Value.([]Tag)
		if !ok {
			return 0, ErrUnsupportedTag
		}
		return TagsLength(v)
	case itemTagsU8:
		v, ok := item.Value.([]Tag)
		if !ok {
			return 0, ErrUnsupportedTag
		}
		n, err := TagsLength(v)
		if err != nil {
			return 0, err
		}
		// TagsLength counts a 4-byte (uint32) tag-count header; this variant uses a
		// 1-byte count, so subtract 4 and add 1.
		return n - 3, nil
	default:
		return 0, fmt.Errorf("%w: 0x%x", ErrUnsupportedTag, item.Type)
	}
}

// itemTagsU8 is an internal PacketItem type that writes a tag list with a uint8
// count instead of TypeTags' uint32 count — the framing eMule's extended
// source-exchange blocks use. 0xfe is outside the wire tag-type space.
const itemTagsU8 uint8 = 0xfe

func putItem(b *Buffer, item PacketItem) error {
	switch item.Type {
	case TypeUint8:
		switch v := item.Value.(type) {
		case uint8:
			return b.PutUInt8(v)
		case int:
			return b.PutUInt8(uint8(v))
		}
	case TypeUint16:
		switch v := item.Value.(type) {
		case uint16:
			return b.PutUInt16LE(v)
		case int:
			return b.PutUInt16LE(uint16(v))
		}
	case TypeUint32:
		switch v := item.Value.(type) {
		case uint32:
			return b.PutUInt32LE(v)
		case int:
			return b.PutUInt32LE(uint32(v))
		}
	case TypeString:
		if v, ok := item.Value.(string); ok {
			return b.PutString(v)
		}
	case TypeHash:
		if v, ok := item.Value.([]byte); ok {
			return b.PutHash(v)
		}
	case TypeTags:
		if v, ok := item.Value.([]Tag); ok {
			return b.PutTags(v)
		}
	case itemTagsU8:
		v, ok := item.Value.([]Tag)
		if !ok {
			return ErrUnsupportedTag
		}
		if err := b.PutUInt8(uint8(len(v))); err != nil {
			return err
		}
		for _, t := range v {
			if err := b.PutTag(t); err != nil {
				return err
			}
		}
		return nil
	}
	return ErrUnsupportedTag
}

func MakePacket(protocol uint8, items []PacketItem) (*Buffer, error) {
	size := 0
	for _, item := range items {
		l, err := itemSize(item)
		if err != nil {
			return nil, err
		}
		size += l
	}
	buf := NewBuffer(5 + size)
	if err := buf.PutUInt8(protocol); err != nil {
		return nil, err
	}
	if err := buf.PutUInt32LE(uint32(size)); err != nil {
		return nil, err
	}
	for _, item := range items {
		if err := putItem(buf, item); err != nil {
			return nil, err
		}
	}
	buf.Pos(0)
	return buf, nil
}

func MakeUDPPacket(protocol uint8, items []PacketItem) (*Buffer, error) {
	size := 0
	for _, item := range items {
		l, err := itemSize(item)
		if err != nil {
			return nil, err
		}
		size += l
	}
	buf := NewBuffer(1 + size)
	if err := buf.PutUInt8(protocol); err != nil {
		return nil, err
	}
	for _, item := range items {
		if err := putItem(buf, item); err != nil {
			return nil, err
		}
	}
	buf.Pos(0)
	return buf, nil
}

// MaybeCompressTCPPacket converts a normal TCP packet into PR_ZLIB format when:
// 1) payload length after opcode is at least minPayloadLen, and
// 2) zlib-compressed payload is smaller than the original payload.
func MaybeCompressTCPPacket(packet *Buffer, minPayloadLen int) (*Buffer, error) {
	if packet == nil {
		return nil, ErrOutOfBounds
	}
	raw := packet.Bytes()
	if len(raw) < 6 {
		return packet, nil
	}
	proto := raw[0]
	if proto != PrED2K && proto != PrEMule {
		return packet, nil
	}
	payload := raw[6:]
	if len(payload) < minPayloadLen {
		return packet, nil
	}

	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(payload); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if compressed.Len() >= len(payload) {
		return packet, nil
	}

	out := NewBuffer(6 + compressed.Len())
	_ = out.PutUInt8(PrZlib)
	_ = out.PutUInt32LE(uint32(compressed.Len() + 1))
	_ = out.PutUInt8(raw[5])
	out.PutBuffer(compressed.Bytes())
	out.Pos(0)
	return out, nil
}

func InflateZlibPayload(payload []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	// Read one byte past the ceiling so an oversized stream can be told apart
	// from one that merely fills it. Limiting to exactly MaxTCPPacketSize would
	// truncate a zlib bomb into a well-formed short packet, which is then parsed
	// as if the peer had sent it — worse than dropping the connection.
	var out bytes.Buffer
	n, err := io.Copy(&out, io.LimitReader(r, MaxTCPPacketSize+1))
	if err != nil {
		return nil, err
	}
	if n > MaxTCPPacketSize {
		return nil, fmt.Errorf("%w: inflated>%d max=%d", ErrInflatedTooLarge, MaxTCPPacketSize, MaxTCPPacketSize)
	}
	return out.Bytes(), nil
}

func AddFile(packet *[]PacketItem, file SharedFile) {
	tags := []Tag{
		{Type: TypeString, Code: TagName, Data: file.Name},
		{Type: TypeUint32, Code: TagSize, Data: uint32(file.Size % 0x100000000)},
		{Type: TypeString, Code: TagType, Data: file.Type},
		{Type: TypeUint32, Code: TagSources, Data: file.Sources},
		{Type: TypeUint32, Code: TagCompleteSources, Data: file.Completed},
	}
	if file.Size >= 0x100000000 {
		tags = append(tags, Tag{
			Type: TypeUint32, Code: TagSizeHi, Data: uint32(file.Size / 0x100000000),
		})
	}
	if file.Title != "" {
		tags = append(tags, Tag{Type: TypeString, Code: TagMediaTitle, Data: file.Title})
	}
	if file.Artist != "" {
		tags = append(tags, Tag{Type: TypeString, Code: TagMediaArtist, Data: file.Artist})
	}
	if file.Album != "" {
		tags = append(tags, Tag{Type: TypeString, Code: TagMediaAlbum, Data: file.Album})
	}
	if file.Runtime > 0 {
		tags = append(tags, Tag{Type: TypeUint32, Code: TagMediaLength, Data: file.Runtime})
	}
	if file.Bitrate > 0 {
		tags = append(tags, Tag{Type: TypeUint32, Code: TagMediaBitrate, Data: file.Bitrate})
	}
	if file.Codec != "" {
		tags = append(tags, Tag{Type: TypeString, Code: TagMediaCodec, Data: file.Codec})
	}
	if file.Meta != nil {
		tags = appendMetaTags(tags, file.Meta)
	}
	*packet = append(*packet,
		PacketItem{Type: TypeHash, Value: file.Hash},
		PacketItem{Type: TypeUint32, Value: file.SourceID},
		PacketItem{Type: TypeUint16, Value: file.SourcePort},
		PacketItem{Type: TypeTags, Value: tags},
	)
}

// Init parses a packet header. Obfuscation is decided before this point, by
// tcpClient.handleBytes, which sniffs the protocol byte and routes to the crypt
// state machine itself — so Init only ever sees plaintext framing. The caller must
// supply at least PacketHeaderSize bytes; see tcpClient.processPacketData.
func (p *Packet) Init(buffer *Buffer) error {
	p.HasExcess = false
	protocol, err := buffer.GetUInt8()
	if err != nil {
		return err
	}
	p.Protocol = protocol

	if p.Protocol == PrED2K || p.Protocol == PrZlib || p.Protocol == PrEMule {
		size, err := buffer.GetUInt32LE()
		if err != nil {
			return err
		}
		if size == 0 {
			return ErrOutOfBounds
		}
		if size-1 > MaxTCPPacketSize {
			return fmt.Errorf("%w: declared=%d max=%d", ErrPacketTooLarge, size-1, MaxTCPPacketSize)
		}
		p.Size = size - 1
		code, err := buffer.GetUInt8()
		if err != nil {
			return err
		}
		p.Code = code
		p.recv = make([]byte, 0, min(int(p.Size), packetInitialCap))
		p.Data = NewBuffer(0)
		p.Append(buffer.Get())
		return nil
	}

	return fmt.Errorf("%w: 0x%x", ErrUnknownProtocol, p.Protocol)
}

// Append adds received bytes to the payload. Once Size bytes are in, Data holds the
// payload and Status is PsReady; bytes past it are kept in Excess (HasExcess).
func (p *Packet) Append(chunk []byte) {
	take := min(int(p.Size)-len(p.recv), len(chunk))
	p.recv = append(p.recv, chunk[:take]...)
	if len(p.recv) < int(p.Size) {
		p.Status = PsWaitingData
		p.HasExcess = false
		return
	}
	p.Data = NewBufferFromBytes(p.recv)
	p.recv = nil
	p.Status = PsReady
	p.HasExcess = take < len(chunk)
	if p.HasExcess {
		p.Excess = append([]byte(nil), chunk[take:]...)
	}
}

// appendMetaTags adds the FT_META_* tags after the classic ones. Kind, version and
// catalogue id are always sent — a capable client drops a row without them — and the
// optional strings only when present, so a row stays as small as its release allows.
func appendMetaTags(tags []Tag, m *storage.MetaInfo) []Tag {
	tags = append(tags,
		Tag{Type: TypeUint8, Code: TagMetaKind, Data: m.Kind},
		Tag{Type: TypeUint8, Code: TagMetaVersion, Data: m.Version},
		Tag{Type: TypeUint32, Code: TagMetaFileIndex, Data: m.FileIndex},
	)
	if m.FilePath != "" {
		tags = append(tags, Tag{Type: TypeString, Code: TagMetaFilePath, Data: m.FilePath})
	}
	if m.TotalSize > 0 {
		tags = append(tags, Tag{Type: TypeUint64, Code: TagMetaTotalSize, Data: m.TotalSize})
	}
	tags = append(tags,
		Tag{Type: TypeString, Code: TagMetaID, Data: m.CatalogID},
		Tag{Type: TypeUint32, Code: TagMetaSeeders, Data: m.Seeders},
		Tag{Type: TypeUint32, Code: TagMetaPeers, Data: m.Peers},
		Tag{Type: TypeUint32, Code: TagMetaAge, Data: m.AgeDays},
	)
	if m.Indexer != "" {
		tags = append(tags, Tag{Type: TypeString, Code: TagMetaIndexer, Data: m.Indexer})
	}
	tags = append(tags, Tag{Type: TypeUint32, Code: TagMetaFlags, Data: m.Flags})
	if m.Magnet != "" {
		tags = append(tags, Tag{Type: TypeString, Code: TagMetaMagnet, Data: m.Magnet})
	}
	return tags
}
