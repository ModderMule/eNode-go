package ed2k

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestMakePacketAndUDPPacket(t *testing.T) {
	items := []PacketItem{
		{Type: TypeUint8, Value: uint8(0xaa)},
		{Type: TypeUint16, Value: uint16(0xbbcc)},
		{Type: TypeUint32, Value: uint32(0x11223344)},
		{Type: TypeString, Value: "xy"},
	}

	tcp, err := MakePacket(PrED2K, items)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := MakeUDPPacket(PrEMule, items)
	if err != nil {
		t.Fatal(err)
	}

	if tcp.Bytes()[0] != PrED2K {
		t.Fatalf("tcp protocol mismatch: 0x%x", tcp.Bytes()[0])
	}
	if udp.Bytes()[0] != PrEMule {
		t.Fatalf("udp protocol mismatch: 0x%x", udp.Bytes()[0])
	}
	if len(tcp.Bytes()) != len(udp.Bytes())+4 {
		t.Fatalf("unexpected sizes: tcp=%d udp=%d", len(tcp.Bytes()), len(udp.Bytes()))
	}
}

func TestAddFileAddsExpectedItems(t *testing.T) {
	items := make([]PacketItem, 0)
	hash := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	AddFile(&items, SharedFile{
		Name:       "song.mp3",
		Size:       0x100000001,
		Type:       "Audio",
		Sources:    10,
		Completed:  3,
		Title:      "Title",
		Artist:     "Artist",
		Album:      "Album",
		Runtime:    120,
		Bitrate:    320,
		Codec:      "mp3",
		Hash:       hash,
		SourceID:   123,
		SourcePort: 4662,
	})

	if len(items) != 4 {
		t.Fatalf("unexpected item count: %d", len(items))
	}
	if !bytes.Equal(items[0].Value.([]byte), hash) {
		t.Fatalf("hash mismatch")
	}
	tags, ok := items[3].Value.([]Tag)
	if !ok {
		t.Fatalf("tags not found")
	}
	foundSizeHi := false
	for _, tag := range tags {
		if tag.Code == TagSizeHi {
			foundSizeHi = true
		}
	}
	if !foundSizeHi {
		t.Fatalf("expected sizehi tag")
	}
}

func TestPacketInitAndAppend(t *testing.T) {
	// protocol + payload size(with opcode) + opcode + payload "AB"
	wire := NewBufferFromBytes([]byte{
		PrED2K, 0x03, 0x00, 0x00, 0x00, 0x34, 'A', 'B',
	})
	p := NewPacket()
	if err := p.Init(wire); err != nil {
		t.Fatal(err)
	}
	if p.Protocol != PrED2K || p.Code != 0x34 || p.Size != 2 {
		t.Fatalf("header mismatch: %+v", p)
	}
	if p.Status != PsReady {
		t.Fatalf("status mismatch: %d", p.Status)
	}
	if string(p.Data.Bytes()) != "AB" {
		t.Fatalf("payload mismatch: %q", string(p.Data.Bytes()))
	}
}

func TestPacketAppendWithExcess(t *testing.T) {
	p := NewPacket()
	p.Size = 2
	p.Data = NewBuffer(2)
	p.Append([]byte{'A', 'B', 'C', 'D'})
	if !p.HasExcess {
		t.Fatalf("expected excess")
	}
	if !bytes.Equal(p.Excess, []byte{'C', 'D'}) {
		t.Fatalf("excess mismatch: %v", p.Excess)
	}
}

// A non-protocol first byte means the stream has lost its framing. Init reports
// it rather than returning success, so the caller can drop the connection instead
// of silently discarding the chunk and misreading the next one.
func TestPacketInitUnknownProtocolIsRejected(t *testing.T) {
	wire := NewBufferFromBytes([]byte{0xff, 0x11, 0x22, 0x33, 0x44, 0x55})
	p := NewPacket()
	t.Logf("input: %v", wire.Bytes())
	err := p.Init(wire)
	t.Logf("output: err=%v protocol=0x%x status=%d", err, p.Protocol, p.Status)
	if !errors.Is(err, ErrUnknownProtocol) {
		t.Fatalf("want ErrUnknownProtocol, got %v", err)
	}
	if p.Status == PsReady {
		t.Fatalf("unknown protocol must not produce a ready packet: status=%d", p.Status)
	}
}

func TestPacketInitRejectsOversizedDeclaration(t *testing.T) {
	// A 6-byte header declaring a ~4 GiB payload. Without the bound, Init
	// allocates the declared size from these six bytes alone.
	wire := NewBufferFromBytes([]byte{PrED2K, 0xff, 0xff, 0xff, 0xff, 0x01})
	p := NewPacket()
	t.Logf("input: %v (declares payload=%d bytes)", wire.Bytes(), uint32(0xffffffff)-1)
	err := p.Init(wire)
	t.Logf("output: err=%v allocated=%d", err, len(p.Data.Bytes()))
	if !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("expected ErrPacketTooLarge, got %v", err)
	}
	if len(p.Data.Bytes()) > MaxTCPPacketSize {
		t.Fatalf("oversized buffer was allocated: %d bytes", len(p.Data.Bytes()))
	}
}

func TestPacketInitAcceptsMaximumSize(t *testing.T) {
	// Exactly at the ceiling must still parse. An off-by-one here would drop
	// legitimate large packets, which is a quieter failure than accepting one.
	header := make([]byte, 6)
	header[0] = PrED2K
	binary.LittleEndian.PutUint32(header[1:5], MaxTCPPacketSize+1) // +1 covers the opcode byte
	header[5] = OpServerMessage
	p := NewPacket()
	t.Logf("input: declared payload=%d, max=%d", MaxTCPPacketSize, MaxTCPPacketSize)
	if err := p.Init(NewBufferFromBytes(header)); err != nil {
		t.Fatalf("a size exactly at the ceiling must be accepted: %v", err)
	}
	t.Logf("output: size=%d status=%d", p.Size, p.Status)
	if p.Size != MaxTCPPacketSize {
		t.Fatalf("size mismatch: got %d want %d", p.Size, MaxTCPPacketSize)
	}
}

func TestMaybeCompressTCPPacket(t *testing.T) {
	items := []PacketItem{
		{Type: TypeUint8, Value: OpServerMessage},
		{Type: TypeString, Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	p, err := MakePacket(PrED2K, items)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := MaybeCompressTCPPacket(p, 16)
	if err != nil {
		t.Fatal(err)
	}
	if compressed.Bytes()[0] != PrZlib {
		t.Fatalf("expected zlib protocol, got 0x%x", compressed.Bytes()[0])
	}
	if compressed.Bytes()[5] != OpServerMessage {
		t.Fatalf("opcode mismatch")
	}
	inflated, err := InflateZlibPayload(compressed.Bytes()[6:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inflated, p.Bytes()[6:]) {
		t.Fatalf("inflated payload mismatch")
	}
}
