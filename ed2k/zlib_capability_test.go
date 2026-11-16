package ed2k

import (
	"bytes"
	"testing"
)

// TestUnpackTCPPacketRestoresFrame: unpacking a PR_ZLIB frame gives back exactly the
// PR_ED2K frame MaybeCompressTCPPacket packed, and a frame that was never packed passes
// through untouched.
func TestUnpackTCPPacketRestoresFrame(t *testing.T) {
	payload := bytes.Repeat([]byte("compressible "), 40)
	items := []PacketItem{{Type: TypeUint8, Value: OpSearchResult}}
	for _, b := range payload {
		items = append(items, PacketItem{Type: TypeUint8, Value: b})
	}
	plain, err := MakePacket(PrED2K, items)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), plain.Bytes()...)
	packed, err := MaybeCompressTCPPacket(plain, minZlibPayloadOnSend)
	if err != nil {
		t.Fatal(err)
	}
	if packed.Bytes()[0] != PrZlib {
		t.Fatalf("setup: payload of %d bytes was not packed", len(payload))
	}
	unpacked, err := UnpackTCPPacket(packed)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: PR_ZLIB frame of %d bytes; output: 0x%02x frame of %d bytes (original %d)",
		len(packed.Bytes()), unpacked.Bytes()[0], len(unpacked.Bytes()), len(original))
	if !bytes.Equal(unpacked.Bytes(), original) {
		t.Fatalf("unpacked frame differs from the original")
	}

	small, err := MakePacket(PrED2K, []PacketItem{{Type: TypeUint8, Value: OpServerStatus}})
	if err != nil {
		t.Fatal(err)
	}
	same, err := UnpackTCPPacket(small)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: plain frame %x; output: %x", small.Bytes(), same.Bytes())
	if !bytes.Equal(same.Bytes(), small.Bytes()) {
		t.Fatal("a plain frame was changed")
	}
}

// TestSearchReplyHonoursZlibFlag: a client that sets SRVCAP_ZLIB in CT_SERVER_FLAGS
// gets a large OP_SEARCHRESULT as PR_ZLIB, and a client that does not gets it plain,
// with the same content. Measured before the fix: eNode-go sent PR_ZLIB to a client
// whose flags were 0x0118 (eMule's word without the zlib bit).
func TestSearchReplyHonoursZlibFlag(t *testing.T) {
	setup, _ := searchPagingClient(t, 50)
	var replies [2][]byte
	for i, flags := range []uint32{0x0118, 0x0118 | FlagZlib} {
		items := loginItems(bytes.Repeat([]byte{0x7a + byte(i)}, 16), 0, 4662)
		items[len(items)-1] = PacketItem{Type: TypeTags, Value: []Tag{{Type: TypeUint32, Code: TagFlags, Data: flags}}}
		wire, err := MakePacket(PrED2K, items)
		if err != nil {
			t.Fatal(err)
		}
		p := NewPacket()
		if err := p.Init(NewBufferFromBytes(wire.Bytes())); err != nil {
			t.Fatal(err)
		}
		conn := &recordingConn{}
		client := newTCPClient(setup.server, conn, false)
		client.handlePacket(p)
		if !client.isLogged() {
			t.Fatalf("flags 0x%x: login failed", flags)
		}
		conn.takeWritten()
		client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
		raw := conn.takeWritten()
		t.Logf("input: login CT_SERVER_FLAGS=0x%04x, search matching 50 files; output: protocol 0x%02x, %d bytes",
			flags, raw[0], len(raw))
		wantProto := PrED2K
		if flags&FlagZlib != 0 {
			wantProto = PrZlib
		}
		if raw[0] != wantProto {
			t.Fatalf("flags 0x%x: reply protocol 0x%02x, want 0x%02x", flags, raw[0], wantProto)
		}
		count, _, _ := decodeSearchResult(t, raw)
		if count != 50 {
			t.Fatalf("flags 0x%x: %d results, want 50", flags, count)
		}
		plain, err := UnpackTCPPacket(NewBufferFromBytes(raw))
		if err != nil {
			t.Fatal(err)
		}
		replies[i] = plain.Bytes()
	}
	if !bytes.Equal(replies[0], replies[1]) {
		t.Fatal("the plain and the packed reply carry different content")
	}
}

// TestHandoffKeepsNoZlib: the flag survives a handover, and a state from an older build
// (field absent, so false) keeps compressing as that build did.
func TestHandoffKeepsNoZlib(t *testing.T) {
	setup, _ := searchPagingClient(t, 0)
	for _, noZlib := range []bool{true, false} {
		old := newTCPClient(setup.server, &recordingConn{}, false)
		old.noZlib = noZlib
		st := old.exportState()
		fresh := newTCPClient(setup.server, &recordingConn{}, false)
		fresh.applyState(st)
		t.Logf("input: noZlib=%t; output: state NoZlib=%t, restored noZlib=%t", noZlib, st.NoZlib, fresh.noZlib)
		if fresh.noZlib != noZlib {
			t.Fatalf("noZlib %t restored as %t", noZlib, fresh.noZlib)
		}
	}
}
