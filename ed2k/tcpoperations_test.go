package ed2k

import (
	"encoding/binary"
	"testing"

	"enode/storage"
)

func TestParseLoginRequest(t *testing.T) {
	tags := []Tag{{Type: TypeString, Code: TagName, Data: "node"}}
	l, _ := TagsLength(tags)
	b := NewBuffer(16 + 4 + 2 + l)
	_ = b.PutHash([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	_ = b.PutUInt32LE(123)
	_ = b.PutUInt16LE(4662)
	_ = b.PutTags(tags)
	b.Pos(0)
	req, err := ParseLoginRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if req.ID != 123 || req.Port != 4662 || req.Tags[0].Name != "name" {
		t.Fatalf("bad parse: %+v", req)
	}
}

func TestBuildServerPackets(t *testing.T) {
	msg, err := BuildServerMessagePacket("hello")
	if err != nil {
		t.Fatal(err)
	}
	if msg.Bytes()[0] != PrED2K {
		t.Fatalf("protocol mismatch")
	}

	st, err := BuildServerStatusPacket(10, 20)
	if err != nil {
		t.Fatal(err)
	}
	if st.Bytes()[5] != OpServerStatus {
		t.Fatalf("opcode mismatch")
	}

	idc, err := BuildIDChangePacket(123, 0x10, 4661, 0)
	if err != nil {
		t.Fatal(err)
	}
	if idc.Bytes()[5] != OpIDChange {
		t.Fatalf("opcode mismatch")
	}
}

// TestHasHighIDMatchesEMuleIsLowID pins the predicate that decides both the ID a
// client is assigned and whether its observed IPv4 is reflected back, against the
// reference client's own test. eMule's IsLowID is purely numeric — it never
// compares the ID to an address — so any address whose packed form falls in that
// range is a LowID as far as every client is concerned, whatever the server
// believes (srchybrid/otherfunctions.h:449).
func TestHasHighIDMatchesEMuleIsLowID(t *testing.T) {
	// Transcribed from srchybrid/otherfunctions.h:449, including the bound.
	emuleIsLowID := func(id uint32) bool { return id < 16777216 }

	cases := []struct {
		ipv4 string
		want bool
		why  string
	}{
		{"1.2.3.4", true, "ordinary address"},
		{"203.0.113.7", true, "ordinary address"},
		{"255.255.255.255", true, "the top of the space"},
		{"0.0.0.1", true, "packs to 0x01000000, the first value above the LowID ceiling"},
		{"203.0.113.0", false, "last octet 0 — the packed value is a LowID"},
		{"10.0.0.0", false, "last octet 0"},
		{"255.255.255.0", false, "last octet 0, however large the rest is"},
		{"0.0.0.0", false, "no address at all"},
	}

	for _, tc := range cases {
		packed, err := IPv4ToInt32LE(tc.ipv4)
		if err != nil {
			t.Fatalf("IPv4ToInt32LE(%q): %v", tc.ipv4, err)
		}
		got := HasHighID(packed)
		t.Logf("input: %-16s packed=0x%08x -> output: HasHighID=%-5t (%s)", tc.ipv4, packed, got, tc.why)

		if got != tc.want {
			t.Fatalf("HasHighID(%s / 0x%08x) = %t, want %t", tc.ipv4, packed, got, tc.want)
		}
		// The two must agree on everything except 0, which eMule calls a LowID and
		// eNode-go treats as "no ID at all"; both refuse it as a HighID.
		if packed != 0 && got == emuleIsLowID(packed) {
			t.Fatalf("disagrees with eMule IsLowID for %s (0x%08x): HasHighID=%t IsLowID=%t",
				tc.ipv4, packed, got, emuleIsLowID(packed))
		}
	}
}

// TestIDChangeCarriesObservedIPv4 checks OP_IDCHANGE fills eMule's full
// documented layout, <newID 4><serverFlags 4><primaryTCPPort 4><clientIP 4>. The
// 4th word is the only public-IPv4 source a LowID client has — eMule reads it at
// offset 12 once size >= 16 and feeds it to SetPublicIP()
// (srchybrid/ServerSocket.cpp:306-315,349-350).
func TestIDChangeCarriesObservedIPv4(t *testing.T) {
	// 192.0.2.10 packed the way an ed2k HighID is: first octet in the low byte.
	const highID = uint32(192) | uint32(0)<<8 | uint32(2)<<16 | uint32(10)<<24
	// 198.51.100.0 — a last octet of 0 makes the packed value look like a LowID.
	const trailingZeroIP = uint32(198) | uint32(51)<<8 | uint32(100)<<16 | uint32(0)<<24

	cases := []struct {
		name     string
		id       uint32
		observed uint32
		wantIP   uint32
	}{
		{
			name:     "HighID reports the same address the ID encodes",
			id:       highID,
			observed: highID,
			wantIP:   highID,
		},
		{
			name:     "LowID still reports the observed IPv4",
			id:       0x00123456,
			observed: highID,
			wantIP:   highID,
		},
		{
			name:     "v6-only session has no IPv4 to report",
			id:       0x00123456,
			observed: 0,
			wantIP:   0,
		},
		{
			name:     "an address eMule would reject as a LowID is zeroed",
			id:       trailingZeroIP,
			observed: trailingZeroIP,
			wantIP:   0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const flags = uint32(0x10)
			const primaryPort = uint16(4661)
			t.Logf("input: id=0x%08x flags=0x%08x primaryPort=%d observedIPv4=0x%08x",
				tc.id, flags, primaryPort, tc.observed)

			buf, err := BuildIDChangePacket(tc.id, flags, primaryPort, tc.observed)
			if err != nil {
				t.Fatal(err)
			}
			opcode, payload := tcpFoundSourcesPayload(t, buf)
			t.Logf("output: opcode=0x%02x payload=% x", opcode, payload)

			if opcode != OpIDChange {
				t.Fatalf("opcode = 0x%02x, want OP_IDCHANGE", opcode)
			}
			if len(payload) != 16 {
				t.Fatalf("payload = %d bytes, want 16 (eMule reads the client IP at offset 12)", len(payload))
			}
			if got := binary.LittleEndian.Uint32(payload[0:4]); got != tc.id {
				t.Fatalf("clientID = 0x%08x, want 0x%08x", got, tc.id)
			}
			if got := binary.LittleEndian.Uint32(payload[4:8]); got != flags {
				t.Fatalf("tcpFlags = 0x%08x, want 0x%08x", got, flags)
			}
			if got := binary.LittleEndian.Uint32(payload[8:12]); got != uint32(primaryPort) {
				t.Fatalf("primaryTCPPort = %d, want %d", got, primaryPort)
			}
			got := binary.LittleEndian.Uint32(payload[12:16])
			if got != tc.wantIP {
				t.Fatalf("observed IPv4 = 0x%08x, want 0x%08x", got, tc.wantIP)
			}
			// eMule asserts the reported IP equals the ID unless the ID is a LowID.
			if HasHighID(tc.id) && got != tc.id {
				t.Fatalf("HighID session: reported IP 0x%08x != clientID 0x%08x", got, tc.id)
			}
		})
	}
}

func TestBuildSearchAndSources(t *testing.T) {
	fileHash := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	fp, err := BuildFoundSourcesPacket(fileHash, []storage.Source{{ID: 11, Port: 22}})
	if err != nil {
		t.Fatal(err)
	}
	if fp.Bytes()[5] != OpFoundSources {
		t.Fatalf("opcode mismatch")
	}
	if fp.Bytes()[27] != 22 || fp.Bytes()[28] != 0 {
		t.Fatalf("normal port mismatch: got=%02x%02x", fp.Bytes()[27], fp.Bytes()[28])
	}
	fpObfu, err := BuildFoundSourcesObfuPacket(fileHash, []storage.Source{{ID: 11, Port: 22}})
	if err != nil {
		t.Fatal(err)
	}
	if fpObfu.Bytes()[5] != OpFoundSourcesObfu {
		t.Fatalf("obfu opcode mismatch")
	}
	if len(fpObfu.Bytes()) != len(fp.Bytes())+1 {
		t.Fatalf("obfu packet size mismatch: normal=%d obfu=%d", len(fp.Bytes()), len(fpObfu.Bytes()))
	}
	// protocol(1)+size(4)+opcode(1)+hash(16)+count(1)+id(4)+port(2) => obfu options at offset 29.
	if fpObfu.Bytes()[29] != 0 {
		t.Fatalf("obfu options mismatch: got=%d", fpObfu.Bytes()[29])
	}
	// ID 11 is a LowID. The obfu variant used to overwrite its port with a
	// fabricated 0xFFFF; the port must be the real one, byte-identical to what
	// the non-obfuscated packet carries.
	if fpObfu.Bytes()[27] != 22 || fpObfu.Bytes()[28] != 0 {
		t.Fatalf("obfu lowid port mismatch: got=%02x%02x want=1600",
			fpObfu.Bytes()[27], fpObfu.Bytes()[28])
	}
	if fpObfu.Bytes()[27] != fp.Bytes()[27] || fpObfu.Bytes()[28] != fp.Bytes()[28] {
		t.Fatalf("obfu and non-obfu ports differ: obfu=%02x%02x normal=%02x%02x",
			fpObfu.Bytes()[27], fpObfu.Bytes()[28], fp.Bytes()[27], fp.Bytes()[28])
	}
	// N2: the user hash is tied to crypt capability. A source that carries a hash
	// but advertised no crypt options must yield options byte 0x00 and NO hash — the
	// old code emitted 0x80 + hash regardless of crypt, which is what this asserts
	// against.
	fpHashNoCrypt, err := BuildFoundSourcesObfuPacket(fileHash, []storage.Source{{
		ID: 11, Port: 22, UserHash: []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: obfu source hash-present crypt=0x00 -> options=0x%02x size=%d",
		fpHashNoCrypt.Bytes()[29], len(fpHashNoCrypt.Bytes()))
	if len(fpHashNoCrypt.Bytes()) != len(fpObfu.Bytes()) {
		t.Fatalf("hash-without-crypt should carry no hash: size=%d want=%d", len(fpHashNoCrypt.Bytes()), len(fpObfu.Bytes()))
	}
	if fpHashNoCrypt.Bytes()[29] != 0x00 {
		t.Fatalf("hash-without-crypt options mismatch: got=0x%02x want=0x00", fpHashNoCrypt.Bytes()[29])
	}

	// A crypt-capable source (0x01 supports) with a hash: options 0x81, hash follows.
	fpObfuHash, err := BuildFoundSourcesObfuPacket(fileHash, []storage.Source{{
		ID: 11, Port: 22, CryptOptions: 0x01,
		UserHash: []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: obfu source crypt=0x01 hash-present -> options=0x%02x size=%d",
		fpObfuHash.Bytes()[29], len(fpObfuHash.Bytes()))
	if len(fpObfuHash.Bytes()) != len(fpObfu.Bytes())+16 {
		t.Fatalf("obfu-hash packet size mismatch: nohash=%d hash=%d", len(fpObfu.Bytes()), len(fpObfuHash.Bytes()))
	}
	if fpObfuHash.Bytes()[29] != 0x81 {
		t.Fatalf("obfu-hash options mismatch: got=0x%02x want=0x81", fpObfuHash.Bytes()[29])
	}
	if got := fpObfuHash.Bytes()[30:46]; len(got) != 16 || got[0] != 9 || got[15] != 9 {
		t.Fatalf("obfu-hash userhash mismatch: %x", got)
	}

	// requests-crypt (0x02) but no hash available: options 0x02, no hash appended.
	fpReqNoHash, err := BuildFoundSourcesObfuPacket(fileHash, []storage.Source{{
		ID: 11, Port: 22, CryptOptions: 0x02,
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: obfu source crypt=0x02 no-hash -> options=0x%02x size=%d",
		fpReqNoHash.Bytes()[29], len(fpReqNoHash.Bytes()))
	if len(fpReqNoHash.Bytes()) != len(fpObfu.Bytes()) {
		t.Fatalf("crypt-without-hash size mismatch: got=%d want=%d", len(fpReqNoHash.Bytes()), len(fpObfu.Bytes()))
	}
	if fpReqNoHash.Bytes()[29] != 0x02 {
		t.Fatalf("crypt-without-hash options mismatch: got=0x%02x want=0x02", fpReqNoHash.Bytes()[29])
	}

	sp, err := BuildSearchResultPacket([]storage.File{{
		Hash: fileHash, Name: "a.bin", Size: 10, Type: "Pro", Sources: 1, Completed: 1, SourceID: 11, SourcePort: 22,
	}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if sp.Bytes()[5] != OpSearchResult {
		t.Fatalf("opcode mismatch")
	}
}

func TestBuildSearchResultPacketCanCompress(t *testing.T) {
	fileHash := []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	files := make([]storage.File, 0, 40)
	for i := 0; i < 40; i++ {
		files = append(files, storage.File{
			Hash: fileHash, Name: "same-name-for-better-compression.bin", Size: 10, Type: "Pro",
			Sources: 1, Completed: 1, SourceID: 11, SourcePort: 22,
		})
	}
	packet, err := BuildSearchResultPacket(files, false)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Bytes()[5] != OpSearchResult {
		t.Fatalf("opcode mismatch")
	}
	if packet.Bytes()[0] == PrZlib {
		inflated, err := InflateZlibPayload(packet.Bytes()[6:])
		if err != nil {
			t.Fatal(err)
		}
		if len(inflated) == 0 {
			t.Fatalf("unexpected empty inflated payload")
		}
	}
}
