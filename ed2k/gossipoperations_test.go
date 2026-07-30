package ed2k

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

// payloadAfterOpcode strips the UDP header (proto + opcode) and returns the opcode
// plus a Buffer positioned where the parsers expect to start.
func payloadAfterOpcode(t *testing.T, packet *Buffer) (uint8, *Buffer) {
	t.Helper()
	raw := packet.Bytes()
	if len(raw) < 2 {
		t.Fatalf("packet too short: %d bytes", len(raw))
	}
	if raw[0] != PrED2K {
		t.Fatalf("protocol byte = 0x%02x, want 0x%02x", raw[0], PrED2K)
	}
	return raw[1], NewBufferFromBytes(raw[2:])
}

// TestServerListReqRoundTrip covers the 10-byte Lugdunum form and pins the exact wire
// bytes, since the address field's byte order is the one thing every description of
// this protocol states ambiguously.
func TestServerListReqRoundTrip(t *testing.T) {
	packet, err := BuildServerListReqPacket(net.ParseIP("1.2.3.4"), 4661, 0x55AA1234)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input:  ip=1.2.3.4 port=4661 challenge=0x55aa1234")
	t.Logf("output: % x", packet.Bytes())

	// e3 a0 | 01 02 03 04 | 35 12 | 34 12 aa 55
	want := []byte{PrED2K, OpServerListReq, 1, 2, 3, 4, 0x35, 0x12, 0x34, 0x12, 0xaa, 0x55}
	if !bytes.Equal(packet.Bytes(), want) {
		t.Fatalf("wire bytes = % x, want % x", packet.Bytes(), want)
	}

	op, b := payloadAfterOpcode(t, packet)
	if op != OpServerListReq {
		t.Fatalf("opcode = 0x%02x, want 0x%02x", op, OpServerListReq)
	}
	ip, port, challenge, hasChallenge, err := ParseServerListReq(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("parsed: ip=%s port=%d challenge=0x%08x hasChallenge=%v", ip, port, challenge, hasChallenge)
	if ip.String() != "1.2.3.4" || port != 4661 || challenge != 0x55AA1234 || !hasChallenge {
		t.Fatalf("round trip mismatch: ip=%s port=%d challenge=0x%08x hasChallenge=%v",
			ip, port, challenge, hasChallenge)
	}
}

// TestServerListReqAcceptsSixByteForm covers eMule's documented <IP 4><PORT 2> shape.
// A real eserver or an mldonkey may send it, and rejecting it would silently ignore
// every registration from such a peer.
func TestServerListReqAcceptsSixByteForm(t *testing.T) {
	b := NewBufferFromBytes([]byte{5, 6, 7, 8, 0x35, 0x12})
	ip, port, challenge, hasChallenge, err := ParseServerListReq(b)
	t.Logf("input:  % x (6-byte form)", []byte{5, 6, 7, 8, 0x35, 0x12})
	t.Logf("output: ip=%s port=%d challenge=0x%08x hasChallenge=%v err=%v",
		ip, port, challenge, hasChallenge, err)
	if err != nil {
		t.Fatalf("the 6-byte form must parse: %v", err)
	}
	if ip.String() != "5.6.7.8" || port != 4661 {
		t.Fatalf("mismatch: ip=%s port=%d", ip, port)
	}
	if hasChallenge {
		t.Error("hasChallenge must be false for the 6-byte form")
	}
}

func TestServerListReqRejectsShortPayload(t *testing.T) {
	for _, n := range []int{0, 1, 3, 4, 5} {
		b := NewBufferFromBytes(make([]byte, n))
		_, _, _, _, err := ParseServerListReq(b)
		t.Logf("payload length %d -> err=%v", n, err)
		if !errors.Is(err, ErrGossipShort) {
			t.Errorf("length %d: err = %v, want ErrGossipShort", n, err)
		}
	}
}

func TestServerListReqRejectsIPv6(t *testing.T) {
	_, err := BuildServerListReqPacket(net.ParseIP("2001:db8::1"), 4661, 1)
	t.Logf("input: 2001:db8::1; output: err=%v", err)
	if err == nil {
		t.Fatal("0xA0's address field is 4 bytes wide; a v6 address must be refused rather than truncated")
	}
}

// TestServerListResRoundTrip pins the 0xA1 layout that must stay byte-identical to
// eserver's, and checks the count byte agrees with the records that follow.
func TestServerListResRoundTrip(t *testing.T) {
	in := []PeerAddr{
		{IP: net.ParseIP("1.2.3.4"), Port: 4661},
		{IP: net.ParseIP("203.0.113.9"), Port: 5555},
	}
	packet, err := BuildServerListResPacket(in)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input:  %v", in)
	t.Logf("output: % x", packet.Bytes())

	want := []byte{PrED2K, OpServerListRes, 2,
		1, 2, 3, 4, 0x35, 0x12,
		203, 0, 113, 9, 0xb3, 0x15,
	}
	if !bytes.Equal(packet.Bytes(), want) {
		t.Fatalf("wire bytes = % x, want % x", packet.Bytes(), want)
	}

	_, b := payloadAfterOpcode(t, packet)
	got, err := ParseServerListRes(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("parsed: %v", got)
	if len(got) != 2 || got[0].String() != "1.2.3.4:4661" || got[1].String() != "203.0.113.9:5555" {
		t.Fatalf("round trip mismatch: %v", got)
	}
}

// TestServerListResSkipsIPv6Entries pins that 0xA1 stays IPv4-only even when handed a
// mixed list. A v6 address serialised into the 4-byte field would desync every peer's
// parser for the rest of the datagram.
func TestServerListResSkipsIPv6Entries(t *testing.T) {
	in := []PeerAddr{
		{IP: net.ParseIP("2001:db8::1"), Port: 4661},
		{IP: net.ParseIP("1.2.3.4"), Port: 4661},
		{IP: net.ParseIP("2001:db8::2"), Port: 4661},
	}
	packet, err := BuildServerListResPacket(in)
	if err != nil {
		t.Fatal(err)
	}
	_, b := payloadAfterOpcode(t, packet)
	got, err := ParseServerListRes(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: 2 v6 + 1 v4; output: count=%d %v", len(got), got)
	if len(got) != 1 || got[0].IP.String() != "1.2.3.4" {
		t.Fatalf("expected only the v4 entry, got %v", got)
	}
}

// TestServerListResCapsAt255 guards the single-byte count. Truncating the slice rather
// than the count is what keeps the two in agreement — the same defect class as H9 in
// the source-list builders.
func TestServerListResCapsAt255(t *testing.T) {
	in := make([]PeerAddr, 300)
	for i := range in {
		in[i] = PeerAddr{IP: net.IPv4(10, byte(i>>8), byte(i), 1), Port: 4661}
	}
	packet, err := BuildServerListResPacket(in)
	if err != nil {
		t.Fatal(err)
	}
	raw := packet.Bytes()
	declared := raw[2]
	records := (len(raw) - 3) / 6
	t.Logf("input: 300 peers; output: count byte=%d records=%d bytes=%d", declared, records, len(raw))
	if declared != 255 || records != 255 {
		t.Fatalf("count=%d records=%d, want both 255", declared, records)
	}

	_, b := payloadAfterOpcode(t, packet)
	got, err := ParseServerListRes(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 255 {
		t.Fatalf("parsed %d entries, want 255", len(got))
	}
}

// TestServerListResRejectsTruncated is the hostile-input case that matters most: 0xA1
// is also emitted by mldonkey *clients* with an unrelated payload, so a declared count
// that the bytes cannot cover must be rejected outright. Accepting the entries that
// happen to fit is how a foreign payload becomes garbage peers that then propagate.
func TestServerListResRejectsTruncated(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"count with no records", []byte{3}},
		{"count of 2 with 1 record", []byte{2, 1, 2, 3, 4, 0x35, 0x12}},
		{"count of 1 with 5 bytes", []byte{1, 1, 2, 3, 4, 0x35}},
		{"empty payload", []byte{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseServerListRes(NewBufferFromBytes(c.payload))
			t.Logf("input: % x; output: err=%v", c.payload, err)
			if err == nil {
				t.Fatal("a truncated peer list must be rejected, not partially accepted")
			}
		})
	}
}

func TestServerListResEmptyIsValid(t *testing.T) {
	packet, err := BuildServerListResPacket(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: no peers; output: % x", packet.Bytes())
	_, b := payloadAfterOpcode(t, packet)
	got, err := ParseServerListRes(b)
	if err != nil {
		t.Fatalf("an empty list is a legitimate answer: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 peers, got %v", got)
	}
}

// TestServerListResIPv6RoundTrip covers the eNode-go 0xA7/0xA8 extension.
func TestServerListResIPv6RoundTrip(t *testing.T) {
	in := []PeerAddr{
		{IP: net.ParseIP("2001:db8::1"), Port: 4661},
		{IP: net.ParseIP("1.2.3.4"), Port: 4661}, // skipped: belongs in 0xA1
		{IP: net.ParseIP("2606:4700:4700::1111"), Port: 5555},
	}
	packet, err := BuildServerListResIPv6Packet(in)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input:  %v", in)
	t.Logf("output: % x", packet.Bytes())

	op, b := payloadAfterOpcode(t, packet)
	if op != OpServerListResIPv6 {
		t.Fatalf("opcode = 0x%02x, want 0x%02x", op, OpServerListResIPv6)
	}
	got, err := ParseServerListResIPv6(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("parsed: %v", got)
	if len(got) != 2 {
		t.Fatalf("expected 2 v6 entries (the v4 one skipped), got %v", got)
	}
	if got[0].IP.String() != "2001:db8::1" || got[0].Port != 4661 {
		t.Errorf("entry 0 = %v", got[0])
	}
	if got[1].IP.String() != "2606:4700:4700::1111" || got[1].Port != 5555 {
		t.Errorf("entry 1 = %v", got[1])
	}
	// 18 bytes per entry, not 6 — the whole point of the separate opcode.
	if wantLen := 3 + 2*18; len(packet.Bytes()) != wantLen {
		t.Errorf("packet length = %d, want %d", len(packet.Bytes()), wantLen)
	}
}

func TestServerListResIPv6RejectsTruncated(t *testing.T) {
	// Count of 2 but only one 18-byte record present.
	payload := append([]byte{2}, make([]byte, 18)...)
	_, err := ParseServerListResIPv6(NewBufferFromBytes(payload))
	t.Logf("input: count=2 with 1 record (%d bytes); output: err=%v", len(payload), err)
	if !errors.Is(err, ErrGossipTruncated) {
		t.Fatalf("err = %v, want ErrGossipTruncated", err)
	}
}

func TestEmptyListRequestPackets(t *testing.T) {
	req2, err := BuildServerListReq2Packet()
	if err != nil {
		t.Fatal(err)
	}
	reqV6, err := BuildServerListReqIPv6Packet()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("0xA4: % x", req2.Bytes())
	t.Logf("0xA7: % x", reqV6.Bytes())
	if !bytes.Equal(req2.Bytes(), []byte{PrED2K, OpServerListReq2}) {
		t.Errorf("0xA4 = % x, want e3 a4 with no payload", req2.Bytes())
	}
	if !bytes.Equal(reqV6.Bytes(), []byte{PrED2K, OpServerListReqIPv6}) {
		t.Errorf("0xA7 = % x, want e3 a7 with no payload", reqV6.Bytes())
	}
}

// TestBuildObfPingRequestShape pins the three properties the bootstrap ping depends
// on. The first-byte rule is the subtle one: a receiver dispatches on byte 0, so a
// challenge that happened to start 0xE3 would be read as a plaintext eD2K frame
// instead of a raw ping — and that would happen to roughly 1 in 85 pings.
func TestBuildObfPingRequestShape(t *testing.T) {
	for i := range 500 {
		packet, challenge, err := BuildObfPingRequest()
		if err != nil {
			t.Fatal(err)
		}
		if len(packet) < 4 || len(packet) > 4+obfPingMaxPad {
			t.Fatalf("iteration %d: length %d outside 4..%d", i, len(packet), 4+obfPingMaxPad)
		}
		if IsProtocol(packet[0]) {
			t.Fatalf("iteration %d: first byte 0x%02x is a protocol constant; the peer would parse this as a plaintext frame",
				i, packet[0])
		}
		if challenge == 0 {
			t.Fatalf("iteration %d: zero challenge — eMule refuses to decrypt a reply keyed on 0", i)
		}
		if got := uint32FromV4(packet[:4]); got != challenge {
			t.Fatalf("iteration %d: returned challenge 0x%08x but packet carries 0x%08x", i, challenge, got)
		}
	}
	packet, challenge, _ := BuildObfPingRequest()
	t.Logf("sample: %d bytes, challenge=0x%08x, wire=% x", len(packet), challenge, packet)
}

// TestParseGlobServStatResMatchesOurBuilder is the round trip that pins the offsets:
// portUDPOBF at +32, portTCPOBF at +34, ServerKey at +36, relative to the payload
// after the opcode. Reading those against the whole datagram instead shifts everything
// by two and yields plausible garbage rather than an error.
func TestParseGlobServStatResMatchesOurBuilder(t *testing.T) {
	packet, err := BuildGlobServStatResPacket(0x55AA1234, UDPConfig{
		UDPFlags:       0x000007fb,
		UDPPortObf:     4675,
		TCPPortObf:     4661,
		UDPServerKey:   0x938a42f5,
		MaxConnections: 200,
	}, 5, 7, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input:  udpflags=0x7fb portUDPOBF=4675 portTCPOBF=4661 ServerKey=0x938a42f5")
	t.Logf("output: %d bytes % x", len(packet.Bytes()), packet.Bytes())

	op, b := payloadAfterOpcode(t, packet)
	if op != OpGlobServStatRes {
		t.Fatalf("opcode = 0x%02x, want 0x%02x", op, OpGlobServStatRes)
	}
	got, err := ParseGlobServStatRes(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("parsed: challenge=0x%08x udpflags=0x%08x portUDPOBF=%d portTCPOBF=%d ServerKey=0x%08x extended=%v",
		got.Challenge, got.UDPFlags, got.UDPPortObf, got.TCPPortObf, got.ServerKey, got.Extended)

	if !got.Extended {
		t.Fatal("our own reply carries the obfuscation ports, so Extended must be true")
	}
	if got.Challenge != 0x55AA1234 {
		t.Errorf("challenge = 0x%08x", got.Challenge)
	}
	if got.UDPFlags != 0x000007fb {
		t.Errorf("udpflags = 0x%08x", got.UDPFlags)
	}
	if got.UDPPortObf != 4675 || got.TCPPortObf != 4661 {
		t.Errorf("ports = %d/%d, want 4675/4661", got.UDPPortObf, got.TCPPortObf)
	}
	if got.ServerKey != 0x938a42f5 {
		t.Errorf("ServerKey = 0x%08x, want 0x938a42f5", got.ServerKey)
	}
}

// TestParseGlobServStatResShortForm covers Lugdunum's plain-channel reply: 32 bytes of
// payload ending at the LowID count, with no obfuscation ports and no ServerKey. That
// is normal, not an error — see the §7.1.5 correction — so it must parse with
// Extended false rather than failing or inventing a zero ServerKey.
func TestParseGlobServStatResShortForm(t *testing.T) {
	// 8 uint32 fields = 32 bytes, exactly what eserver answers a plain 0x96 with.
	payload := make([]byte, 32)
	payload[0], payload[1], payload[2], payload[3] = 0x34, 0x12, 0xaa, 0x55 // challenge
	got, err := ParseGlobServStatRes(NewBufferFromBytes(payload))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: 32-byte short-form payload")
	t.Logf("output: challenge=0x%08x extended=%v ServerKey=0x%08x observedIP=%v",
		got.Challenge, got.Extended, got.ServerKey, got.ObservedIP)
	if got.Challenge != 0x55AA1234 {
		t.Errorf("challenge = 0x%08x", got.Challenge)
	}
	if got.Extended {
		t.Error("a 32-byte reply carries no obfuscation data; Extended must be false")
	}
	if got.ServerKey != 0 {
		t.Error("ServerKey must stay zero rather than being read from absent bytes")
	}
}

// TestParseGlobServStatResRejectsRunt covers the floor: fewer than the three fields
// every 0x97 carries is not a stat reply at all.
func TestParseGlobServStatResRejectsRunt(t *testing.T) {
	for _, n := range []int{0, 4, 8, 11} {
		_, err := ParseGlobServStatRes(NewBufferFromBytes(make([]byte, n)))
		t.Logf("payload length %d -> err=%v", n, err)
		if !errors.Is(err, ErrGossipShort) {
			t.Errorf("length %d: err = %v, want ErrGossipShort", n, err)
		}
	}
}

// TestParseGlobServStatResPartialTailIsNotExtended covers a reply that starts the
// extended block but is cut short. Accepting a partial tail would hand the caller a
// zero ServerKey, which reads as "this peer does not support obfuscation" rather than
// "we could not parse it" — and the peer would then never be gossiped with.
func TestParseGlobServStatResPartialTailIsNotExtended(t *testing.T) {
	for _, n := range []int{33, 34, 36, 38, 39} {
		payload := make([]byte, n)
		got, err := ParseGlobServStatRes(NewBufferFromBytes(payload))
		if err != nil {
			t.Fatalf("length %d: unexpected error %v", n, err)
		}
		t.Logf("payload length %d -> extended=%v ServerKey=0x%08x", n, got.Extended, got.ServerKey)
		if got.Extended {
			t.Errorf("length %d: Extended must be false, the ports/key block needs 8 bytes", n)
		}
	}
}

// TestParseGlobServStatResReadsObservedIP covers the 4 trailing bytes Lugdunum appends
// and eMule discards — the address the peer saw us on. Measured against the real
// binary as 192.168.65.1.
func TestParseGlobServStatResReadsObservedIP(t *testing.T) {
	payload := make([]byte, 44)
	// Extended block: ports at +32/+34, key at +36, observed IP at +40.
	payload[32], payload[33] = 0x43, 0x12 // portUDPOBF 4675
	payload[34], payload[35] = 0x35, 0x12 // portTCPOBF 4661
	payload[36], payload[37], payload[38], payload[39] = 0xf5, 0x42, 0x8a, 0x93
	payload[40], payload[41], payload[42], payload[43] = 192, 168, 65, 1

	got, err := ParseGlobServStatRes(NewBufferFromBytes(payload))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: 44-byte payload with a trailing observed IP")
	t.Logf("output: portUDPOBF=%d portTCPOBF=%d ServerKey=0x%08x observedIP=%v",
		got.UDPPortObf, got.TCPPortObf, got.ServerKey, got.ObservedIP)
	if !got.Extended {
		t.Fatal("Extended must be true")
	}
	if got.UDPPortObf != 4675 || got.TCPPortObf != 4661 {
		t.Errorf("ports = %d/%d, want 4675/4661", got.UDPPortObf, got.TCPPortObf)
	}
	if got.ObservedIP == nil || got.ObservedIP.String() != "192.168.65.1" {
		t.Fatalf("observedIP = %v, want 192.168.65.1", got.ObservedIP)
	}
}

func TestPeerAddrString(t *testing.T) {
	cases := []struct {
		addr PeerAddr
		want string
	}{
		{PeerAddr{IP: net.ParseIP("1.2.3.4"), Port: 4661}, "1.2.3.4:4661"},
		{PeerAddr{IP: net.ParseIP("2001:db8::1"), Port: 4661}, "[2001:db8::1]:4661"},
	}
	for _, c := range cases {
		got := c.addr.String()
		t.Logf("%v -> %s", c.addr.IP, got)
		if got != c.want {
			t.Errorf("String() = %q, want %q", got, c.want)
		}
	}
}
