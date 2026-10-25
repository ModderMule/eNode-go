package ed2k

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestNATRegisterAndSync2(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetRegisterEndpoint("1.2.3.4", 2004)
	local := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 2004}
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}

	hashA := bytes.Repeat([]byte{0x11}, 16)
	hashB := bytes.Repeat([]byte{0x22}, 16)

	outA := handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, uint16(local.Port))
	outB := handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, uint16(local.Port))
	if len(outA) != 1 || len(outB) != 1 {
		t.Fatalf("register responses mismatch")
	}

	_, payloadA, ok := decodeNATPacket(outA[0].packet)
	if !ok {
		t.Fatalf("bad register packet for A")
	}
	_, payloadB, ok := decodeNATPacket(outB[0].packet)
	if !ok {
		t.Fatalf("bad register packet for B")
	}
	if binary.BigEndian.Uint16(payloadA[0:2]) != uint16(local.Port) {
		t.Fatalf("bad register port A")
	}
	if binary.BigEndian.Uint16(payloadB[0:2]) != uint16(local.Port) {
		t.Fatalf("bad register port B")
	}
	if binary.BigEndian.Uint32(payloadA[2:6]) != binary.BigEndian.Uint32(net.ParseIP("1.2.3.4").To4()) {
		t.Fatalf("bad register ip A")
	}
	if binary.BigEndian.Uint32(payloadB[2:6]) != binary.BigEndian.Uint32(net.ParseIP("1.2.3.4").To4()) {
		t.Fatalf("bad register ip B")
	}

	connAck := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	sync2Payload := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA, uint16(local.Port))
	if len(outs) != 2 {
		t.Fatalf("sync2 responses len=%d", len(outs))
	}

	for _, out := range outs {
		opcode, payload, ok := decodeNATPacket(out.packet)
		if !ok {
			t.Fatalf("bad sync packet")
		}
		if opcode != OpNatSync {
			t.Fatalf("bad opcode %#x", opcode)
		}
		if len(payload) != 26 {
			t.Fatalf("bad payload len=%d", len(payload))
		}
		switch out.to.Port {
		case remoteA.Port:
			if !bytes.Equal(payload[6:22], hashB) {
				t.Fatalf("A packet peer hash mismatch")
			}
			if binary.BigEndian.Uint16(payload[4:6]) != uint16(remoteB.Port) {
				t.Fatalf("A packet peer port mismatch")
			}
		case remoteB.Port:
			if !bytes.Equal(payload[6:22], hashA) {
				t.Fatalf("B packet peer hash mismatch")
			}
			if binary.BigEndian.Uint16(payload[4:6]) != uint16(remoteA.Port) {
				t.Fatalf("B packet peer port mismatch")
			}
		default:
			t.Fatalf("unexpected target port %d", out.to.Port)
		}
		if !bytes.Equal(payload[22:26], connAck) {
			t.Fatalf("connAck mismatch")
		}
	}
}

func TestNATSync2AfterBothRegisteredReturnsNatSync(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.10.0.1"), Port: 31001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.10.0.2"), Port: 31002}

	hashA := []byte{0x46, 0xa7, 0xde, 0xd3, 0x6e, 0x0e, 0xd3, 0xba, 0xbd, 0x84, 0x02, 0xea, 0x5d, 0xfe, 0x6f, 0x7e}
	hashB := []byte{0xe9, 0x27, 0x88, 0xe7, 0x52, 0x0e, 0x75, 0x3c, 0xb6, 0x74, 0xb2, 0xdf, 0x37, 0x45, 0x6f, 0x9f}

	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, 2004); len(got) != 1 {
		t.Fatalf("register A responses len=%d", len(got))
	}
	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, 2004); len(got) != 1 {
		t.Fatalf("register B responses len=%d", len(got))
	}

	connAck := []byte{0xc3, 0x2e, 0x00, 0x15}
	sync2 := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2), remoteA, 2004)
	if len(outs) != 2 {
		t.Fatalf("sync2 responses len=%d", len(outs))
	}

	for i, out := range outs {
		opcode, payload, ok := decodeNATPacket(out.packet)
		if !ok {
			t.Fatalf("decode out[%d] failed", i)
		}
		if opcode != OpNatSync {
			t.Fatalf("out[%d] opcode=%#x want=%#x", i, opcode, OpNatSync)
		}
		if len(payload) != 26 {
			t.Fatalf("out[%d] payload len=%d", i, len(payload))
		}
	}
}

func TestNATSync2TargetNotRegistered(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}

	hashA := bytes.Repeat([]byte{0x33}, 16)
	hashUnknown := bytes.Repeat([]byte{0x44}, 16)

	_ = handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, 2004)
	connAck := []byte{1, 2, 3, 4}
	sync2Payload := append(append(append([]byte(nil), hashA...), connAck...), hashUnknown...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA, 2004)
	if len(outs) != 1 {
		t.Fatalf("responses len=%d", len(outs))
	}

	opcode, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok {
		t.Fatalf("bad nat failed packet")
	}
	if opcode != OpNatFailed {
		t.Fatalf("opcode=%#x", opcode)
	}
	if len(payload) != 17 {
		t.Fatalf("payload len=%d", len(payload))
	}
	if payload[0] != 0x01 {
		t.Fatalf("reason=%d", payload[0])
	}
	if !bytes.Equal(payload[1:], hashUnknown) {
		t.Fatalf("target hash mismatch")
	}
}

func TestNATRegisterUsesConfiguredEndpoint(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetRegisterEndpoint("66.154.127.95", 2004)

	// local is wildcard; response should still use configured public endpoint.
	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	hash := bytes.Repeat([]byte{0x55}, 16)

	outs := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote, 2004)
	if len(outs) != 1 {
		t.Fatalf("responses len=%d", len(outs))
	}
	_, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok || len(payload) != 6 {
		t.Fatalf("bad register ack")
	}

	wantIP := binary.BigEndian.Uint32(net.ParseIP("66.154.127.95").To4())
	gotPort := binary.BigEndian.Uint16(payload[0:2])
	gotIP := binary.BigEndian.Uint32(payload[2:6])
	if gotPort != 2004 {
		t.Fatalf("port=%d", gotPort)
	}
	if gotIP != wantIP {
		t.Fatalf("ip=%d want=%d", gotIP, wantIP)
	}
}

func TestNATRegisterWildcardLocalWithoutConfiguredEndpoint(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)

	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	hash := bytes.Repeat([]byte{0x66}, 16)

	outs := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote, 2004)
	if len(outs) != 1 {
		t.Fatalf("responses len=%d", len(outs))
	}
	_, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok || len(payload) != 6 {
		t.Fatalf("bad register ack")
	}

	// Without configured endpoint and wildcard bind, response IP is 0.0.0.0.
	gotIP := binary.BigEndian.Uint32(payload[2:6])
	if gotIP != 0 {
		t.Fatalf("ip=%d want=0", gotIP)
	}
}

func TestNATRegisterUsesObfuscatedPortByLocalListener(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetRegisterEndpoint("66.154.127.95", 2004)
	handler.SetRegisterEndpointForLocalPort(5559, 5559)

	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	hash := bytes.Repeat([]byte{0x77}, 16)

	outs := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote, 5559)
	if len(outs) != 1 {
		t.Fatalf("responses len=%d", len(outs))
	}
	_, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok || len(payload) != 6 {
		t.Fatalf("bad register ack")
	}
	gotPort := binary.BigEndian.Uint16(payload[0:2])
	if gotPort != 5559 {
		t.Fatalf("port=%d want=5559", gotPort)
	}
}

func TestNATRegisterOnNatPortReturnsPlainUDPPort(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetRegisterEndpoint("66.154.127.95", 4665)
	handler.SetRegisterEndpointForLocalPort(2004, 4665)
	handler.SetRegisterEndpointForLocalPort(5559, 5559)

	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	hash := bytes.Repeat([]byte{0x7a}, 16)

	outs := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote, 2004)
	if len(outs) != 1 {
		t.Fatalf("responses len=%d", len(outs))
	}
	_, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok || len(payload) != 6 {
		t.Fatalf("bad register ack")
	}
	gotPort := binary.BigEndian.Uint16(payload[0:2])
	if gotPort != 4665 {
		t.Fatalf("port=%d want=4665", gotPort)
	}
}

func TestNATSync2ReturnsSyncExToRegisterExClient(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}

	hashA := bytes.Repeat([]byte{0xa1}, 16)
	hashB := bytes.Repeat([]byte{0xb2}, 16)

	registerA := append(append([]byte(nil), hashA...), byte(1))
	if got := handler.processPacket(encodeNATPacket(OpNatRegisterEx, registerA), remoteA, 2004); len(got) != 1 {
		t.Fatalf("register A responses len=%d", len(got))
	}
	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, 2004); len(got) != 1 {
		t.Fatalf("register B responses len=%d", len(got))
	}

	connAck := []byte{0x12, 0x34, 0x56, 0x78}
	sync2Payload := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA, 2004)
	if len(outs) != 2 {
		t.Fatalf("sync2 responses len=%d", len(outs))
	}

	for _, out := range outs {
		opcode, payload, ok := decodeNATPacket(out.packet)
		if !ok {
			t.Fatalf("decode sync response failed")
		}
		switch out.to.Port {
		case remoteA.Port:
			if opcode != OpNatSyncEx {
				t.Fatalf("A opcode=%#x want=%#x", opcode, OpNatSyncEx)
			}
			if len(payload) != 27 {
				t.Fatalf("A payload len=%d want=27", len(payload))
			}
			if payload[26] != 0 {
				t.Fatalf("A peer version=%d want=0", payload[26])
			}
		case remoteB.Port:
			if opcode != OpNatSync {
				t.Fatalf("B opcode=%#x want=%#x", opcode, OpNatSync)
			}
			if len(payload) != 26 {
				t.Fatalf("B payload len=%d want=26", len(payload))
			}
		default:
			t.Fatalf("unexpected target port %d", out.to.Port)
		}
	}
}

func TestNATRegisterWithLegacyStatsKeepsSyncOpcode(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}

	hashA := bytes.Repeat([]byte{0xc1}, 16)
	hashB := bytes.Repeat([]byte{0xd2}, 16)
	legacyStats := []byte{0x00, 0x03, 0x00, 0x04, 0x00, 0x05}
	registerA := append(append([]byte(nil), hashA...), legacyStats...)
	if got := handler.processPacket(encodeNATPacket(OpNatRegister, registerA), remoteA, 2004); len(got) != 1 {
		t.Fatalf("register A responses len=%d", len(got))
	}
	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, 2004); len(got) != 1 {
		t.Fatalf("register B responses len=%d", len(got))
	}

	connAck := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	sync2Payload := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA, 2004)
	if len(outs) != 2 {
		t.Fatalf("sync2 responses len=%d", len(outs))
	}
	for _, out := range outs {
		opcode, _, ok := decodeNATPacket(out.packet)
		if !ok {
			t.Fatalf("decode sync response failed")
		}
		if opcode != OpNatSync {
			t.Fatalf("opcode=%#x want=%#x", opcode, OpNatSync)
		}
	}
}

func TestNATEntriesSharedAcrossAllListenerPorts(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetRegisterEndpoint("66.154.127.95", 2004)
	handler.SetRegisterEndpointForLocalPort(5559, 5559) // udp obfuscated

	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}

	hashA := bytes.Repeat([]byte{0x88}, 16)
	hashB := bytes.Repeat([]byte{0x99}, 16)

	// Register A from natTraversal.port (example: 2004)
	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, 2004); len(got) != 1 {
		t.Fatalf("register A responses len=%d", len(got))
	}
	// Register B from udp.portObfuscated (example: 5559)
	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, 5559); len(got) != 1 {
		t.Fatalf("register B responses len=%d", len(got))
	}

	// Send sync2 from udp.port and ensure cross-port registry lookup succeeds.
	connAck := []byte{0x12, 0x34, 0x56, 0x78}
	sync2Payload := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA, 5555)
	if len(outs) != 2 {
		t.Fatalf("sync2 responses len=%d", len(outs))
	}
	for i, out := range outs {
		opcode, _, ok := decodeNATPacket(out.packet)
		if !ok {
			t.Fatalf("decode out[%d] failed", i)
		}
		if opcode != OpNatSync {
			t.Fatalf("out[%d] opcode=%#x want=%#x", i, opcode, OpNatSync)
		}
	}
}

func TestNATKeepaliveOneByteRefreshesLastSeen(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	hash := bytes.Repeat([]byte{0xaa}, 16)

	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote, 2004); len(got) != 1 {
		t.Fatalf("register responses len=%d", len(got))
	}
	var key [16]byte
	copy(key[:], hash)
	entryBefore, ok := handler.get(key)
	if !ok {
		t.Fatalf("entry not found after register")
	}

	time.Sleep(5 * time.Millisecond)
	outs := handler.processPacket([]byte{0x42}, remote, 2004)
	if len(outs) != 1 {
		t.Fatalf("keepalive responses len=%d", len(outs))
	}
	opcode, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok {
		t.Fatalf("decode keepalive response failed")
	}
	if opcode != OpNatPing {
		t.Fatalf("keepalive response opcode=%#x want=%#x", opcode, OpNatPing)
	}
	if len(payload) != 0 {
		t.Fatalf("keepalive response payload len=%d want=0", len(payload))
	}

	entryAfter, ok := handler.get(key)
	if !ok {
		t.Fatalf("entry missing after keepalive")
	}
	if !entryAfter.v4.lastSeen.After(entryBefore.v4.lastSeen) {
		t.Fatalf("lastSeen not refreshed: before=%v after=%v", entryBefore.v4.lastSeen, entryAfter.v4.lastSeen)
	}
}

func TestNATKeepaliveOpcodeRefreshesLastSeen(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	hash := bytes.Repeat([]byte{0xbb}, 16)

	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote, 2004); len(got) != 1 {
		t.Fatalf("register responses len=%d", len(got))
	}
	var key [16]byte
	copy(key[:], hash)
	entryBefore, ok := handler.get(key)
	if !ok {
		t.Fatalf("entry not found after register")
	}

	time.Sleep(5 * time.Millisecond)
	outs := handler.processPacket(encodeNATPacket(OpNatKeepAlive, nil), remote, 2004)
	if len(outs) != 1 {
		t.Fatalf("nat keepalive responses len=%d", len(outs))
	}
	opcode, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok {
		t.Fatalf("decode nat keepalive response failed")
	}
	if opcode != OpNatPing {
		t.Fatalf("nat keepalive response opcode=%#x want=%#x", opcode, OpNatPing)
	}
	if len(payload) != 0 {
		t.Fatalf("nat keepalive response payload len=%d want=0", len(payload))
	}

	entryAfter, ok := handler.get(key)
	if !ok {
		t.Fatalf("entry missing after nat keepalive")
	}
	if !entryAfter.v4.lastSeen.After(entryBefore.v4.lastSeen) {
		t.Fatalf("lastSeen not refreshed: before=%v after=%v", entryBefore.v4.lastSeen, entryAfter.v4.lastSeen)
	}
}

func TestNATKeepaliveUnregisteredClientNoPing(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 40009}

	if got := handler.processPacket([]byte{0x42}, remote, 2004); len(got) != 0 {
		t.Fatalf("legacy keepalive for unregistered client should not respond, len=%d", len(got))
	}
	if got := handler.processPacket(encodeNATPacket(OpNatKeepAlive, nil), remote, 2004); len(got) != 0 {
		t.Fatalf("nat keepalive for unregistered client should not respond, len=%d", len(got))
	}
}

// TestNATRegisterIPv6Ack pins the widened v6 register ack: a client that registers
// over IPv6 (with v6-NAT enabled) gets an 18-byte OP_NAT_REGISTER_IPV6 carrying the
// server's public IPv6 and the family-independent announce port.
func TestNATRegisterIPv6Ack(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetIPv6Enabled(true)
	handler.SetRegisterEndpoint("1.2.3.4", 2004) // sets the announce port to 2004
	serverV6 := net.ParseIP("2001:db8::feed").To16()
	handler.SetRegisterEndpointV6(serverV6)
	localPort := uint16(2004)
	v6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40001}
	hash := bytes.Repeat([]byte{0x33}, 16)

	out := handler.processPacket(encodeNATPacket(OpNatRegister, hash), v6, localPort)
	t.Logf("input: OP_NAT_REGISTER from %s (v6 enabled); output: %d outbound", v6, len(out))
	if len(out) != 1 {
		t.Fatalf("v6 register produced %d outbound packets, want 1", len(out))
	}
	opcode, payload, ok := decodeNATPacket(out[0].packet)
	if !ok {
		t.Fatalf("bad register ack packet")
	}
	t.Logf("output: opcode=%s payload=% x", natOpcodeLabel(opcode), payload)
	if opcode != OpNatRegisterIPv6 {
		t.Fatalf("opcode=%#x want OP_NAT_REGISTER_IPV6 %#x", opcode, OpNatRegisterIPv6)
	}
	if len(payload) != 18 {
		t.Fatalf("payload len=%d want 18", len(payload))
	}
	if got := binary.BigEndian.Uint16(payload[0:2]); got != 2004 {
		t.Fatalf("ack port=%d want 2004", got)
	}
	if !bytes.Equal(payload[2:18], serverV6) {
		t.Fatalf("ack ipv6=% x want % x", payload[2:18], serverV6)
	}
	var key [16]byte
	copy(key[:], hash)
	if got := handler.candidateCount(key); got != 1 {
		t.Fatalf("candidateCount=%d want 1 (v6 only)", got)
	}
}

// TestNATSync2PrefersIPv6WhenBothDualStack pins the family selection: two peers that
// each registered on v4 AND v6 are paired on v6, so both get OP_NAT_SYNC_IPV6 with
// the other peer's v6 endpoint (the two-firewalled-v6-peers hole-punch).
func TestNATSync2PrefersIPv6WhenBothDualStack(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetIPv6Enabled(true)
	handler.SetRegisterEndpoint("1.2.3.4", 2004)
	localPort := uint16(2004)

	hashA := bytes.Repeat([]byte{0x11}, 16)
	hashB := bytes.Repeat([]byte{0x22}, 16)
	aV4 := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	aV6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::a"), Port: 50001}
	bV4 := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}
	bV6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::b"), Port: 50002}

	for _, r := range []struct {
		hash []byte
		addr *net.UDPAddr
	}{{hashA, aV4}, {hashA, aV6}, {hashB, bV4}, {hashB, bV6}} {
		handler.processPacket(encodeNATPacket(OpNatRegister, r.hash), r.addr, localPort)
	}
	var keyA, keyB [16]byte
	copy(keyA[:], hashA)
	copy(keyB[:], hashB)
	t.Logf("registry: A candidates=%d, B candidates=%d", handler.candidateCount(keyA), handler.candidateCount(keyB))

	connAck := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	sync2 := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2), aV6, localPort) // SYNC2 over v6
	if len(outs) != 2 {
		t.Fatalf("sync2 responses=%d want 2", len(outs))
	}
	for _, out := range outs {
		opcode, payload, ok := decodeNATPacket(out.packet)
		if !ok {
			t.Fatalf("bad sync packet")
		}
		t.Logf("to %s: opcode=%s payload=% x", out.to, natOpcodeLabel(opcode), payload)
		if opcode != OpNatSyncIPv6 {
			t.Fatalf("opcode=%#x want OP_NAT_SYNC_IPV6 %#x", opcode, OpNatSyncIPv6)
		}
		if len(payload) != 39 {
			t.Fatalf("payload len=%d want 39", len(payload))
		}
		switch {
		case out.to.IP.Equal(aV6.IP): // A gets B's v6 endpoint
			if !bytes.Equal(payload[0:16], bV6.IP.To16()) {
				t.Fatalf("A: peer ipv6=% x want % x", payload[0:16], bV6.IP.To16())
			}
			if got := binary.BigEndian.Uint16(payload[16:18]); got != uint16(bV6.Port) {
				t.Fatalf("A: peer port=%d want %d", got, bV6.Port)
			}
			if !bytes.Equal(payload[18:34], hashB) {
				t.Fatalf("A: peer hash mismatch")
			}
		case out.to.IP.Equal(bV6.IP): // B gets A's v6 endpoint
			if !bytes.Equal(payload[0:16], aV6.IP.To16()) {
				t.Fatalf("B: peer ipv6=% x want % x", payload[0:16], aV6.IP.To16())
			}
			if got := binary.BigEndian.Uint16(payload[16:18]); got != uint16(aV6.Port) {
				t.Fatalf("B: peer port=%d want %d", got, aV6.Port)
			}
			if !bytes.Equal(payload[18:34], hashA) {
				t.Fatalf("B: peer hash mismatch")
			}
		default:
			t.Fatalf("unexpected target %s", out.to)
		}
		if !bytes.Equal(payload[34:38], connAck) {
			t.Fatalf("connAck mismatch")
		}
	}
}

// TestNATSync2FallsBackToIPv4 is the v4 LowID↔LowID regression guard: with v6-NAT
// enabled but neither peer holding a v6 candidate, the pair is served the classic,
// byte-identical OP_NAT_SYNC (26-byte) as before.
func TestNATSync2FallsBackToIPv4(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetIPv6Enabled(true) // enabled, but no v6 candidates -> must fall back to v4
	handler.SetRegisterEndpoint("1.2.3.4", 2004)
	localPort := uint16(2004)
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}
	hashA := bytes.Repeat([]byte{0x11}, 16)
	hashB := bytes.Repeat([]byte{0x22}, 16)

	handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, localPort)
	handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, localPort)

	connAck := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	sync2 := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2), remoteA, localPort)
	if len(outs) != 2 {
		t.Fatalf("sync2 responses=%d want 2", len(outs))
	}
	for _, out := range outs {
		opcode, payload, ok := decodeNATPacket(out.packet)
		if !ok {
			t.Fatalf("bad sync packet")
		}
		t.Logf("to %s: opcode=%s payload=% x", out.to, natOpcodeLabel(opcode), payload)
		if opcode != OpNatSync {
			t.Fatalf("opcode=%#x want OP_NAT_SYNC (v4 fallback)", opcode)
		}
		if len(payload) != 26 {
			t.Fatalf("payload len=%d want 26", len(payload))
		}
	}
}

// TestNATSync2FamilyMismatchFails pins that two peers with no shared address family
// (src v4-only, dst v6-only) cannot punch: the requester gets OP_NAT_FAILED with the
// new no-common-family reason 0x02.
func TestNATSync2FamilyMismatchFails(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetIPv6Enabled(true)
	handler.SetRegisterEndpoint("1.2.3.4", 2004)
	localPort := uint16(2004)
	hashA := bytes.Repeat([]byte{0x11}, 16)
	hashB := bytes.Repeat([]byte{0x22}, 16)
	aV4 := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	bV6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::b"), Port: 50002}

	handler.processPacket(encodeNATPacket(OpNatRegister, hashA), aV4, localPort) // A: v4 only
	handler.processPacket(encodeNATPacket(OpNatRegister, hashB), bV6, localPort) // B: v6 only

	connAck := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	sync2 := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2), aV4, localPort)
	if len(outs) != 1 {
		t.Fatalf("responses=%d want 1 (failed)", len(outs))
	}
	opcode, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok {
		t.Fatalf("bad failed packet")
	}
	t.Logf("input: A(v4-only) SYNC2 -> B(v6-only); output: opcode=%s payload=% x", natOpcodeLabel(opcode), payload)
	if opcode != OpNatFailed {
		t.Fatalf("opcode=%#x want OP_NAT_FAILED", opcode)
	}
	if len(payload) != 17 || payload[0] != natFailReasonNoCommonFamily {
		t.Fatalf("reason=0x%02x len=%d want reason 0x02 len 17", payload[0], len(payload))
	}
	if !bytes.Equal(payload[1:], hashB) {
		t.Fatalf("target hash mismatch")
	}
}

// TestNATDeclinesIPv6WhenDisabled pins that with v6-NAT off (the default) an IPv6
// registrant is still dropped and never stored, while a mapped-v4 peer registers.
func TestNATDeclinesIPv6WhenDisabled(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	// IPv6 left disabled (the default).
	handler.SetRegisterEndpoint("1.2.3.4", 2004)
	localPort := uint16(2004)
	v6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40001}
	hash := bytes.Repeat([]byte{0x33}, 16)

	out := handler.processPacket(encodeNATPacket(OpNatRegister, hash), v6, localPort)
	t.Logf("input: OP_NAT_REGISTER from %s (v6 disabled); output: %d outbound, registry=%d", v6, len(out), handler.entryCount())
	if len(out) != 0 {
		t.Fatalf("v6 register produced %d outbound packets, want 0", len(out))
	}
	if handler.entryCount() != 0 {
		t.Fatalf("v6 register stored %d entries, want 0", handler.entryCount())
	}

	// A dual-stack socket reports an IPv4 peer as ::ffff:a.b.c.d; that mapped form is
	// treated as IPv4 and registers normally even with v6 disabled.
	mapped := &net.UDPAddr{IP: net.ParseIP("::ffff:10.0.0.7"), Port: 40007}
	outV4 := handler.processPacket(encodeNATPacket(OpNatRegister, hash), mapped, localPort)
	t.Logf("input: OP_NAT_REGISTER from mapped %s; output: %d outbound", mapped, len(outV4))
	if len(outV4) != 1 {
		t.Fatalf("mapped-v4 register produced %d outbound, want 1", len(outV4))
	}
	if handler.entryCount() != 1 {
		t.Fatalf("mapped-v4 register stored %d entries, want 1", handler.entryCount())
	}
}

// TestNATRegisterKeepsBothCandidates pins the dual-stack registry: v4 then v6 under
// one hash keeps both slots, and a mapped ::ffff: register lands in the v4 slot
// (replacing it) rather than adding a third candidate.
func TestNATRegisterKeepsBothCandidates(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetIPv6Enabled(true)
	handler.SetRegisterEndpoint("1.2.3.4", 2004)
	localPort := uint16(2004)
	hash := bytes.Repeat([]byte{0x55}, 16)
	var key [16]byte
	copy(key[:], hash)

	v4 := &net.UDPAddr{IP: net.ParseIP("10.0.0.5"), Port: 40005}
	v6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Port: 50005}

	handler.processPacket(encodeNATPacket(OpNatRegister, hash), v4, localPort)
	t.Logf("after v4 register: candidateCount=%d", handler.candidateCount(key))
	handler.processPacket(encodeNATPacket(OpNatRegister, hash), v6, localPort)
	t.Logf("after v6 register: candidateCount=%d", handler.candidateCount(key))
	if got := handler.candidateCount(key); got != 2 {
		t.Fatalf("candidateCount=%d want 2 (v4+v6 under one hash)", got)
	}
	if handler.entryCount() != 1 {
		t.Fatalf("entryCount=%d want 1", handler.entryCount())
	}

	// A mapped ::ffff: register lands in the v4 slot, not a third candidate.
	mapped := &net.UDPAddr{IP: net.ParseIP("::ffff:10.0.0.9"), Port: 40009}
	handler.processPacket(encodeNATPacket(OpNatRegister, hash), mapped, localPort)
	t.Logf("after mapped-v4 register: candidateCount=%d", handler.candidateCount(key))
	if got := handler.candidateCount(key); got != 2 {
		t.Fatalf("candidateCount=%d want 2 (mapped-v4 replaces v4 slot)", got)
	}
}

// hashKey converts a []byte hash into the [16]byte the membership predicate takes.
func hashKey(h []byte) [16]byte {
	var k [16]byte
	copy(k[:], h)
	return k
}

// TestNATSync2RestrictedRefusesNonLocal pins the login gate: a SYNC2 whose target is not logged into this server is refused with
// OP_NAT_FAILED reason 0x03 and nothing is paired.
func TestNATSync2RestrictedRefusesNonLocal(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	localPort := uint16(2004)
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}
	hashA := bytes.Repeat([]byte{0x11}, 16)
	hashB := bytes.Repeat([]byte{0x22}, 16)
	// Only A is logged into this server; B is a cross-server / serverless peer.
	handler.SetLocalMembership(func(h [16]byte) bool { return h == hashKey(hashA) })

	handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, localPort)
	handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, localPort)

	connAck := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	sync2 := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2), remoteA, localPort)
	if len(outs) != 1 {
		t.Fatalf("responses=%d want 1 (failed)", len(outs))
	}
	opcode, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok {
		t.Fatalf("bad failed packet")
	}
	t.Logf("input: dst not local, SYNC2 A->B; output: opcode=%s payload=% x", natOpcodeLabel(opcode), payload)
	if opcode != OpNatFailed {
		t.Fatalf("opcode=%#x want OP_NAT_FAILED", opcode)
	}
	if len(payload) != 17 || payload[0] != natFailReasonRendezvousRestricted {
		t.Fatalf("reason=0x%02x len=%d want reason 0x03 len 17", payload[0], len(payload))
	}
	if !bytes.Equal(payload[1:], hashB) {
		t.Fatalf("target hash mismatch")
	}
}

// TestNATSync2RestrictedAllowsLocal pins that a pair both logged into this server still hole-punches (same-server LowID↔LowID keeps
// working).
func TestNATSync2RestrictedAllowsLocal(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	localPort := uint16(2004)
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}
	hashA := bytes.Repeat([]byte{0x11}, 16)
	hashB := bytes.Repeat([]byte{0x22}, 16)
	// Both are logged in here.
	handler.SetLocalMembership(func(h [16]byte) bool { return h == hashKey(hashA) || h == hashKey(hashB) })

	handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, localPort)
	handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, localPort)

	connAck := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	sync2 := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2), remoteA, localPort)
	t.Logf("input: both local, SYNC2 A->B; output: %d outbound", len(outs))
	if len(outs) != 2 {
		t.Fatalf("sync2 responses=%d want 2 (both local -> paired)", len(outs))
	}
	for _, out := range outs {
		opcode, _, ok := decodeNATPacket(out.packet)
		if !ok || opcode != OpNatSync {
			t.Fatalf("to %s: opcode=%s want OP_NAT_SYNC", out.to, natOpcodeLabel(opcode))
		}
	}
}

// TestNATSync2RestrictedFamilyAgnostic confirms the gate runs before family selection:
// with both peers local over IPv6, the pair is served
// OP_NAT_SYNC_IPV6 — the restriction is orthogonal to the address family.
func TestNATSync2RestrictedFamilyAgnostic(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetIPv6Enabled(true)
	localPort := uint16(2004)
	hashA := bytes.Repeat([]byte{0x11}, 16)
	hashB := bytes.Repeat([]byte{0x22}, 16)
	handler.SetLocalMembership(func(h [16]byte) bool { return h == hashKey(hashA) || h == hashKey(hashB) })

	aV6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::a"), Port: 50001}
	bV6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::b"), Port: 50002}
	handler.processPacket(encodeNATPacket(OpNatRegister, hashA), aV6, localPort)
	handler.processPacket(encodeNATPacket(OpNatRegister, hashB), bV6, localPort)

	connAck := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	sync2 := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2), aV6, localPort)
	t.Logf("input: both local over v6, SYNC2 A->B; output: %d outbound", len(outs))
	if len(outs) != 2 {
		t.Fatalf("sync2 responses=%d want 2 (both local v6 -> paired)", len(outs))
	}
	for _, out := range outs {
		opcode, payload, ok := decodeNATPacket(out.packet)
		if !ok || opcode != OpNatSyncIPv6 {
			t.Fatalf("to %s: opcode=%s want OP_NAT_SYNC_IPV6", out.to, natOpcodeLabel(opcode))
		}
		if len(payload) != 39 {
			t.Fatalf("payload len=%d want 39", len(payload))
		}
	}
}
