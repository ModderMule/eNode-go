package ed2k

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// wakeRecorder is a SetSessionWake hook that records its calls.
type wakeRecorder struct {
	mu     sync.Mutex
	calls  []byte // families per call
	accept bool
}

func (w *wakeRecorder) wake(_ [16]byte, families byte) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, families)
	return w.accept
}

func (w *wakeRecorder) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.calls)
}

func sync2Payload(src, dst []byte, connAck byte) []byte {
	return append(append(append([]byte(nil), src...), connAck, 0, 0, 0), dst...)
}

func outOpcodes(outs []natOutbound) []string {
	var s []string
	for _, o := range outs {
		op, _, _ := decodeNATPacket(o.packet)
		s = append(s, natOpcodeLabel(op)+"->"+o.to.String())
	}
	return s
}

func TestNatWakePairsOnRegister(t *testing.T) {
	h := NewNATTraversalHandler(time.Minute)
	rec := &wakeRecorder{accept: true}
	h.SetSessionWake(rec.wake)
	hashA := bytes.Repeat([]byte{0xa1}, 16)
	hashB := bytes.Repeat([]byte{0xb2}, 16)
	remoteA := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4672}
	remoteB := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 4673}

	h.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, 2004)
	outs := h.processPacket(encodeNATPacket(OpNatSync2, sync2Payload(hashA, hashB, 7)), remoteA, 2004)
	t.Logf("SYNC2 A->B (B unregistered): outs=%v wakes=%v pending=%d", outOpcodes(outs), rec.calls, h.pendingWakes())
	if len(outs) != 0 || rec.count() != 1 || rec.calls[0] != NatWakeIPv4 || h.pendingWakes() != 1 {
		t.Fatalf("want no answer, one IPv4 wake and one pending; got %v, %v, %d", outOpcodes(outs), rec.calls, h.pendingWakes())
	}
	// A repeated SYNC2 joins the wait without waking again.
	h.processPacket(encodeNATPacket(OpNatSync2, sync2Payload(hashA, hashB, 7)), remoteA, 2004)
	if rec.count() != 1 {
		t.Fatalf("repeated SYNC2 woke again: %v", rec.calls)
	}

	outs = h.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, 2004)
	t.Logf("REGISTER B: outs=%v pending=%d", outOpcodes(outs), h.pendingWakes())
	if len(outs) != 3 {
		t.Fatalf("want ack + 2 SYNCs, got %v", outOpcodes(outs))
	}
	if op, _, _ := decodeNATPacket(outs[0].packet); op != OpNatRegister || !sameEndpoint(outs[0].to, remoteB) {
		t.Fatalf("first out %v, want the ack to B", outOpcodes(outs[:1]))
	}
	opA, payA, _ := decodeNATPacket(outs[1].packet)
	opB, payB, _ := decodeNATPacket(outs[2].packet)
	if opA != OpNatSync || !sameEndpoint(outs[1].to, remoteA) || !bytes.Equal(payA[6:22], hashB) || payA[22] != 7 {
		t.Fatalf("SYNC to A wrong: %x to %s", payA, outs[1].to)
	}
	if opB != OpNatSync || !sameEndpoint(outs[2].to, remoteB) || !bytes.Equal(payB[6:22], hashA) {
		t.Fatalf("SYNC to B wrong: %x to %s", payB, outs[2].to)
	}
	if h.pendingWakes() != 0 {
		t.Fatalf("pending not cleared: %d", h.pendingWakes())
	}
}

func TestNatWakeTimesOutWithFailed(t *testing.T) {
	old := natWakeTimeout
	natWakeTimeout = 100 * time.Millisecond
	defer func() { natWakeTimeout = old }()

	h := NewNATTraversalHandler(time.Minute)
	h.SetSessionWake((&wakeRecorder{accept: true}).wake)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	remote := client.LocalAddr().(*net.UDPAddr)
	hashA := bytes.Repeat([]byte{0xa1}, 16)
	hashB := bytes.Repeat([]byte{0xb2}, 16)

	h.HandlePacket(encodeNATPacket(OpNatSync2, sync2Payload(hashA, hashB, 9)), remote, server)
	start := time.Now()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no answer after the wake timeout: %v", err)
	}
	op, payload, _ := decodeNATPacket(buf[:n])
	t.Logf("after %v: opcode=%s payload=%x", time.Since(start).Round(time.Millisecond), natOpcodeLabel(op), payload)
	if op != OpNatFailed || payload[0] != natFailReasonNotRegistered || !bytes.Equal(payload[1:17], hashB) {
		t.Fatalf("want FAILED 0x01 for B, got %s %x", natOpcodeLabel(op), payload)
	}
	if h.pendingWakes() != 0 {
		t.Fatalf("pending not cleared: %d", h.pendingWakes())
	}
}

func TestNatWakeRefusals(t *testing.T) {
	hashA := bytes.Repeat([]byte{0xa1}, 16)
	hashB := bytes.Repeat([]byte{0xb2}, 16)
	remoteA := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4672}
	cases := []struct {
		name  string
		setup func(h *NATTraversalHandler)
	}{
		{"no hook", func(h *NATTraversalHandler) {}},
		{"session without the bit", func(h *NATTraversalHandler) { h.SetSessionWake((&wakeRecorder{}).wake) }},
		{"pending full", func(h *NATTraversalHandler) {
			h.SetSessionWake((&wakeRecorder{accept: true}).wake)
			for i := 0; i < natWakeMaxPending; i++ {
				h.pending[[16]byte{byte(i), byte(i >> 8), 0xff}] = &natWakePending{}
			}
		}},
		{"restricted, requester not local", func(h *NATTraversalHandler) {
			h.SetSessionWake((&wakeRecorder{accept: true}).wake)
			h.SetServerIndependent(false)
			h.SetLocalMembership(func(hash [16]byte) bool { return hash[0] == 0xb2 })
		}},
	}
	for _, tc := range cases {
		h := NewNATTraversalHandler(time.Minute)
		tc.setup(h)
		outs := h.processPacket(encodeNATPacket(OpNatSync2, sync2Payload(hashA, hashB, 1)), remoteA, 2004)
		t.Logf("input: %s, output: %v", tc.name, outOpcodes(outs))
		if len(outs) != 1 {
			t.Fatalf("%s: want one FAILED, got %v", tc.name, outOpcodes(outs))
		}
		op, payload, _ := decodeNATPacket(outs[0].packet)
		if op != OpNatFailed || payload[0] != natFailReasonNotRegistered {
			t.Fatalf("%s: want FAILED 0x01, got %s %x", tc.name, natOpcodeLabel(op), payload)
		}
	}
}

// A woken target that registers over a family that was not asked for completes nothing.
func TestNatWakeIgnoresOtherFamily(t *testing.T) {
	h := NewNATTraversalHandler(time.Minute)
	h.SetIPv6Enabled(true)
	h.SetSessionWake((&wakeRecorder{accept: true}).wake)
	hashA := bytes.Repeat([]byte{0xa1}, 16)
	hashB := bytes.Repeat([]byte{0xb2}, 16)
	remoteA := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4672}
	h.processPacket(encodeNATPacket(OpNatSync2, sync2Payload(hashA, hashB, 1)), remoteA, 2004)
	outs := h.processPacket(encodeNATPacket(OpNatRegister, hashB), &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 4673}, 2004)
	t.Logf("v6 requester, target registers over IPv4: outs=%v pending=%d", outOpcodes(outs), h.pendingWakes())
	if len(outs) != 1 || h.pendingWakes() != 1 {
		t.Fatalf("want only the ack and the wait kept, got %v pending=%d", outOpcodes(outs), h.pendingWakes())
	}
	outs = h.processPacket(encodeNATPacket(OpNatRegister, hashB), &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 4673}, 2004)
	t.Logf("target registers over IPv6: outs=%v", outOpcodes(outs))
	if len(outs) != 3 {
		t.Fatalf("want ack + 2 SYNC_IPV6, got %v", outOpcodes(outs))
	}
	if op, _, _ := decodeNATPacket(outs[1].packet); op != OpNatSyncIPv6 {
		t.Fatalf("want SYNC_IPV6, got %s", natOpcodeLabel(op))
	}
}

// End to end through the runtime: the SYNC2 sends OP_NAT_WAKE over the target's TCP
// session, and the target's REGISTER brings the SYNC to the requester's socket.
func TestNatWakeThroughRuntime(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{Port: 4661, AllowLowIDs: true, Flags: FlagNatWake},
		UDPRuntimeConfig{}, nil)
	nat := NewNATTraversalHandler(time.Minute)
	rt.SetNATHandler(nat)
	handler := rt.UDPHandler(false)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	a, _, aUDP := natSession(t, rt, 3, false, 0x5a)
	b, bTCP, bUDP := natSession(t, rt, 5, false, 0x6b)
	b.infoMu.Lock()
	b.natWakeCapable = true
	b.infoMu.Unlock()
	rt.registerSession(b.info.Hash, b)
	_ = a

	sync2 := sync2Payload(bytes.Repeat([]byte{0x5a}, 16), bytes.Repeat([]byte{0x6b}, 16), 3)
	handler(encodeNATPacket(OpNatSync2, sync2), aUDP.LocalAddr().(*net.UDPAddr), server)
	wake := payloadOfOpcode(t, bTCP.written(), OpNatWake)
	t.Logf("TCP to B after SYNC2: OP_NAT_WAKE payload=%x", wake)
	if len(wake) != 1 || wake[0] != NatWakeIPv4 {
		t.Fatalf("OP_NAT_WAKE payload %x, want 01", wake)
	}

	handler(encodeNATPacket(OpNatRegister, bytes.Repeat([]byte{0x6b}, 16)), bUDP.LocalAddr().(*net.UDPAddr), server)
	gotA := readUDP(aUDP)
	opA, payA, _ := decodeNATPacket(gotA)
	t.Logf("A got %s %x", natOpcodeLabel(opA), payA)
	if opA != OpNatSync || int(payA[4])<<8|int(payA[5]) != bUDP.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("A: want SYNC with B's port, got %s %x", natOpcodeLabel(opA), payA)
	}
	ack, sync := readUDP(bUDP), readUDP(bUDP)
	opAck, _, _ := decodeNATPacket(ack)
	opSync, _, _ := decodeNATPacket(sync)
	t.Logf("B got %s then %s", natOpcodeLabel(opAck), natOpcodeLabel(opSync))
	if opAck != OpNatRegister || opSync != OpNatSync {
		t.Fatalf("B: want ack then SYNC")
	}
}

func TestBuildFlagsNatRendezvousAndWake(t *testing.T) {
	udp := BuildUDPFlags(UDPServerConfig{NatRendezvous: true, NatWake: true})
	tcp := BuildTCPFlags(TCPServerConfig{NatRendezvous: true, NatWake: true})
	off := BuildUDPFlags(UDPServerConfig{})
	t.Logf("input: rendezvous+wake on, output: udp=0x%x tcp=0x%x, off: udp=0x%x", udp, tcp, off)
	if udp&FlagNatRendezvous == 0 || udp&FlagNatWake == 0 || tcp&FlagNatWake == 0 || off&(FlagNatRendezvous|FlagNatWake) != 0 {
		t.Fatal("UDP/TCP flags do not follow NatRendezvous/NatWake")
	}
}

func TestLoginNatWakeBit(t *testing.T) {
	for _, tc := range []struct {
		server, login uint32
		want          bool
	}{
		{FlagNatWake, SrvCapNatWake, true},
		{FlagNatWake, 0, false},
		{0, SrvCapNatWake, false},
	} {
		c, _ := natLogin(t, tc.server, tc.login, "203.0.113.9")
		c.infoMu.RLock()
		got := c.natWakeCapable
		c.infoMu.RUnlock()
		t.Logf("input: server=0x%x login=0x%x, output: natWakeCapable=%t", tc.server, tc.login, got)
		if got != tc.want {
			t.Fatalf("natWakeCapable=%t, want %t", got, tc.want)
		}
	}
}

// A dual-stack requester: the target's IPv4 REGISTER arrives first, its IPv6 inside the
// grace, and the pairing is IPv6.
func TestNatWakePrefersIPv6WithinGrace(t *testing.T) {
	h := NewNATTraversalHandler(time.Minute)
	h.SetIPv6Enabled(true)
	h.SetSessionWake((&wakeRecorder{accept: true}).wake)
	hashA := bytes.Repeat([]byte{0xa1}, 16)
	hashB := bytes.Repeat([]byte{0xb2}, 16)
	h.processPacket(encodeNATPacket(OpNatRegister, hashA), &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4672}, 2004)
	h.processPacket(encodeNATPacket(OpNatSync2, sync2Payload(hashA, hashB, 1)), &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4672}, 2004)
	outs := h.processPacket(encodeNATPacket(OpNatRegister, hashB), &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 4673}, 2004)
	t.Logf("target IPv4 first: outs=%v pending=%d", outOpcodes(outs), h.pendingWakes())
	if len(outs) != 1 || h.pendingWakes() != 1 {
		t.Fatalf("IPv4 REGISTER paired before the IPv6 one: %v", outOpcodes(outs))
	}
	outs = h.processPacket(encodeNATPacket(OpNatRegister, hashB), &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 4673}, 2004)
	t.Logf("target IPv6 next: outs=%v", outOpcodes(outs))
	if len(outs) != 3 {
		t.Fatalf("want ack + 2 SYNC_IPV6, got %v", outOpcodes(outs))
	}
	if op, _, _ := decodeNATPacket(outs[1].packet); op != OpNatSyncIPv6 {
		t.Fatalf("want SYNC_IPV6, got %s", natOpcodeLabel(op))
	}
}

// Only the target's IPv4 arrives: the grace ends and the pairing is IPv4, sent to both.
func TestNatWakeFallsBackToIPv4AfterGrace(t *testing.T) {
	oldGrace := natWakeIPv6Grace
	natWakeIPv6Grace = 50 * time.Millisecond
	defer func() { natWakeIPv6Grace = oldGrace }()
	h := NewNATTraversalHandler(time.Minute)
	h.SetIPv6Enabled(true)
	h.SetSessionWake((&wakeRecorder{accept: true}).wake)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	peerA, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer peerA.Close()
	peerB, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer peerB.Close()
	hashA := bytes.Repeat([]byte{0xa1}, 16)
	hashB := bytes.Repeat([]byte{0xb2}, 16)
	aAddr := peerA.LocalAddr().(*net.UDPAddr)

	h.HandlePacket(encodeNATPacket(OpNatRegister, hashA), aAddr, server)
	readUDP(peerA) // ack
	h.upsert([16]byte(hashA), &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4672}, 0, 0)
	h.HandlePacket(encodeNATPacket(OpNatSync2, sync2Payload(hashA, hashB, 2)), aAddr, server)
	h.HandlePacket(encodeNATPacket(OpNatRegister, hashB), peerB.LocalAddr().(*net.UDPAddr), server)
	ack := readUDP(peerB)
	start := time.Now()
	gotA, gotB := readUDP(peerA), readUDP(peerB)
	opAck, _, _ := decodeNATPacket(ack)
	opA, _, _ := decodeNATPacket(gotA)
	opB, _, _ := decodeNATPacket(gotB)
	t.Logf("after the grace (%v): B ack=%s, A got %s, B got %s", time.Since(start).Round(time.Millisecond),
		natOpcodeLabel(opAck), natOpcodeLabel(opA), natOpcodeLabel(opB))
	if opAck != OpNatRegister || opA != OpNatSync || opB != OpNatSync {
		t.Fatalf("want IPv4 SYNC to both after the grace")
	}
}
