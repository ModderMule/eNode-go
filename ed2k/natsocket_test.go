package ed2k

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// natRecConn is a fake reply conn: one instance per datagram, as RunUDPServer hands
// out, recording which instance each write left from.
type natRecConn struct {
	name string
	port int
	log  *natSendLog
}

type natSendLog struct {
	mu    sync.Mutex
	sends []string
}

func (c *natRecConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	op, _, _ := decodeNATPacket(b)
	c.log.mu.Lock()
	c.log.sends = append(c.log.sends, fmt.Sprintf("%s->%s via %s", natOpcodeLabel(op), addr, c.name))
	c.log.mu.Unlock()
	return len(b), nil
}

func (c *natRecConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: c.port}
}

func (l *natSendLog) take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.sends
	l.sends = nil
	return out
}

func natHandle(h *NATTraversalHandler, log *natSendLog, name string, port int, data []byte, remote *net.UDPAddr) {
	h.HandlePacket(data, remote, &natRecConn{name: name, port: port, log: log})
}

// readUDPFrom is readUDP plus the source the datagram came from.
func readUDPFrom(conn *net.UDPConn) ([]byte, *net.UDPAddr) {
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 1500)
	n, from, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil
	}
	return buf[:n], from
}

func listenLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// A candidate past the TTL but not yet swept is gone: SYNC2 gets FAILED 0x01 (or a
// wake), its keepalive no PING and no session touch.
func TestNatExpiryBeforeSweep(t *testing.T) {
	hashA := bytes.Repeat([]byte{0xa1}, 16)
	hashB := bytes.Repeat([]byte{0xb2}, 16)
	remoteA := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4672}
	remoteB := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 4673}

	h := NewNATTraversalHandler(50 * time.Millisecond)
	touched := 0
	h.SetSessionTouch(func([16]byte) { touched++ })
	h.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, 2004)
	time.Sleep(80 * time.Millisecond)

	outs := h.processPacket(encodeNATPacket(OpNatSync2, sync2Payload(hashA, hashB, 1)), remoteA, 2004)
	t.Logf("input: B registered, aged past TTL, not swept; SYNC2 A->B, output: %v (entries=%d)", outOpcodes(outs), h.entryCount())
	if len(outs) != 1 {
		t.Fatalf("want one FAILED, got %v", outOpcodes(outs))
	}
	if op, payload, _ := decodeNATPacket(outs[0].packet); op != OpNatFailed || payload[0] != natFailReasonNotRegistered {
		t.Fatalf("want FAILED 0x01, got %s %x", natOpcodeLabel(op), payload)
	}

	for _, ka := range [][]byte{{0x00}, encodeNATPacket(OpNatKeepAlive, nil)} {
		outs = h.processPacket(ka, remoteB, 2004)
		t.Logf("input: keepalive len=%d from expired B, output: %v, touched=%d", len(ka), outOpcodes(outs), touched)
		if len(outs) != 0 || touched != 0 {
			t.Fatalf("expired keepalive answered: %v, touched=%d", outOpcodes(outs), touched)
		}
	}

	// It re-registers and is live again.
	h.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, 2004)
	outs = h.processPacket([]byte{0x00}, remoteB, 2004)
	if len(outs) != 1 || touched != 1 {
		t.Fatalf("keepalive after re-register: %v touched=%d", outOpcodes(outs), touched)
	}

	// With a wake hook the expired target is woken instead.
	h2 := NewNATTraversalHandler(50 * time.Millisecond)
	rec := &wakeRecorder{accept: true}
	h2.SetSessionWake(rec.wake)
	h2.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, 2004)
	time.Sleep(80 * time.Millisecond)
	outs = h2.processPacket(encodeNATPacket(OpNatSync2, sync2Payload(hashA, hashB, 1)), remoteA, 2004)
	t.Logf("input: same with wake hook, output: %v wakes=%v pending=%d", outOpcodes(outs), rec.calls, h2.pendingWakes())
	if len(outs) != 0 || rec.count() != 1 || h2.pendingWakes() != 1 {
		t.Fatalf("expired target not woken: %v wakes=%v", outOpcodes(outs), rec.calls)
	}
}

// The expired candidate no longer pins its hash to its IP.
func TestNatExpiredCandidateDoesNotPin(t *testing.T) {
	h := NewNATTraversalHandler(50 * time.Millisecond)
	hash := bytes.Repeat([]byte{0xc3}, 16)
	h.processPacket(encodeNATPacket(OpNatRegister, hash), &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4672}, 2004)
	other := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 4672}
	if ok, _ := h.registerAllowed([16]byte(hash), other); ok {
		t.Fatal("live candidate did not pin")
	}
	time.Sleep(80 * time.Millisecond)
	ok, reason := h.registerAllowed([16]byte(hash), other)
	t.Logf("input: other IP after TTL, output: allowed=%t %s", ok, reason)
	if !ok {
		t.Fatal("expired candidate still pins")
	}
}

// Real sockets: the target registered on socket A, the requester's SYNC2 came on B.
// The target's SYNC leaves from A, the requester's from B.
func TestNatForwardLeavesFromTargetSocket(t *testing.T) {
	h := NewNATTraversalHandler(time.Minute)
	sockA, sockB, sockC := listenLoopback(t), listenLoopback(t), listenLoopback(t)
	peerR, peerT := listenLoopback(t), listenLoopback(t)
	hashR := bytes.Repeat([]byte{0x11}, 16)
	hashT := bytes.Repeat([]byte{0x22}, 16)
	rAddr, tAddr := peerR.LocalAddr().(*net.UDPAddr), peerT.LocalAddr().(*net.UDPAddr)

	h.HandlePacket(encodeNATPacket(OpNatRegister, hashT), tAddr, sockA)
	if _, from := readUDPFrom(peerT); !sameEndpoint(from, sockA.LocalAddr().(*net.UDPAddr)) {
		t.Fatalf("ack from %v, want socket A", from)
	}
	h.HandlePacket(encodeNATPacket(OpNatSync2, sync2Payload(hashR, hashT, 5)), rAddr, sockB)
	gotR, fromR := readUDPFrom(peerR)
	gotT, fromT := readUDPFrom(peerT)
	opR, _, _ := decodeNATPacket(gotR)
	opT, _, _ := decodeNATPacket(gotT)
	t.Logf("input: T REGISTER on A=%s, R SYNC2 on B=%s; output: R got %s from %v, T got %s from %v",
		sockA.LocalAddr(), sockB.LocalAddr(), natOpcodeLabel(opR), fromR, natOpcodeLabel(opT), fromT)
	if opR != OpNatSync || !sameEndpoint(fromR, sockB.LocalAddr().(*net.UDPAddr)) {
		t.Fatalf("requester SYNC from %v, want socket B", fromR)
	}
	if opT != OpNatSync || !sameEndpoint(fromT, sockA.LocalAddr().(*net.UDPAddr)) {
		t.Fatalf("target SYNC from %v, want socket A", fromT)
	}

	// A keepalive on C moves the target's socket to C.
	h.HandlePacket([]byte{0x00}, tAddr, sockC)
	if got, from := readUDPFrom(peerT); got == nil || !sameEndpoint(from, sockC.LocalAddr().(*net.UDPAddr)) {
		t.Fatalf("PING from %v, want socket C", from)
	}
	h.HandlePacket(encodeNATPacket(OpNatSync2, sync2Payload(hashR, hashT, 6)), rAddr, sockB)
	readUDPFrom(peerR)
	_, fromT = readUDPFrom(peerT)
	t.Logf("input: T keepalive on C, R SYNC2 on B; output: T SYNC from %v", fromT)
	if !sameEndpoint(fromT, sockC.LocalAddr().(*net.UDPAddr)) {
		t.Fatalf("target SYNC from %v after keepalive on C, want C", fromT)
	}
}

// IPv6 forwards follow the target's socket too.
func TestNatForwardIPv6FromTargetSocket(t *testing.T) {
	h := NewNATTraversalHandler(time.Minute)
	h.SetIPv6Enabled(true)
	log := &natSendLog{}
	hashR := bytes.Repeat([]byte{0x11}, 16)
	hashT := bytes.Repeat([]byte{0x22}, 16)
	rAddr := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4672}
	tAddr := &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 4673}
	natHandle(h, log, "t-register@2004", 2004, encodeNATPacket(OpNatRegister, hashT), tAddr)
	natHandle(h, log, "r-sync2@5559", 5559, encodeNATPacket(OpNatSync2, sync2Payload(hashR, hashT, 1)), rAddr)
	sends := log.take()
	t.Logf("input: T v6 REGISTER on 2004, R v6 SYNC2 on 5559; output: %v", sends)
	want := []string{
		"OP_NATREGISTER_IPV6(0xec)->" + tAddr.String() + " via t-register@2004",
		"OP_NATSYNC_IPV6(0xed)->" + rAddr.String() + " via r-sync2@5559",
		"OP_NATSYNC_IPV6(0xed)->" + tAddr.String() + " via t-register@2004",
	}
	if fmt.Sprint(sends) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", sends, want)
	}
}

// A wake completed by the target's REGISTER: the requester's SYNC leaves through the
// conn of its own SYNC2, the target's from the conn its REGISTER came on.
func TestNatWakeCompleteSockets(t *testing.T) {
	h := NewNATTraversalHandler(time.Minute)
	h.SetSessionWake((&wakeRecorder{accept: true}).wake)
	log := &natSendLog{}
	hashR := bytes.Repeat([]byte{0xa1}, 16)
	hashT := bytes.Repeat([]byte{0xb2}, 16)
	rAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4672}
	tAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 4673}
	natHandle(h, log, "r-sync2@5559", 5559, encodeNATPacket(OpNatSync2, sync2Payload(hashR, hashT, 1)), rAddr)
	natHandle(h, log, "t-register@2004", 2004, encodeNATPacket(OpNatRegister, hashT), tAddr)
	sends := log.take()
	t.Logf("output: %v", sends)
	want := []string{
		"OP_NATREGISTER(0xe4)->" + tAddr.String() + " via t-register@2004",
		"OP_NATSYNC(0xe1)->" + rAddr.String() + " via r-sync2@5559",
		"OP_NATSYNC(0xe1)->" + tAddr.String() + " via t-register@2004",
	}
	if fmt.Sprint(sends) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", sends, want)
	}
}

// A wake ended by the IPv6 grace: the requester's SYNC through the conn of its SYNC2
// (not an earlier datagram's, not the target's), the target's from its REGISTER socket.
func TestNatWakeGraceSockets(t *testing.T) {
	oldGrace := natWakeIPv6Grace
	natWakeIPv6Grace = 50 * time.Millisecond
	defer func() { natWakeIPv6Grace = oldGrace }()
	h := NewNATTraversalHandler(time.Minute)
	h.SetIPv6Enabled(true)
	h.SetSessionWake((&wakeRecorder{accept: true}).wake)
	log := &natSendLog{}
	hashR := bytes.Repeat([]byte{0xa1}, 16)
	hashT := bytes.Repeat([]byte{0xb2}, 16)
	rAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4672}
	tAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 4673}

	natHandle(h, log, "r-register@5559", 5559, encodeNATPacket(OpNatRegister, hashR), rAddr)
	h.upsert([16]byte(hashR), &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4672}, 0, 0)
	natHandle(h, log, "r-sync2@5559", 5559, encodeNATPacket(OpNatSync2, sync2Payload(hashR, hashT, 2)), rAddr)
	natHandle(h, log, "t-register@2004", 2004, encodeNATPacket(OpNatRegister, hashT), tAddr)
	log.take()
	time.Sleep(150 * time.Millisecond)
	sends := log.take()
	t.Logf("input: R dual-stack SYNC2 on 5559, T IPv4 REGISTER on 2004, grace ends; output: %v", sends)
	want := []string{
		"OP_NATSYNC(0xe1)->" + rAddr.String() + " via r-sync2@5559",
		"OP_NATSYNC(0xe1)->" + tAddr.String() + " via t-register@2004",
	}
	if fmt.Sprint(sends) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", sends, want)
	}
}

// A wake that times out: FAILED 0x01 through the conn of the requester's SYNC2.
func TestNatWakeTimeoutSocket(t *testing.T) {
	old := natWakeTimeout
	natWakeTimeout = 50 * time.Millisecond
	defer func() { natWakeTimeout = old }()
	h := NewNATTraversalHandler(time.Minute)
	h.SetSessionWake((&wakeRecorder{accept: true}).wake)
	log := &natSendLog{}
	hashR := bytes.Repeat([]byte{0xa1}, 16)
	hashT := bytes.Repeat([]byte{0xb2}, 16)
	rAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4672}
	natHandle(h, log, "r-register@2004", 2004, encodeNATPacket(OpNatRegister, hashR), rAddr)
	natHandle(h, log, "r-sync2@5559", 5559, encodeNATPacket(OpNatSync2, sync2Payload(hashR, hashT, 3)), rAddr)
	log.take()
	time.Sleep(150 * time.Millisecond)
	sends := log.take()
	t.Logf("input: SYNC2 on 5559, target never registers; output: %v", sends)
	want := "OP_NATFAILED(0xe5)->" + rAddr.String() + " via r-sync2@5559"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("got %v, want [%s]", sends, want)
	}
}

// Real sockets through the timer path: after the grace the requester's SYNC leaves from
// the socket of its SYNC2, the target's from the socket it registered on.
func TestNatWakeGraceRealSockets(t *testing.T) {
	oldGrace := natWakeIPv6Grace
	natWakeIPv6Grace = 50 * time.Millisecond
	defer func() { natWakeIPv6Grace = oldGrace }()
	h := NewNATTraversalHandler(time.Minute)
	h.SetIPv6Enabled(true)
	h.SetSessionWake((&wakeRecorder{accept: true}).wake)
	sockA, sockB := listenLoopback(t), listenLoopback(t)
	peerR, peerT := listenLoopback(t), listenLoopback(t)
	hashR := bytes.Repeat([]byte{0xa1}, 16)
	hashT := bytes.Repeat([]byte{0xb2}, 16)
	rAddr, tAddr := peerR.LocalAddr().(*net.UDPAddr), peerT.LocalAddr().(*net.UDPAddr)

	h.HandlePacket(encodeNATPacket(OpNatRegister, hashR), rAddr, sockB)
	readUDPFrom(peerR)
	h.upsert([16]byte(hashR), &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4672}, 0, 0)
	h.HandlePacket(encodeNATPacket(OpNatSync2, sync2Payload(hashR, hashT, 4)), rAddr, sockB)
	h.HandlePacket(encodeNATPacket(OpNatRegister, hashT), tAddr, sockA)
	readUDPFrom(peerT) // ack
	_, fromR := readUDPFrom(peerR)
	_, fromT := readUDPFrom(peerT)
	t.Logf("input: R SYNC2 on B=%s, T REGISTER on A=%s; output: R SYNC from %v, T SYNC from %v",
		sockB.LocalAddr(), sockA.LocalAddr(), fromR, fromT)
	if !sameEndpoint(fromR, sockB.LocalAddr().(*net.UDPAddr)) || !sameEndpoint(fromT, sockA.LocalAddr().(*net.UDPAddr)) {
		t.Fatalf("R from %v (want B), T from %v (want A)", fromR, fromT)
	}
}
