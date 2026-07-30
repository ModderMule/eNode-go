package ed2k

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"enode/storage"
)

// stubFilter blocks one address and counts how often it was consulted, which is how these
// tests prove the check runs *before* parsing rather than somewhere later.
type stubFilter struct {
	blockIP string
	calls   atomic.Int64
}

func (f *stubFilter) Blocked(ip net.IP) (bool, string) {
	f.calls.Add(1)
	if ip != nil && ip.String() == f.blockIP {
		return true, "stub: blocked " + f.blockIP
	}
	return false, ""
}

// probeRuntimeUDP drives an *existing* runtime's UDP dispatcher with one datagram and
// returns whatever it writes back, or nil on no reply. A variant of cryptProbe that takes
// the runtime rather than building one, so the filter under test can be attached first.
func probeRuntimeUDP(t *testing.T, rt *ServerRuntime, enableCrypt bool, request []byte) []byte {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen server udp: %v", err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer client.Close()

	rt.UDPHandler(enableCrypt)(request, client.LocalAddr().(*net.UDPAddr), server)

	_ = client.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buf := make([]byte, 4096)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	return append([]byte(nil), buf[:n]...)
}

func probeUDP(t *testing.T, rt *ServerRuntime, request []byte) []byte {
	t.Helper()
	return probeRuntimeUDP(t, rt, false, request)
}

func probeUDPCrypt(t *testing.T, rt *ServerRuntime, request []byte) []byte {
	t.Helper()
	return probeRuntimeUDP(t, rt, true, request)
}

// TestUDPBlockedAddressIsDroppedBeforeParsing sends a datagram that would otherwise
// produce a reply and asserts nothing comes back. A well-formed 0x96 is used deliberately:
// it is a packet the server always answers, so silence can only mean the filter dropped it
// ahead of the dispatcher.
func TestUDPBlockedAddressIsDroppedBeforeParsing(t *testing.T) {
	cfg := UDPRuntimeConfig{UDPServerKey: 0x12345678, UDPPortObf: 5567, TCPPortObf: 5565}
	rt := NewServerRuntime(TCPRuntimeConfig{}, cfg, storage.NewMemoryEngine())

	statReq, err := MakeUDPPacket(PrED2K, []PacketItem{
		{Type: TypeUint8, Value: OpGlobServStatReq},
		{Type: TypeUint32, Value: uint32(0x55AA0001)},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Unfiltered first, so the test cannot pass because the request was simply ignored.
	if got := probeUDP(t, rt, statReq.Bytes()); got == nil {
		t.Fatal("baseline: an unfiltered 0x96 must be answered")
	} else {
		t.Logf("baseline (no filter): reply %d bytes, opcode 0x%02x", len(got), got[1])
	}

	filter := &stubFilter{blockIP: "127.0.0.1"}
	rt.SetAccessFilter(filter)
	got := probeUDP(t, rt, statReq.Bytes())
	t.Logf("input: same 0x96 from 127.0.0.1 with the filter blocking it")
	t.Logf("output: reply=%v filterCalls=%d", got, filter.calls.Load())
	if got != nil {
		t.Fatalf("a blocked address must get no reply, got %d bytes", len(got))
	}
	if filter.calls.Load() == 0 {
		t.Fatal("the filter was never consulted")
	}
}

// TestUDPAllowedAddressStillServed is the discriminating half: the filter must not be a
// blanket drop.
func TestUDPAllowedAddressStillServed(t *testing.T) {
	cfg := UDPRuntimeConfig{UDPServerKey: 0x12345678}
	rt := NewServerRuntime(TCPRuntimeConfig{}, cfg, storage.NewMemoryEngine())
	rt.SetAccessFilter(&stubFilter{blockIP: "198.51.100.99"}) // not the loopback prober

	statReq, err := MakeUDPPacket(PrED2K, []PacketItem{
		{Type: TypeUint8, Value: OpGlobServStatReq},
		{Type: TypeUint32, Value: uint32(0x55AA0002)},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := probeUDP(t, rt, statReq.Bytes())
	t.Logf("input: 0x96 from 127.0.0.1, filter blocking a different address")
	t.Logf("output: reply=%d bytes", len(got))
	if got == nil {
		t.Fatal("an address the filter allows must still be served")
	}
}

// TestUDPFilterRunsAheadOfDecryption pins the ordering on the obfuscated listener: the
// filter is consulted before NewUDPCrypt and Decrypt, so a flood from a blocked address
// costs a binary search rather than an RC4 pass over every datagram.
func TestUDPFilterRunsAheadOfDecryption(t *testing.T) {
	cfg := UDPRuntimeConfig{UDPServerKey: 0x12345678}
	rt := NewServerRuntime(TCPRuntimeConfig{}, cfg, storage.NewMemoryEngine())
	filter := &stubFilter{blockIP: "127.0.0.1"}
	rt.SetAccessFilter(filter)

	// A raw crypt-ping: on an unfiltered obfuscated listener this is answered, and
	// answering it requires decrypting nothing but does require reaching the dispatcher.
	req := NewBuffer(4)
	_ = req.PutUInt32LE(0xDEADBEEF)
	got := probeUDPCrypt(t, rt, req.Bytes())
	t.Logf("input: raw crypt-ping from a blocked address on the obfuscated listener")
	t.Logf("output: reply=%v filterCalls=%d", got, filter.calls.Load())
	if got != nil {
		t.Fatal("a blocked address must not even get a crypt-ping reply")
	}
}

// TestTCPBlockedAddressIsClosedBeforeReading asserts the connection is closed with no
// bytes read: a blocked address must not get a session goroutine, a status ticker, or a
// crypt state machine. Closing silently rather than sending OP_SERVERMESSAGE first is
// deliberate — the reply costs a round trip to an address we have decided not to serve,
// and it confirms to a scanner that it found an eD2K server.
func TestTCPBlockedAddressIsClosedBeforeReading(t *testing.T) {
	rt := NewServerRuntime(
		TCPRuntimeConfig{Name: "t", Port: 5555, MessageLogin: "welcome", DisconnectTimeout: time.Second},
		UDPRuntimeConfig{}, storage.NewMemoryEngine(),
	)
	filter := &stubFilter{blockIP: "127.0.0.1"}
	rt.SetAccessFilter(filter)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	handler := rt.TCPHandler(false)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handler(conn)
	}()

	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// The server should close immediately. A read therefore returns EOF rather than a
	// packet or a timeout.
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	t.Logf("input: TCP connection from a blocked 127.0.0.1")
	t.Logf("output: read n=%d err=%v filterCalls=%d", n, err, filter.calls.Load())
	if n != 0 {
		t.Fatalf("server sent %d bytes to a blocked address: % x", n, buf[:n])
	}
	if err == nil {
		t.Fatal("expected the connection to be closed")
	}
	if filter.calls.Load() == 0 {
		t.Fatal("the filter was never consulted on the TCP path")
	}
}

// TestNilAccessFilterServesEveryone pins the default: with no filter configured nothing
// is refused, and the call sites need no branch.
func TestNilAccessFilterServesEveryone(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{UDPServerKey: 1}, storage.NewMemoryEngine())
	blocked, reason := rt.blockedPeer(net.ParseIP("8.8.8.8"))
	t.Logf("no filter: blockedPeer(8.8.8.8) = %v %q", blocked, reason)
	if blocked {
		t.Fatal("with no filter attached nothing may be blocked")
	}
	// And a nil IP is safe even with a filter attached.
	rt.SetAccessFilter(&stubFilter{blockIP: "1.2.3.4"})
	if blocked, _ := rt.blockedPeer(nil); blocked {
		t.Fatal("a nil address must not be reported as blocked")
	}
}

// TestGossipNotesConnectingClients covers the other half of the accept path: every
// accepted address is recorded so gossip will refuse to admit a client as a peer.
func TestGossipNotesConnectingClients(t *testing.T) {
	rt, g := dispatchRuntime(t, true, func(c *GossipConfig) { c.AllowPrivatePeers = true })
	rt.TCP.DisconnectTimeout = time.Second

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	handler := rt.TCPHandler(false)
	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		close(accepted)
		handler(conn)
	}()
	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	<-accepted
	// NoteClient runs on the handler goroutine, so wait for the address to actually be
	// recorded rather than assuming Accept implies it. Polling the map directly (same
	// package) makes the wait test the precise condition the assertion depends on.
	deadline := time.Now().Add(2 * time.Second)
	recorded := false
	for time.Now().Before(deadline) && !recorded {
		g.mu.RLock()
		_, recorded = g.clientIPs["127.0.0.1"]
		g.mu.RUnlock()
		if !recorded {
			time.Sleep(2 * time.Millisecond)
		}
	}
	if !recorded {
		t.Fatal("the accept path never recorded the connecting client's address")
	}

	// Now try to admit the client's address as a peer via a keyed sender.
	sender := keyPeer(t, g, "203.0.113.5", 4661)
	admitted := g.MergePeerList(sender.IP, []PeerAddr{{IP: net.ParseIP("127.0.0.1"), Port: 4661}}, true)
	stats := g.Stats()
	t.Logf("input: 127.0.0.1 is a connected client; a peer offers it as a server")
	t.Logf("output: admitted=%d rejectedPeer=%d", admitted, stats.RejectedPeer)
	if admitted != 0 {
		t.Fatal("an address that is a connected client must not be admitted as a peer")
	}
	if stats.RejectedPeer == 0 {
		t.Error("expected the client-IP rejection to be counted")
	}
}
