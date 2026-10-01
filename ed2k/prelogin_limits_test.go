package ed2k

import (
	"encoding/binary"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"enode/storage"
)

// The read deadline is pushed out by every read, so a socket that never logs in
// (or trickles a byte now and then) used to live for disconnectTimeout, 3600 s by
// default, after every byte. Until login the deadline is capped at accept +
// loginTimeout, however much arrives.
func TestLoginTimeoutReapsTricklingSocket(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{Address: "127.0.0.1", Port: 4661,
		DisconnectTimeout: time.Hour, LoginTimeout: 300 * time.Millisecond}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	server, client := net.Pipe()
	t.Cleanup(func() { client.Close() })
	c := newTCPClient(rt, server, false)
	done := make(chan struct{})
	go func() { c.run(); close(done) }()

	start := time.Now()
	stop := make(chan struct{})
	go func() { // one header byte every 100 ms, never a whole packet
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
				_, _ = client.Write([]byte{PrED2K})
			}
		}
	}()
	defer close(stop)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pre-login socket outlived the login timeout")
	}
	t.Logf("input: a byte every 100ms, loginTimeout=300ms; output: closed after %s reason=%q",
		time.Since(start).Round(10*time.Millisecond), c.getCloseReason())
	if !strings.HasPrefix(c.getCloseReason(), "login-timeout") {
		t.Fatalf("want login-timeout, got %q", c.getCloseReason())
	}
}

// Before login a header declaring a large payload is refused at the header: it used
// to reserve the declared size (up to 2 MB) per connection before any payload came.
func TestPreLoginOversizedHeaderClosesWithoutBuffering(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{Address: "127.0.0.1", Port: 4661}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	c := newTCPClient(rt, &mockConn{}, false)

	header := []byte{PrED2K, 0, 0, 0, 0, OpLoginRequest}
	binary.LittleEndian.PutUint32(header[1:5], 2_000_000)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	c.handleBytes(header)
	runtime.ReadMemStats(&after)
	t.Logf("input: pre-login header % x, output: closeReason=%q allocated=%d bytes",
		header, c.getCloseReason(), after.TotalAlloc-before.TotalAlloc)
	if c.getCloseReason() != "prelogin-packet-too-large" {
		t.Fatalf("want prelogin-packet-too-large, got %q", c.getCloseReason())
	}

	other := newTCPClient(rt, &mockConn{}, false)
	other.handleBytes([]byte{PrED2K, 2, 0, 0, 0, OpGetServerList, 0})
	t.Logf("input: pre-login OP_GETSERVERLIST, output: closeReason=%q", other.getCloseReason())
	if other.getCloseReason() != "not-logged-in" {
		t.Fatalf("want not-logged-in at the header, got %q", other.getCloseReason())
	}
}

// After login a large packet still only allocates what has arrived.
func TestPacketBufferGrowsWithData(t *testing.T) {
	header := []byte{PrED2K, 0, 0, 0, 0, OpOfferFiles}
	binary.LittleEndian.PutUint32(header[1:5], 2_000_000)
	p := NewPacket()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := p.Init(NewBufferFromBytes(header)); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("input: header declaring %d bytes, no payload; output: status=%d allocated=%d bytes", 2_000_000, p.Status, allocated)
	if p.Status != PsWaitingData || allocated > 2*packetInitialCap {
		t.Fatalf("status=%d allocated=%d, want waiting and at most %d", p.Status, allocated, 2*packetInitialCap)
	}
}

// One address may hold at most MaxConnsPerIP connections, across both listeners;
// the limit frees up as connections close.
func TestTCPHandlerCapsConnectionsPerIP(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{Address: "127.0.0.1", Port: 4661, MaxConnsPerIP: 2}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	handler := rt.TCPHandler(false)

	var wg sync.WaitGroup
	var clients []net.Conn
	open := func(remote string) net.Conn {
		server, client := net.Pipe()
		conn := &remoteConn{Conn: server, remote: &net.TCPAddr{IP: net.ParseIP(remote), Port: 50000}}
		wg.Add(1)
		go func() { defer wg.Done(); handler(conn) }()
		clients = append(clients, client)
		return client
	}
	alive := func(c net.Conn) bool {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err := c.Read(make([]byte, 1))
		ne, ok := err.(net.Error)
		return ok && ne.Timeout()
	}

	same := []net.Conn{open("198.51.100.7"), open("198.51.100.7"), open("198.51.100.7")}
	d := open("198.51.100.8")
	// The handlers race for the two slots, so which of the three loses is not fixed.
	var kept []net.Conn
	for _, c := range same {
		if alive(c) {
			kept = append(kept, c)
		}
	}
	otherAlive := alive(d)
	t.Logf("input: 3 connections from one address and 1 from another, limit 2; output: %d kept, other alive=%t", len(kept), otherAlive)
	if len(kept) != 2 || !otherAlive {
		t.Fatalf("want 2 of 3 kept and the other address unaffected")
	}
	kept[0].Close()
	time.Sleep(100 * time.Millisecond)
	e := open("198.51.100.7")
	t.Logf("output: after one closes, a new one is alive=%t", alive(e))
	if !alive(e) {
		t.Fatal("a freed slot was not reusable")
	}
	for _, cl := range clients {
		cl.Close()
	}
	wg.Wait()
}

// remoteConn gives a net.Pipe end a TCP remote address.
type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (r *remoteConn) RemoteAddr() net.Addr { return r.remote }
