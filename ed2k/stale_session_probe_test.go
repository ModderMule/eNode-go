package ed2k

import (
	"bytes"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"enode/storage"
)

// probeConn is a session socket that records what the server writes to it. With
// dead set, it plays a client whose process is gone: the first write draws a TCP
// reset, so the blocked read fails with ECONNRESET, as on a real socket.
type probeConn struct {
	mockConn
	dead bool

	mu     sync.Mutex
	writes [][]byte
	reset  chan struct{}
	once   sync.Once
}

func newProbeConn(remote net.Addr, dead bool) *probeConn {
	return &probeConn{mockConn: mockConn{remote: remote}, dead: dead, reset: make(chan struct{})}
}

func (p *probeConn) Write(b []byte) (int, error) {
	p.mu.Lock()
	p.writes = append(p.writes, append([]byte(nil), b...))
	p.mu.Unlock()
	if p.dead {
		p.once.Do(func() { close(p.reset) })
	}
	return len(b), nil
}

func (p *probeConn) Read(_ []byte) (int, error) {
	<-p.reset
	return 0, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
}

func (p *probeConn) Close() error {
	p.once.Do(func() { close(p.reset) })
	return p.mockConn.Close()
}

// sawOpcode reports whether any write was an ed2k packet with this opcode.
func (p *probeConn) sawOpcode(op uint8) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, w := range p.writes {
		if len(w) > 5 && w[0] == PrED2K && w[5] == op {
			return true
		}
	}
	return false
}

// The crash case: the client's last session was IPv6, it crashed without the close
// reaching the server, and the restart logs in over IPv4. Neither the same-IP nor the
// dual-stack exception matches, but the probe finds the IPv6 session dead, so the new
// login is granted instead of "Already connected from another session".
func TestDuplicateLoginProbeFreesDeadSession(t *testing.T) {
	engine := storage.NewMemoryEngine()
	rt := newHandoverRuntime(engine)
	rt.staleProbeWait = time.Second
	hash := bytes.Repeat([]byte{0xc1}, 16)

	firstConn := newProbeConn(&net.TCPAddr{IP: handoverV6, Port: 50011}, true)
	first := newTCPClient(rt, firstConn, false)
	first.handlePacket(loginPacket(t, hash, 0, 4662))
	if !first.logged {
		t.Fatalf("ipv6 login refused (reason=%q)", first.getCloseReason())
	}
	done := make(chan struct{})
	go func() { first.run(); close(done) }()
	t.Logf("input: ipv6 session hash=%x remote=%s, client process gone", hash, first.remoteHost)

	secondConn := v4Conn()
	second := newTCPClient(rt, secondConn, false)
	start := time.Now()
	second.handlePacket(loginPacket(t, hash, 0, 4662))
	<-done
	t.Logf("output: ipv4 logged=%t closed=%d after %s; old reason=%q probed=%t",
		second.logged, secondConn.closed, time.Since(start).Round(time.Millisecond),
		first.getCloseReason(), firstConn.sawOpcode(OpServerStatus))

	if !firstConn.sawOpcode(OpServerStatus) {
		t.Fatal("the held session was not probed with OP_SERVERSTATUS")
	}
	if !second.logged {
		t.Fatalf("login after the dead session was refused (reason=%q)", second.getCloseReason())
	}
	if got := rt.sessionByHash(hash); got != second {
		t.Fatalf("hash index points at %p, want the new session %p", got, second)
	}
	if !engine.IsConnected(storage.ClientInfo{Hash: hash}) {
		t.Fatal("the new session is not online in storage")
	}
}

// A live session answers the probe with nothing at all — the status packet is one a
// client takes silently — so the duplicate is refused and the session kept. This is
// what keeps the public user hash from being a remote kick.
func TestDuplicateLoginProbeKeepsLiveSession(t *testing.T) {
	engine := storage.NewMemoryEngine()
	rt := newHandoverRuntime(engine)
	rt.staleProbeWait = 100 * time.Millisecond
	hash := bytes.Repeat([]byte{0xc2}, 16)

	firstConn := newProbeConn(&net.TCPAddr{IP: handoverV6, Port: 50011}, false)
	first := newTCPClient(rt, firstConn, false)
	first.handlePacket(loginPacket(t, hash, 0, 4662))
	if !first.logged {
		t.Fatalf("ipv6 login refused (reason=%q)", first.getCloseReason())
	}
	t.Logf("input: live ipv6 session hash=%x remote=%s", hash, first.remoteHost)

	secondConn := v4Conn()
	second := newTCPClient(rt, secondConn, false)
	second.handlePacket(loginPacket(t, hash, 0, 4662))
	t.Logf("output: ipv4 logged=%t reason=%q; old closed=%d probed=%t",
		second.logged, second.getCloseReason(), firstConn.closed, firstConn.sawOpcode(OpServerStatus))

	if !firstConn.sawOpcode(OpServerStatus) {
		t.Fatal("the held session was not probed with OP_SERVERSTATUS")
	}
	if second.logged {
		t.Fatal("a duplicate login took over a live session")
	}
	if got := second.getCloseReason(); got != "duplicate-login" {
		t.Fatalf("refusal reason=%q want %q", got, "duplicate-login")
	}
	if firstConn.closed != 0 || rt.sessionByHash(hash) != first {
		t.Fatal("the live session was kicked")
	}
}
