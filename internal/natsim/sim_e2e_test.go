package natsim

import (
	"context"
	"net"
	"testing"
	"time"

	"enode/ed2k"
)

// startNATServer binds a loopback UDP socket and drives every datagram through a
// real ed2k.NATTraversalHandler — the same handler the server wires onto its UDP
// listeners. It announces its own address as the register endpoint so the sims'
// SYNC2/keepalives return to this socket. Returns the server address.
func startNATServer(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr)
	handler := ed2k.NewNATTraversalHandler(time.Minute)
	handler.SetRegisterEndpoint("127.0.0.1", uint16(addr.Port))
	t.Logf("nat server listening on %s (announce 127.0.0.1:%d)", addr.String(), addr.Port)

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return // socket closed on cleanup
			}
			pkt := append([]byte(nil), buf[:n]...)
			handler.HandlePacket(pkt, remote, conn)
		}
	}()
	t.Cleanup(func() {
		conn.Close()
		<-done
	})
	return addr
}

// startNATServerV6 is the IPv6 twin of startNATServer: it binds ::1, enables
// dual-stack hole-punching, and announces [::1]:port in the v6 REGISTER ack. Skips
// the test when IPv6 loopback is unavailable.
func startNATServerV6(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr)
	handler := ed2k.NewNATTraversalHandler(time.Minute)
	handler.SetIPv6Enabled(true)
	handler.SetRegisterEndpoint("::1", uint16(addr.Port)) // sets the announce port
	handler.SetRegisterEndpointV6(net.IPv6loopback)
	t.Logf("nat server (v6) listening on %s (announce [::1]:%d)", addr.String(), addr.Port)

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return // socket closed on cleanup
			}
			pkt := append([]byte(nil), buf[:n]...)
			handler.HandlePacket(pkt, remote, conn)
		}
	}()
	t.Cleanup(func() {
		conn.Close()
		<-done
	})
	return addr
}

type testLogger struct{ t *testing.T }

func (l testLogger) Printf(format string, v ...any) { l.t.Logf(format, v...) }

func mkHash(seed byte) [16]byte {
	var h [16]byte
	for i := range h {
		h[i] = seed + byte(i)
	}
	return h
}

type sim1Outcome struct {
	res Sim1Result
	err error
}

// waitReady blocks until the target sim signals registration or fails the test.
func waitReady(t *testing.T, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatalf("target sim did not register in time")
	}
}

// TestSimEndToEndHolePunch drives the full rendezvous over loopback UDP: target
// (sim1) registers, initiator (sim2) pairs via OP_NAT_SYNC2, both receive the
// peer endpoint and complete a PING/PONG hole-punch.
func TestSimEndToEndHolePunch(t *testing.T) {
	serverAddr := startNATServer(t)
	lg := testLogger{t}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hashTarget := mkHash(0xa1)
	hashInitiator := mkHash(0xb2)
	t.Logf("input: target hash=%x initiator hash=%x nat=%s", hashTarget, hashInitiator, serverAddr)

	ready := make(chan struct{}, 1)
	sim1Done := make(chan sim1Outcome, 1)
	go func() {
		res, err := RunSim1(ctx, Sim1Options{
			NATAddr:       serverAddr,
			Hash:          hashTarget,
			Timeout:       5 * time.Second,
			PingAfterSync: true,
			ExitAfterPong: true,
			Ready:         ready,
			Logger:        lg,
		})
		sim1Done <- sim1Outcome{res, err}
	}()
	waitReady(t, ready)

	res2, err2 := RunSim2(ctx, Sim2Options{
		NATAddr: serverAddr,
		Hash:    hashInitiator,
		Peer:    hashTarget,
		Timeout: 5 * time.Second,
		Logger:  lg,
	})
	if err2 != nil {
		t.Fatalf("initiator (sim2) failed: %v", err2)
	}

	var got sim1Outcome
	select {
	case got = <-sim1Done:
	case <-time.After(5 * time.Second):
		t.Fatalf("target (sim1) did not finish")
	}
	if got.err != nil {
		t.Fatalf("target (sim1) failed: %v", got.err)
	}

	t.Logf("output: sim1 registered=%t pingsAnswered=%d sync=%+v", got.res.Registered, got.res.PingsAnswered, got.res.Sync)
	t.Logf("output: sim2 registered=%t gotPong=%t sync=%+v", res2.Registered, res2.GotPong, res2.Sync)

	if !res2.Registered || !res2.GotPong || res2.Sync == nil {
		t.Fatalf("initiator: registered=%t gotPong=%t sync=%v, want true/true/non-nil", res2.Registered, res2.GotPong, res2.Sync)
	}
	if !got.res.Registered || got.res.Sync == nil || got.res.PingsAnswered < 1 {
		t.Fatalf("target: registered=%t sync=%v pingsAnswered=%d, want true/non-nil/>=1", got.res.Registered, got.res.Sync, got.res.PingsAnswered)
	}
	if got.res.Sync.PeerHash != hashInitiator {
		t.Fatalf("target learned peer hash %x, want initiator %x", got.res.Sync.PeerHash, hashInitiator)
	}
	if res2.Sync.PeerHash != hashTarget {
		t.Fatalf("initiator learned peer hash %x, want target %x", res2.Sync.PeerHash, hashTarget)
	}
	// The server relays the same connAck to both sides.
	if got.res.Sync.ConnAck != res2.Sync.ConnAck {
		t.Fatalf("connAck mismatch: target=%x initiator=%x", got.res.Sync.ConnAck, res2.Sync.ConnAck)
	}
}

// TestSimRegisterExTriggersSyncEx proves feature 1 end-to-end: a target that
// registers with OP_NAT_REGISTER_EX (version>0) is answered with OP_NAT_SYNC_EX,
// while a legacy initiator still gets the plain 26-byte OP_NAT_SYNC.
func TestSimRegisterExTriggersSyncEx(t *testing.T) {
	serverAddr := startNATServer(t)
	lg := testLogger{t}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hashTarget := mkHash(0xc3)
	hashInitiator := mkHash(0xd4)
	t.Logf("input: target registers EX(version=1); initiator registers legacy")

	ready := make(chan struct{}, 1)
	sim1Done := make(chan sim1Outcome, 1)
	go func() {
		res, err := RunSim1(ctx, Sim1Options{
			NATAddr:       serverAddr,
			Hash:          hashTarget,
			Timeout:       5 * time.Second,
			RegisterMode:  "ex",
			Version:       1,
			PingAfterSync: true,
			ExitAfterPong: true,
			Ready:         ready,
			Logger:        lg,
		})
		sim1Done <- sim1Outcome{res, err}
	}()
	waitReady(t, ready)

	res2, err2 := RunSim2(ctx, Sim2Options{
		NATAddr: serverAddr,
		Hash:    hashInitiator,
		Peer:    hashTarget,
		Timeout: 5 * time.Second,
		Logger:  lg,
	})
	if err2 != nil {
		t.Fatalf("initiator (sim2) failed: %v", err2)
	}

	var got sim1Outcome
	select {
	case got = <-sim1Done:
	case <-time.After(5 * time.Second):
		t.Fatalf("target (sim1) did not finish")
	}
	if got.err != nil {
		t.Fatalf("target (sim1) failed: %v", got.err)
	}

	t.Logf("output: target sync=%+v initiator sync=%+v", got.res.Sync, res2.Sync)
	if got.res.Sync == nil || !got.res.Sync.HasVersion {
		t.Fatalf("target registered EX but did not receive SYNC_EX: sync=%+v", got.res.Sync)
	}
	if res2.Sync == nil || res2.Sync.HasVersion {
		t.Fatalf("legacy initiator should receive plain SYNC, got sync=%+v", res2.Sync)
	}
	t.Logf("target got OP_NAT_SYNC_EX (peerVersion=%d), initiator got plain OP_NAT_SYNC", got.res.Sync.PeerVersion)
}

// TestSimEndToEndHolePunchIPv6 is the IPv6 twin of TestSimEndToEndHolePunch: both
// peers register over IPv6 (::1), the initiator pairs via OP_NAT_SYNC2, both receive
// the peer's v6 endpoint via OP_NAT_SYNC_IPV6, and complete a PING/PONG punch. This
// is the "two firewalled IPv6 peers" case the 0x26 callback cannot reach.
func TestSimEndToEndHolePunchIPv6(t *testing.T) {
	serverAddr := startNATServerV6(t)
	lg := testLogger{t}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hashTarget := mkHash(0x71)
	hashInitiator := mkHash(0x82)
	t.Logf("input: IPv6 hole-punch; target hash=%x initiator hash=%x nat=%s", hashTarget, hashInitiator, serverAddr)

	ready := make(chan struct{}, 1)
	sim1Done := make(chan sim1Outcome, 1)
	go func() {
		res, err := RunSim1(ctx, Sim1Options{
			NATAddr:       serverAddr,
			Hash:          hashTarget,
			ListenIP:      net.IPv6loopback,
			Timeout:       5 * time.Second,
			PingAfterSync: true,
			ExitAfterPong: true,
			Ready:         ready,
			Logger:        lg,
		})
		sim1Done <- sim1Outcome{res, err}
	}()
	waitReady(t, ready)

	res2, err2 := RunSim2(ctx, Sim2Options{
		NATAddr:  serverAddr,
		Hash:     hashInitiator,
		Peer:     hashTarget,
		ListenIP: net.IPv6loopback,
		Timeout:  5 * time.Second,
		Logger:   lg,
	})
	if err2 != nil {
		t.Fatalf("initiator (sim2) failed: %v", err2)
	}

	var got sim1Outcome
	select {
	case got = <-sim1Done:
	case <-time.After(5 * time.Second):
		t.Fatalf("target (sim1) did not finish")
	}
	if got.err != nil {
		t.Fatalf("target (sim1) failed: %v", got.err)
	}

	t.Logf("output: sim1 registered=%t pingsAnswered=%d sync=%+v", got.res.Registered, got.res.PingsAnswered, got.res.Sync)
	t.Logf("output: sim2 registered=%t gotPong=%t sync=%+v", res2.Registered, res2.GotPong, res2.Sync)

	if !res2.Registered || !res2.GotPong || res2.Sync == nil {
		t.Fatalf("initiator: registered=%t gotPong=%t sync=%v", res2.Registered, res2.GotPong, res2.Sync)
	}
	if !got.res.Registered || got.res.Sync == nil || got.res.PingsAnswered < 1 {
		t.Fatalf("target: registered=%t sync=%v pingsAnswered=%d", got.res.Registered, got.res.Sync, got.res.PingsAnswered)
	}
	// The learned peer endpoints must be genuine IPv6 — proof the v6 SYNC path ran.
	if ip := res2.Sync.PeerIP; ip.To4() != nil || ip.To16() == nil {
		t.Fatalf("initiator learned non-v6 peer IP %v; v6 sync path not taken", ip)
	}
	if got.res.Sync.PeerHash != hashInitiator {
		t.Fatalf("target learned peer hash %x, want initiator %x", got.res.Sync.PeerHash, hashInitiator)
	}
	if res2.Sync.PeerHash != hashTarget {
		t.Fatalf("initiator learned peer hash %x, want target %x", res2.Sync.PeerHash, hashTarget)
	}
	if got.res.Sync.ConnAck != res2.Sync.ConnAck {
		t.Fatalf("connAck mismatch: target=%x initiator=%x", got.res.Sync.ConnAck, res2.Sync.ConnAck)
	}
}

// TestSimKeepalivePingAck proves feature 2 end-to-end: the server answers each
// accepted keepalive with OP_NAT_PING, which the sim now observes, for both the
// legacy 1-byte and the OP_NAT_KEEPALIVE forms.
func TestSimKeepalivePingAck(t *testing.T) {
	for _, mode := range []string{"legacy", "nat"} {
		t.Run(mode, func(t *testing.T) {
			serverAddr := startNATServer(t)
			lg := testLogger{t}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			ready := make(chan struct{}, 1)
			done := make(chan sim1Outcome, 1)
			go func() {
				res, err := RunSim1(ctx, Sim1Options{
					NATAddr:           serverAddr,
					Hash:              mkHash(0xe5),
					Timeout:           5 * time.Second,
					KeepaliveInterval: 20 * time.Millisecond,
					KeepaliveMode:     mode,
					Ready:             ready,
					Logger:            lg,
				})
				done <- sim1Outcome{res, err}
			}()
			waitReady(t, ready)
			t.Logf("input: keepalive-mode=%s interval=20ms; letting several round-trip", mode)

			// Let several keepalives round-trip, then stop and inspect the count.
			time.Sleep(300 * time.Millisecond)
			cancel()

			var got sim1Outcome
			select {
			case got = <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("sim1 did not finish")
			}
			t.Logf("output: mode=%s natPings=%d", mode, got.res.NatPings)
			if got.res.NatPings < 1 {
				t.Fatalf("expected >=1 OP_NAT_PING keepalive ack (mode=%s), got %d", mode, got.res.NatPings)
			}
		})
	}
}
