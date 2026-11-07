package ed2k

import (
	"net"
	"testing"
	"time"
)

// TestRunUDPServerRepliesFromArrivalAddress needs two public IPv6 addresses on this
// host. The client sends from address A to address B of a wildcard dual-stack
// listener. Unpinned, the kernel would answer from A (RFC 6724 rule 1 prefers the
// destination itself as source), so a reply from B proves the IPV6_PKTINFO pinning.
func TestRunUDPServerRepliesFromArrivalAddress(t *testing.T) {
	var public []net.IP
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && IsPublicIPv6(ipNet.IP) {
				public = append(public, ipNet.IP)
			}
		}
	}
	if len(public) < 2 {
		t.Skipf("needs two public IPv6 addresses, host has %d", len(public))
	}

	conn, err := RunUDPServer(UDPServerConfig{Port: 0, DualStack: true},
		func(data []byte, remote *net.UDPAddr, reply UDPReplyConn) {
			_, _ = reply.WriteToUDP(append([]byte("re:"), data...), remote)
		})
	if err != nil {
		t.Fatalf("run udp server: %v", err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	from := public[0]
	client, err := net.ListenUDP("udp6", &net.UDPAddr{IP: from})
	if err != nil {
		t.Fatalf("bind client to %s: %v", from, err)
	}
	defer client.Close()
	for _, target := range public[1:] {
		dst := &net.UDPAddr{IP: target, Port: port}
		if _, err := client.WriteToUDP([]byte("ping"), dst); err != nil {
			t.Fatalf("send %s -> %s: %v", from, dst, err)
		}
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		n, replyFrom, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("no reply for %s: %v", dst, err)
		}
		t.Logf("sent from %s to %s -> reply %q from %s", from, dst, buf[:n], replyFrom)
		if !replyFrom.IP.Equal(target) {
			t.Errorf("reply to a datagram sent to %s came from %s", target, replyFrom.IP)
		}
	}
}

// TestRunUDPServerIPv4OnDualStack confirms IPv4 on the dual-stack listener is answered
// over the v4-mapped path, which pins the source on Linux only.
func TestRunUDPServerIPv4OnDualStack(t *testing.T) {
	conn, err := RunUDPServer(UDPServerConfig{Port: 0, DualStack: true},
		func(data []byte, remote *net.UDPAddr, reply UDPReplyConn) {
			_, _ = reply.WriteToUDP(data, remote)
		})
	if err != nil {
		t.Fatalf("run udp server: %v", err)
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: conn.LocalAddr().(*net.UDPAddr).Port}
	client, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("v4")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("no v4 reply: %v", err)
	}
	t.Logf("sent %q to %s -> reply %q", "v4", dst, buf[:n])
}

func TestNativeIPv6(t *testing.T) {
	cases := map[string]bool{"2001:db8::1": true, "::1": true, "::": false, "::ffff:192.0.2.1": false, "192.0.2.1": false}
	for in, want := range cases {
		got := nativeIPv6(net.ParseIP(in)) != nil
		t.Logf("nativeIPv6(%s) = %v", in, got)
		if got != want {
			t.Errorf("nativeIPv6(%s) = %v, want %v", in, got, want)
		}
	}
}

// The IPv4 tests below stand in for two servers on one host, each on its own IPv4 with
// a wildcard bind (bang and razor): on Linux all of 127.0.0.0/8 is local, so 127.0.0.2
// is a second address. Unpinned, the kernel sends to 127.0.0.1 from 127.0.0.1, the
// route's preferred source, so a frame from 127.0.0.2 proves the pin.
var (
	loopbackA = net.IPv4(127, 0, 0, 1).To4()
	loopbackB = net.IPv4(127, 0, 0, 2).To4()
)

// TestRunUDPServerIPv4RepliesFromArrivalAddress: a client at 127.0.0.1 pings the
// listener at 127.0.0.2. The reply must come from 127.0.0.2, or the client (eMule
// matching a server's status reply by IP) drops it.
func TestRunUDPServerIPv4RepliesFromArrivalAddress(t *testing.T) {
	for _, dualStack := range []bool{true, false} {
		t.Run(map[bool]string{true: "dual-stack", false: "udp4"}[dualStack], func(t *testing.T) {
			client := bindSecondLoopback(t, loopbackA)
			conn, err := RunUDPServer(UDPServerConfig{Port: 0, DualStack: dualStack},
				func(data []byte, remote *net.UDPAddr, reply UDPReplyConn) {
					_, _ = reply.WriteToUDP(append([]byte("re:"), data...), remote)
				})
			if err != nil {
				t.Fatalf("run udp server: %v", err)
			}
			defer conn.Close()

			dst := &net.UDPAddr{IP: loopbackB, Port: conn.LocalAddr().(*net.UDPAddr).Port}
			if _, err := client.WriteToUDP([]byte("ping"), dst); err != nil {
				t.Fatalf("send to %s: %v", dst, err)
			}
			payload, from := readOne(t, client)
			t.Logf("input: %q from %s to %s (dualStack=%t)", "ping", client.LocalAddr(), dst, dualStack)
			t.Logf("output: %q from %s", payload, from)
			if !from.IP.Equal(loopbackB) {
				t.Errorf("reply to a datagram sent to %s came from %s", loopbackB, from.IP)
			}
		})
	}
}

// TestRunUDPServerIPv4SourceForForwards: a datagram arrives on 127.0.0.1 and the
// handler forwards to a third party, as PR_NAT does. The forward answers no datagram of
// its own, so it must leave from SourceIPv4 (127.0.0.2), not the arrival address and
// not the kernel's choice.
func TestRunUDPServerIPv4SourceForForwards(t *testing.T) {
	sender := bindSecondLoopback(t, loopbackA)
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopbackA})
	if err != nil {
		t.Fatalf("bind target: %v", err)
	}
	defer target.Close()
	targetAddr := target.LocalAddr().(*net.UDPAddr)

	conn, err := RunUDPServer(UDPServerConfig{Port: 0, DualStack: true, SourceIPv4: loopbackB},
		func(data []byte, remote *net.UDPAddr, reply UDPReplyConn) {
			// The announced IPv6 PR_NAT passes must not stop the IPv4 pin.
			_, _ = WriteToUDPFrom(baseReplyConn(reply), data, targetAddr, net.ParseIP("2001:db8::1"))
		})
	if err != nil {
		t.Fatalf("run udp server: %v", err)
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: loopbackA, Port: conn.LocalAddr().(*net.UDPAddr).Port}
	if _, err := sender.WriteToUDP([]byte("forward-me"), dst); err != nil {
		t.Fatalf("send to %s: %v", dst, err)
	}
	payload, from := readOne(t, target)
	t.Logf("input: %q to %s, SourceIPv4=%s, forward to %s", "forward-me", dst, loopbackB, targetAddr)
	t.Logf("output: %q at the target from %s", payload, from)
	if !from.IP.Equal(loopbackB) {
		t.Errorf("forward came from %s, want SourceIPv4 %s", from.IP, loopbackB)
	}
}

// TestUDPSourceConnIPv4 covers the gossip wrapper: an initiated send leaves from the
// configured IPv4, and one the kernel refuses (an address no interface holds) still
// goes out, unpinned.
func TestUDPSourceConnIPv4(t *testing.T) {
	bindSecondLoopback(t, loopbackA).Close()
	cases := []struct {
		name     string
		src      net.IP
		wantFrom net.IP
	}{
		{name: "assigned source", src: loopbackB, wantFrom: loopbackB},
		{name: "unassigned source falls back", src: net.IPv4(192, 0, 2, 1), wantFrom: loopbackA},
		{name: "no source keeps the kernel's choice", src: nil, wantFrom: loopbackA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopbackA})
			if err != nil {
				t.Fatalf("bind peer: %v", err)
			}
			defer peer.Close()
			listener, err := net.ListenUDP("udp", &net.UDPAddr{})
			if err != nil {
				t.Fatalf("bind listener: %v", err)
			}
			defer listener.Close()

			w := NewUDPSourceConn(listener, tc.src)
			if _, err := w.WriteToUDP([]byte("hello"), peer.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatalf("send: %v", err)
			}
			payload, from := readOne(t, peer)
			t.Logf("input: src=%v to %s", tc.src, peer.LocalAddr())
			t.Logf("output: %q from %s", payload, from)
			if !from.IP.Equal(tc.wantFrom) {
				t.Errorf("frame came from %s, want %s", from.IP, tc.wantFrom)
			}
		})
	}
}

func TestPlainIPv4(t *testing.T) {
	cases := map[string]string{"192.0.2.1": "192.0.2.1", "::ffff:192.0.2.1": "192.0.2.1", "0.0.0.0": "<nil>", "2001:db8::1": "<nil>", "": "<nil>"}
	for in, want := range cases {
		got := plainIPv4(net.ParseIP(in)).String()
		t.Logf("plainIPv4(%q) = %s", in, got)
		if got != want {
			t.Errorf("plainIPv4(%q) = %s, want %s", in, got, want)
		}
	}
}

// bindSecondLoopback skips unless this platform pins IPv4 sources and holds 127.0.0.2
// (Linux), and returns a UDP socket bound to ip.
func bindSecondLoopback(t *testing.T, ip net.IP) *net.UDPConn {
	t.Helper()
	if !IPv4SourcePinning {
		t.Skip("IPv4 source pinning is Linux only")
	}
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopbackB})
	if err != nil {
		t.Skipf("needs 127.0.0.2 on loopback: %v", err)
	}
	probe.Close()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
	if err != nil {
		t.Fatalf("bind %s: %v", ip, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// readOne reads one datagram within two seconds.
func readOne(t *testing.T, conn *net.UDPConn) ([]byte, *net.UDPAddr) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, from, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no datagram reached %s: %v", conn.LocalAddr(), err)
	}
	return buf[:n], from
}
