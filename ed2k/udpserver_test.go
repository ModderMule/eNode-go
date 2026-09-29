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
// as before (the v4-mapped path does not pin a source).
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
