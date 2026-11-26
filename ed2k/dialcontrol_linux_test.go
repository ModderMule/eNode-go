//go:build linux

package ed2k

import (
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestDialBackControlSharesPorts pins that a dial-back socket bound to a source IP
// carries IP_BIND_ADDRESS_NO_PORT, on IPv4 and IPv6, so its ephemeral port is picked
// at connect time and not reserved for every destination.
func TestDialBackControlSharesPorts(t *testing.T) {
	for _, tc := range []struct{ network, ip string }{{"tcp4", "127.0.0.1"}, {"tcp6", "::1"}} {
		ln, err := net.Listen(tc.network, net.JoinHostPort(tc.ip, "0"))
		if err != nil {
			t.Logf("input: %s, output: no loopback (%v), skipped", tc.network, err)
			continue
		}
		go func() {
			if c, err := ln.Accept(); err == nil {
				c.Close()
			}
		}()
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(tc.ip)}, Control: dialBackControl}
		conn, err := d.Dial(tc.network, ln.Addr().String())
		if err != nil {
			ln.Close()
			t.Fatalf("%s dial: %v", tc.network, err)
		}
		raw, _ := conn.(*net.TCPConn).SyscallConn()
		var v int
		var gerr error
		_ = raw.Control(func(fd uintptr) {
			v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BIND_ADDRESS_NO_PORT)
		})
		conn.Close()
		ln.Close()
		t.Logf("input: %s dial from %s, output: IP_BIND_ADDRESS_NO_PORT=%d err=%v", tc.network, tc.ip, v, gerr)
		if gerr != nil && gerr != syscall.ENOPROTOOPT {
			t.Fatalf("%s getsockopt: %v", tc.network, gerr)
		}
		if gerr == nil && v != 1 {
			t.Fatalf("%s: IP_BIND_ADDRESS_NO_PORT=%d, want 1", tc.network, v)
		}
	}
}
