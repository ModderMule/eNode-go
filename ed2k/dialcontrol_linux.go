//go:build linux

package ed2k

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// dialBackControl sets IP_BIND_ADDRESS_NO_PORT on a dial-back socket. A dial-back
// binds its source IP before it connects (dialBackSource), and a bind to port 0
// otherwise reserves an ephemeral port for every destination at once. With the
// option the kernel picks the port at connect time and only needs the four-tuple
// to be unique, so dial-backs to different clients can share a port. Without it,
// login bursts run out of ports: each probe holds its port for its own time and the
// 60 s TIME_WAIT after the server closes it, and net.ipv4.ip_local_port_range has
// about 28,000 of them.
//
// The option is best effort: a kernel before 4.2 rejects it and the dial goes on
// as before.
func dialBackControl(_, _ string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BIND_ADDRESS_NO_PORT, 1)
	})
}
