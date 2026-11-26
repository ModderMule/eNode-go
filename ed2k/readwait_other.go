//go:build !unix

package ed2k

import (
	"net"
	"syscall"
)

// readWaiterFor returns nil: on this platform the read loop blocks in Read with a
// buffer in hand, as before readwait_unix.go.
func readWaiterFor(net.Conn) syscall.RawConn { return nil }

func waitReadable(syscall.RawConn) error { return nil }
