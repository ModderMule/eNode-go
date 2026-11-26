//go:build !linux

package ed2k

import "syscall"

// dialBackControl is a no-op outside Linux, which has no IP_BIND_ADDRESS_NO_PORT;
// see dialcontrol_linux.go.
func dialBackControl(_, _ string, _ syscall.RawConn) error { return nil }
