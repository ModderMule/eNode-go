//go:build unix

package ed2k

import (
	"net"
	"syscall"
)

// readWaiterFor returns the socket under conn when the read loop can wait for data
// on it without holding a buffer, nil otherwise. Only a bare *net.TCPConn
// qualifies: a wrapper may hold bytes of its own that the socket no longer shows.
func readWaiterFor(conn net.Conn) syscall.RawConn {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	rc, err := tcp.SyscallConn()
	if err != nil {
		return nil
	}
	return rc
}

// waitReadable blocks until the socket has data, has reached EOF or has failed,
// honouring the read deadline. It reads nothing, so the caller needs a buffer only
// once there is something to read.
func waitReadable(rc syscall.RawConn) error {
	return rc.Read(socketReadable)
}

// socketReadable peeks one byte. It answers false only while the socket has nothing
// yet (EAGAIN), which makes RawConn.Read park on the poller and ask again. It must
// look at the socket itself rather than wait first: the poller is edge-triggered,
// and data left over from an earlier read raises no new edge. EOF and errors count
// as readable, so the Read that follows reports them.
func socketReadable(fd uintptr) bool {
	var b [1]byte
	_, _, err := syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK)
	return err != syscall.EAGAIN
}
