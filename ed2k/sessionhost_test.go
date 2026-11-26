package ed2k

import (
	"fmt"
	"net"
	"testing"
	"unsafe"

	"enode/storage"
)

// TestTCPClientSizeClass pins a session to Go's 448-byte size class. It was 480
// while the module and remoteHost strings were fields; a new field that crosses 448
// costs every session 32 bytes, so it should take a byte of padding or replace one.
func TestTCPClientSizeClass(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("size pinned for 64-bit")
	}
	got := unsafe.Sizeof(tcpClient{})
	t.Logf("input: tcpClient{}, output: %d bytes (size class limit 448)", got)
	if got > 448 {
		t.Fatalf("tcpClient is %d bytes, over the 448-byte size class", got)
	}
}

// TestSessionRemoteHost pins what remoteHost prints: the normalised peer address,
// or the RemoteAddr host of a connection that is not TCP, and the module from the
// listener. Passing it to a log call must not allocate.
func TestSessionRemoteHost(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{Address: "127.0.0.1", Port: 4661}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	cases := []struct {
		remote net.Addr
		crypt  bool
		host   string
		module string
	}{
		{&net.TCPAddr{IP: net.ParseIP("::ffff:198.51.100.7"), Port: 4662}, false, "198.51.100.7", "tcp"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8::5"), Port: 4662}, true, "2001:db8::5", "tcp-obfs"},
		{&net.UnixAddr{Name: "pipe", Net: "unix"}, false, "pipe", "tcp"},
	}
	for _, tc := range cases {
		c := newTCPClient(rt, &mockConn{remote: tc.remote}, tc.crypt)
		host, module := c.remoteHost().String(), c.module()
		t.Logf("input: remote=%s crypt=%t, output: host=%q module=%q", tc.remote, tc.crypt, host, module)
		if host != tc.host || module != tc.module {
			t.Errorf("got host=%q module=%q, want %q %q", host, module, tc.host, tc.module)
		}
		if got := fmt.Sprintf("remote=%s", c.remoteHost()); got != "remote="+tc.host {
			t.Errorf("formatted %q", got)
		}
	}

	c := newTCPClient(rt, &mockConn{}, false)
	var sink any
	allocs := testing.AllocsPerRun(100, func() { sink = c.remoteHost() })
	t.Logf("input: box remoteHost() into an interface, output: %.0f allocations (%v)", allocs, sink)
	if allocs != 0 {
		t.Fatalf("remoteHost() allocated %.0f times when boxed", allocs)
	}
}
