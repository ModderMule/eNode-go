package ed2k

import (
	"encoding/binary"
	"net"
	"testing"

	"enode/storage"
)

// OP_IDCHANGE +12 tells a LowID client its public IPv4. A client reached over a
// private or loopback address (LAN, hairpin NAT, docker bridge) would adopt that
// address as its public IP (MFC ServerSocket.cpp SetPublicIP), so a LowID gets 0.
func TestIDChangeOmitsLANAddress(t *testing.T) {
	for _, tc := range []struct {
		remote string
		want   uint32
	}{
		{"192.168.1.20", 0},
		{"10.0.0.7", 0},
		{"127.0.0.1", 0},
		{"203.0.113.9", binary.LittleEndian.Uint32(net.ParseIP("203.0.113.9").To4())},
	} {
		rt := NewServerRuntime(TCPRuntimeConfig{Address: "127.0.0.1", Port: 4661}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
		conn := &captureConn{mockConn: mockConn{remote: &net.TCPAddr{IP: net.ParseIP(tc.remote), Port: 50000}}}
		c := newTCPClient(rt, conn, false)
		c.infoMu.Lock()
		c.info.IPv4 = binary.LittleEndian.Uint32(net.ParseIP(tc.remote).To4())
		c.infoMu.Unlock()

		c.sendIDChange(1234)
		b := conn.written()
		got := binary.LittleEndian.Uint32(b[6+12 : 6+16])
		t.Logf("input: remote=%s, output: +12=%#08x", tc.remote, got)
		if got != tc.want {
			t.Fatalf("remote %s: +12 = %#08x, want %#08x", tc.remote, got, tc.want)
		}
	}
}
