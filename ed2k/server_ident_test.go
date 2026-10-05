package ed2k

import (
	"encoding/binary"
	"testing"

	"enode/storage"
)

// serverIPFromIdentPacket extracts the advertised IP from an OP_SERVERIDENT
// packet: protocol(1) size(4) opcode(1) hash(16) ip(4).
func serverIPFromIdentPacket(t *testing.T, packet *Buffer) uint32 {
	t.Helper()
	raw := packet.Bytes()
	const ipOffset = 1 + 4 + 1 + 16
	if len(raw) < ipOffset+4 {
		t.Fatalf("packet too short: %d bytes", len(raw))
	}
	return binary.LittleEndian.Uint32(raw[ipOffset : ipOffset+4])
}

// cfg.Address is the bind address and defaults to the 0.0.0.0 wildcard, which
// IPv4ToInt32LE encodes as 0 with no error — so every OP_SERVERIDENT advertised
// server IP 0.0.0.0. The UDP path already fell back to DynIP; the TCP ident path
// had no such fallback.
func TestSendServerIdentPrefersAdvertisedIP(t *testing.T) {
	cases := []struct {
		name         string
		address      string
		advertisedIP string
		wantIP       string
	}{
		{"a routable bind address is used as-is", "203.0.113.7", "203.0.113.7", "203.0.113.7"},
		{"the wildcard falls back to the advertised IP", "0.0.0.0", "198.51.100.4", "198.51.100.4"},
		{"no advertised IP keeps the old behaviour", "0.0.0.0", "", "0.0.0.0"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := NewServerRuntime(TCPRuntimeConfig{
				Name:         "test",
				Address:      tc.address,
				AdvertisedIP: tc.advertisedIP,
				Port:         4661,
				Hash:         []byte("1111111111111111"),
			}, UDPRuntimeConfig{}, storage.NewMemoryEngine())

			packet, err := BuildServerIdentPacket(ServerConfig{
				Name:    rt.tcp().Name,
				Address: rt.advertisedAddress(),
				Hash:    rt.tcp().Hash,
				TCPPort: rt.tcp().Port,
			})
			if err != nil {
				t.Fatal(err)
			}

			wantIP, err := IPv4ToInt32LE(tc.wantIP)
			if err != nil {
				t.Fatal(err)
			}
			gotIP := serverIPFromIdentPacket(t, packet)
			t.Logf("input: address=%q advertisedIP=%q", tc.address, tc.advertisedIP)
			t.Logf("output: advertised server IP encodes to %d (want %d for %s)", gotIP, wantIP, tc.wantIP)

			if gotIP != wantIP {
				t.Fatalf("advertised IP mismatch: got %d, want %d (%s)", gotIP, wantIP, tc.wantIP)
			}
		})
	}
}

// The bind address must not be replaced by the advertised one: probeClient uses
// TCP.Address as its dialer LocalAddr and special-cases the wildcard there. If
// the advertised IP leaked into it, the firewall probe would try to bind a
// source address the host may not own — and every client would land on LowID.
func TestAdvertisedIPDoesNotChangeBindAddress(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address:      "0.0.0.0",
		AdvertisedIP: "198.51.100.4",
		Port:         4661,
	}, UDPRuntimeConfig{}, storage.NewMemoryEngine())

	t.Logf("input: address=%q advertisedIP=%q", rt.tcp().Address, rt.tcp().AdvertisedIP)
	t.Logf("output: bind address=%q advertised=%q", rt.tcp().Address, rt.advertisedAddress())

	if rt.tcp().Address != "0.0.0.0" {
		t.Fatalf("bind address was changed to %q", rt.tcp().Address)
	}
	if rt.advertisedAddress() != "198.51.100.4" {
		t.Fatalf("advertised address is %q", rt.advertisedAddress())
	}
}
