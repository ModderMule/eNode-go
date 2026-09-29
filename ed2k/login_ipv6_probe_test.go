package ed2k

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"enode/storage"
)

// loginV6WithProbe runs one login from remote on an IPv6-publishing runtime, with
// the IPv6 dial-back stubbed to reachable, and returns the session, the bytes it
// wrote and how many times the dial-back was consulted. The IPv4 dial-back is
// stubbed to "firewalled" so a v4 remote never dials either.
func loginV6WithProbe(t *testing.T, remote string, probeIPv6, reachable bool) (*tcpClient, []byte, int) {
	t.Helper()
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address:           "127.0.0.1",
		Port:              4661,
		Hash:              []byte("1111111111111111"),
		AllowLowIDs:       true,
		ConnectionTimeout: 50 * time.Millisecond,
		IPv6:              true,
		PublishV6Sources:  true,
		ProbeIPv6:         probeIPv6,
	}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	rt.firewallProbe = func(*tcpClient) bool { return true }
	probes := 0
	rt.ipv6Probe = func(*tcpClient) bool {
		probes++
		return reachable
	}
	client, conn := newReflectClient(t, rt, remote)
	client.handlePacket(loginPacket(t, bytes.Repeat([]byte{0x6a}, 16), 0, 4662))
	return client, conn.written(), probes
}

// TestLoginProbesIPv6ConnectedSessions pins that a session which arrived over
// IPv6 is dialled back before its address is published. The connection proves
// only that the client can reach the server; a stateful IPv6 firewall still drops
// the unsolicited SYN a peer sends to the eD2K port, so trusting the address would
// publish firewalled clients as IPv6 sources and route IPv6 callbacks to them.
func TestLoginProbesIPv6ConnectedSessions(t *testing.T) {
	cases := []struct {
		name          string
		probeIPv6     bool
		reachable     bool // what the stubbed IPv6 dial-back reports
		wantProbes    int
		wantReachable bool
		wantStatus    uint8
	}{
		{
			name:          "reachable v6 port is verified",
			probeIPv6:     true,
			reachable:     true,
			wantProbes:    1,
			wantReachable: true,
			wantStatus:    IPv6StatusHave | IPv6StatusReachable | IPv6StatusProbed,
		},
		{
			name:          "firewalled v6 port is not published",
			probeIPv6:     true,
			reachable:     false,
			wantProbes:    1,
			wantReachable: false,
			wantStatus:    IPv6StatusHave | IPv6StatusProbed,
		},
		{
			name:          "probing off trusts the address without dialling",
			probeIPv6:     false,
			reachable:     false,
			wantProbes:    0,
			wantReachable: true,
			wantStatus:    IPv6StatusHave | IPv6StatusReachable,
		},
	}

	const remote = "2001:db8::1"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, written, probes := loginV6WithProbe(t, remote, tc.probeIPv6, tc.reachable)
			info := client.snapshotInfo()
			t.Logf("input: peer=%s probeIPv6=%t dialBackSaysReachable=%t", remote, tc.probeIPv6, tc.reachable)
			t.Logf("output: logged=%t lowID=%t ipv6=%s ipv6Reachable=%t dialBackCalls=%d",
				client.isLogged(), info.LowID, net.IP(info.IPv6), info.IPv6Reachable, probes)

			if !client.isLogged() {
				t.Fatalf("login was rejected: %q", client.getCloseReason())
			}
			if !bytes.Equal(info.IPv6, net.ParseIP(remote).To16()) {
				t.Fatalf("ipv6 = %s, want the connecting address %s", net.IP(info.IPv6), remote)
			}
			if probes != tc.wantProbes {
				t.Fatalf("IPv6 dial-back called %d time(s), want %d", probes, tc.wantProbes)
			}
			if info.IPv6Reachable != tc.wantReachable {
				t.Fatalf("ipv6Reachable = %t, want %t", info.IPv6Reachable, tc.wantReachable)
			}
			src := storage.Source{ID: info.ID, Port: info.Port, IPv6: info.IPv6, IPv6Reachable: info.IPv6Reachable}
			if got := sourceHasReachableIPv6(src); got != tc.wantReachable {
				t.Fatalf("published as IPv6 source = %t, want %t", got, tc.wantReachable)
			}

			// The status the client receives must report what the login path did.
			tags := parseServerIdentTags(t, NewBufferFromBytes(frameOfOpcode(t, written, OpServerIdent)))
			got, ok := tags["ipv6status"]
			if !ok {
				t.Fatalf("OP_SERVERIDENT carries no ipv6status, want 0x%02x", tc.wantStatus)
			}
			var status uint8
			switch v := got.(type) {
			case uint8:
				status = v
			case uint32:
				status = uint8(v)
			case uint64:
				status = uint8(v)
			default:
				t.Fatalf("ipv6status has unexpected type %T", got)
			}
			t.Logf("output: ipv6status=0x%02x", status)
			if status != tc.wantStatus {
				t.Fatalf("ipv6status = 0x%02x, want 0x%02x", status, tc.wantStatus)
			}
		})
	}
}

// frameOfOpcode returns the whole framed packet (header included) carrying the
// wanted opcode from a captured stream, for helpers that parse from the header.
// Framing matches payloadOfOpcode: protocol(1) + size(4 LE) + opcode(1) + payload.
func frameOfOpcode(t *testing.T, raw []byte, opcode byte) []byte {
	t.Helper()
	for off := 0; off+6 <= len(raw); {
		size := int(binary.LittleEndian.Uint32(raw[off+1 : off+5]))
		if size < 1 || off+5+size > len(raw) {
			t.Fatalf("malformed frame at offset %d: size=%d, %d bytes remain", off, size, len(raw)-off-5)
		}
		if raw[off] == PrED2K && raw[off+5] == opcode {
			return raw[off : off+5+size]
		}
		off += 5 + size
	}
	t.Fatalf("no packet with opcode 0x%02x in the %d bytes written", opcode, len(raw))
	return nil
}
