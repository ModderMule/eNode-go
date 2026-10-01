package ed2k

import (
	"net"
	"testing"
	"time"

	"enode/storage"
)

// natRegistered returns the v4 candidate address registered for hash, or "".
func natRegistered(h *NATTraversalHandler, hash [16]byte) string {
	e, ok := h.get(hash)
	if !ok || e.v4 == nil {
		return ""
	}
	return e.v4.addr.String()
}

// A user hash is public, and REGISTER took any hash from any address: an attacker
// could re-point a victim's punch candidate at itself. A hash logged in here now
// registers only from its session's address.
func TestNATRegisterBoundToLocalSession(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{Address: "127.0.0.1", Port: 4661}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	nat := NewNATTraversalHandler(time.Minute)
	rt.SetNATHandler(nat)

	victim := newTCPClient(rt, &mockConn{remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 50000}}, false)
	var hash [16]byte
	copy(hash[:], "victim-user-hash")
	rt.registerSession(hash[:], victim)

	spoof := &net.UDPAddr{IP: net.ParseIP("203.0.113.66"), Port: 4000}
	nat.processPacket(encodeNATPacket(OpNatRegister, hash[:]), spoof, 2004)
	t.Logf("input: REGISTER for a logged-in hash from %s, output: candidate=%q", spoof, natRegistered(nat, hash))
	if natRegistered(nat, hash) != "" {
		t.Fatal("a REGISTER from another address was accepted for a logged-in hash")
	}

	own := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 4000}
	nat.processPacket(encodeNATPacket(OpNatRegister, hash[:]), own, 2004)
	rebind := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 4111}
	nat.processPacket(encodeNATPacket(OpNatRegister, hash[:]), rebind, 2004)
	t.Logf("input: REGISTER from the session's IP, then a new port; output: candidate=%q", natRegistered(nat, hash))
	if natRegistered(nat, hash) != rebind.String() {
		t.Fatalf("the session's own REGISTER (and a NAT rebinding) must be accepted, got %q", natRegistered(nat, hash))
	}
}

// A hash not logged in here (server-independent rendezvous) has no session to check
// against, so the first live registration holds until it expires: another IP cannot
// take it over, the same IP may change port.
func TestNATRegisterPinsRemoteHash(t *testing.T) {
	nat := NewNATTraversalHandler(200 * time.Millisecond)
	var hash [16]byte
	copy(hash[:], "remote-user-hash")
	first := &net.UDPAddr{IP: net.ParseIP("198.51.100.30"), Port: 4000}
	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.77"), Port: 4000}

	nat.processPacket(encodeNATPacket(OpNatRegister, hash[:]), first, 2004)
	nat.processPacket(encodeNATPacket(OpNatRegister, hash[:]), other, 2004)
	t.Logf("input: REGISTER from %s, then from %s; output: candidate=%q", first, other, natRegistered(nat, hash))
	if natRegistered(nat, hash) != first.String() {
		t.Fatal("a live candidate was taken over from another IP")
	}

	time.Sleep(250 * time.Millisecond)
	nat.processPacket(encodeNATPacket(OpNatRegister, hash[:]), other, 2004)
	t.Logf("input: REGISTER from %s after the TTL; output: candidate=%q", other, natRegistered(nat, hash))
	if natRegistered(nat, hash) != other.String() {
		t.Fatal("an expired candidate must be replaceable")
	}
}

func TestSameIPv6Prefix64(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"2001:db8:1:2::1", "2001:db8:1:2:aaaa::9", true},
		{"2001:db8:1:2::1", "2001:db8:1:3::1", false},
		{"2001:db8:1:2::1", "198.51.100.1", false},
	} {
		got := sameIPv6Prefix64(net.ParseIP(tc.a), net.ParseIP(tc.b))
		t.Logf("input: %s %s, output: %t", tc.a, tc.b, got)
		if got != tc.want {
			t.Fatalf("%s vs %s: got %t", tc.a, tc.b, got)
		}
	}
}
