package ed2k

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestClientUDPPortOffByDefault checks that with tracking off no table exists,
// observations are ignored and lookups miss.
func TestClientUDPPortOffByDefault(t *testing.T) {
	s := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, nil)
	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41234}
	s.NoteClientUDPPort(remote)
	_, _, ok := s.ClientUDPPort(remote.IP)
	t.Logf("tracking off: note %s -> table=%v lookup ok=%v", remote, s.udpPorts.Load() != nil, ok)
	if s.udpPorts.Load() != nil {
		t.Fatal("table allocated while tracking is off")
	}
	if ok {
		t.Fatal("lookup answered while tracking is off")
	}
}

// TestClientUDPPortToggle checks a reload allocates the table on enable, keeps
// it across an unchanged apply, and drops it on disable.
func TestClientUDPPortToggle(t *testing.T) {
	s := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, nil)
	s.ApplyRuntimeConfig(TCPRuntimeConfig{}, UDPRuntimeConfig{TrackClientUDPPorts: true})
	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41234}
	s.NoteClientUDPPort(remote)
	s.ApplyRuntimeConfig(TCPRuntimeConfig{}, UDPRuntimeConfig{TrackClientUDPPorts: true})
	port, _, ok := s.ClientUDPPort(remote.IP)
	t.Logf("enabled + unchanged apply: port=%d ok=%v", port, ok)
	if !ok || port != 41234 {
		t.Fatalf("observation lost across unchanged apply: port=%d ok=%v", port, ok)
	}
	s.ApplyRuntimeConfig(TCPRuntimeConfig{}, UDPRuntimeConfig{})
	_, _, ok = s.ClientUDPPort(remote.IP)
	t.Logf("disabled: table=%v ok=%v", s.udpPorts.Load() != nil, ok)
	if s.udpPorts.Load() != nil || ok {
		t.Fatal("disable did not drop the table")
	}
}

// TestClientUDPPortNoteAndLookup covers the observation table that hands out
// the client's server-UDP listener port: record, lookup, IPv4-mapped keying,
// expiry, sweeping and the bounded-table path.
func TestClientUDPPortNoteAndLookup(t *testing.T) {
	s := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{TrackClientUDPPorts: true}, nil)
	tbl := s.udpPorts.Load()

	ip := net.ParseIP("203.0.113.7")
	remote := &net.UDPAddr{IP: ip, Port: 41234}
	t.Logf("note remote=%s", remote)
	s.NoteClientUDPPort(remote)

	port, seen, ok := s.ClientUDPPort(ip)
	t.Logf("lookup ip=%s -> port=%d age=%v ok=%v", ip, port, time.Since(seen), ok)
	if !ok || port != 41234 || time.Since(seen) > time.Second {
		t.Fatalf("fresh observation not answerable: port=%d seen=%v ok=%v", port, seen, ok)
	}

	// The dual-stack mapped form must hit the same entry, and a port change is
	// applied at once even inside the refresh window.
	mapped := &net.UDPAddr{IP: net.ParseIP("::ffff:203.0.113.7"), Port: 41999}
	t.Logf("note mapped remote=%s", mapped)
	s.NoteClientUDPPort(mapped)
	port, _, ok = s.ClientUDPPort(ip)
	t.Logf("lookup after mapped update -> port=%d ok=%v", port, ok)
	if !ok || port != 41999 {
		t.Fatalf("mapped IPv6 did not update the shared entry: port=%d ok=%v", port, ok)
	}
	if n := len(tbl.m); n != 1 {
		t.Fatalf("mapped address created a second entry: n=%d", n)
	}

	// Junk callers are ignored rather than recorded.
	s.NoteClientUDPPort(nil)
	s.NoteClientUDPPort(&net.UDPAddr{IP: ip, Port: 0})
	s.NoteClientUDPPort(&net.UDPAddr{Port: 1})
	t.Logf("after junk notes table=%d", len(tbl.m))
	if n := len(tbl.m); n != 1 {
		t.Fatalf("junk observation recorded: n=%d", n)
	}

	// Expired entries answer not-found, and the next sweep removes them.
	key, _ := udpPortKey(ip)
	now := int64(time.Since(udpPortEpoch))
	tbl.m[key] = udpPortEntry{port: 5555, seen: now - int64(clientUDPPortTTL) - int64(time.Second)}
	_, _, ok = s.ClientUDPPort(ip)
	t.Logf("expired lookup -> ok=%v", ok)
	if ok {
		t.Fatal("expired entry answered")
	}
	tbl.lastSweep = now - int64(clientUDPPortSweepInterval)
	s.NoteClientUDPPort(&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 9})
	t.Logf("after sweep table=%d", len(tbl.m))
	if _, still := tbl.m[key]; still {
		t.Fatal("expired entry not swept")
	}

	// A full table of fresh entries drops new addresses instead of growing, but
	// an address already present still updates.
	tbl.m = make(map[netip.Addr]udpPortEntry)
	tbl.lastSweep = now
	for i := 0; i < clientUDPPortMaxEntries; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		tbl.m[a] = udpPortEntry{port: 1, seen: now}
	}
	s.NoteClientUDPPort(&net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 7})
	if _, _, ok := s.ClientUDPPort(net.ParseIP("198.51.100.9")); ok {
		t.Fatal("new observation accepted into a full fresh table")
	}
	s.NoteClientUDPPort(&net.UDPAddr{IP: net.ParseIP("10.0.0.5"), Port: 4321})
	port, _, ok = s.ClientUDPPort(net.ParseIP("10.0.0.5"))
	t.Logf("full table=%d; existing entry update -> port=%d ok=%v", len(tbl.m), port, ok)
	if !ok || port != 4321 {
		t.Fatalf("existing entry not updated in a full table: port=%d ok=%v", port, ok)
	}
	if n := len(tbl.m); n != clientUDPPortMaxEntries {
		t.Fatalf("table grew past its bound: n=%d", n)
	}
}
