package ed2k

import (
	"bytes"
	"net"
	"testing"
)

func TestLoginIPv6ExtractsPublicAddress(t *testing.T) {
	pub := net.ParseIP("2001:db8::1").To16()
	tags := []NamedTag{
		{Name: "name", Value: "someone"},
		{Name: "version", Value: uint64(0x3c)},
		{Name: "ipv6", Value: []byte(pub), Type: TypeHash},
		{Name: "flags", Value: uint64(FlagSupportCrypt)},
	}
	addr, present := loginIPv6(tags)
	if !present {
		t.Fatal("tag present flag should be true")
	}
	if !bytes.Equal(addr, pub) {
		t.Fatalf("addr mismatch: got %x want %x", addr, pub)
	}
	t.Logf("extracted public IPv6 %x, present=%v", addr, present)
}

func TestLoginIPv6PresentButUnusable(t *testing.T) {
	// A link-local value: present (capability signalled) but not stored.
	ll := net.ParseIP("fe80::1").To16()
	addr, present := loginIPv6([]NamedTag{{Name: "ipv6", Value: []byte(ll), Type: TypeHash}})
	if !present {
		t.Fatal("present should be true even for an unusable value")
	}
	if addr != nil {
		t.Fatalf("link-local must not be stored, got %x", addr)
	}
	t.Logf("link-local: addr=%v present=%v (capability signalled, value dropped)", addr, present)
}

func TestLoginIPv6Absent(t *testing.T) {
	addr, present := loginIPv6([]NamedTag{{Name: "name", Value: "x"}})
	if present || addr != nil {
		t.Fatalf("no ipv6 tag: got addr=%x present=%v", addr, present)
	}
}

func TestAddByAddressDistinguishesV6OnlyClients(t *testing.T) {
	l := NewLowIDClients(true, 0, 0)
	// Two v6-only clients (ipv4 == 0) on the same port must not collide on one
	// seed the way AddByEndpoint(0, port) would; they get distinct LowIDs.
	a := net.ParseIP("2001:db8::1")
	b := net.ParseIP("2001:db8::2")
	idA, okA := l.AddByAddress(a, 0, 4662, "a")
	idB, okB := l.AddByAddress(b, 0, 4662, "b")
	if !okA || !okB {
		t.Fatalf("both adds should succeed: %v %v", okA, okB)
	}
	if idA == idB {
		t.Fatalf("v6-only clients collided on LowID %d", idA)
	}
	t.Logf("v6-only clients -> distinct LowIDs %d, %d", idA, idB)
}

func TestAddByAddressV4MatchesAddByEndpoint(t *testing.T) {
	// A v4 peer must produce the same LowID as the legacy AddByEndpoint path, so
	// existing IPv4 assignment is unchanged.
	ipv4, err := IPv4ToInt32LE("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	l1 := NewLowIDClients(true, 0, 0)
	want, _ := l1.AddByEndpoint(ipv4, 4662, "x")

	l2 := NewLowIDClients(true, 0, 0)
	got, _ := l2.AddByAddress(net.ParseIP("1.2.3.4"), ipv4, 4662, "x")
	if got != want {
		t.Fatalf("v4 AddByAddress diverged from AddByEndpoint: got %d want %d", got, want)
	}
	t.Logf("v4 AddByAddress == AddByEndpoint == %d", got)
}

// CT_MOD_IP_V6 is a HASH tag (ipv6-spec.md; eMuleQt and eMuleAI both send one). A
// 16-byte BLOB or BSOB decodes to the same []byte, but it is not the tag: present,
// so the capability counts, and no address is taken from it.
func TestLoginIPv6RequiresHashType(t *testing.T) {
	pub := net.ParseIP("2001:db8::1").To16()
	for _, typ := range []uint8{TypeBlob, TypeBsob} {
		addr, present := loginIPv6([]NamedTag{{Name: "ipv6", Value: []byte(pub), Type: typ}})
		t.Logf("input: 0xae as type %#x, output: addr=%x present=%t", typ, addr, present)
		if !present || addr != nil {
			t.Fatalf("type %#x: got addr=%x present=%t, want nil/true", typ, addr, present)
		}
	}
}
