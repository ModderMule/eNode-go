package ed2k

import (
	"net"
	"testing"
)

func TestNormalizeIPCollapsesMappedV4(t *testing.T) {
	mapped := net.ParseIP("::ffff:1.2.3.4")
	got := NormalizeIP(mapped)
	if got.To4() == nil {
		t.Fatalf("mapped v4 should collapse to 4-byte form, got %v (%d bytes)", got, len(got))
	}
	if got.String() != "1.2.3.4" {
		t.Fatalf("normalized address mismatch: %s", got.String())
	}
	t.Logf("input: %v -> %v (%d bytes)", mapped, got, len(got))
}

func TestIPv4ToUint32LEMatchesStringParser(t *testing.T) {
	want, err := IPv4ToInt32LE("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := IPv4ToUint32LE(net.ParseIP("1.2.3.4"))
	if !ok {
		t.Fatal("expected an IPv4 result")
	}
	if got != want {
		t.Fatalf("byte order mismatch with IPv4ToInt32LE: got 0x%08x want 0x%08x", got, want)
	}
	// A v6 address has no HighID.
	if _, ok := IPv4ToUint32LE(net.ParseIP("2001:db8::1")); ok {
		t.Fatal("v6 address must not yield a uint32")
	}
	t.Logf("1.2.3.4 -> 0x%08x (matches string parser)", got)
}

func TestIPv6BytesRejectsV4(t *testing.T) {
	if _, ok := IPv6Bytes(net.ParseIP("1.2.3.4")); ok {
		t.Fatal("IPv4 must not yield 16-byte v6 form")
	}
	if _, ok := IPv6Bytes(net.ParseIP("::ffff:1.2.3.4")); ok {
		t.Fatal("mapped v4 must not yield 16-byte v6 form")
	}
	b, ok := IPv6Bytes(net.ParseIP("2001:db8::1"))
	if !ok {
		t.Fatal("expected a v6 result")
	}
	want := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	if b != want {
		t.Fatalf("bytes mismatch: got %x want %x", b, want)
	}
	t.Logf("2001:db8::1 -> %x (network order)", b)
}

// TestIsLANIP pins the private/non-routable set against the two C++ references.
// The boundaries either side of each range are included: an off-by-one in the
// 172.16-31 test is the classic way this predicate goes wrong, and it would either
// admit 172.32.x peers we cannot reach or reject 172.15.x peers we can.
func TestIsLANIP(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"0.0.0.0", true},         // "this" network
		{"0.1.2.3", true},         // whole 0.* block, not just the unspecified address
		{"1.0.0.1", false},        // first routable octet
		{"9.255.255.255", false},  // just below class A
		{"10.0.0.0", true},        // class A low
		{"10.255.255.255", true},  // class A high
		{"11.0.0.0", false},       // just above class A
		{"127.0.0.1", true},       // loopback
		{"127.255.255.255", true}, // whole loopback block
		{"172.15.255.255", false}, // just below class B
		{"172.16.0.0", true},      // class B low
		{"172.31.255.255", true},  // class B high
		{"172.32.0.0", false},     // just above class B
		{"192.167.255.255", false},
		{"192.168.0.0", true}, // class C low
		{"192.168.255.255", true},
		{"192.169.0.0", false},
		{"169.253.255.255", false},
		{"169.254.0.1", true}, // link-local
		{"169.255.0.1", false},
		{"8.8.8.8", false},
		{"224.0.0.1", false},      // multicast is not LAN — IsGoodIP rejects it separately
		{"2001:db8::1", false},    // v6 is judged by IsPublicIPv6
		{"::ffff:10.0.0.1", true}, // mapped v4 still resolves to the v4 test
	}
	for _, c := range cases {
		got := IsLANIP(net.ParseIP(c.in))
		if got != c.want {
			t.Errorf("IsLANIP(%s) = %v, want %v", c.in, got, c.want)
		}
		t.Logf("IsLANIP(%-16s) = %v", c.in, got)
	}
}

// TestIsGoodIP pins eMule's IsGoodIP (srchybrid/OtherFunctions.cpp:2051-2068) and,
// crucially, which rejections allowLAN can and cannot lift.
//
// 0.* and >= 224 are refused whatever allowLAN says: multicast, reserved and broadcast
// are not hosts, so no configuration should admit them as a contact. Loopback and the
// RFC1918 ranges are different — they are unreachable only from *elsewhere* — and
// allowLAN lifts both, standing in for eMule's FilterLANIPs() and GetAllowLocalHostIP()
// respectively. Conflating the two groups is the mistake this table exists to catch:
// making 127.* unconditional makes a same-host peer permanently unreachable, and making
// 224.* conditional would let a peer inject multicast addresses.
func TestIsGoodIP(t *testing.T) {
	cases := []struct {
		in                  string
		wantStrict, wantLAN bool
	}{
		{"8.8.8.8", true, true},
		{"1.0.0.1", true, true},
		{"223.255.255.255", true, true}, // last address below the multicast block
		{"0.0.0.0", false, false},       // unspecified — never good
		{"0.1.2.3", false, false},       // whole 0.* block — never good
		{"224.0.0.0", false, false},     // multicast low — never good
		{"239.255.255.255", false, false},
		{"240.0.0.0", false, false},         // reserved for future use
		{"255.255.255.255", false, false},   // broadcast
		{"127.0.0.1", false, true},          // loopback: eMule's GetAllowLocalHostIP
		{"127.255.255.255", false, true},    // whole loopback block
		{"10.0.0.1", false, true},           // LAN: eMule's FilterLANIPs
		{"172.16.0.1", false, true},         // LAN: gated on allowLAN
		{"192.168.1.1", false, true},        // LAN: gated on allowLAN
		{"169.254.1.1", false, true},        // link-local: gated on allowLAN
		{"2001:db8::1", false, false},       // v6 has no 32-bit form here
		{"::ffff:8.8.8.8", true, true},      // mapped v4 behaves as plain v4
		{"::ffff:192.168.1.1", false, true}, // mapped LAN v4 likewise
	}
	for _, c := range cases {
		ip := net.ParseIP(c.in)
		if got := IsGoodIP(ip, false); got != c.wantStrict {
			t.Errorf("IsGoodIP(%s, allowLAN=false) = %v, want %v", c.in, got, c.wantStrict)
		}
		if got := IsGoodIP(ip, true); got != c.wantLAN {
			t.Errorf("IsGoodIP(%s, allowLAN=true) = %v, want %v", c.in, got, c.wantLAN)
		}
		t.Logf("IsGoodIP(%-20s) strict=%-5v allowLAN=%v", c.in, c.wantStrict, c.wantLAN)
	}
}

// TestIsGoodIPPortRequiresNonZeroPort covers the half of IsGoodIPPort that the IP
// tests cannot: port 0 is what a gossip entry carries when the sender does not
// actually know where the peer listens, and it must never be admitted.
func TestIsGoodIPPortRequiresNonZeroPort(t *testing.T) {
	good := net.ParseIP("8.8.8.8")
	if IsGoodIPPort(good, 0, false) {
		t.Error("port 0 must never be a good contact")
	}
	if !IsGoodIPPort(good, 4661, false) {
		t.Error("8.8.8.8:4661 should be a good contact")
	}
	if IsGoodIPPort(net.ParseIP("10.0.0.1"), 4661, false) {
		t.Error("LAN address must be refused without allowLAN")
	}
	if !IsGoodIPPort(net.ParseIP("10.0.0.1"), 4661, true) {
		t.Error("LAN address must be accepted with allowLAN")
	}
	t.Logf("port gate: 8.8.8.8:0=%v 8.8.8.8:4661=%v",
		IsGoodIPPort(good, 0, false), IsGoodIPPort(good, 4661, false))
}

// TestIsGoodServerEntry covers the dynIP exemption, which is the non-obvious half of
// CServerList::IsGoodServerIP (srchybrid/ServerList.cpp:322-325): a server published
// under a dynamic hostname is expected to have a stale recorded IP, so its address
// says nothing about whether the entry is worth keeping. Port 0 is still fatal.
func TestIsGoodServerEntry(t *testing.T) {
	stale := net.ParseIP("10.0.0.1")
	if IsGoodServerEntry(stale, 4661, false, false) {
		t.Error("a LAN address without dynIP must be refused")
	}
	if !IsGoodServerEntry(stale, 4661, true, false) {
		t.Error("dynIP must exempt the entry from the IP test")
	}
	if IsGoodServerEntry(stale, 0, true, false) {
		t.Error("port 0 must be fatal even with dynIP")
	}
	if !IsGoodServerEntry(net.ParseIP("2001:db8::1"), 4661, false, false) {
		t.Error("a public IPv6 entry should be admitted")
	}
	if IsGoodServerEntry(net.ParseIP("fe80::1"), 4661, false, false) {
		t.Error("a link-local IPv6 entry must be refused")
	}
	t.Logf("dynIP exemption: 10.0.0.1:4661 plain=%v dynIP=%v",
		IsGoodServerEntry(stale, 4661, false, false),
		IsGoodServerEntry(stale, 4661, true, false))
}

func TestIsPublicIPv6(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"2001:db8::1", true},
		{"2606:4700:4700::1111", true},
		{"::1", false},            // loopback
		{"fe80::1", false},        // link-local
		{"fc00::1", false},        // unique-local
		{"ff02::1", false},        // multicast
		{"::", false},             // unspecified
		{"1.2.3.4", false},        // IPv4
		{"::ffff:1.2.3.4", false}, // mapped IPv4
	}
	for _, c := range cases {
		if got := IsPublicIPv6(net.ParseIP(c.in)); got != c.want {
			t.Errorf("IsPublicIPv6(%s) = %v, want %v", c.in, got, c.want)
		}
		t.Logf("IsPublicIPv6(%s) = %v", c.in, IsPublicIPv6(net.ParseIP(c.in)))
	}
}
