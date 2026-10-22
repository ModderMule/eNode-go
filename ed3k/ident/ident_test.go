package ident

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/netip"
	"path/filepath"
	"testing"
)

// Vectors from the ed3k spec, tests/vectors-v1.md "Identity", "Routing ID",
// "Record targets", "Keyword targets" and "Derived eD2K user hash".

const samplePub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

func TestNodeIDVector(t *testing.T) {
	pub := mustHex(t, samplePub)
	id := NodeIDOf(pub)
	obf := id.Obf()
	t.Logf("pub=%s nodeID=%s obf=%x", samplePub, id, obf)
	if id.String() != "cf617f4479e97358c9d31741900a90ae" {
		t.Fatalf("node id %s", id)
	}
	if hex.EncodeToString(obf[:]) != "cf617f4479e97358c9d31741" {
		t.Fatalf("obf id %x", obf)
	}
}

func TestRoutingIDVectors(t *testing.T) {
	id := NodeIDOf(mustHex(t, samplePub))
	cases := []struct{ addr, want string }{
		{"124.31.75.21", "719c3f4479e97358c9d31741900a90ae"},
		{"21.75.31.124", "5a3cef4479e97358c9d31741900a90ae"},
	}
	for _, c := range cases {
		got := RoutingID(id, netip.MustParseAddr(c.addr), false)
		t.Logf("addr=%s routingID=%x", c.addr, got)
		if hex.EncodeToString(got[:]) != c.want {
			t.Errorf("%s: got %x want %s", c.addr, got, c.want)
		}
	}
	// The table rows: only r and the top 21 bits are vectors.
	rows := []struct {
		addr string
		r    byte
		top  uint32
	}{
		{"124.31.75.21", 1, 0x0bf7f7},
		{"21.75.31.124", 6, 0x0b479d},
		{"65.23.51.170", 6, 0x14ba86},
		{"2001:db8:1234:5678::1", 3, 0x06565a},
	}
	for _, row := range rows {
		var fake NodeID
		fake[15] = row.r
		got := RoutingID(fake, netip.MustParseAddr(row.addr), false)
		top := uint32(got[0])<<13 | uint32(got[1])<<5 | uint32(got[2])>>3
		t.Logf("addr=%s r=%d top21=%06x", row.addr, row.r, top)
		if top != row.top {
			t.Errorf("%s: top %06x want %06x", row.addr, top, row.top)
		}
	}
}

// In a named network a node at a private address has its node ID as routing
// ID (§6.3); a public address there, or a private one elsewhere, does not.
func TestRoutingIDNamedNetwork(t *testing.T) {
	id := NodeIDOf(mustHex(t, samplePub))
	cases := []struct {
		addr  string
		named bool
		same  bool
	}{
		{"192.168.1.20", true, true},
		{"fd00::5", true, true},
		{"192.168.1.20", false, false},
		{"124.31.75.21", true, false},
	}
	for _, c := range cases {
		got := RoutingID(id, netip.MustParseAddr(c.addr), c.named)
		t.Logf("addr=%s named=%v routingID=%x nodeID=%x", c.addr, c.named, got, id)
		if (got == [16]byte(id)) != c.same {
			t.Errorf("%s named=%v: routing ID = node ID is %v, want %v", c.addr, c.named, !c.same, c.same)
		}
	}
}

func TestTargetVectors(t *testing.T) {
	key := mustHex(t, samplePub)
	id := []byte("sid1")
	cases := []struct {
		name string
		got  [16]byte
		want string
	}{
		{"HEAD", H16("ed3k v1 set head", key, id), "db35cab4ac16050fa47f13fbcc4fe600"},
		{"LIVE", H16("ed3k v1 live", key, id), "d6c1deaa5cf816f5f5430d7dd6c0e59a"},
		{"GATE", H16("ed3k v1 gate", mustHex(t, "cf617f4479e97358c9d31741900a90ae")), "65c28351371c965dc864a4e0f14ef72d"},
		{"keyword sleep", H16("ed3k v1 keyword", []byte{0}, []byte("sleep")), "f797b920611f6bebcb89cad846086177"},
		{"keyword 東京", H16("ed3k v1 keyword", []byte{0}, []byte("東京")), "988b051341ac734878ffb07e7c97c1d9"},
	}
	for _, c := range cases {
		t.Logf("%s -> %x", c.name, c.got)
		if hex.EncodeToString(c.got[:]) != c.want {
			t.Errorf("%s: got %x want %s", c.name, c.got, c.want)
		}
	}
}

func TestDerivedUserHashVector(t *testing.T) {
	id := NodeIDOf(mustHex(t, samplePub))
	u := DerivedUserHash(id)
	t.Logf("nodeID=%s userHash=%x", id, u)
	if hex.EncodeToString(u[:]) != "cf617f44790ee97358c9d31741c16f2e" {
		t.Fatalf("user hash %x", u)
	}
	obf, ok := ObfFromUserHash(u[:])
	if !ok || obf != id.Obf() {
		t.Fatalf("recognise: ok=%v obf=%x", ok, obf)
	}
	u[13] ^= 1
	if _, ok := ObfFromUserHash(u[:]); ok {
		t.Fatal("a wrong check byte was accepted")
	}
}

func TestEndpointRoundTrip(t *testing.T) {
	for _, s := range []string{"1.2.3.4:4661", "[2a00:1450::1]:4662"} {
		ep := netip.MustParseAddrPort(s)
		b := EncodeEndpoint(ep)
		got, ok, err := DecodeEndpoint(b)
		t.Logf("%s -> %x -> %v", s, b, got)
		if err != nil || !ok || got != ep {
			t.Fatalf("%s: %v %v %v", s, got, ok, err)
		}
	}
	if _, _, err := DecodeEndpoint([]byte{1, 2, 3}); err == nil {
		t.Fatal("3-byte endpoint accepted")
	}
}

func TestAcceptable(t *testing.T) {
	cases := []struct {
		addr  string
		named bool
		want  bool
	}{
		{"8.8.8.8", false, true},
		{"10.1.2.3", false, false},
		{"10.1.2.3", true, true},
		{"100.64.1.1", true, false},
		{"127.0.0.1", true, true},
		{"2001:db8::1", false, false},
		{"2a00:1450::1", false, true},
		{"2002::1", false, false},
		{"224.0.0.1", false, false},
		// Spec ruling A: IPv6 only inside 2000::/3.
		{"2600::1", false, true},
		{"3fff:1::1", false, false},
		{"::81.2.3.4", false, false},
		{"1::1", false, false},
		{"4000::1", false, false},
		{"fec0::1", false, false},
		{"5f00::1", false, false},
		{"ff02::1", false, false},
		{"fc00::1", false, false},
		{"fc00::1", true, true},
		{"fe80::1", true, true},
		{"::1", true, true},
	}
	for _, c := range cases {
		got := Acceptable(netip.MustParseAddr(c.addr), c.named)
		t.Logf("addr=%s named=%v acceptable=%v", c.addr, c.named, got)
		if got != c.want {
			t.Errorf("%s named=%v: got %v", c.addr, c.named, got)
		}
	}
	if AcceptableEndpoint(netip.MustParseAddrPort("[::ffff:8.8.8.8]:1"), false) {
		t.Error("IPv4-mapped endpoint accepted")
	}
	if AcceptableEndpoint(netip.MustParseAddrPort("8.8.8.8:0"), false) {
		t.Error("port 0 accepted")
	}
}

func TestGroups(t *testing.T) {
	a := netip.MustParseAddr("2a00:1450:4001:81a::200e")
	t.Logf("host=%v site=%v", HostKey(a, false), SiteKey(a))
	if HostKey(a, false).String() != "2a00:1450:4001:81a::/64" || SiteKey(a).String() != "2a00:1450:4001::/48" {
		t.Fatal("IPv6 groups")
	}
	b := netip.MustParseAddr("81.2.3.4")
	if HostKey(b, false).String() != "81.2.3.4/32" || SiteKey(b).String() != "81.2.3.0/24" {
		t.Fatal("IPv4 groups")
	}
}

func TestNodeLink(t *testing.T) {
	id := NodeIDOf(mustHex(t, samplePub))
	l := NodeLink{ID: id, EP4: netip.MustParseAddrPort("81.2.3.4:4661"), EP6: netip.MustParseAddrPort("[2a00:1450::1]:4661")}
	s := l.String()
	t.Logf("link=%s", s)
	if s != "ed3k:node?id=cf617f4479e97358c9d31741900a90ae&ep=81.2.3.4:4661&ep=[2a00:1450::1]:4661" {
		t.Fatalf("format: %s", s)
	}
	got, err := ParseNodeLink("ED3K:node?ep=%5B2a00:1450::1%5D:4661&id=CF617F4479E97358C9D31741900A90AE&x=1&ep=81.2.3.4:4661", false)
	if err != nil || got != l {
		t.Fatalf("parse: %+v %v", got, err)
	}
	bad := []string{
		"ed3k:node?id=cf617f4479e97358c9d31741900a90ae",
		"ed3k:node?ep=81.2.3.4:4661",
		"ed3k:node?id=cf617f4479e97358c9d31741900a90ae&ep=81.2.3.4:0",
		"ed3k:node?id=cf617f4479e97358c9d31741900a90ae&ep=10.0.0.1:4661",
		"ed3k:node?id=cf617f4479e97358c9d31741900a90ae&ep=81.2.3.4:1&ep=81.2.3.5:1",
		"ed3k:Node?id=cf617f4479e97358c9d31741900a90ae&ep=81.2.3.4:1",
		"ed3k:node?id=cf617f4479e97358c9d31741900a90ae&ep=[81.2.3.4]:80",
	}
	for _, s := range bad {
		_, err := ParseNodeLink(s, false)
		t.Logf("bad link %q -> %v", s, err)
		if err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if _, err := ParseNodeLink("ed3k:node?id=cf617f4479e97358c9d31741900a90ae&ep=127.0.0.1:4661", true); err != nil {
		t.Errorf("private endpoint in a named network: %v", err)
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "ed3k.key")
	k1, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("path=%s nodeID=%s", path, NodeIDOf(k1.Public().(ed25519.PublicKey)))
	if !k1.Equal(k2) {
		t.Fatal("key changed on reload")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
