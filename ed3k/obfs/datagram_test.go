package obfs

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"enode/ed3k/ident"
)

// Vectors from tests/vectors-v1.md "Obfuscation (§4.3)".

func sampleObf(t *testing.T) ident.ObfID {
	pub, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	return ident.NodeIDOf(pub).Obf()
}

func TestKeyVectors(t *testing.T) {
	obf := sampleObf(t)
	salt := hx(t, "0102030405060708")
	net := NetID("ed3k test")
	t.Logf("net_id=%x", net)
	if hex.EncodeToString(net) != "19f07e3be153aed603e15b7c7c50ee13" {
		t.Fatal("net_id")
	}
	cases := []struct {
		name string
		k    Keys
		key  string
	}{
		{"public dir 00", NewKeys(nil, obf, 0), "015bc0e543423a9ede489325944e161ff19848369026217d2944ecd547e08588"},
		{"public dir 01", NewKeys(nil, obf, 1), "044d7656afac36bcaf6015a915045f7c3ce8f1da93d2cde4edfcde8285b62fe2"},
		{"test net dir 00", NewKeys(net, obf, 0), "cf09d12875ae26aa9753d30b2841f2114549a29eb7e82ea736bc60f223c5009a"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(c.k.Key(salt))
		t.Logf("%s key=%s", c.name, got)
		if got != c.key {
			t.Errorf("%s: key %s want %s", c.name, got, c.key)
		}
	}
}

func TestDatagramVectors(t *testing.T) {
	obf := sampleObf(t)
	k0 := NewKeys(nil, obf, 0)
	k1 := NewKeys(nil, obf, 1)
	hsBody := hx(t, "c30102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627")
	dataBody := hx(t, "400102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	cases := []struct {
		name      string
		k         Keys
		kind      byte
		salt, pad string
		body      []byte
		want      string
	}{
		{"HANDSHAKE", k0, KindHandshake, "0102030405060708", "aabbcc", hsBody,
			"0102030405060708c7cf7179594074fb6e1a0f2d1517dd0fc6ac011ab50118d11530787ba50a25e1c3b67728c5e44ded1e3831c44199cce8"},
		{"FRAGMENT 0", k0, KindFragment, "1112131415161718", "ddee", append([]byte{0x5c, 0x02}, hsBody[:15]...),
			"11121314151617187465c88fdaad03a9b0d3143a5d81e2e0c07e666be20cccf3"},
		{"FRAGMENT 1", k0, KindFragment, "2122232425262728", "", append([]byte{0x5c, 0x12}, hsBody[15:]...),
			"2122232425262728f46df8f16fb1babe6be0094bff77f58100c67e8956f37dc665d51fade09f5560"},
		{"DATA", k1, KindData, "3132333435363738", "f00f", dataBody,
			"313233343536373859688f3efab84209604dd4fd78a27e225d9ee2a2a657f09908f07d24c828bba0d4f507ad8a6023682e43353f3168ba6744fbaf11f4265723f45897db07a553529bb86c05f5e723404142434445464748494a4b4c4d4e4f"},
		{"PROBE", k0, KindProbe, "4142434445464748", "99", hx(t, "a1a2a3a4a5a6a7a8"),
			"414243444546474860859be56816b55f2f5d527512f3"},
	}
	for _, c := range cases {
		got := c.k.Seal(nil, c.kind, hx(t, c.salt), hx(t, c.pad), c.body)
		t.Logf("%s: %x", c.name, got)
		if hex.EncodeToString(got) != c.want {
			t.Errorf("%s: datagram differs\n got %x\nwant %s", c.name, got, c.want)
			continue
		}
		kind, body, err := c.k.Open(bytes.Clone(got))
		if err != nil || kind != c.kind || !bytes.Equal(body, c.body) {
			t.Errorf("%s: open kind=%d err=%v", c.name, kind, err)
		}
	}
}

func TestOpenRejects(t *testing.T) {
	obf := sampleObf(t)
	k0 := NewKeys(nil, obf, 0)
	other := NewKeys(NetID("other"), obf, 0)
	short := k0.Seal(nil, KindData, nil, nil, []byte{0x40, 1, 2})
	long := k0.Seal(nil, KindData, nil, nil, []byte{0xc0, 1, 2})
	probe7 := k0.Seal(nil, KindProbe, nil, nil, make([]byte, 7))
	cases := []struct {
		name string
		k    Keys
		d    []byte
		ok   bool
	}{
		{"DATA short header", k0, short, true},
		{"DATA with long header", k0, long, false},
		{"other network", other, bytes.Clone(short), false},
		{"PROBE of 7 bytes", k0, probe7, false},
		{"12 bytes", k0, make([]byte, 12), false},
	}
	for _, c := range cases {
		_, _, err := c.k.Open(c.d)
		t.Logf("%s: err=%v", c.name, err)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
}

func TestSaltRule(t *testing.T) {
	for range 2000 {
		s := NewSalt()
		if strings.Contains("\xe3\xe4\xe5\xc5\xd4\xa3\xb2", string(s[:1])) {
			t.Fatalf("salt starts with %#x", s[0])
		}
	}
	t.Logf("2000 salts drawn, none starts with an eD2K header byte")
}

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
