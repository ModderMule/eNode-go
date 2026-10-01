package ed2k

import (
	"net"
	"testing"
)

func TestUDPCryptRoundTrip(t *testing.T) {
	u := NewUDPCrypt(true, 0x11223344)
	plain := []byte{PrED2K, 0x01, 0x02, 0x03}
	randomKey := uint16(0x3344)

	enc := NewBuffer(len(plain) + 5)
	_ = enc.PutUInt32LE(MagicValueUDPSyncServer)
	_ = enc.PutUInt8(0)
	enc.PutBuffer(plain)
	cipher := RC4Crypt(enc.Bytes(), len(enc.Bytes()), u.rc4Key(MagicValueUDPClientServer, randomKey))

	wire := NewBuffer(3 + len(cipher))
	_ = wire.PutUInt8(0xff) // invalid protocol to trigger decrypt
	_ = wire.PutUInt16LE(randomKey)
	wire.PutBuffer(cipher)

	got := u.Decrypt(wire.Bytes())
	if string(got) != string(plain) {
		t.Fatalf("udp decrypt mismatch: %v != %v", got, plain)
	}
}

func TestUDPCryptDisabled(t *testing.T) {
	u := NewUDPCrypt(false, 0)
	plain := []byte{1, 2, 3}
	got := u.Encrypt(plain)
	if string(got) != string(plain) {
		t.Fatalf("encrypt should pass through")
	}
}

func TestUDPCryptDecryptMarkerCollisionWithProtocolByte(t *testing.T) {
	u := NewUDPCrypt(true, 0x55667788)
	plain := []byte{PrED2K, 0x99, 0x01}
	randomKey := uint16(0x1122)

	enc := NewBuffer(len(plain) + 5)
	_ = enc.PutUInt32LE(MagicValueUDPSyncServer)
	_ = enc.PutUInt8(0)
	enc.PutBuffer(plain)
	cipher := RC4Crypt(enc.Bytes(), len(enc.Bytes()), u.rc4Key(MagicValueUDPClientServer, randomKey))

	wire := NewBuffer(3 + len(cipher))
	_ = wire.PutUInt8(PrEMule) // marker byte collides with known protocol value
	_ = wire.PutUInt16LE(randomKey)
	wire.PutBuffer(cipher)

	got := u.Decrypt(wire.Bytes())
	if string(got) != string(plain) {
		t.Fatalf("udp decrypt mismatch with marker collision: %v != %v", got, plain)
	}
}

// deriveUDPKey must be a deterministic, IP-bound, always-nonzero function of the
// server secret so the server can recompute a client's obfuscation key from the
// datagram source IP without storing per-client state.
func TestDeriveUDPKey(t *testing.T) {
	const secret uint32 = 0x12345678
	ipA := net.IPv4(203, 0, 113, 7)
	ipB := net.IPv4(198, 51, 100, 42)

	// Determinism: same (secret, IP) -> same key.
	k1 := deriveUDPKey(LegacyUDPSecret(secret), ipA)
	k2 := deriveUDPKey(LegacyUDPSecret(secret), ipA)
	t.Logf("input: secret=0x%08x ip=%s -> key=0x%08x (repeat 0x%08x)", secret, ipA, k1, k2)
	if k1 != k2 {
		t.Fatalf("non-deterministic: 0x%08x != 0x%08x", k1, k2)
	}

	// Distinct IPs -> distinct keys (the anti-spoofing property).
	kB := deriveUDPKey(LegacyUDPSecret(secret), ipB)
	t.Logf("input: secret=0x%08x ip=%s -> key=0x%08x", secret, ipB, kB)
	if k1 == kB {
		t.Fatalf("distinct IPs collided: %s and %s both 0x%08x", ipA, ipB, k1)
	}

	// Distinct secrets over the same IP -> distinct keys (rotating the secret
	// invalidates cached client keys).
	kOther := deriveUDPKey(LegacyUDPSecret(secret^0xFFFFFFFF), ipA)
	t.Logf("input: secret=0x%08x ip=%s -> key=0x%08x", secret^0xFFFFFFFF, ipA, kOther)
	if kOther == k1 {
		t.Fatalf("secret ignored: both secrets yield 0x%08x", k1)
	}

	// net.IPv4 returns a 16-byte form; its To4() 4-byte form must agree so the key
	// does not depend on the IP's in-memory representation.
	k16 := deriveUDPKey(LegacyUDPSecret(secret), ipA)      // 16-byte (net.IPv4)
	k4 := deriveUDPKey(LegacyUDPSecret(secret), ipA.To4()) // 4-byte
	t.Logf("input: ip=%s 16-byte=0x%08x 4-byte=0x%08x", ipA, k16, k4)
	if k16 != k4 {
		t.Fatalf("v4 representation leaked into key: 0x%08x != 0x%08x", k16, k4)
	}

	// IPv6 is handled without panic and yields a usable key.
	kV6 := deriveUDPKey(LegacyUDPSecret(secret), net.ParseIP("2001:db8::1"))
	t.Logf("input: ipv6=2001:db8::1 -> key=0x%08x", kV6)
	if kV6 == 0 {
		t.Fatalf("v6 key must be nonzero")
	}

	// Never returns 0 across a sweep of IPs — a zero key means "no key" to the client.
	for i := 0; i < 256; i++ {
		if k := deriveUDPKey(LegacyUDPSecret(secret), net.IPv4(10, 0, 0, byte(i))); k == 0 {
			t.Fatalf("zero key for 10.0.0.%d", i)
		}
	}
}
