package ed2k

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The server-UDP secret used to be the 32-bit udp.serverKey, set to the same public
// value in every shipped config, so anyone could compute any client's key. It is now
// 128 random bits, generated once and kept, since clients store the derived key.
func TestLoadOrCreateUDPSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "udp.secret")
	first, err := LoadOrCreateUDPSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreateUDPSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	t.Logf("input: %s, output: %d bytes %x, reloaded equal=%t, mode=%v", path, len(first), first, bytes.Equal(first, again), info.Mode())
	if len(first) != UDPSecretSize || !bytes.Equal(first, again) {
		t.Fatal("the secret must be 16 bytes and survive a restart")
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode %v, want 0600", info.Mode().Perm())
	}

	other, err := LoadOrCreateUDPSecret(filepath.Join(t.TempDir(), "udp.secret"))
	if err != nil {
		t.Fatal(err)
	}
	ip := net.IPv4(203, 0, 113, 5)
	t.Logf("output: key from one server %#08x, from another %#08x", deriveUDPKey(first, ip), deriveUDPKey(other, ip))
	if bytes.Equal(first, other) || deriveUDPKey(first, ip) == deriveUDPKey(other, ip) {
		t.Fatal("two servers must not share a secret or a client key")
	}

	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateUDPSecret(path); err == nil {
		t.Fatal("a truncated secret file must be refused, not silently replaced")
	}
}

// A configured udp.serverKey keeps deriving exactly the keys it always did, so
// clients holding one are not cut off by the upgrade.
func TestLegacyUDPSecretKeepsKeys(t *testing.T) {
	ip := net.IPv4(127, 0, 0, 1)
	got := deriveUDPKey(LegacyUDPSecret(305419896), ip)
	// MD5(78 56 34 12 7f 00 00 01) folded to its first little-endian word, as before.
	want := le32(MD5([]byte{0x78, 0x56, 0x34, 0x12, 127, 0, 0, 1}))
	t.Logf("input: serverKey=305419896 ip=%s, output: %#08x want %#08x", ip, got, want)
	if got != want {
		t.Fatal("legacy serverKey derivation changed")
	}
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
