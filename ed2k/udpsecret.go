package ed2k

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

// UDPSecretSize is the length of the generated server-UDP secret. The key a client
// gets is still 32 bits — the protocol carries it in 4 bytes at OP_GLOBSERVSTATRES
// +36, and eMule keys RC4 with exactly those 4 bytes — but it is now derived from 128
// secret bits instead of 32 that every shipped config set to the same public value.
const UDPSecretSize = 16

// LoadOrCreateUDPSecret returns the server-UDP secret stored at path, creating it
// from crypto/rand on first start. It persists across restarts because clients keep
// the derived key in server.met (ST_UDPKEY) and a new secret silently breaks their
// obfuscated UDP until they ping again. The file is written atomically, 0600.
func LoadOrCreateUDPSecret(path string) ([]byte, error) {
	secret, err := os.ReadFile(path)
	if err == nil {
		if len(secret) != UDPSecretSize {
			return nil, fmt.Errorf("udp secret %s is %d bytes, want %d; delete it to generate a new one", path, len(secret), UDPSecretSize)
		}
		return secret, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read udp secret: %w", err)
	}

	secret = make([]byte, UDPSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate udp secret: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create udp secret dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("create temp udp secret: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("chmod udp secret: %w", err)
	}
	if _, err := tmp.Write(secret); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("write udp secret: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close udp secret: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return nil, fmt.Errorf("install udp secret: %w", err)
	}
	return secret, nil
}

// LegacyUDPSecret is the secret a configured udp.serverKey stands for. Its 4 bytes
// derive exactly the keys that value always derived, so clients keep theirs.
func LegacyUDPSecret(serverKey uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], serverKey)
	return b[:]
}
