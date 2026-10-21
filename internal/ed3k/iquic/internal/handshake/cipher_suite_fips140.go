package handshake

import (
	"crypto/cipher"
)

// ed3k: upstream reaches into crypto/tls with go:linkname for the FIPS 140
// AES-GCM AEAD. This fork runs on the vendored TLS of internal/ed3k/itls, which
// has no FIPS 140 mode, so the path is refused instead of linked.
func cryptoTLSAEAD_AESGCMTLS13(key, nonceMask []byte) cipher.AEAD {
	panic("ed3k: QUIC in FIPS 140 mode is not supported by this fork")
}

func aeadAESGCMTLS13FIPS140(key, nonceMask []byte) cipher.AEAD {
	return &tls13AESGCMAEADFIPS140{aead: cryptoTLSAEAD_AESGCMTLS13(key, nonceMask)}
}

type tls13AESGCMAEADFIPS140 struct {
	aead       cipher.AEAD
	primedSeal bool
}

func (f *tls13AESGCMAEADFIPS140) NonceSize() int { return f.aead.NonceSize() }
func (f *tls13AESGCMAEADFIPS140) Overhead() int  { return f.aead.Overhead() }

func (f *tls13AESGCMAEADFIPS140) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	if !f.primedSeal {
		f.primedSeal = true
		if nonce[0]|nonce[1]|nonce[2]|nonce[3]|nonce[4]|nonce[5]|nonce[6]|nonce[7] != 0 {
			// Go's TLS 1.3 AES-GCM AEAD learns the XOR mask from the first Seal
			// call and enforces monotonically increasing packet numbers after that.
			// QUIC packet numbers don't reset on key updates, so prime it with
			// packet number 0 before the first real, non-zero packet number.
			var zeroNonce [8]byte
			f.aead.Seal(nil, zeroNonce[:], nil, nil)
		}
	}
	return f.aead.Seal(out, nonce, plaintext, additionalData)
}

func (f *tls13AESGCMAEADFIPS140) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return f.aead.Open(out, nonce, ciphertext, additionalData)
}
