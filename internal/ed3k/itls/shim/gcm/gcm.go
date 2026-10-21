// Package gcm stands in for crypto/internal/fips140/aes/gcm. The upstream TLS
// constructors only add FIPS-gated nonce enforcement on top of standard GCM;
// without FIPS mode they are plain AES-GCM.
package gcm

import "crypto/cipher"

// NewGCMForTLS12 returns AES-GCM for TLS 1.2 records.
func NewGCMForTLS12(b cipher.Block) (cipher.AEAD, error) { return cipher.NewGCM(b) }

// NewGCMForTLS13 returns AES-GCM for TLS 1.3 records.
func NewGCMForTLS13(b cipher.Block) (cipher.AEAD, error) { return cipher.NewGCM(b) }
