// Package boring stands in for crypto/internal/boring: BoringCrypto is never
// enabled in this fork.
package boring

import "crypto/cipher"

// Enabled is always false.
const Enabled = false

// Unreachable marks code that only runs with BoringCrypto.
func Unreachable() {}

// NewGCMTLS is never called while Enabled is false.
func NewGCMTLS(cipher.Block) (cipher.AEAD, error) { panic("boring: not enabled") }

// NewGCMTLS13 is never called while Enabled is false.
func NewGCMTLS13(cipher.Block) (cipher.AEAD, error) { panic("boring: not enabled") }
