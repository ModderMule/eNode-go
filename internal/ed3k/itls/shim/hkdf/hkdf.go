// Package hkdf adapts crypto/hkdf to the error-free signatures of
// crypto/internal/fips140/hkdf, which the TLS 1.3 key schedule uses.
package hkdf

import (
	"crypto/hkdf"
	"hash"
)

// Extract is HKDF-Extract(salt, secret).
func Extract[H hash.Hash](h func() H, secret, salt []byte) []byte {
	out, err := hkdf.Extract(h, secret, salt)
	if err != nil {
		panic("hkdf: " + err.Error())
	}
	return out
}

// Expand is HKDF-Expand(prk, info, length).
func Expand[H hash.Hash](h func() H, prk []byte, info string, length int) []byte {
	out, err := hkdf.Expand(h, prk, info, length)
	if err != nil {
		panic("hkdf: " + err.Error())
	}
	return out
}
