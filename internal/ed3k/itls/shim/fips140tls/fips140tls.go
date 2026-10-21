// Package fips140tls stands in for crypto/tls/internal/fips140tls: FIPS 140-3
// mode is never required in this fork.
package fips140tls

// Required reports false.
func Required() bool { return false }
