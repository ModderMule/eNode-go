// Package ident holds the ed3k identity derivations: H, the node ID, the
// obfuscation ID, the routing ID, the derived eD2K user hash, endpoints, address
// acceptability and the ed3k:node link (Protocol.md §0, §6, §8.2, §13.2, §14.2).
package ident

import "lukechampine.com/blake3"

// H is BLAKE3 in derive_key mode with context string ctx (Protocol.md §0),
// returning n bytes. A longer output extends the 32-byte one.
func H(ctx string, n int, parts ...[]byte) []byte {
	var src []byte
	if len(parts) == 1 {
		src = parts[0]
	} else {
		for _, p := range parts {
			src = append(src, p...)
		}
	}
	out := make([]byte, n)
	blake3.DeriveKey(out, ctx, src)
	return out
}

// H16 is H(ctx, …)[0..16), the length of every target and node ID.
func H16(ctx string, parts ...[]byte) [16]byte {
	var out [16]byte
	copy(out[:], H(ctx, 16, parts...))
	return out
}
