package ident

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"net/netip"
)

// NodeID is H("ed3k v1 node id", public key)[0..16) (Protocol.md §6.1).
type NodeID [16]byte

// ObfID is the first 12 bytes of a node ID: the obfuscation key of the node that
// accepted a connection (Protocol.md §4.3).
type ObfID [12]byte

// NodeIDOf returns the node ID of an Ed25519 public key.
func NodeIDOf(pub ed25519.PublicKey) NodeID {
	return NodeID(H16("ed3k v1 node id", pub))
}

// String is the node ID as 32 lower-case hex digits.
func (n NodeID) String() string { return hex.EncodeToString(n[:]) }

// Obf returns the node's obfuscation ID.
func (n NodeID) Obf() ObfID {
	var o ObfID
	copy(o[:], n[:12])
	return o
}

// ParseNodeID reads 32 hex digits in either case.
func ParseNodeID(s string) (NodeID, error) {
	var n NodeID
	if len(s) != 32 {
		return n, errors.New("ed3k: node id is not 32 hex digits")
	}
	if _, err := hex.Decode(n[:], []byte(s)); err != nil {
		return n, errors.New("ed3k: node id is not hex")
	}
	return n, nil
}

// RoutingID is the IP-bound position of a node in Kad (Protocol.md §6.3). An
// index node without ROUTER does not need it for itself; it is here for the
// vectors and for the checks that use contacts. In a named network the routing
// ID of a node at a private address is its node ID.
func RoutingID(id NodeID, addr netip.Addr, named bool) [16]byte {
	addr = addr.Unmap()
	if named && Private(addr) {
		return id
	}
	r := id[15] & 0x07
	var m []byte
	if addr.Is4() {
		a := addr.As4()
		mask := [4]byte{0x03, 0x0f, 0x3f, 0xff}
		m = make([]byte, 4)
		for i := range m {
			m[i] = a[i] & mask[i]
		}
	} else {
		a := addr.As16()
		mask := [8]byte{0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x00, 0x00}
		m = make([]byte, 8)
		for i := range m {
			m[i] = a[i] & mask[i]
		}
	}
	m[0] |= r << 5
	c := crc32.Checksum(m, castagnoli)
	out := id
	// top 21 bits of c, then bits 21..127 of the node ID
	out[0] = byte(c >> 24)
	out[1] = byte(c >> 16)
	out[2] = byte(c>>8)&0xf8 | id[2]&0x07
	return out
}

// DerivedUserHash is the eD2K user hash a dual-protocol client derives from its
// node ID (Protocol.md §14.2).
func DerivedUserHash(id NodeID) [16]byte {
	c := H("ed3k v1 ed2k user hash", 2, id[:12])
	var u [16]byte
	copy(u[0:5], id[0:5])
	u[5] = 14
	copy(u[6:13], id[5:12])
	u[13] = c[0]
	u[14] = 111
	u[15] = c[1]
	return u
}

// ObfFromUserHash returns the obfuscation ID a user hash hints at, and whether
// the hash is a derived one (Protocol.md §14.2). It is a hint only: one legacy
// hash in 65,536 matches by accident.
func ObfFromUserHash(u []byte) (ObfID, bool) {
	var o ObfID
	if len(u) != 16 || u[5] != 14 || u[14] != 111 {
		return o, false
	}
	copy(o[0:5], u[0:5])
	copy(o[5:12], u[6:13])
	c := H("ed3k v1 ed2k user hash", 2, o[:])
	if c[0] != u[13] || c[1] != u[15] {
		return o, false
	}
	return o, true
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)
