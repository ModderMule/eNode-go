// Package obfs is the datagram layer of the ed3k quic-obfs binding
// (Protocol.md §4.3–§4.5): every QUIC datagram is wrapped as
// salt(8) ‖ mask(magic(4) ‖ kp(1) ‖ pad ‖ body), long-header datagrams may be
// split into fragments, and the bytes sent to an unvalidated address stay within
// three times the bytes received from it.
package obfs

import (
	"crypto/rand"
	"errors"

	"lukechampine.com/blake3"

	"enode/ed3k/ident"
)

// Kinds of Protocol.md §4.3.
const (
	KindData      = 0
	KindHandshake = 1
	KindFragment  = 2
	KindProbe     = 3
)

// Directions: towards the node that accepted the connection, and from it.
const (
	DirToAcceptor   = 0x00
	DirFromAcceptor = 0x01
)

// Overhead is the bytes this layer adds to a datagram without padding; a
// fragment adds 2 more.
const Overhead = 13

// maskedData is how much of a DATA packet is masked after header and padding.
const maskedData = 64

var magic = [4]byte{0x65, 0x33, 0x6b, 0x01}

// Errors of Open. Every one means "not ed3k under this key": drop.
var (
	ErrShort  = errors.New("obfs: datagram too short")
	ErrMagic  = errors.New("obfs: magic does not match")
	ErrLayout = errors.New("obfs: body does not fit its kind")
)

// Keys derives masks for one (network, obf_id, dir).
type Keys struct {
	prefix []byte // net_id ‖ obf_id ‖ dir; the salt follows per datagram
}

// NewKeys returns the key source for datagrams of dir under obf. netID is
// H("ed3k v1 net", name)[0..16) in a named network, nil in the public one.
func NewKeys(netID []byte, obf ident.ObfID, dir byte) Keys {
	p := make([]byte, 0, len(netID)+len(obf)+1)
	p = append(p, netID...)
	p = append(p, obf[:]...)
	p = append(p, dir)
	return Keys{prefix: p}
}

// NetID is H("ed3k v1 net", name)[0..16), or nil for the public network.
func NetID(name string) []byte {
	if name == "" {
		return nil
	}
	return ident.H("ed3k v1 net", 16, []byte(name))
}

// Key returns H("ed3k v1 obfs", net_id ‖ obf_id ‖ dir ‖ salt).
func (k Keys) Key(salt []byte) []byte {
	in := make([]byte, 0, len(k.prefix)+8)
	in = append(in, k.prefix...)
	in = append(in, salt...)
	return ident.H("ed3k v1 obfs", 32, in)
}

// Seal builds one datagram: salt, then the masked header, padding and body.
// salt and pad are drawn at random when nil. For KindData only the header, the
// padding and the first 64 bytes of the body are masked.
func (k Keys) Seal(dst []byte, kind byte, salt, pad, body []byte) []byte {
	if salt == nil {
		salt = NewSalt()
	}
	start := len(dst)
	dst = append(dst, salt...)
	dst = append(dst, magic[:]...)
	dst = append(dst, kind<<6|byte(len(pad)))
	dst = append(dst, pad...)
	dst = append(dst, body...)
	n := len(dst) - start - 8
	if kind == KindData {
		n = min(n, 5+len(pad)+maskedData)
	}
	xorStream(dst[start+8:start+8+n], k.Key(salt))
	return dst
}

// Open unmasks a datagram in place and returns its kind and body. The first 5
// bytes are unmasked to check magic before anything else.
func (k Keys) Open(d []byte) (kind byte, body []byte, err error) {
	if len(d) < 8+5 {
		return 0, nil, ErrShort
	}
	key := k.Key(d[:8])
	x := blake3.New(32, key).XOF()
	var head [5]byte
	x.Read(head[:])
	for i := range 4 {
		if d[8+i]^head[i] != magic[i] {
			return 0, nil, ErrMagic
		}
	}
	kp := d[12] ^ head[4]
	kind = kp >> 6
	padLen := int(kp & 0x3f)
	if len(d) < 13+padLen {
		return 0, nil, ErrLayout
	}
	n := len(d) - 13
	if kind == KindData {
		n = min(n, padLen+maskedData)
	}
	rest := d[13 : 13+n]
	stream := make([]byte, len(rest))
	x.Read(stream)
	for i := range rest {
		rest[i] ^= stream[i]
	}
	body = d[13+padLen:]
	switch kind {
	case KindProbe:
		if len(body) != 8 {
			return 0, nil, ErrLayout
		}
	case KindFragment:
		if len(body) < 2 {
			return 0, nil, ErrLayout
		}
	case KindData:
		if len(body) == 0 || body[0]&0x80 != 0 {
			return 0, nil, ErrLayout // a DATA packet has a short header
		}
	case KindHandshake:
		if len(body) == 0 || body[0]&0x80 == 0 {
			return 0, nil, ErrLayout // a HANDSHAKE starts with a long header
		}
	}
	return kind, body, nil
}

// NewSalt draws 8 random bytes whose first byte is none of the plaintext eD2K
// UDP headers (Protocol.md §4.3).
func NewSalt() []byte {
	s := make([]byte, 8)
	for {
		rand.Read(s)
		switch s[0] {
		case 0xe3, 0xe4, 0xe5, 0xc5, 0xd4, 0xa3, 0xb2:
			continue
		}
		return s
	}
}

func xorStream(b, key []byte) {
	stream := make([]byte, len(b))
	blake3.New(32, key).XOF().Read(stream)
	for i := range b {
		b[i] ^= stream[i]
	}
}
