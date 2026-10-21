// Package sig holds the signed-record rules of ed3k (Protocol.md §10.7): the
// strict Ed25519 verifier, the bytes a record signature covers, and the
// canonical size measure of a Signed.
package sig

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"filippo.io/edwards25519"
	"google.golang.org/protobuf/proto"

	"enode/ed3k/ed3kpb"
)

// AlgEd25519 is Signature.alg for Ed25519, the one required algorithm of v1.
const AlgEd25519 = 1

// MaxSigned is the largest Signed a node accepts, measured canonically.
const MaxSigned = 1024

// Errors of CheckSigned. Every one makes the record REJECTED.
var (
	ErrNoSignature  = errors.New("ed3k: no Ed25519 signature")
	ErrAlgZero      = errors.New("ed3k: signature with alg 0")
	ErrDuplicateAlg = errors.New("ed3k: two signatures of one algorithm")
	ErrBadSignature = errors.New("ed3k: signature does not verify")
	ErrTooLarge     = errors.New("ed3k: signed record above 1 KiB")
)

// Verify checks an Ed25519 signature as §10.7 fixes it: S below L, canonical
// encodings of A and R, neither of small order, cofactorless equation. This is
// ed25519-dalek's verify_strict plus a canonical-A check. Go's
// crypto/ed25519.Verify alone accepts small-order R and A and a non-canonical A,
// so those checks run first.
func Verify(pub, msg, signature []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	if !strictPoint(pub) || !strictPoint(signature[:32]) {
		return false
	}
	// stdlib rejects S >= L and a non-canonical R (it compares encodings) and
	// checks [S]B = R + [k]A without the cofactor.
	return ed25519.Verify(ed25519.PublicKey(pub), msg, signature)
}

// SignedBytes is what a record signature covers:
// "ed3k v1 record" ‖ kind(1) ‖ target(16) ‖ body.
func SignedBytes(kind ed3kpb.Kind, target, body []byte) []byte {
	out := make([]byte, 0, len(recordPrefix)+1+len(target)+len(body))
	out = append(out, recordPrefix...)
	out = append(out, byte(kind))
	out = append(out, target...)
	return append(out, body...)
}

// Sign makes the one Ed25519 signature of a record (publisher side; used by
// tests and tools).
func Sign(priv ed25519.PrivateKey, kind ed3kpb.Kind, target, body []byte) *ed3kpb.Signed {
	s := ed25519.Sign(priv, SignedBytes(kind, target, body))
	return &ed3kpb.Signed{Body: body, Sigs: []*ed3kpb.Signature{{Alg: AlgEd25519, Sig: s}}}
}

// CanonicalSize is the §10.7 measure of a Signed: body and sigs as the
// canonical serialisation writes them, without key and without unknown fields.
func CanonicalSize(s *ed3kpb.Signed) int {
	c := &ed3kpb.Signed{Body: s.GetBody()}
	for _, g := range s.GetSigs() {
		c.Sigs = append(c.Sigs, &ed3kpb.Signature{Alg: g.GetAlg(), Sig: g.GetSig()})
	}
	return proto.Size(c)
}

// CheckSigned applies the signature and size rules of §10.7 to a record stored
// under (kind, target) by pub: at most 1 KiB, no alg 0, one signature per
// algorithm, the Ed25519 one present and valid. Signatures of other algorithms
// are ignored and kept.
func CheckSigned(s *ed3kpb.Signed, kind ed3kpb.Kind, target, pub []byte) error {
	if CanonicalSize(s) > MaxSigned {
		return ErrTooLarge
	}
	seen := map[uint32]bool{}
	var ed []byte
	for _, g := range s.GetSigs() {
		if g.GetAlg() == 0 {
			return ErrAlgZero
		}
		if seen[g.GetAlg()] {
			return ErrDuplicateAlg
		}
		seen[g.GetAlg()] = true
		if g.GetAlg() == AlgEd25519 {
			ed = g.GetSig()
		}
	}
	if ed == nil {
		return ErrNoSignature
	}
	if !Verify(pub, SignedBytes(kind, target, s.GetBody()), ed) {
		return ErrBadSignature
	}
	return nil
}

var recordPrefix = []byte("ed3k v1 record")

// strictPoint reports whether b is the canonical encoding of a point that is not
// of small order.
func strictPoint(b []byte) bool {
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return false
	}
	if !bytes.Equal(p.Bytes(), b) {
		return false
	}
	return new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) != 1
}
