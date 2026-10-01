package ed2k

import (
	"bytes"
	"math/big"
	"testing"
)

func cloneRC4Key(k *RC4Key) *RC4Key {
	cp := *k
	return &cp
}

func TestTCPCryptNegotiateAndHandshake(t *testing.T) {
	p := NewPacket()
	tc := NewTCPCrypt(p, true)

	g := big.NewInt(2)
	pmod := new(big.Int).SetBytes(CryptPrime)
	A := new(big.Int).Exp(g, big.NewInt(5), pmod).Bytes()
	aBuf := make([]byte, CryptPrimeSize)
	copy(aBuf[CryptPrimeSize-len(A):], A)

	negIn := append([]byte{0x7a}, aBuf...) // random non-protocol marker
	negIn = append(negIn, 0x00)            // pad len = 0
	resp, err := tc.ProcessData(NewBufferFromBytes(negIn))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) <= CryptPrimeSize {
		t.Fatalf("unexpected negotiate response size: %d", len(resp))
	}
	if tc.State() != CsNegotiating {
		t.Fatalf("status mismatch after negotiate: %d", tc.State())
	}

	plain := NewBuffer(4 + 1 + 1 + 1)
	_ = plain.PutUInt32LE(MagicValueSync)
	_ = plain.PutUInt8(uint8(EmObfuscate))
	_ = plain.PutUInt8(0)
	plain.PutBuffer([]byte{0x99})

	recvKey, _ := tc.RecvCipher()
	clientKey := cloneRC4Key(recvKey)
	wire := RC4Crypt(plain.Bytes(), len(plain.Bytes()), clientKey)
	rest, err := tc.ProcessData(NewBufferFromBytes(wire))
	if err != nil {
		t.Fatal(err)
	}
	if tc.State() != CsEncrypting {
		t.Fatalf("status mismatch after handshake: %d", tc.State())
	}
	if !bytes.Equal(rest, []byte{0x99}) {
		t.Fatalf("unexpected remaining payload: %v", rest)
	}
}

// cryptClientOpening builds a client's key exchange with the given padding.
func cryptClientOpening(t *testing.T, pad int) []byte {
	t.Helper()
	g := big.NewInt(2)
	pmod := new(big.Int).SetBytes(CryptPrime)
	A := new(big.Int).Exp(g, big.NewInt(7), pmod).Bytes()
	out := []byte{0x7a}
	out = append(out, make([]byte, CryptPrimeSize-len(A))...)
	out = append(out, A...)
	out = append(out, byte(pad))
	return append(out, bytes.Repeat([]byte{0x55}, pad)...)
}

// Both handshake stages may arrive in any number of pieces, padding included. The
// state machine used to need each stage's fixed part in one chunk, skipped a short
// padding unchecked, and in the second stage handed the rest of the padding on as
// packet data.
func TestTCPCryptHandshakeFragmented(t *testing.T) {
	for _, step := range []int{1, 2, 7, 50} {
		tc := NewTCPCrypt(NewPacket(), true)
		opening := cryptClientOpening(t, 9)

		var resp []byte
		for i := 0; i < len(opening); i += step {
			end := min(i+step, len(opening))
			out, err := tc.ProcessData(NewBufferFromBytes(opening[i:end]))
			if err != nil {
				t.Fatalf("step=%d opening[%d:%d]: %v", step, i, end, err)
			}
			if out != nil && end != len(opening) {
				t.Fatalf("step=%d: answered at byte %d of %d", step, end, len(opening))
			}
			resp = out
		}
		if len(resp) <= CryptPrimeSize || tc.State() != CsNegotiating {
			t.Fatalf("step=%d: key exchange incomplete: resp=%d state=%d", step, len(resp), tc.State())
		}

		plain := NewBuffer(4 + 1 + 1 + 3 + 2)
		_ = plain.PutUInt32LE(MagicValueSync)
		_ = plain.PutUInt8(uint8(EmObfuscate))
		_ = plain.PutUInt8(3)
		plain.PutBuffer([]byte{0x11, 0x22, 0x33}) // padding
		plain.PutBuffer([]byte{0xe3, 0x99})       // the login's first bytes
		recvKey, _ := tc.RecvCipher()
		wire := RC4Crypt(plain.Bytes(), len(plain.Bytes()), cloneRC4Key(recvKey))

		var rest []byte
		for i := 0; i < len(wire); i += step {
			end := min(i+step, len(wire))
			out, err := tc.ProcessData(NewBufferFromBytes(wire[i:end]))
			if err != nil {
				t.Fatalf("step=%d reply[%d:%d]: %v", step, i, end, err)
			}
			if tc.State() == CsEncrypting && rest == nil {
				rest = append([]byte{}, out...)
				// Whatever follows is ordinary encrypted stream.
				if end < len(wire) {
					rest = append(rest, tc.Decrypt(wire[end:])...)
				}
				break
			}
		}
		t.Logf("input: opening %d B and reply %d B in %d-byte pieces, output: state=%d rest=% x",
			len(opening), len(wire), step, tc.State(), rest)
		if tc.State() != CsEncrypting || !bytes.Equal(rest, []byte{0xe3, 0x99}) {
			t.Fatalf("step=%d: state=%d rest=% x, want encrypting and e3 99", step, tc.State(), rest)
		}
	}
}
