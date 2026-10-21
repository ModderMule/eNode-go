package sig

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"enode/ed3k/ed3kpb"
)

// Vectors from tests/vectors-v1.md "Signed record (§10.7)".

const (
	seedHex   = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	pubHex    = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	bodyHex   = "08808cbbd60612460a20453b9482e0d4f14e084be18f10b4b16b0f61bfa2ffae0f6e48fc4a0e9bc3e39410101a205468652e4269675f536c65657020283139343629205b31303830705d2e6d6b76"
	targetHex = "f797b920611f6bebcb89cad846086177"
	sigHex    = "b1c5bcac6211b9e588444546096a6b4a817476d8103a32084162df8641ce5f8b7960c6196eec9e53ef5430e4ba978024b30bec48f02861507ce71c8d67b25102"
)

func TestSignedRecordVector(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(h(t, seedHex))
	s := Sign(priv, ed3kpb.Kind_KEYWORD, h(t, targetHex), h(t, bodyHex))
	t.Logf("signature=%x", s.Sigs[0].Sig)
	if hex.EncodeToString(s.Sigs[0].Sig) != sigHex {
		t.Fatalf("signature differs")
	}
	var rec ed3kpb.Record
	if err := proto.Unmarshal(h(t, bodyHex), &rec); err != nil {
		t.Fatal(err)
	}
	t.Logf("record expires=%d name=%q size=%d", rec.Expires, rec.File.Name, rec.File.Size)
	if rec.Expires != 1791936000 || rec.File.Name != "The.Big_Sleep (1946) [1080p].mkv" {
		t.Fatal("body does not decode as the vector says")
	}
	if err := CheckSigned(s, ed3kpb.Kind_KEYWORD, h(t, targetHex), h(t, pubHex)); err != nil {
		t.Fatalf("valid record refused: %v", err)
	}
	if err := CheckSigned(s, ed3kpb.Kind_NOTE, h(t, targetHex), h(t, pubHex)); err == nil {
		t.Fatal("record verified under another kind")
	}
}

func TestRejectedSignatures(t *testing.T) {
	msg := SignedBytes(ed3kpb.Kind_KEYWORD, h(t, targetHex), h(t, bodyHex))
	cases := []struct {
		name, pub, sig string
		want           bool
	}{
		{"valid", pubHex, sigHex, true},
		{"S not below L", pubHex, "b1c5bcac6211b9e588444546096a6b4a817476d8103a32084162df8641ce5f8b6634bc76884fb1abc5f1278799915f39b30bec48f02861507ce71c8d67b25112", false},
		{"R of small order", pubHex, "0100000000000000000000000000000000000000000000000000000000000000a466c59a42f6107cb6af91b61f753b1f0637a80cace2234de45f5254eb8da90d", false},
		{"R not canonical", pubHex, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fef4e5f0ad5f8dcc6e01eceeca12eab1b0621a0be115e2a07239f73b87403a90c", false},
		{"A of small order", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "f47e49f9d07ad2c1606b4d94067c41f9777d4ffda709b71da1d88628fce34d850600000000000000000000000000000000000000000000000000000000000000", false},
		{"A not canonical", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "2f1132ca61ab38dff00f2fea3228f24c6c71d58085b80e47e19515cb27e8d0470400000000000000000000000000000000000000000000000000000000000000", false},
	}
	for _, c := range cases {
		got := Verify(h(t, c.pub), msg, h(t, c.sig))
		std := ed25519.Verify(h(t, c.pub), msg, h(t, c.sig))
		t.Logf("%-18s strict=%v stdlib=%v", c.name, got, std)
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestSignedForms(t *testing.T) {
	sig := h(t, sigHex)
	body := h(t, bodyHex)
	target := h(t, targetHex)
	pub := h(t, pubHex)
	cases := []struct {
		name string
		s    *ed3kpb.Signed
		want error
	}{
		{"valid", &ed3kpb.Signed{Body: body, Sigs: []*ed3kpb.Signature{{Alg: 1, Sig: sig}}}, nil},
		{"alg 0", &ed3kpb.Signed{Body: body, Sigs: []*ed3kpb.Signature{{Sig: sig}}}, ErrAlgZero},
		{"two Ed25519", &ed3kpb.Signed{Body: body, Sigs: []*ed3kpb.Signature{{Alg: 1, Sig: sig}, {Alg: 1, Sig: sig}}}, ErrDuplicateAlg},
		{"unknown alg kept", &ed3kpb.Signed{Body: body, Sigs: []*ed3kpb.Signature{{Alg: 1, Sig: sig}, {Alg: 7, Sig: []byte{1}}}}, nil},
		{"no signature", &ed3kpb.Signed{Body: body}, ErrNoSignature},
		{"too large", &ed3kpb.Signed{Body: body, Sigs: []*ed3kpb.Signature{{Alg: 1, Sig: sig}, {Alg: 9, Sig: make([]byte, 1000)}}}, ErrTooLarge},
	}
	for _, c := range cases {
		err := CheckSigned(c.s, ed3kpb.Kind_KEYWORD, target, pub)
		t.Logf("%-16s size=%d err=%v", c.name, CanonicalSize(c.s), err)
		if err != c.want {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	// The serialised form after the body, from the vectors.
	valid, _ := proto.Marshal(&ed3kpb.Signed{Body: body, Sigs: []*ed3kpb.Signature{{Alg: 1, Sig: sig}}})
	after := hex.EncodeToString(valid[2+len(body):])
	want := strings.ReplaceAll("1a4408011240b1c5bcac6211b9e588444546096a6b4a817476d8103a32084162df8641ce5f8b7960c6196eec9e53ef54 30e4ba978024b30bec48f02861507ce71c8d67b25102", " ", "")
	t.Logf("after body=%s", after)
	if after != want {
		t.Fatalf("serialised Signed differs")
	}
	// key does not count towards the size.
	withKey := &ed3kpb.Signed{Body: body, Key: 300, Sigs: []*ed3kpb.Signature{{Alg: 1, Sig: sig}}}
	if CanonicalSize(withKey) != len(valid) {
		t.Fatalf("key counted: %d vs %d", CanonicalSize(withKey), len(valid))
	}
}

func h(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
