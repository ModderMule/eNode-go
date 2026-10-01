package ed2k

import "testing"

func TestBuildHelloPacket(t *testing.T) {
	c := NewClient(ClientConfig{
		EnableCrypt: false,
		Address:     "1.2.3.4",
		TCPPort:     4661,
		Hash:        []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	})
	buf, err := c.BuildHelloPacket()
	if err != nil {
		t.Fatal(err)
	}
	if buf.Bytes()[0] != PrED2K {
		t.Fatalf("bad protocol")
	}
}

func TestReadOpHelloAnswer(t *testing.T) {
	tags := []Tag{{Type: TypeString, Code: TagName, Data: "srv"}}
	tl, err := TagsLength(tags)
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuffer(16 + 4 + 2 + tl + 4 + 2)
	_ = b.PutHash([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	_ = b.PutUInt32LE(123)
	_ = b.PutUInt16LE(4662)
	_ = b.PutTags(tags)
	_ = b.PutUInt32LE(0x04030201)
	_ = b.PutUInt16LE(4661)
	b.Pos(0)

	info, err := ReadOpHelloAnswer(b)
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != 123 || info.Port != 4662 || info.ServerPort != 4661 {
		t.Fatalf("unexpected hello answer: %+v", info)
	}
	if info.Tags["name"].(string) != "srv" {
		t.Fatalf("bad tags")
	}
}

func TestHandshakeAndDecryptNegotiation(t *testing.T) {
	c := NewClient(ClientConfig{EnableCrypt: true})
	c.Hash = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	_, err := c.BuildHandshake(0xaa, 0x11223344, []byte{9, 8, 7})
	if err != nil {
		t.Fatal(err)
	}

	// emulate server response encrypted with recv key stream.
	plain := NewBuffer(4 + 1 + 1 + 2)
	_ = plain.PutUInt32LE(MagicValueSync)
	_ = plain.PutUInt8(uint8(EmObfuscate))
	_ = plain.PutUInt8(2)
	plain.PutBuffer([]byte{1, 2})

	k := *c.RecvKey
	wire := RC4Crypt(plain.Bytes(), len(plain.Bytes()), &k)
	_, handshakeDone, err := c.Decrypt(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !handshakeDone || c.CryptStatus != CsEncrypting {
		t.Fatalf("handshake not done: status=%d", c.CryptStatus)
	}
}

// TestHandshakeRecvKeyMatchesProtocolSpec pins the receive key against an
// independently computed MD5 rather than against the implementation's own
// derivation. TestHandshakeAndDecryptNegotiation above encrypts its fake response
// with c.RecvKey itself, so it only proves Decrypt is self-inverse and passes even
// when the seed is wrong.
//
// Spec (EncryptedStreamSocket.cpp):
//
//	ReceiveKey = MD5(<UserHash 16><MAGICVALUE_203 1><RandomKeyPart 4>)  -- 21 bytes
func TestHandshakeRecvKeyMatchesProtocolSpec(t *testing.T) {
	hash := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	const randomKey uint32 = 0x11223344

	// MD5 of the 21-byte key data, computed outside this package:
	//   000102030405060708090a0b0c0d0e0f cb 44332211
	// Hashing only the first 17 bytes (the pre-fix behaviour) instead yields
	// 0693761ed2667c97241ab0888ad1f9cd, so this test distinguishes the two.
	expectedSeed := []byte{
		0x12, 0xa8, 0x5a, 0xc9, 0x3b, 0xd5, 0xba, 0x30,
		0xba, 0x94, 0x1a, 0x19, 0x1d, 0x29, 0x93, 0x33,
	}

	t.Logf("input: hash=%x magic=%d randomKey=0x%08x", hash, MagicValue203, randomKey)
	t.Logf("expected recv seed (independently derived) = %x", expectedSeed)

	c := NewClient(ClientConfig{EnableCrypt: true})
	c.Hash = hash
	if _, err := c.BuildHandshake(0xaa, randomKey, []byte{9, 8, 7}); err != nil {
		t.Fatal(err)
	}

	want := RC4CreateKey(expectedSeed, true)
	if *c.RecvKey != *want {
		t.Fatalf("RecvKey mismatch: not derived from the full 21-byte key data " +
			"(hashing only userhash+magic omits the 4 randomKey bytes)")
	}
	t.Logf("output: RecvKey matches the RC4 key built from the expected seed")

	// End-to-end: a peer encrypting with the spec key must be decryptable.
	plain := NewBuffer(4 + 1 + 1 + 2)
	_ = plain.PutUInt32LE(MagicValueSync)
	_ = plain.PutUInt8(uint8(EmObfuscate))
	_ = plain.PutUInt8(2)
	plain.PutBuffer([]byte{1, 2})

	peerKey := RC4CreateKey(expectedSeed, true)
	wire := RC4Crypt(plain.Bytes(), len(plain.Bytes()), peerKey)
	t.Logf("input: peer ciphertext = %x", wire)

	_, handshakeDone, err := c.Decrypt(wire)
	if err != nil {
		t.Fatalf("decrypting a spec-conformant peer stream failed: %v", err)
	}
	if !handshakeDone || c.CryptStatus != CsEncrypting {
		t.Fatalf("handshake not completed: status=%d", c.CryptStatus)
	}
	t.Logf("output: handshake completed, status=%d method=%d", c.CryptStatus, c.CryptMethod)
}

// The dial-back probe's handshake answer may arrive in any number of pieces, pad
// included, and the hello answer can follow in the same read. Decrypt used to need
// the fixed part in one chunk and dropped both a short pad and what came after it.
func TestDecryptNegotiationFragmented(t *testing.T) {
	c := NewClient(ClientConfig{EnableCrypt: true})
	c.Hash = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if _, err := c.BuildHandshake(0xaa, 0x11223344, nil); err != nil {
		t.Fatal(err)
	}

	plain := NewBuffer(4 + 1 + 1 + 5 + 3)
	_ = plain.PutUInt32LE(MagicValueSync)
	_ = plain.PutUInt8(uint8(EmObfuscate))
	_ = plain.PutUInt8(5)
	plain.PutBuffer([]byte{1, 2, 3, 4, 5})
	plain.PutBuffer([]byte{0xe3, 0x01, 0x02}) // the start of the hello answer
	k := *c.RecvKey
	wire := RC4Crypt(plain.Bytes(), len(plain.Bytes()), &k)
	t.Logf("input: %d-byte answer (pad 5, then 3 payload bytes) fed one byte per read", len(wire))

	var rest []byte
	var done bool
	for i, b := range wire {
		out, d, err := c.Decrypt([]byte{b})
		if err != nil {
			t.Fatalf("byte %d: %v", i, err)
		}
		if d {
			if i != len(wire)-1-3 { // the last pad byte
				t.Fatalf("handshake completed at byte %d, want %d", i, len(wire)-4)
			}
			done = true
			rest = append(rest, out...)
			continue
		}
		if done {
			rest = append(rest, out...)
		}
	}
	t.Logf("output: done=%t status=%d rest=% x", done, c.CryptStatus, rest)
	if !done || c.CryptStatus != CsEncrypting {
		t.Fatalf("handshake not completed")
	}
	if string(rest) != "\xe3\x01\x02" {
		t.Fatalf("payload after the handshake = % x, want e3 01 02", rest)
	}
}
