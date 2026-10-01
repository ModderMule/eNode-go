package ed2k

import (
	"bytes"
	"testing"
)

// OP_CALLBACKREQUESTED carries the requester's crypt options and user hash after its
// IPv4 and port. Clients read them when the payload is at least 23 bytes (MFC
// ServerSocket.cpp); without them the target calls back in plaintext with no hash to
// key obfuscation, and a requester that requires obfuscation refuses it.
func TestCallbackRequestedCarriesCryptTrailer(t *testing.T) {
	hash := bytes.Repeat([]byte{0xab}, 16)
	for _, tc := range []struct {
		name        string
		crypt       byte
		hash        []byte
		wantPayload int
	}{
		{"with hash", 0x0f, hash, 23}, // 0x08 (direct UDP callback) is not the server's to set
		{"without hash", 0x07, nil, 6},
	} {
		packet, err := BuildCallbackRequestedPacket(0x0a0b0c0d, 4662, tc.crypt, tc.hash)
		if err != nil {
			t.Fatal(err)
		}
		b := packet.Bytes()
		t.Logf("input: %s crypt=%#x, output: % x", tc.name, tc.crypt, b)
		if b[5] != OpCallbackReqd {
			t.Fatalf("opcode = %#x", b[5])
		}
		payload := b[6:]
		if len(payload) != tc.wantPayload {
			t.Fatalf("payload is %d bytes, want %d", len(payload), tc.wantPayload)
		}
		if !bytes.Equal(payload[:6], []byte{0x0d, 0x0c, 0x0b, 0x0a, 0x36, 0x12}) {
			t.Fatalf("ip/port = % x", payload[:6])
		}
		if tc.wantPayload == 23 {
			if payload[6] != tc.crypt&0x07 {
				t.Fatalf("crypt options = %#x, want %#x", payload[6], tc.crypt&0x07)
			}
			if !bytes.Equal(payload[7:], tc.hash) {
				t.Fatalf("hash = % x", payload[7:])
			}
		}
	}
}
