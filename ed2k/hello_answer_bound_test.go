package ed2k

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// helloAnswerHeader frames a packet header declaring `size` payload bytes.
func helloAnswerHeader(size uint32) []byte {
	hdr := make([]byte, 5)
	hdr[0] = PrED2K
	binary.LittleEndian.PutUint32(hdr[1:5], size)
	return hdr
}

// readHelloAnswer reassembles the reply from the client the server is probing
// for HighID. That peer picked the address we dialed and controls the bytes
// coming back, so an unbounded declared size is remotely triggerable: log in,
// advertise any port, then answer the probe with a huge header.
func TestReadHelloAnswerRejectsHugeDeclaredSize(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		// 0xFFFFFFFE payload bytes declared, then a trickle that never satisfies it.
		_, _ = client.Write(helloAnswerHeader(0xFFFFFFFE))
		_, _ = client.Write(make([]byte, 64))
	}()

	t.Logf("input: peer declares a %d-byte payload then stalls", uint32(0xFFFFFFFE))

	start := time.Now()
	cli := &Client{CryptStatus: CsNone}
	ok, err := readHelloAnswer(cli, server, 5*time.Second, make([]byte, 16), nil)
	elapsed := time.Since(start)

	t.Logf("output: ok=%t err=%v elapsed=%s", ok, err, elapsed.Round(time.Millisecond))

	if err == nil {
		t.Fatal("a 4 GiB declared size was accepted")
	}
	if !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("expected ErrPacketTooLarge, got %v", err)
	}
	// It must fail on the declaration, not sit until the read deadline.
	if elapsed > time.Second {
		t.Fatalf("took %s to reject — it waited for the timeout instead of the header", elapsed)
	}
}

// Note: there is deliberately no test for maxHelloAnswerBytes. With the
// declared-size check above in place, every packet completes and is sliced off
// once 5+size bytes arrive, so the reassembly buffer cannot reach that ceiling
// — any test would pass with or without it, which counts as no coverage. It is
// kept in the code as a guard for the day the size check changes.

// A well-behaved peer must still be understood, including when its answer is
// split across reads — the reassembly loop is the reason this function exists.
func TestReadHelloAnswerAcceptsSegmentedAnswer(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	// OP_HELLOANSWER: hash(16) id(4) port(2) tagcount(4), no tags.
	payload := make([]byte, 1+16+4+2+4)
	payload[0] = OpHelloAnswer
	binary.LittleEndian.PutUint32(payload[17:21], 0x0100007F)
	binary.LittleEndian.PutUint16(payload[21:23], 4662)
	packet := append(helloAnswerHeader(uint32(len(payload))), payload...)

	go func() {
		defer client.Close()
		// Deliberately split mid-payload so the inner loop has to wait for more.
		_, _ = client.Write(packet[:8])
		time.Sleep(20 * time.Millisecond)
		_, _ = client.Write(packet[8:])
	}()

	t.Logf("input: a valid OP_HELLOANSWER of %d bytes, split 8/%d across two writes",
		len(packet), len(packet)-8)

	cli := &Client{CryptStatus: CsNone}
	ok, err := readHelloAnswer(cli, server, 5*time.Second, make([]byte, 16), nil) // the answer's hash is all zero
	t.Logf("output: ok=%t err=%v", ok, err)

	if err != nil {
		t.Fatalf("a valid segmented hello answer was rejected: %v", err)
	}
	if !ok {
		t.Fatal("a valid hello answer was not recognised")
	}
}

// The dial-back reaches whoever answers the client's IP and port. Behind a CGNAT that
// can be another user; only an answer carrying the logged-in hash proves the client
// itself is reachable.
func TestReadHelloAnswerRejectsOtherUserHash(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	payload := make([]byte, 1+16+4+2+4)
	payload[0] = OpHelloAnswer
	for i := 1; i <= 16; i++ {
		payload[i] = 0xee
	}
	packet := append(helloAnswerHeader(uint32(len(payload))), payload...)
	go func() {
		defer client.Close()
		_, _ = client.Write(packet)
	}()

	want := make([]byte, 16)
	t.Logf("input: answer hash=% x, logged-in hash=% x", payload[1:17], want)
	ok, err := readHelloAnswer(&Client{CryptStatus: CsNone}, server, 5*time.Second, want, nil)
	t.Logf("output: ok=%t err=%v", ok, err)
	if ok || !errors.Is(err, errHelloHashMismatch) {
		t.Fatalf("want errHelloHashMismatch, got ok=%t err=%v", ok, err)
	}
}
