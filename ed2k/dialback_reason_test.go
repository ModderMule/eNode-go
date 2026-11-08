package ed2k

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"enode/storage"
)

// TestDialHelloNamesTheFailingStep pins what the dial-back log line reports: the
// step that failed and the source address the probe left from. A LowID is decided
// from these, and without them a closed port, a slow answer and an answer from
// another user hash all look the same in the server log.
func TestDialHelloNamesTheFailingStep(t *testing.T) {
	loginHash := bytes.Repeat([]byte{0x6a}, 16)
	otherHash := bytes.Repeat([]byte{0x5b}, 16)

	cases := []struct {
		name       string
		answer     []byte // hash the fake client answers with; nil = no listener
		silent     bool   // listener accepts but never answers
		wantOK     bool
		wantStep   string // prefix of the error; "" = no error
		wantSource bool
		wantIs     error
	}{
		{name: "closed port fails at dial", wantStep: "dial: "},
		{name: "silent client times out reading the answer", silent: true, wantStep: "read hello answer: ", wantSource: true},
		{name: "answer from another user hash", answer: otherHash, wantStep: "read hello answer: ", wantSource: true, wantIs: errHelloHashMismatch},
		{name: "open port answers", answer: loginHash, wantOK: true, wantSource: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := NewServerRuntime(TCPRuntimeConfig{
				Address: "127.0.0.1", Port: 4661, Hash: []byte("1111111111111111"),
				AllowLowIDs: true, ConnectionTimeout: 200 * time.Millisecond,
			}, UDPRuntimeConfig{}, storage.NewMemoryEngine())

			l, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := uint16(l.Addr().(*net.TCPAddr).Port)
			if tc.answer == nil && !tc.silent {
				l.Close()
			} else {
				defer l.Close()
				go serveHelloAnswer(l, tc.answer, port, tc.silent)
			}

			client, _ := newReflectClient(t, rt, "127.0.0.1")
			client.info.Hash = loginHash
			client.info.Port = port

			ok, source, err := rt.dialHello(client, client.snapshotInfo().Port, false, "tcp4", "127.0.0.1")
			t.Logf("input: target=127.0.0.1:%d answerHash=%x silent=%t", port, tc.answer, tc.silent)
			t.Logf("output: ok=%t source=%q err=%v", ok, source, err)

			if ok != tc.wantOK {
				t.Fatalf("ok = %t, want %t", ok, tc.wantOK)
			}
			if tc.wantStep == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantStep != "" && (err == nil || !strings.HasPrefix(err.Error(), tc.wantStep)) {
				t.Fatalf("err = %v, want it to start with %q", err, tc.wantStep)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("err = %v, want errors.Is %v", err, tc.wantIs)
			}
			if tc.wantSource != (source != "") {
				t.Fatalf("source = %q, want present=%t", source, tc.wantSource)
			}
			if tc.wantSource && !strings.HasPrefix(source, "127.0.0.1:") {
				t.Fatalf("source = %q, want the 127.0.0.1 bind", source)
			}
		})
	}
}

// serveHelloAnswer answers each probe's OP_HELLO with an OP_HELLOANSWER carrying
// hash, or holds the connection open without answering when silent.
func serveHelloAnswer(l net.Listener, hash []byte, port uint16, silent bool) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			hdr := make([]byte, 5)
			if _, err := io.ReadFull(conn, hdr); err != nil {
				return
			}
			if _, err := io.ReadFull(conn, make([]byte, binary.LittleEndian.Uint32(hdr[1:]))); err != nil {
				return
			}
			if silent {
				time.Sleep(time.Second)
				return
			}
			// OP_HELLOANSWER: hash(16) id(4) port(2) tagcount(4) server ip(4) port(2).
			payload := make([]byte, 1+16+4+2+4+4+2)
			payload[0] = OpHelloAnswer
			copy(payload[1:], hash)
			binary.LittleEndian.PutUint32(payload[17:], 0x0100007F)
			binary.LittleEndian.PutUint16(payload[21:], port)
			out := []byte{PrED2K, 0, 0, 0, 0}
			binary.LittleEndian.PutUint32(out[1:], uint32(len(payload)))
			_, _ = conn.Write(append(out, payload...))
			time.Sleep(50 * time.Millisecond)
		}(conn)
	}
}
