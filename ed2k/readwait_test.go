package ed2k

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"enode/storage"
)

// TestReadLoopOnRealSocket drives the read loop over a real TCP socket, where it waits
// for data without a buffer (readwait_unix.go). One write carries a login, a frame
// larger than the pooled read buffer and an OP_GETSERVERLIST: the bytes left on the
// socket after the first read raise no new poller edge, so a wait that did not look
// at the socket first would hang here instead of answering. The session must then
// be reaped by the idle deadline, which the wait has to honour too.
func TestReadLoopOnRealSocket(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address: "127.0.0.1", Port: 4661, AllowLowIDs: true, Hash: []byte("1111111111111111"),
		DisconnectTimeout: 400 * time.Millisecond,
	}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	rt.firewallProbe = func(*tcpClient) bool { return true }

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	handler := rt.TCPHandler(false)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handler(conn)
	}()

	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	login, err := MakePacket(PrED2K, loginItems(bytes.Repeat([]byte{0x6c}, 16), 0, 4662))
	if err != nil {
		t.Fatal(err)
	}
	var stream []byte
	stream = append(stream, login.Bytes()...)
	stream = append(stream, rawFrame(0xfe, make([]byte, 3*readBufSize))...)
	stream = append(stream, rawFrame(OpGetServerList, nil)...)
	t.Logf("input: one write of %d bytes: login, %d-byte unknown frame, OP_GETSERVERLIST", len(stream), 3*readBufSize)
	if _, err := client.Write(stream); err != nil {
		t.Fatal(err)
	}

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	var opcodes []byte
	for !bytes.Contains(opcodes, []byte{OpServerList}) {
		code, err := readFrame(client)
		if err != nil {
			t.Fatalf("no OP_SERVERLIST: %v (got opcodes %x)", err, opcodes)
		}
		opcodes = append(opcodes, code)
	}
	t.Logf("output: opcodes received %x", opcodes)

	start := time.Now()
	for {
		if _, err := readFrame(client); err != nil {
			t.Logf("output: server closed the idle session after %s: %v", time.Since(start).Round(time.Millisecond), err)
			if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
				t.Fatalf("want the server to close the idle session, got %v", err)
			}
			return
		}
	}
}

func rawFrame(opcode byte, payload []byte) []byte {
	out := make([]byte, 6, 6+len(payload))
	out[0] = PrED2K
	binary.LittleEndian.PutUint32(out[1:5], uint32(len(payload)+1))
	out[5] = opcode
	return append(out, payload...)
}

// readFrame reads one ed2k frame and returns its opcode.
func readFrame(r io.Reader) (byte, error) {
	var hdr [6]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	size := binary.LittleEndian.Uint32(hdr[1:5])
	if _, err := io.CopyN(io.Discard, r, int64(size-1)); err != nil {
		return 0, err
	}
	return hdr[5], nil
}
