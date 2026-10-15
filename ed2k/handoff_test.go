package ed2k

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"enode/storage"
)

// wireClient is the client end of a real TCP session, optionally obfuscated: it
// runs the client half of the DH key exchange and then keeps its own RC4 state, so
// a server that loses its place in the keystream garbles what this reads.
type wireClient struct {
	t    *testing.T
	conn net.Conn
	send *RC4Key
	recv *RC4Key
}

func dialWireClient(t *testing.T, addr string, obfuscate bool) *wireClient {
	t.Helper()
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &wireClient{t: t, conn: conn}
	if obfuscate {
		c.handshake()
	}
	return c
}

func (c *wireClient) handshake() {
	c.t.Helper()
	p := new(big.Int).SetBytes(CryptPrime)
	a := big.NewInt(0x1d2e3f)
	A := new(big.Int).Exp(big.NewInt(2), a, p).Bytes()
	opening := []byte{0x7a}
	opening = append(opening, make([]byte, CryptPrimeSize-len(A))...)
	opening = append(opening, A...)
	opening = append(opening, 0) // no padding
	c.writeRaw(opening)

	B := c.readRaw(CryptPrimeSize)
	K := new(big.Int).Exp(new(big.Int).SetBytes(B), a, p).Bytes()
	kBuf := make([]byte, CryptPrimeSize+1)
	copy(kBuf[CryptPrimeSize-len(K):CryptPrimeSize], K)
	kBuf[CryptPrimeSize] = MagicValueRequester
	c.send = RC4CreateKey(MD5(kBuf), true)
	kBuf[CryptPrimeSize] = MagicValueServer
	c.recv = RC4CreateKey(MD5(kBuf), true)

	sync := RC4Crypt(c.readRaw(7), 7, c.recv)
	if binary.LittleEndian.Uint32(sync) != MagicValueSync {
		c.t.Fatalf("server sync block % x does not decrypt", sync)
	}
	RC4Crypt(c.readRaw(int(sync[6])), int(sync[6]), c.recv) // its padding

	reply := NewBuffer(6)
	_ = reply.PutUInt32LE(MagicValueSync)
	_ = reply.PutUInt8(uint8(EmObfuscate))
	_ = reply.PutUInt8(0)
	c.write(reply.Bytes())
}

func (c *wireClient) writeRaw(b []byte) {
	c.t.Helper()
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatal(err)
	}
}

func (c *wireClient) readRaw(n int) []byte {
	c.t.Helper()
	b := make([]byte, n)
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c.conn, b); err != nil {
		c.t.Fatalf("read %d bytes: %v", n, err)
	}
	return b
}

// write sends b through the client's send cipher.
func (c *wireClient) write(b []byte) {
	c.t.Helper()
	if c.send != nil {
		b = RC4Crypt(b, len(b), c.send)
	}
	c.writeRaw(b)
}

func (c *wireClient) read(n int) []byte {
	c.t.Helper()
	b := c.readRaw(n)
	if c.recv != nil {
		b = RC4Crypt(b, len(b), c.recv)
	}
	return b
}

func (c *wireClient) frame(items []PacketItem) []byte {
	c.t.Helper()
	wire, err := MakePacket(PrED2K, items)
	if err != nil {
		c.t.Fatal(err)
	}
	return wire.Bytes()
}

// expect reads frames until one with opcode arrives and returns its payload.
func (c *wireClient) expect(opcode uint8) []byte {
	c.t.Helper()
	for range 20 {
		hdr := c.read(PacketHeaderSize)
		if !IsProtocol(hdr[0]) {
			c.t.Fatalf("garbled stream: header % x", hdr)
		}
		payload := c.read(int(binary.LittleEndian.Uint32(hdr[1:5])) - 1)
		if hdr[5] == opcode {
			return payload
		}
	}
	c.t.Fatalf("no opcode 0x%02x in 20 frames", opcode)
	return nil
}

// login logs in and returns the ID the server assigned.
func (c *wireClient) login(hash []byte, port uint16) uint32 {
	c.t.Helper()
	c.write(c.frame(loginItems(hash, 0, port)))
	return binary.LittleEndian.Uint32(c.expect(OpIDChange))
}

func getSourcesItems(hash []byte, size uint32) []PacketItem {
	return []PacketItem{
		{Type: TypeUint8, Value: OpGetSources},
		{Type: TypeHash, Value: hash},
		{Type: TypeUint32, Value: size},
	}
}

// handoffRuntime is a server whose clients on port 4662 are firewalled (LowID) and
// all others reachable (HighID), without a dial-back.
func handoffRuntime(t *testing.T) (*ServerRuntime, *storage.MemoryEngine, string) {
	t.Helper()
	engine := storage.NewMemoryEngine()
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address:      "127.0.0.1",
		Port:         4661,
		Hash:         bytes.Repeat([]byte{0x11}, 16),
		AllowLowIDs:  true,
		SupportCrypt: true,
		MessageLogin: "welcome",
		MessageLowID: "lowid",
	}, UDPRuntimeConfig{}, engine)
	rt.firewallProbe = func(c *tcpClient) bool { return c.snapshotInfo().Port == 4662 }
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go rt.TCPHandler(true)(conn)
		}
	}()
	return rt, engine, ln.Addr().String()
}

// waitFor polls cond for up to two seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// handOver runs both sides of a handover in one process: park on from, carry
// storage and sessions across their wire forms, restore on to.
func handOver(t *testing.T, from *ServerRuntime, fromEngine storage.Engine, to *ServerRuntime, toEngine storage.Engine) int {
	t.Helper()
	parked := from.ParkSessions(2 * time.Second)
	states, files, err := parked.Export()
	if err != nil {
		t.Fatal(err)
	}
	decoded := make([]SessionState, 0, len(states))
	for _, st := range states {
		raw, err := EncodeSessionState(st)
		if err != nil {
			t.Fatal(err)
		}
		back, err := DecodeSessionState(raw)
		if err != nil {
			t.Fatal(err)
		}
		decoded = append(decoded, back)
	}
	var buf bytes.Buffer
	if err := storage.ExportHandoff(fromEngine, &buf); err != nil {
		t.Fatal(err)
	}
	if err := storage.ImportHandoff(toEngine, &buf); err != nil {
		t.Fatal(err)
	}
	restored, err := to.RestoreSessions(decoded, files)
	if err != nil {
		t.Fatal(err)
	}
	parked.HandOff()
	restored.Start()
	return restored.Len()
}

// The whole point: an obfuscated LowID session and a plaintext HighID one move to
// another runtime mid-packet — one with half a header received, the other with half
// a payload — and carry on there. The RC4 stream continues at the right byte, the
// half packets complete, the offered file is still sourced by its session, and a
// callback request reaches the LowID client through the new LowID table.
func TestHandoffMovesLiveSessionsToAnotherRuntime(t *testing.T) {
	rtA, engineA, addr := handoffRuntime(t)
	rtB, engineB, _ := handoffRuntime(t)

	low := dialWireClient(t, addr, true)
	lowID := low.login(bytes.Repeat([]byte{0xa1}, 16), 4662)
	high := dialWireClient(t, addr, false)
	highID := high.login(bytes.Repeat([]byte{0xb2}, 16), 4672)

	file := offerHash(7)
	low.write(low.frame(offerOne(file, "handed over.avi", 7000)))
	waitFor(t, "the offer to be stored", func() bool { return len(engineA.GetSources(file, 7000)) == 1 })

	lowAsk := low.frame(getSourcesItems(file, 7000))
	highAsk := high.frame(getSourcesItems(file, 7000))
	low.write(lowAsk[:3])   // half a header
	high.write(highAsk[:9]) // a header and part of the payload
	time.Sleep(50 * time.Millisecond)

	moved := handOver(t, rtA, engineA, rtB, engineB)
	t.Logf("input: lowID=%d highID=%d, half packets pending; output: %d session(s) moved, B LowIDs=%d connected(low)=%t",
		lowID, highID, moved, rtB.LowIDs.Count(), engineB.IsConnected(storage.ClientInfo{Hash: bytes.Repeat([]byte{0xa1}, 16)}))
	if moved != 2 || rtB.LowIDs.Count() != 1 {
		t.Fatalf("moved %d sessions, B holds %d LowIDs; want 2 and 1", moved, rtB.LowIDs.Count())
	}

	low.write(lowAsk[3:])
	high.write(highAsk[9:])
	for name, c := range map[string]*wireClient{"obfuscated LowID": low, "plaintext HighID": high} {
		payload := c.expect(OpFoundSources)
		count := payload[16]
		id := binary.LittleEndian.Uint32(payload[17:21])
		port := binary.LittleEndian.Uint16(payload[21:23])
		t.Logf("%s client after handover: OP_FOUNDSOURCES count=%d first=%d:%d", name, count, id, port)
		if count != 1 || id != lowID || port != 4662 {
			t.Fatalf("%s: sources count=%d %d:%d, want the LowID client %d:4662", name, count, id, port, lowID)
		}
	}

	// The HighID client asks for a callback from the LowID one; only runtime B knows
	// that LowID now.
	high.write(high.frame([]PacketItem{{Type: TypeUint8, Value: OpCallbackRequest}, {Type: TypeUint32, Value: lowID}}))
	cb := low.expect(OpCallbackReqd)
	gotIP, gotPort := binary.LittleEndian.Uint32(cb[0:4]), binary.LittleEndian.Uint16(cb[4:6])
	t.Logf("output: OP_CALLBACKREQUESTED %d:%d", gotIP, gotPort)
	if gotIP != highID || gotPort != 4672 {
		t.Fatalf("callback names %d:%d, want %d:4672", gotIP, gotPort, highID)
	}

	// A's sessions are gone without being released: the rows, the sources and the
	// LowID moved, and nothing in A told storage otherwise.
	waitFor(t, "runtime A to let go of its sessions", func() bool { return rtA.LiveSessions() == 0 })
	if engineA.ClientsCount() != 2 {
		t.Fatalf("runtime A disconnected handed-over clients from its storage: %d left", engineA.ClientsCount())
	}

	// A client that leaves the new runtime is released there as usual.
	_ = low.conn.Close()
	waitFor(t, "the LowID client to be released by B", func() bool {
		return rtB.LowIDs.Count() == 0 && len(engineB.GetSources(file, 7000)) == 0
	})
}

// A handover that fails puts the parked sessions back to serving where they were.
func TestParkedSessionsResume(t *testing.T) {
	rt, engine, addr := handoffRuntime(t)
	c := dialWireClient(t, addr, true)
	id := c.login(bytes.Repeat([]byte{0xc3}, 16), 4662)
	c.write(c.frame(offerOne(offerHash(9), "stays.bin", 900)))
	waitFor(t, "the offer to be stored", func() bool { return engine.FilesCount() == 1 })

	parked := rt.ParkSessions(2 * time.Second)
	ask := c.frame(getSourcesItems(offerHash(9), 900))
	c.write(ask) // arrives while parked: read only after Resume
	if _, _, err := parked.Export(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	parked.Resume()

	payload := c.expect(OpFoundSources)
	t.Logf("input: request sent while parked; output after resume: count=%d id=%d (session id %d)",
		payload[16], binary.LittleEndian.Uint32(payload[17:21]), id)
	if payload[16] != 1 || binary.LittleEndian.Uint32(payload[17:21]) != id {
		t.Fatal("the resumed session did not answer correctly")
	}
}

// A session that stays busy past the park timeout is dropped and released, not
// handed over half-way through a handler.
func TestParkSessionsDropsStragglers(t *testing.T) {
	rt, engine, addr := handoffRuntime(t)
	c := dialWireClient(t, addr, false)
	c.login(bytes.Repeat([]byte{0xd4}, 16), 4672)

	// Hold the session's write lock, so the next reply it sends blocks its handler.
	var target *tcpClient
	for _, s := range rt.liveSessions() {
		target = s
	}
	target.writeMu.Lock()
	c.write(c.frame(getSourcesItems(offerHash(1), 10)))
	time.Sleep(50 * time.Millisecond)

	parked := rt.ParkSessions(100 * time.Millisecond)
	target.writeMu.Unlock()
	states, _, _ := parked.Export()
	t.Logf("output: stragglers=%d exported=%d clients=%d", parked.Stragglers, len(states), engine.ClientsCount())
	if parked.Stragglers != 1 || len(states) != 0 || engine.ClientsCount() != 0 {
		t.Fatal("a busy session was not dropped and released")
	}
	parked.HandOff()
}

// The restored LowID table refuses an ID that is taken.
func TestLowIDRestore(t *testing.T) {
	l := NewLowIDClients(true, 0, 0)
	first, second := l.Restore(77, "a"), l.Restore(77, "b")
	got, _ := l.Get(77)
	t.Logf("input: Restore(77) twice; output: %t %t holder=%v count=%d", first, second, got, l.Count())
	if !first || second || got != "a" || l.Count() != 1 {
		t.Fatal("Restore must take a free ID once and refuse a taken one")
	}
}

// offerOne is an OP_OFFERFILES carrying one file.
func offerOne(hash []byte, name string, size uint32) []PacketItem {
	items := []PacketItem{
		{Type: TypeUint8, Value: OpOfferFiles},
		{Type: TypeUint32, Value: uint32(1)},
	}
	AddFile(&items, SharedFile{Name: name, Size: uint64(size), Hash: hash,
		SourceID: ValCompleteID, SourcePort: ValCompletePort, Completed: 1, Sources: 1})
	return items
}
