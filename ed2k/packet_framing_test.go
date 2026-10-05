package ed2k

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"enode/storage"
)

// framingSearchFrame renders one OP_SEARCHREQUEST for a single keyword leaf.
func framingSearchFrame(t *testing.T, keyword string) []byte {
	t.Helper()
	return frameFor(t, []PacketItem{
		{Type: TypeUint8, Value: OpSearchRequest},
		{Type: TypeUint8, Value: uint8(0x01)},
		{Type: TypeString, Value: keyword},
	})
}

// framingEngine holds one file per keyword, offered by one client.
func framingEngine(t *testing.T) storage.Engine {
	t.Helper()
	engine := storage.NewMemoryEngine()
	info := storage.ClientInfo{ID: 0x0100000a, Port: 4662, Hash: []byte("framing-client-1")}
	storeID, err := engine.Connect(info)
	if err != nil {
		t.Fatal(err)
	}
	info.StoreID = storeID
	engine.AddFile(storage.File{Hash: []byte("alpha-hash-00001"), Name: "alpha.iso", Size: 1000}, info)
	engine.AddFile(storage.File{Hash: []byte("beta-hash-000001"), Name: "beta.iso", Size: 2000}, info)
	return engine
}

// searchResultCount decodes the count of an OP_SEARCHRESULT reply, or -1.
func searchResultCount(reply []byte) int {
	if len(reply) < 10 || reply[0] != PrED2K || reply[5] != OpSearchResult {
		return -1
	}
	return int(binary.LittleEndian.Uint32(reply[6:10]))
}

// Two pipelined packets whose boundary falls inside the second header, at every offset
// a split can land on. Init needs all six header bytes at once; the fragment used to be
// dropped, so the second packet was lost and the rest of the stream misframed.
func TestProcessPacketDataReassemblesSplitHeader(t *testing.T) {
	for cut := 1; cut < PacketHeaderSize; cut++ {
		c, nextReply := tcpClientProbe(t, framingEngine(t))
		c.logged = true

		first := framingSearchFrame(t, "alpha")
		stream := segment(first, framingSearchFrame(t, "beta"))
		split := len(first) + cut
		t.Logf("input: cut=%d, chunk1=% x, chunk2=% x", cut, stream[:split], stream[split:])

		c.handleBytes(stream[:split])
		c.handleBytes(stream[split:])

		got := []int{searchResultCount(nextReply()), searchResultCount(nextReply())}
		t.Logf("output: cut=%d result counts=%v closeReason=%q", cut, got, c.getCloseReason())
		if got[0] != 1 || got[1] != 1 {
			t.Fatalf("cut=%d: want two OP_SEARCHRESULT replies with 1 result each, got %v", cut, got)
		}
	}
}

// A lone protocol byte is buffered too: the size and opcode can arrive a read later.
func TestProcessPacketDataHeaderInSingleBytes(t *testing.T) {
	c, nextReply := tcpClientProbe(t, framingEngine(t))
	c.logged = true

	frame := framingSearchFrame(t, "alpha")
	t.Logf("input: %d-byte frame fed one byte per read", len(frame))
	for _, b := range frame {
		c.handleBytes([]byte{b})
	}
	got := searchResultCount(nextReply())
	t.Logf("output: result count=%d", got)
	if got != 1 {
		t.Fatalf("want 1 result, got %d", got)
	}
}

// A byte that is no ed2k protocol means the stream has lost its framing. It used to be
// logged and the chunk dropped, leaving the session to misread whatever came next.
func TestProcessPacketDataUnknownProtocolCloses(t *testing.T) {
	c, _ := tcpClientProbe(t, framingEngine(t))
	c.logged = true

	input := []byte{0x00, 0x05, 0x00, 0x00, 0x00, 0x16}
	t.Logf("input: % x", input)
	c.handleBytes(input)

	reason := c.getCloseReason()
	t.Logf("output: closeReason=%q", reason)
	if reason != "unknown-protocol" {
		t.Fatalf("want close reason unknown-protocol, got %q", reason)
	}
}

// A zero declared size leaves no way to find the next packet; the session is dropped.
func TestProcessPacketDataZeroSizeCloses(t *testing.T) {
	c, _ := tcpClientProbe(t, framingEngine(t))
	c.logged = true

	input := []byte{PrED2K, 0x00, 0x00, 0x00, 0x00, OpSearchRequest}
	t.Logf("input: % x", input)
	c.handleBytes(input)

	reason := c.getCloseReason()
	t.Logf("output: closeReason=%q", reason)
	if !strings.HasPrefix(reason, "bad-packet-header") {
		t.Fatalf("want close reason bad-packet-header, got %q", reason)
	}
}

// A peer that stops reading must not hold writeMu forever: writeRaw gives up after
// tcpWriteTimeout and drops the session.
func TestWriteRawTimesOutOnStalledReader(t *testing.T) {
	saved := tcpWriteTimeout
	tcpWriteTimeout = 100 * time.Millisecond
	t.Cleanup(func() { tcpWriteTimeout = saved })

	server, client := net.Pipe() // nobody reads client
	t.Cleanup(func() { server.Close(); client.Close() })
	rt := NewServerRuntime(TCPRuntimeConfig{Hash: []byte("0123456789abcdef")}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	c := newTCPClient(rt, server, false)

	payload := []byte{PrED2K, 0x01, 0x00, 0x00, 0x00, OpServerMessage}
	t.Logf("input: %d-byte write to a peer that never reads, timeout=%s", len(payload), tcpWriteTimeout)
	start := time.Now()
	err := c.writeRaw(payload)
	took := time.Since(start)
	t.Logf("output: err=%v took=%s closeReason=%q", err, took, c.getCloseReason())

	if err == nil {
		t.Fatal("write to a stalled peer succeeded")
	}
	if took > 2*time.Second {
		t.Fatalf("write took %s, want about %s", took, tcpWriteTimeout)
	}
	if !strings.HasPrefix(c.getCloseReason(), "write-timeout") {
		t.Fatalf("want close reason write-timeout, got %q", c.getCloseReason())
	}
}

// touchDeadline runs on the NAT UDP worker pool. It used to take writeMu, so a session
// stuck in a write parked a worker for every keepalive its client sent.
func TestTouchDeadlineDoesNotWaitForWriter(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	rt := NewServerRuntime(TCPRuntimeConfig{Hash: []byte("0123456789abcdef")}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	rt.tcp().DisconnectTimeout = time.Hour
	c := newTCPClient(rt, server, false)

	c.writeMu.Lock() // a writer blocked on the socket
	defer c.writeMu.Unlock()

	done := make(chan struct{})
	go func() {
		c.touchDeadline()
		close(done)
	}()
	t.Logf("input: touchDeadline while writeMu is held")
	select {
	case <-done:
		t.Logf("output: touchDeadline returned")
	case <-time.After(time.Second):
		t.Fatal("touchDeadline blocked on writeMu")
	}
}

// A search that fails to parse is still answered, with an empty page, so the client's
// search ends instead of waiting out its timeout.
func TestSearchRequestParseErrorRepliesEmpty(t *testing.T) {
	c, nextReply := tcpClientProbe(t, framingEngine(t))
	c.logged = true

	payload := []byte{0x7f}
	t.Logf("input: OP_SEARCHREQUEST payload % x (unknown token)", payload)
	go c.handleSearchRequest(NewBufferFromBytes(payload))

	reply := nextReply()
	t.Logf("output: reply=% x", reply)
	if got := searchResultCount(reply); got != 0 {
		t.Fatalf("want an empty OP_SEARCHRESULT, got count=%d", got)
	}
}
