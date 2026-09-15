package ed2k

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"enode/storage"
)

// recordingConn captures what the server writes and counts SetReadDeadline calls.
//
// A local type rather than an extension of the shared mockConn, which deliberately
// discards writes and is relied on by other tests for being that simple. Guarded by a
// mutex because touchDeadline is reached from the NAT worker pool, not the connection's own
// goroutine, so -race would otherwise flag the counter.
type recordingConn struct {
	mu        sync.Mutex
	written   [][]byte
	deadlines int
	closed    int
}

func (c *recordingConn) Read(_ []byte) (int, error) { return 0, net.ErrClosed }

func (c *recordingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, append([]byte(nil), b...))
	return len(b), nil
}

func (c *recordingConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed++
	return nil
}

func (c *recordingConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4661}
}

func (c *recordingConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 50000}
}

func (c *recordingConn) SetDeadline(_ time.Time) error { return nil }

func (c *recordingConn) SetReadDeadline(_ time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlines++
	return nil
}

func (c *recordingConn) SetWriteDeadline(_ time.Time) error { return nil }

// takeWritten returns the most recent frame and clears the buffer, so each assertion sees
// only what the call under test produced.
func (c *recordingConn) takeWritten() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.written) == 0 {
		return nil
	}
	last := c.written[len(c.written)-1]
	c.written = nil
	return last
}

func (c *recordingConn) readDeadlineCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadlines
}

// decodeSearchResult pulls the result count and the trailing more-results byte out of an
// OP_SEARCHRESULT packet, inflating it first when it went out compressed.
func decodeSearchResult(t *testing.T, raw []byte) (count uint32, more uint8, trailing int) {
	t.Helper()
	if len(raw) < 6 {
		t.Fatalf("packet too short: %d bytes", len(raw))
	}
	payload := raw[6:]
	if raw[0] == PrZlib {
		inflated, err := InflateZlibPayload(payload)
		if err != nil {
			t.Fatalf("inflate: %v", err)
		}
		payload = inflated
	}
	if raw[5] != OpSearchResult {
		t.Fatalf("opcode = 0x%02x, want 0x%02x", raw[5], OpSearchResult)
	}
	// GetFileList reads the leading uint32 count itself, so it consumes the whole
	// count-plus-records block. Whatever is left after it is the trailer, which is exactly
	// the position eMule's ProcessSearchAnswer is in when it measures its "AddData".
	b := NewBufferFromBytes(payload)
	records, err := b.GetFileList()
	if err != nil {
		t.Fatalf("decode file list: %v", err)
	}
	count = uint32(len(records))
	trailing = b.Remaining()
	if trailing == 1 {
		more, _ = b.GetUInt8()
	}
	return count, more, trailing
}

// TestSearchResultTrailerIsExactlyOneByte pins eMule's contract, which is narrow enough
// that getting it approximately right does nothing at all.
// srchybrid/SearchList.cpp:266-277 reads the trailer only when exactly one byte remains,
// and accepts only 0x00 or 0x01; two trailing bytes, or a 0x02, are logged as unexpected
// AddData and the more-results flag stays false — so the client's More button never
// appears and a deep result set is silently truncated.
func TestSearchResultTrailerIsExactlyOneByte(t *testing.T) {
	files := []storage.File{{
		Hash: make([]byte, 16), Name: "a.bin", Size: 10, Type: "Pro", Sources: 1, Completed: 1,
	}}
	for _, more := range []bool{false, true} {
		packet, err := BuildSearchResultPacket(files, more)
		if err != nil {
			t.Fatal(err)
		}
		count, gotMore, trailing := decodeSearchResult(t, packet.Bytes())
		t.Logf("input: 1 file, moreAvailable=%v", more)
		t.Logf("output: count=%d trailingBytes=%d moreByte=0x%02x", count, trailing, gotMore)
		if trailing != 1 {
			t.Fatalf("trailing bytes = %d, want exactly 1 — eMule ignores any other amount", trailing)
		}
		want := uint8(0)
		if more {
			want = 1
		}
		if gotMore != want {
			t.Fatalf("more byte = 0x%02x, want 0x%02x", gotMore, want)
		}
		if gotMore != 0x00 && gotMore != 0x01 {
			t.Fatalf("more byte 0x%02x is outside the accepted {0x00, 0x01}", gotMore)
		}
	}
}

// TestSearchResultTrailerOnEmptyResult covers the zero-result reply, which must still be
// sent (it is what cancels eMule's local search timer) and must still carry a well-formed
// trailer.
func TestSearchResultTrailerOnEmptyResult(t *testing.T) {
	packet, err := BuildSearchResultPacket(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	count, more, trailing := decodeSearchResult(t, packet.Bytes())
	t.Logf("input: 0 files; output: count=%d trailingBytes=%d moreByte=0x%02x", count, trailing, more)
	if count != 0 || trailing != 1 || more != 0 {
		t.Fatalf("count=%d trailing=%d more=0x%02x, want 0/1/0x00", count, trailing, more)
	}
}

// searchPagingClient builds a logged-in client over a recordingConn, with a seeded engine,
// so the paging path can be driven through the real opcode dispatcher.
//
// The login is real, not a flag flipped by hand: handleED2K refuses every opcode but
// OP_LOGINREQUEST and OP_DISCONNECT on a session that has not logged in, so a client that
// only looked logged in would have its searches dropped rather than paged.
func searchPagingClient(t *testing.T, fileCount int) (*tcpClient, *recordingConn) {
	t.Helper()
	engine := storage.NewMemoryEngine()
	owner := storage.ClientInfo{Hash: []byte("0123456789abcdef"), ID: 0x0100007F, Port: 4662}
	if _, err := engine.Connect(owner); err != nil {
		t.Fatal(err)
	}
	for i := range fileCount {
		hash := make([]byte, 16)
		hash[0], hash[1] = byte(i>>8), byte(i)
		engine.AddFile(storage.File{
			Hash: hash, Size: uint64(1024 + i), Name: fmt.Sprintf("paging-%04d.bin", i), Type: "Pro",
		}, owner)
	}
	rt := NewServerRuntime(
		TCPRuntimeConfig{Address: "127.0.0.1", Port: 4661, AllowLowIDs: true},
		UDPRuntimeConfig{}, engine,
	)
	// Stubbed so login takes the LowID branch without spending the dial-back timeout.
	rt.firewallProbe = func(*tcpClient) bool { return true }

	conn := &recordingConn{}
	client := newTCPClient(rt, conn, false)
	client.handlePacket(loginPacket(t, bytes.Repeat([]byte{0x5b}, 16), 0, 4662))
	if !client.isLogged() {
		t.Fatal("setup: login failed, so every search below would be refused by the login gate")
	}
	conn.mu.Lock()
	conn.written = nil // drop the login chatter; takeWritten must see search frames only
	conn.mu.Unlock()
	return client, conn
}

// searchFor builds an OP_SEARCHREQUEST for a substring, matching what eMule sends.
func searchFor(t *testing.T, term string) *Buffer {
	t.Helper()
	b := NewBuffer(3 + len(term))
	_ = b.PutUInt8(0x01) // string node
	_ = b.PutString(term)
	b.Pos(0)
	return b
}

// TestSearchPagingDeliversEveryResult is the end-to-end case: a result set larger than one
// page must be fully retrievable through OP_QUERY_MORE_RESULT, with the more-results flag
// set on every page but the last.
//
// Before this, all three engines capped FindBySearch at 255 — the same number as the page
// size — so a deeper set was truncated and the client had no way to ask for the remainder.
func TestSearchPagingDeliversEveryResult(t *testing.T) {
	const total = storage.MaxSearchPage + 40 // two pages, second partial
	client, conn := searchPagingClient(t, total)

	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	page1 := conn.takeWritten()
	count1, more1, trailing1 := decodeSearchResult(t, page1)
	t.Logf("input: %d matching files, page size %d", total, storage.MaxSearchPage)
	t.Logf("output page 1: count=%d moreByte=0x%02x trailing=%d pending=%d",
		count1, more1, trailing1, len(client.pendingResults))
	if count1 != storage.MaxSearchPage {
		t.Fatalf("page 1 carried %d results, want the full page of %d", count1, storage.MaxSearchPage)
	}
	if more1 != 1 {
		t.Fatal("page 1 must set the more-results byte, or eMule shows no More button")
	}

	client.handleED2K(OpQueryMoreResult, NewBufferFromBytes(nil))
	page2 := conn.takeWritten()
	count2, more2, _ := decodeSearchResult(t, page2)
	t.Logf("output page 2: count=%d moreByte=0x%02x pending=%d",
		count2, more2, len(client.pendingResults))
	if int(count1+count2) != total {
		t.Fatalf("pages carried %d+%d=%d results, want all %d", count1, count2, count1+count2, total)
	}
	if more2 != 0 {
		t.Fatal("the final page must clear the more-results byte")
	}
	if len(client.pendingResults) != 0 {
		t.Fatalf("%d results still pending after the last page", len(client.pendingResults))
	}
}

// TestSearchWithinOnePageSetsNoMoreFlag is the discriminating half: a result set that fits
// must not claim there is more, or the client offers a More button that returns nothing.
func TestSearchWithinOnePageSetsNoMoreFlag(t *testing.T) {
	client, conn := searchPagingClient(t, 10)
	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	count, more, _ := decodeSearchResult(t, conn.takeWritten())
	t.Logf("input: 10 matching files; output: count=%d moreByte=0x%02x pending=%d",
		count, more, len(client.pendingResults))
	if count != 10 {
		t.Fatalf("count = %d, want 10", count)
	}
	if more != 0 {
		t.Fatal("a result set that fits in one page must not set the more-results byte")
	}
	if len(client.pendingResults) != 0 {
		t.Fatal("nothing should be pending")
	}
}

// TestQueryMoreResultWithNothingPendingStillReplies covers the unsolicited More: silence
// would leave the client's search UI waiting on its local timer, the same failure the
// zero-result reply exists to prevent.
func TestQueryMoreResultWithNothingPendingStillReplies(t *testing.T) {
	client, conn := searchPagingClient(t, 3)
	client.handleED2K(OpQueryMoreResult, NewBufferFromBytes(nil))
	raw := conn.takeWritten()
	t.Logf("input: OP_QUERY_MORE_RESULT with no prior search")
	if len(raw) == 0 {
		t.Fatal("an unsolicited More must still get a reply, not silence")
	}
	count, more, trailing := decodeSearchResult(t, raw)
	t.Logf("output: count=%d moreByte=0x%02x trailing=%d", count, more, trailing)
	if count != 0 || more != 0 {
		t.Fatalf("count=%d more=0x%02x, want an empty final page", count, more)
	}
}

// TestNewSearchReplacesPendingPage pins that a fresh query discards the old tail. Keeping
// it would let a More press after a new search return results from the previous one.
func TestNewSearchReplacesPendingPage(t *testing.T) {
	const total = storage.MaxSearchPage + 5
	client, conn := searchPagingClient(t, total)

	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	_ = conn.takeWritten()
	first := len(client.pendingResults)

	// A second, narrower search that fits in one page.
	client.handleED2K(OpSearchRequest, searchFor(t, "paging-0001"))
	_ = conn.takeWritten()
	second := len(client.pendingResults)

	t.Logf("input: a broad search then a narrow one")
	t.Logf("output: pending after broad=%d, after narrow=%d", first, second)
	if first == 0 {
		t.Fatal("the broad search should have left results pending")
	}
	if second != 0 {
		t.Fatalf("%d results from the previous search are still pending", second)
	}
}

// TestOpDisconnectClosesSession covers §7.4. Acting on the opcode releases the session,
// its LowID and its storage row at once, rather than waiting for the read loop to notice a
// FIN — or, for a socket that dies without one, for disconnectTimeout.
func TestOpDisconnectClosesSession(t *testing.T) {
	client, _ := searchPagingClient(t, 1)
	t.Logf("input: OP_DISCONNECT (0x18), empty payload")
	client.handleED2K(OpDisconnect, NewBufferFromBytes(nil))
	reason := client.getCloseReason()
	t.Logf("output: closeReason=%q", reason)
	if reason != "client-disconnect" {
		t.Fatalf("closeReason = %q, want client-disconnect", reason)
	}
}

// TestNATKeepaliveExtendsSessionDeadline covers §9.2 end to end: a keepalive for a
// registered user hash must push out that user's TCP read deadline.
//
// This is what keeps a share-only LowID client alive — one that publishes files, keeps its
// PR_NAT registration fresh so it stays punchable, and sends no TCP traffic for hours.
// Refreshing the NAT registry alone was not enough: that governs whether the client can be
// *paired*, not whether its eD2K session survives the read deadline.
func TestNATKeepaliveExtendsSessionDeadline(t *testing.T) {
	engine := storage.NewMemoryEngine()
	rt := NewServerRuntime(
		TCPRuntimeConfig{Address: "127.0.0.1", Port: 4661, AllowLowIDs: true, DisconnectTimeout: time.Hour},
		UDPRuntimeConfig{}, engine,
	)
	nat := NewNATTraversalHandler(time.Minute)
	rt.SetNATHandler(nat)

	hash := []byte("0123456789abcdef")
	conn := &recordingConn{}
	client := newTCPClient(rt, conn, false)
	client.infoMu.Lock()
	client.info.Hash = hash
	client.infoMu.Unlock()
	rt.registerSession(hash, client)

	// Register the client with the NAT handler so a keepalive from its address matches.
	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.44"), Port: 40001}
	nat.processPacket(encodeNATPacket(OpNatRegister, hash), remote, 2004)

	before := conn.readDeadlineCalls()
	out := nat.processPacket(encodeNATPacket(OpNatKeepAlive, nil), remote, 2004)
	after := conn.readDeadlineCalls()
	t.Logf("input: OP_NATKEEPALIVE from a registered client's address")
	t.Logf("output: natReplies=%d SetReadDeadline calls %d -> %d", len(out), before, after)
	if len(out) == 0 {
		t.Fatal("a matched keepalive should be answered with a ping")
	}
	if after <= before {
		t.Fatal("the keepalive did not extend the eD2K session's read deadline")
	}

	// An unregistered hash must not touch anything.
	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.45"), Port: 40002}
	beforeOther := conn.readDeadlineCalls()
	nat.processPacket(encodeNATPacket(OpNatKeepAlive, nil), other, 2004)
	t.Logf("output: keepalive from an unknown address left calls at %d", conn.readDeadlineCalls())
	if conn.readDeadlineCalls() != beforeOther {
		t.Fatal("a keepalive from an unregistered address must not touch any session")
	}
}

// TestUnregisterSessionOnlyRemovesItsOwnEntry guards the identity check. A departing
// session must not unregister a live one that has since taken the same user hash, or the
// live client silently loses keepalive-based liveness for the rest of its session.
func TestUnregisterSessionOnlyRemovesItsOwnEntry(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{DisconnectTimeout: time.Hour}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	hash := []byte("0123456789abcdef")
	old := newTCPClient(rt, &recordingConn{}, false)
	live := newTCPClient(rt, &recordingConn{}, false)

	rt.registerSession(hash, old)
	rt.registerSession(hash, live) // the reconnect replaces the index entry
	rt.unregisterSession(hash, old)

	var key [16]byte
	copy(key[:], hash)
	rt.sessionsMu.RLock()
	got := rt.sessionsByHash[key]
	rt.sessionsMu.RUnlock()
	t.Logf("input: old session unregisters after a reconnect replaced it")
	t.Logf("output: indexed session is the live one = %v", got == live)
	if got != live {
		t.Fatal("the departing session removed the live one's index entry")
	}

	rt.unregisterSession(hash, live)
	rt.sessionsMu.RLock()
	got = rt.sessionsByHash[key]
	rt.sessionsMu.RUnlock()
	t.Logf("output: after the live session unregisters, indexed = %v", got)
	if got != nil {
		t.Fatal("the live session's own unregister should have removed it")
	}
}
