package ed2k

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"enode/storage"
)

// allWritten returns every frame the server wrote, oldest first. takeWritten returns
// only the newest; the limit tests need the whole sequence, because "exactly one
// warning per session" and "WARNING before ERROR" are assertions about the sequence.
func (c *recordingConn) allWritten() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.written))
	copy(out, c.written)
	return out
}

// newOfferLimitClient builds a logged-in session with the given caps.
//
// The runtime deliberately leaves MessageLogin and MessageLowID empty: sendServerMessage
// returns early on an empty string, so the only OP_SERVERMESSAGE frames in the capture
// are the ones the limits produced. Setting either field here would break every
// message-count assertion below.
func newOfferLimitClient(t *testing.T, engine storage.Engine, softLimit, hardLimit int) (*tcpClient, *recordingConn) {
	t.Helper()
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address:           "127.0.0.1",
		Port:              4661,
		Hash:              []byte("1111111111111111"),
		AllowLowIDs:       true,
		ConnectionTimeout: 50 * time.Millisecond,
		SoftFileLimit:     softLimit,
		HardFileLimit:     hardLimit,
	}, UDPRuntimeConfig{}, engine)
	// Stubbed so login takes the LowID branch without spending the dial-back timeout.
	rt.firewallProbe = func(*tcpClient) bool { return true }

	conn := &recordingConn{}
	client := newTCPClient(rt, conn, false)
	client.handlePacket(loginPacket(t, bytes.Repeat([]byte{0x5a}, 16), 0, 4662))
	if !client.logged {
		t.Fatal("setup: login failed, so the offer path would run without an identity")
	}
	conn.mu.Lock()
	conn.written = nil // drop the login chatter; only limit messages matter below
	conn.mu.Unlock()
	return client, conn
}

// offerFiles sends one OP_OFFERFILES carrying count files whose hashes start at first,
// so successive calls publish distinct files rather than re-offering the same ones.
func offerFiles(t *testing.T, client *tcpClient, first, count int) {
	t.Helper()
	dispatchIncomingTCPPacket(t, client, offerItems(first, count))
}

// offerItems builds the item list offerFiles sends. Split out so a test can place the
// frame inside a segment next to another packet, which is the only way to exercise
// processPacketData's Excess recursion — and that recursion is what the login gate's
// latch exists for.
func offerItems(first, count int) []PacketItem {
	offer := []PacketItem{
		{Type: TypeUint8, Value: OpOfferFiles},
		{Type: TypeUint32, Value: uint32(count)},
	}
	for i := first; i < first+count; i++ {
		AddFile(&offer, SharedFile{
			Name:       fmt.Sprintf("offer-limit-%03d.bin", i),
			Size:       uint64(1024 + i),
			Hash:       offerHash(i),
			SourceID:   ValCompleteID,
			SourcePort: ValCompletePort,
			Completed:  1,
			Sources:    1,
		})
	}
	return offer
}

func offerHash(i int) []byte {
	h := bytes.Repeat([]byte{0xc0}, 16)
	h[15] = byte(i)
	h[14] = byte(i >> 8)
	return h
}

// serverMessages decodes every OP_SERVERMESSAGE the session sent, in order.
func serverMessages(t *testing.T, conn *recordingConn) []string {
	t.Helper()
	var out []string
	for _, frame := range conn.allWritten() {
		if len(frame) >= 6 && frame[0] == PrED2K && frame[5] == OpServerMessage {
			out = append(out, decodeServerMessagePayload(t, frame))
		}
	}
	return out
}

// TestOfferFilesSoftLimitWarnsOnceAndIgnoresExcess pins the soft half of Lugdunum's
// definition (kiten-20071012.txt:462): warn, ignore the excess, keep the connection.
//
// The second packet is the point of the test. The warning latch has to be per session,
// not per packet, or a client sitting above the cap is warned again every 60 s for as
// long as it stays connected.
func TestOfferFilesSoftLimitWarnsOnceAndIgnoresExcess(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 3, 0)
	t.Logf("input: softLimit=3 hardLimit=0 (unlimited), then 5 files followed by 2 more")

	offerFiles(t, client, 0, 5)
	offerFiles(t, client, 5, 2)

	msgs := serverMessages(t, conn)
	t.Logf("output: stored=%d offeredFiles=%d messages=%q closed=%d",
		engine.FilesCount(), client.offeredFiles, msgs, conn.closed)

	if engine.FilesCount() != 3 {
		t.Errorf("stored %d files, want 3 — the excess was not ignored", engine.FilesCount())
	}
	if client.offeredFiles != 7 {
		t.Errorf("offeredFiles=%d, want 7 — every record must be counted, stored or not", client.offeredFiles)
	}
	if len(msgs) != 1 {
		t.Fatalf("sent %d server messages, want exactly 1 per session: %q", len(msgs), msgs)
	}
	if want := fmt.Sprintf(msgSoftFileLimit, 3); msgs[0] != want {
		t.Errorf("warning text is %q, want %q", msgs[0], want)
	}
	if conn.closed != 0 {
		t.Errorf("connection closed %d time(s); the soft limit must not disconnect", conn.closed)
	}
}

// TestOfferFilesSoftLimitKeepsTheEarliestFiles pins prefix-wins, which is not an
// arbitrary choice: eMule sorts its offer by upload priority before truncating to the
// packet cap (srchybrid/SharedFileList.cpp:814-828), so the files that survive the
// server's cap are the client's own highest-priority share.
func TestOfferFilesSoftLimitKeepsTheEarliestFiles(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, _ := newOfferLimitClient(t, engine, 2, 0)
	t.Logf("input: softLimit=2, one packet of 4 distinct hashes")

	offerFiles(t, client, 0, 4)

	var kept, dropped []int
	for i := 0; i < 4; i++ {
		if len(engine.GetSourcesByHash(offerHash(i))) > 0 {
			kept = append(kept, i)
		} else {
			dropped = append(dropped, i)
		}
	}
	t.Logf("output: kept=%v dropped=%v", kept, dropped)

	if len(kept) != 2 || kept[0] != 0 || kept[1] != 1 {
		t.Errorf("kept %v, want the first two offered (0, 1)", kept)
	}
}

// TestOfferFilesHardLimitMessagesThenCloses pins the hard half
// (kiten-20071012.txt:349) plus our one deliberate divergence: eserver drops silently,
// we say why first.
//
// The follow-up offer is the regression guard for pipelined packets. closeWithReason
// only closes the socket; processPacketData still dispatches bytes that already arrived,
// so without the hardLimitHit latch a second offer in the same segment would write a
// second message onto a closed connection.
func TestOfferFilesHardLimitMessagesThenCloses(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 0, 3)
	t.Logf("input: softLimit=0 (unlimited) hardLimit=3, one packet of 5, then another of 2")

	offerFiles(t, client, 0, 5)
	storedAtDrop := engine.FilesCount()
	offerFiles(t, client, 5, 2)

	msgs := serverMessages(t, conn)
	t.Logf("output: storedAtDrop=%d storedAfter=%d messages=%q closed=%d reason=%q",
		storedAtDrop, engine.FilesCount(), msgs, conn.closed, client.getCloseReason())

	if storedAtDrop != 3 {
		t.Errorf("stored %d files, want 3 — records past the hard limit must not be stored", storedAtDrop)
	}
	if engine.FilesCount() != storedAtDrop {
		t.Errorf("a further offer stored %d more files; the session is already closed",
			engine.FilesCount()-storedAtDrop)
	}
	if len(msgs) != 1 {
		t.Fatalf("sent %d server messages, want exactly 1: %q", len(msgs), msgs)
	}
	if want := fmt.Sprintf(msgHardFileLimit, 3); msgs[0] != want {
		t.Errorf("message text is %q, want %q", msgs[0], want)
	}
	if conn.closed == 0 {
		t.Error("connection was never closed")
	}
	if got := client.getCloseReason(); got != "file-hard-limit" {
		t.Errorf("close reason is %q, want %q", got, "file-hard-limit")
	}
}

// TestOfferFilesCountsCumulativelyAcrossPackets is the test that justifies the design.
//
// eMule never sends more than 200 files in one OP_OFFERFILES and republishes the rest
// every 60 s, so a per-packet check could never see a client exceed any sane cap. Two
// packets of 3 against a hard limit of 4 must drop the session; a per-packet check would
// let all 6 through.
func TestOfferFilesCountsCumulativelyAcrossPackets(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 0, 4)
	t.Logf("input: hardLimit=4, two packets of 3 files each")

	offerFiles(t, client, 0, 3)
	afterFirst, closedAfterFirst := engine.FilesCount(), conn.closed
	offerFiles(t, client, 3, 3)

	t.Logf("output: afterFirst=%d closedAfterFirst=%d afterSecond=%d closedAfterSecond=%d reason=%q",
		afterFirst, closedAfterFirst, engine.FilesCount(), conn.closed, client.getCloseReason())

	if afterFirst != 3 || closedAfterFirst != 0 {
		t.Fatalf("after the first packet: stored=%d closed=%d, want 3 and 0 — the first packet is under the cap",
			afterFirst, closedAfterFirst)
	}
	if engine.FilesCount() != 4 {
		t.Errorf("stored %d files, want 4 — the 5th record crosses the cap", engine.FilesCount())
	}
	if conn.closed == 0 {
		t.Error("session survived 6 records against a hard limit of 4; the count is not cumulative")
	}
}

// TestOfferFilesZeroLimitsMeanUnlimited pins the sentinel against a future
// "0 looks unset, default it" regression in the config layer.
func TestOfferFilesZeroLimitsMeanUnlimited(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 0, 0)
	const count = 500
	t.Logf("input: softLimit=0 hardLimit=0, one packet of %d files", count)

	offerFiles(t, client, 0, count)

	msgs := serverMessages(t, conn)
	t.Logf("output: stored=%d messages=%q closed=%d", engine.FilesCount(), msgs, conn.closed)

	if engine.FilesCount() != count {
		t.Errorf("stored %d files, want all %d", engine.FilesCount(), count)
	}
	if len(msgs) != 0 || conn.closed != 0 {
		t.Errorf("messages=%q closed=%d, want neither — zero means unlimited", msgs, conn.closed)
	}
}

// TestOfferFilesBothLimitsWarnThenDrop walks the full ladder in one session and pins the
// order: the soft warning has to arrive before the hard drop, which is why the hard
// check comes first per record but the soft limit is the lower number.
func TestOfferFilesBothLimitsWarnThenDrop(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 2, 4)
	t.Logf("input: softLimit=2 hardLimit=4, one packet of 6")

	offerFiles(t, client, 0, 6)

	msgs := serverMessages(t, conn)
	t.Logf("output: stored=%d messages=%q closed=%d reason=%q",
		engine.FilesCount(), msgs, conn.closed, client.getCloseReason())

	if engine.FilesCount() != 2 {
		t.Errorf("stored %d files, want 2 — the soft limit caps what is indexed", engine.FilesCount())
	}
	if len(msgs) != 2 {
		t.Fatalf("sent %d messages, want 2 (one WARNING then one ERROR): %q", len(msgs), msgs)
	}
	if want := fmt.Sprintf(msgSoftFileLimit, 2); msgs[0] != want {
		t.Errorf("first message is %q, want the soft warning %q", msgs[0], want)
	}
	if want := fmt.Sprintf(msgHardFileLimit, 4); msgs[1] != want {
		t.Errorf("second message is %q, want the hard error %q", msgs[1], want)
	}
	if conn.closed == 0 {
		t.Error("session was not closed after crossing the hard limit")
	}
}

// TestOfferFilesCounterIsPerSession guards against the counter accidentally living on
// ServerRuntime. Two clients each publishing up to the cap must both survive.
func TestOfferFilesCounterIsPerSession(t *testing.T) {
	engine := storage.NewMemoryEngine()
	first, firstConn := newOfferLimitClient(t, engine, 0, 3)
	t.Logf("input: hardLimit=3, two separate sessions offering 3 files each")

	offerFiles(t, first, 0, 3)

	// A second session on the same runtime, with its own identity.
	rt := first.server
	secondConn := &recordingConn{}
	second := newTCPClient(rt, secondConn, false)
	second.handlePacket(loginPacket(t, bytes.Repeat([]byte{0x7b}, 16), 0, 4663))
	offerFiles(t, second, 100, 3)

	t.Logf("output: stored=%d firstClosed=%d secondClosed=%d firstOffered=%d secondOffered=%d",
		engine.FilesCount(), firstConn.closed, secondConn.closed, first.offeredFiles, second.offeredFiles)

	if firstConn.closed != 0 || secondConn.closed != 0 {
		t.Errorf("closed first=%d second=%d, want neither — each session has its own budget",
			firstConn.closed, secondConn.closed)
	}
	if engine.FilesCount() != 6 {
		t.Errorf("stored %d files, want 6", engine.FilesCount())
	}
}

// TestStatResAdvertisesConfiguredFileLimits covers the plumbing rather than the builder:
// UDPRuntimeConfig -> buildStatRes -> UDPConfig -> the wire. The builder itself is pinned
// by TestParseGlobServStatResMatchesOurBuilder; this is what catches the two fields being
// added and then never copied across, which would advertise 0/0 while enforcing the real
// caps — exactly the mismatch this feature exists to remove.
func TestStatResAdvertisesConfiguredFileLimits(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{
		SoftFiles: 4321,
		HardFiles: 8765,
	}, storage.NewMemoryEngine())
	t.Logf("input: UDPRuntimeConfig{SoftFiles: 4321, HardFiles: 8765}")

	packet, err := rt.buildStatRes(0x1122, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	op, b := payloadAfterOpcode(t, packet)
	if op != OpGlobServStatRes {
		t.Fatalf("opcode = 0x%02x, want 0x%02x", op, OpGlobServStatRes)
	}
	got, err := ParseGlobServStatRes(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: softFiles=%d hardFiles=%d", got.SoftFiles, got.HardFiles)

	if got.SoftFiles != 4321 || got.HardFiles != 8765 {
		t.Errorf("advertised %d/%d, want 4321/8765", got.SoftFiles, got.HardFiles)
	}
}

// batchCountingEngine records how the offer path reaches storage.
type batchCountingEngine struct {
	*storage.MemoryEngine
	mu         sync.Mutex
	addFile    int
	batchSizes []int
}

func (e *batchCountingEngine) AddFile(file storage.File, info storage.ClientInfo) {
	e.mu.Lock()
	e.addFile++
	e.mu.Unlock()
	e.MemoryEngine.AddFile(file, info)
}

func (e *batchCountingEngine) AddFiles(files []storage.File, info storage.ClientInfo) {
	e.mu.Lock()
	e.batchSizes = append(e.batchSizes, len(files))
	e.mu.Unlock()
	e.MemoryEngine.AddFiles(files, info)
}

// TestOfferFilesStoresOnePacketInOneBatch pins the change that makes a remote database
// usable: one OP_OFFERFILES is one storage call, not one per record. Per record, a
// 200-file packet was 200 sets of round-trips on the session's read loop.
//
// The hard-limit case matters as much as the plain one. The records up to the cap have
// to reach storage before the drop — they did when each was written as it was read — so
// the batch is flushed, and holds exactly those, before the session closes.
func TestOfferFilesStoresOnePacketInOneBatch(t *testing.T) {
	t.Run("unlimited", func(t *testing.T) {
		engine := &batchCountingEngine{MemoryEngine: storage.NewMemoryEngine()}
		client, conn := newOfferLimitClient(t, engine, 0, 0)
		t.Logf("input: softLimit=0 hardLimit=0, packets of 200 then 3 files")

		offerFiles(t, client, 0, 200)
		offerFiles(t, client, 200, 3)

		t.Logf("output: batchSizes=%v addFile=%d stored=%d closed=%d",
			engine.batchSizes, engine.addFile, engine.FilesCount(), conn.closed)
		if engine.addFile != 0 {
			t.Errorf("offer path called AddFile %d times; each packet must go through AddFiles", engine.addFile)
		}
		if fmt.Sprint(engine.batchSizes) != "[200 3]" {
			t.Errorf("batch sizes %v, want [200 3] — one AddFiles per packet", engine.batchSizes)
		}
		if engine.FilesCount() != 203 {
			t.Errorf("stored %d files, want 203", engine.FilesCount())
		}
	})

	t.Run("hard limit flushes before the drop", func(t *testing.T) {
		engine := &batchCountingEngine{MemoryEngine: storage.NewMemoryEngine()}
		client, conn := newOfferLimitClient(t, engine, 0, 3)
		t.Logf("input: softLimit=0 hardLimit=3, one packet of 5 files")

		offerFiles(t, client, 0, 5)

		t.Logf("output: batchSizes=%v addFile=%d stored=%d closed=%d reason=%q",
			engine.batchSizes, engine.addFile, engine.FilesCount(), conn.closed, client.getCloseReason())
		if fmt.Sprint(engine.batchSizes) != "[3]" {
			t.Errorf("batch sizes %v, want [3] — the accepted records, flushed once before the close", engine.batchSizes)
		}
		if engine.FilesCount() != 3 || conn.closed == 0 {
			t.Errorf("stored=%d closed=%d, want 3 stored and the session closed", engine.FilesCount(), conn.closed)
		}
	})
}
