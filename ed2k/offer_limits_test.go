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

// offeredCount is how many distinct files storage says the session sources: what the
// soft limit is held against.
func offeredCount(client *tcpClient) int {
	return client.server.Storage.OfferedCount(client.snapshotInfo())
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
	t.Logf("output: stored=%d offered=%d messages=%q closed=%d",
		engine.FilesCount(), offeredCount(client), msgs, conn.closed)

	if engine.FilesCount() != 3 {
		t.Errorf("stored %d files, want 3 — the excess was not ignored", engine.FilesCount())
	}
	if offeredCount(client) != 3 {
		t.Errorf("offered=%d, want 3 — the count is the files the session sources, not the records it sent", offeredCount(client))
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

// TestOfferFilesReofferCostsNoSoftBudget is what counting distinct files buys. A
// client republishes a file when a download completes or its share list is reloaded;
// counted per record, a hundred re-offers of 200 files were 20,000 against the limit.
func TestOfferFilesReofferCostsNoSoftBudget(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 250, 0)
	t.Logf("input: softLimit=250; the same 200 files offered 100 times, then 50 new files, then 1 more")

	for range 100 {
		offerFiles(t, client, 0, 200)
	}
	afterReoffers, msgsAfterReoffers := offeredCount(client), len(serverMessages(t, conn))
	offerFiles(t, client, 200, 50)
	afterNew, msgsAfterNew := offeredCount(client), len(serverMessages(t, conn))
	offerFiles(t, client, 250, 1)

	msgs := serverMessages(t, conn)
	t.Logf("output: offered after re-offers=%d (messages=%d), after 50 new=%d (messages=%d), after 1 more=%d stored=%d messages=%q closed=%d",
		afterReoffers, msgsAfterReoffers, afterNew, msgsAfterNew, offeredCount(client), engine.FilesCount(), msgs, conn.closed)

	if afterReoffers != 200 || msgsAfterReoffers != 0 {
		t.Fatalf("after 100 re-offers: offered=%d messages=%d, want 200 and none", afterReoffers, msgsAfterReoffers)
	}
	if afterNew != 250 || msgsAfterNew != 0 {
		t.Fatalf("the 50 new files must fit the budget the re-offers left: offered=%d messages=%d", afterNew, msgsAfterNew)
	}
	if offeredCount(client) != 250 || engine.FilesCount() != 250 {
		t.Errorf("offered=%d stored=%d, want 250 — file 251 is past the limit", offeredCount(client), engine.FilesCount())
	}
	if len(msgs) != 1 || conn.closed != 0 {
		t.Errorf("messages=%q closed=%d, want the one WARNING and an open session", msgs, conn.closed)
	}
}

// TestOfferFilesReofferPastSoftLimitIsAccepted: a session at its limit can still
// update the files it sources. Here it turns a partial file into a complete one.
func TestOfferFilesReofferPastSoftLimitIsAccepted(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 2, 0)
	partial := func(first, count int) []PacketItem {
		offer := []PacketItem{{Type: TypeUint8, Value: OpOfferFiles}, {Type: TypeUint32, Value: uint32(count)}}
		for i := first; i < first+count; i++ {
			AddFile(&offer, SharedFile{
				Name: fmt.Sprintf("offer-limit-%03d.bin", i), Size: uint64(1024 + i), Hash: offerHash(i),
				SourceID: ValPartialID, SourcePort: ValPartialPort,
			})
		}
		return offer
	}
	t.Logf("input: softLimit=2; 4 partial files, then files 1 and 3 re-offered complete")

	dispatchIncomingTCPPacket(t, client, partial(0, 4))
	before := engine.SharedFiles([][]byte{offerHash(1)})
	offerFiles(t, client, 1, 1) // sourced already: accepted
	offerFiles(t, client, 3, 1) // skipped the first time: still new, still skipped
	after := engine.SharedFiles([][]byte{offerHash(1)})

	msgs := serverMessages(t, conn)
	t.Logf("output: offered=%d stored=%d file1 completed before=%d after=%d sources(file3)=%d messages=%q",
		offeredCount(client), engine.FilesCount(), before[0].Completed, after[0].Completed,
		len(engine.GetSourcesByHash(offerHash(3))), msgs)

	if before[0].Completed != 0 || after[0].Completed != 1 {
		t.Errorf("file 1 completed %d -> %d, want 0 -> 1: the re-offer was not stored", before[0].Completed, after[0].Completed)
	}
	if n := len(engine.GetSourcesByHash(offerHash(3))); n != 0 {
		t.Errorf("file 3 has %d source(s); it was past the limit both times", n)
	}
	if offeredCount(client) != 2 || len(msgs) != 1 {
		t.Errorf("offered=%d messages=%d, want 2 and the one WARNING", offeredCount(client), len(msgs))
	}
}

// TestOfferFilesDuplicateInPacketIsOneFile: a file listed twice in the packet that
// reaches the limit takes one place, not two.
func TestOfferFilesDuplicateInPacketIsOneFile(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 2, 0)
	offer := offerItems(0, 1)
	offer[1].Value = uint32(4)
	for _, i := range []int{0, 0, 1} {
		offer = append(offer, offerItems(i, 1)[2:]...)
	}
	t.Logf("input: softLimit=2, one packet listing files 0, 0, 0, 1")

	dispatchIncomingTCPPacket(t, client, offer)

	msgs := serverMessages(t, conn)
	t.Logf("output: offered=%d stored=%d messages=%q", offeredCount(client), engine.FilesCount(), msgs)
	if offeredCount(client) != 2 || engine.FilesCount() != 2 || len(msgs) != 0 {
		t.Errorf("offered=%d stored=%d messages=%d, want 2, 2 and none", offeredCount(client), engine.FilesCount(), len(msgs))
	}
}

// TestOfferFilesHardLimitIsPerPacket pins the hard half (kiten-20071012.txt:349) plus
// our one deliberate divergence: eserver drops silently, we say why first.
//
// A packet declaring the limit or more is refused whole: nothing of it is stored. The
// follow-up offer is the regression guard for pipelined packets. closeWithReason only
// closes the socket; processPacketData still dispatches bytes that already arrived, so
// without the hardLimitHit latch a second offer in the same segment would write a
// second message onto a closed connection.
func TestOfferFilesHardLimitIsPerPacket(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
	}{{"at the limit", 3}, {"over the limit", 5}} {
		t.Run(tc.name, func(t *testing.T) {
			engine := storage.NewMemoryEngine()
			client, conn := newOfferLimitClient(t, engine, 0, 3)
			t.Logf("input: softLimit=0 (unlimited) hardLimit=3, a packet of 2, one of %d, then another of 2", tc.count)

			offerFiles(t, client, 0, 2)
			storedBefore, closedBefore := engine.FilesCount(), conn.closed
			offerFiles(t, client, 10, tc.count)
			storedAtDrop := engine.FilesCount()
			offerFiles(t, client, 20, 2)

			msgs := serverMessages(t, conn)
			t.Logf("output: storedBefore=%d storedAtDrop=%d storedAfter=%d messages=%q closed=%d reason=%q",
				storedBefore, storedAtDrop, engine.FilesCount(), msgs, conn.closed, client.getCloseReason())

			if storedBefore != 2 || closedBefore != 0 {
				t.Fatalf("a packet under the limit: stored=%d closed=%d, want 2 and 0", storedBefore, closedBefore)
			}
			if storedAtDrop != 2 {
				t.Errorf("stored %d files, want 2 — nothing of a refused packet may be stored", storedAtDrop)
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
		})
	}
}

// TestOfferFilesHardLimitReadsTheDeclaredCount: the limit is applied to the count the
// packet opens with, before a record is parsed. The packet here carries no records at
// all; parsed first, it would have failed as malformed and the client stayed.
func TestOfferFilesHardLimitReadsTheDeclaredCount(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 0, 20000)
	t.Logf("input: hardLimit=20000, an OP_OFFERFILES declaring 20000 records and carrying none")

	dispatchIncomingTCPPacket(t, client, []PacketItem{
		{Type: TypeUint8, Value: OpOfferFiles},
		{Type: TypeUint32, Value: uint32(20000)},
	})

	msgs := serverMessages(t, conn)
	t.Logf("output: stored=%d messages=%q closed=%d reason=%q", engine.FilesCount(), msgs, conn.closed, client.getCloseReason())
	if len(msgs) != 1 || msgs[0] != fmt.Sprintf(msgHardFileLimit, 20000) {
		t.Fatalf("messages=%q, want the hard-limit error", msgs)
	}
	if conn.closed == 0 || client.getCloseReason() != "file-hard-limit" {
		t.Errorf("closed=%d reason=%q, want the session closed for the hard limit", conn.closed, client.getCloseReason())
	}
}

// TestOfferFilesLargeShareStaysConnected is the case the per-packet limit exists for.
//
// Both eMule trees send 200 files a packet until the whole share is published. With
// the hard limit on the session's running total, a client sharing 60,000 files was
// dropped at the 101st packet, reconnected, and started over, for as long as it ran.
func TestOfferFilesLargeShareStaysConnected(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 0, 20000)
	const packets, perPacket = 300, 200
	t.Logf("input: softLimit=0 hardLimit=20000, %d packets of %d files each", packets, perPacket)

	for p := range packets {
		offerFiles(t, client, p*perPacket, perPacket)
	}

	msgs := serverMessages(t, conn)
	t.Logf("output: stored=%d offered=%d messages=%q closed=%d", engine.FilesCount(), offeredCount(client), msgs, conn.closed)
	if conn.closed != 0 || len(msgs) != 0 {
		t.Fatalf("closed=%d messages=%q, want the session up and nothing said", conn.closed, msgs)
	}
	if engine.FilesCount() != packets*perPacket || offeredCount(client) != packets*perPacket {
		t.Errorf("stored=%d offered=%d, want %d", engine.FilesCount(), offeredCount(client), packets*perPacket)
	}
}

// TestOfferFilesLargeShareIsCappedBySoftLimit: with both limits at their defaults'
// proportions the large sharer keeps its session and the soft limit does the capping.
func TestOfferFilesLargeShareIsCappedBySoftLimit(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 1000, 2000)
	t.Logf("input: softLimit=1000 hardLimit=2000, 30 packets of 200 files each")

	for p := range 30 {
		offerFiles(t, client, p*200, 200)
	}

	msgs := serverMessages(t, conn)
	t.Logf("output: stored=%d offered=%d messages=%q closed=%d", engine.FilesCount(), offeredCount(client), msgs, conn.closed)
	if conn.closed != 0 {
		t.Fatalf("the session was closed (%q); only a single oversized packet may do that", client.getCloseReason())
	}
	if engine.FilesCount() != 1000 || offeredCount(client) != 1000 {
		t.Errorf("stored=%d offered=%d, want 1000", engine.FilesCount(), offeredCount(client))
	}
	if len(msgs) != 1 || msgs[0] != fmt.Sprintf(msgSoftFileLimit, 1000) {
		t.Errorf("messages=%q, want one soft-limit WARNING", msgs)
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

// TestOfferFilesBothLimitsWarnThenDrop walks the full ladder in one session: packets
// under the hard limit run into the soft one and are warned about, and a packet at the
// hard limit ends the session.
func TestOfferFilesBothLimitsWarnThenDrop(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 2, 6)
	t.Logf("input: softLimit=2 hardLimit=6, a packet of 5, then one of 6")

	offerFiles(t, client, 0, 5)
	closedAfterFirst := conn.closed
	offerFiles(t, client, 5, 6)

	msgs := serverMessages(t, conn)
	t.Logf("output: stored=%d closedAfterFirst=%d messages=%q closed=%d reason=%q",
		engine.FilesCount(), closedAfterFirst, msgs, conn.closed, client.getCloseReason())

	if engine.FilesCount() != 2 {
		t.Errorf("stored %d files, want 2 — the soft limit caps what is indexed", engine.FilesCount())
	}
	if closedAfterFirst != 0 {
		t.Errorf("the packet under the hard limit closed the session")
	}
	if len(msgs) != 2 {
		t.Fatalf("sent %d messages, want 2 (one WARNING then one ERROR): %q", len(msgs), msgs)
	}
	if want := fmt.Sprintf(msgSoftFileLimit, 2); msgs[0] != want {
		t.Errorf("first message is %q, want the soft warning %q", msgs[0], want)
	}
	if want := fmt.Sprintf(msgHardFileLimit, 6); msgs[1] != want {
		t.Errorf("second message is %q, want the hard error %q", msgs[1], want)
	}
	if conn.closed == 0 {
		t.Error("session was not closed by the packet at the hard limit")
	}
}

// TestOfferFilesSoftLimitIsPerSession guards against the budget being shared. Two
// clients each publishing up to the cap must both be served in full.
func TestOfferFilesSoftLimitIsPerSession(t *testing.T) {
	engine := storage.NewMemoryEngine()
	first, firstConn := newOfferLimitClient(t, engine, 3, 0)
	t.Logf("input: softLimit=3, two separate sessions offering 3 files each")

	offerFiles(t, first, 0, 3)

	// A second session on the same runtime, with its own identity.
	rt := first.server
	secondConn := &recordingConn{}
	second := newTCPClient(rt, secondConn, false)
	second.handlePacket(loginPacket(t, bytes.Repeat([]byte{0x7b}, 16), 0, 4663))
	secondConn.mu.Lock()
	secondConn.written = nil
	secondConn.mu.Unlock()
	offerFiles(t, second, 100, 3)

	t.Logf("output: stored=%d firstOffered=%d secondOffered=%d firstMessages=%q secondMessages=%q",
		engine.FilesCount(), offeredCount(first), offeredCount(second), serverMessages(t, firstConn), serverMessages(t, secondConn))

	if len(serverMessages(t, firstConn)) != 0 || len(serverMessages(t, secondConn)) != 0 {
		t.Errorf("a session was warned; each has its own budget")
	}
	if engine.FilesCount() != 6 || offeredCount(first) != 3 || offeredCount(second) != 3 {
		t.Errorf("stored=%d first=%d second=%d, want 6, 3 and 3", engine.FilesCount(), offeredCount(first), offeredCount(second))
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
// The limit cases matter as much as the plain one: what the soft limit lets through
// still goes in one call, and a packet the hard limit refuses makes none.
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

	t.Run("soft limit stores what fits in one batch", func(t *testing.T) {
		engine := &batchCountingEngine{MemoryEngine: storage.NewMemoryEngine()}
		client, conn := newOfferLimitClient(t, engine, 3, 0)
		t.Logf("input: softLimit=3 hardLimit=0, one packet of 5 files, then one of 2")

		offerFiles(t, client, 0, 5)
		offerFiles(t, client, 5, 2)

		t.Logf("output: batchSizes=%v addFile=%d stored=%d closed=%d",
			engine.batchSizes, engine.addFile, engine.FilesCount(), conn.closed)
		if fmt.Sprint(engine.batchSizes) != "[3]" {
			t.Errorf("batch sizes %v, want [3] — the files under the limit, and no call for a packet with none", engine.batchSizes)
		}
		if engine.FilesCount() != 3 || conn.closed != 0 {
			t.Errorf("stored=%d closed=%d, want 3 stored and the session open", engine.FilesCount(), conn.closed)
		}
	})

	t.Run("hard limit stores nothing", func(t *testing.T) {
		engine := &batchCountingEngine{MemoryEngine: storage.NewMemoryEngine()}
		client, conn := newOfferLimitClient(t, engine, 0, 3)
		t.Logf("input: softLimit=0 hardLimit=3, one packet of 5 files")

		offerFiles(t, client, 0, 5)

		t.Logf("output: batchSizes=%v addFile=%d stored=%d closed=%d reason=%q",
			engine.batchSizes, engine.addFile, engine.FilesCount(), conn.closed, client.getCloseReason())
		if len(engine.batchSizes) != 0 || engine.FilesCount() != 0 {
			t.Errorf("batch sizes %v stored=%d, want no storage call for a refused packet", engine.batchSizes, engine.FilesCount())
		}
		if conn.closed == 0 {
			t.Error("the session was not closed")
		}
	})
}

// TestOfferFilesPayloadIsReleasedAfterDispatch: once an offer has been handled the
// session must not keep its payload. It used to, until the next packet's header
// arrived, so a connection idling after a 200-file offer held those bytes for as long
// as it idled.
func TestOfferFilesPayloadIsReleasedAfterDispatch(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, _ := newOfferLimitClient(t, engine, 0, 0)
	frame := frameFor(t, offerItems(0, 200))
	t.Logf("input: one OP_OFFERFILES of 200 files, %d bytes on the wire, in two reads", len(frame))

	client.handleBytes(frame[:len(frame)/2])
	held := cap(client.packet.recv)
	client.handleBytes(frame[len(frame)/2:])

	t.Logf("output: buffered mid-packet=%d bytes; after dispatch status=%d payload=%d bytes recv=%d bytes stored=%d",
		held, client.packet.Status, len(client.packet.Data.Bytes()), cap(client.packet.recv), engine.FilesCount())
	if engine.FilesCount() != 200 {
		t.Fatalf("stored %d files, want 200", engine.FilesCount())
	}
	if held == 0 {
		t.Fatal("setup: the packet was not buffered across the two reads")
	}
	if n := len(client.packet.Data.Bytes()); n != 0 || client.packet.recv != nil {
		t.Errorf("the session still holds %d payload bytes after dispatch", n)
	}
}
