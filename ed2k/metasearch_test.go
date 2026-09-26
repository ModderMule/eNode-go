package ed2k

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"enode/storage"

	"github.com/ModderMule/enodemeta/metahash"
	"github.com/ModderMule/enodemeta/tags"
)

// fakeMeta is a MetaSearcher with a fixed answer that records how it was asked.
type fakeMeta struct {
	mu    sync.Mutex
	rows  []storage.File
	calls []bool // the udp argument of each call
	files int    // what AdvertisedFiles reports
}

func (f *fakeMeta) Search(_ context.Context, _ *storage.SearchExpr, udp bool) []storage.File {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, udp)
	return f.rows
}

func (f *fakeMeta) AdvertisedFiles() int { return f.files }

func (f *fakeMeta) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// testMetaHash mints a real pseudo-hash, so the rows under test are what the meta
// package would produce and the OP_OFFERFILES guard recognises them.
func testMetaHash(t *testing.T, seed byte) []byte {
	t.Helper()
	// Hashed, not repeated: twenty equal bytes fold to an all-zero digest, so every
	// seed would mint the same hash.
	identity := sha1.Sum([]byte{seed})
	h, err := metahash.Build(metahash.KindBTV1, 0, 0, identity[:])
	if err != nil {
		t.Fatal(err)
	}
	return h.Bytes()
}

// metaRows returns n torrent rows whose names contain "paging-", so they also match
// the searches the paging helpers send.
func metaRows(t *testing.T, n int) []storage.File {
	t.Helper()
	rows := make([]storage.File, n)
	for i := range rows {
		rows[i] = storage.File{
			Hash:    testMetaHash(t, byte(i+1)),
			Name:    fmt.Sprintf("[torrent] paging-meta-%02d.mkv", i),
			Size:    uint64(1<<20 + i),
			Type:    "Video",
			Sources: 42, Completed: 42,
			Meta: &storage.MetaInfo{
				Kind: 1, Version: 1, FileIndex: 0, FilePath: fmt.Sprintf("dir/paging-meta-%02d.mkv", i),
				TotalSize: 5 << 30, CatalogID: fmt.Sprintf("bt:v1:%040X", i), Seeders: 42, Peers: 7,
				AgeDays: 3, Indexer: "dht", Flags: 0, Magnet: "magnet:?xt=urn:btih:00",
			},
		}
	}
	return rows
}

// decodeSearchRecords returns the file records of an OP_SEARCHRESULT.
func decodeSearchRecords(t *testing.T, raw []byte) []FileRecord {
	t.Helper()
	payload := raw[6:]
	if raw[0] == PrZlib {
		inflated, err := InflateZlibPayload(payload)
		if err != nil {
			t.Fatalf("inflate: %v", err)
		}
		payload = inflated
	}
	records, err := NewBufferFromBytes(payload).GetFileList()
	if err != nil {
		t.Fatalf("decode file list: %v", err)
	}
	return records
}

// TestSearchMergesMetaRowsAfterEd2kFiles is the end-to-end TCP case: the meta rows are
// in the same single OP_SEARCHRESULT as the eD2K files, after them, with no source
// address and with their FT_META_* tags intact.
func TestSearchMergesMetaRowsAfterEd2kFiles(t *testing.T) {
	client, conn := searchPagingClient(t, 3)
	fake := &fakeMeta{rows: metaRows(t, 2)}
	client.server.SetMetaSearcher(fake, true)

	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	records := decodeSearchRecords(t, conn.takeWritten())

	t.Logf("input: 3 eD2K files + 2 meta rows, search \"paging-\"")
	for i, r := range records {
		t.Logf("output: record %d name=%v hash=%x id=%d port=%d kind=%v catalog=%v",
			i, r.Tags["name"], r.Hash, r.ID, r.Port, r.Tags[tagName(TagMetaKind)], r.Tags[tagName(TagMetaID)])
	}
	if len(records) != 5 {
		t.Fatalf("got %d records, want 3 eD2K + 2 meta", len(records))
	}
	for i := 0; i < 3; i++ {
		if _, isMeta := records[i].Tags[tagName(TagMetaKind)]; isMeta {
			t.Fatalf("record %d is a meta row; eD2K files must come first", i)
		}
	}
	for i, r := range records[3:] {
		if !metahash.IsMetaHash(r.Hash) {
			t.Fatalf("meta record %d hash %x is not a meta hash", i, r.Hash)
		}
		if r.ID != 0 || r.Port != 0 {
			t.Fatalf("meta record %d carries source %d:%d, want 0:0 (no source)", i, r.ID, r.Port)
		}
		if r.Tags[tagName(TagMetaKind)] != uint64(1) {
			t.Fatalf("meta record %d FT_META_KIND = %v, want 1", i, r.Tags[tagName(TagMetaKind)])
		}
	}
	if fake.callCount() != 1 || fake.calls[0] {
		t.Fatalf("meta searcher calls = %v, want exactly one TCP (udp=false) call", fake.calls)
	}
}

// TestSearchPagingIncludesMetaRows: meta rows ride the existing OP_QUERY_MORE_RESULT
// paging, so a merged set larger than a page is still fully retrievable.
func TestSearchPagingIncludesMetaRows(t *testing.T) {
	const ed2kFiles, metaFiles = storage.MaxSearchPage, 20
	client, conn := searchPagingClient(t, ed2kFiles)
	client.server.SetMetaSearcher(&fakeMeta{rows: metaRows(t, metaFiles)}, true)

	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	count1, more1, _ := decodeSearchResult(t, conn.takeWritten())
	client.handleED2K(OpQueryMoreResult, NewBufferFromBytes(nil))
	page2 := conn.takeWritten()
	count2, more2, _ := decodeSearchResult(t, page2)
	records2 := decodeSearchRecords(t, page2)

	t.Logf("input: %d eD2K files + %d meta rows", ed2kFiles, metaFiles)
	t.Logf("output: page1 count=%d more=%d, page2 count=%d more=%d", count1, more1, count2, more2)
	if int(count1+count2) != ed2kFiles+metaFiles || more1 != 1 || more2 != 0 {
		t.Fatalf("pages %d+%d (more %d/%d), want %d rows over two pages", count1, count2, more1, more2, ed2kFiles+metaFiles)
	}
	if _, isMeta := records2[len(records2)-1].Tags[tagName(TagMetaKind)]; !isMeta {
		t.Fatal("the last row of the last page should be a meta row")
	}
}

// TestMergeMetaResultsRespectsCeiling: the merged set never exceeds MaxSearchResults,
// the bound every engine and the pending-page memory assume, and a duplicate hash is
// sent once.
func TestMergeMetaResultsRespectsCeiling(t *testing.T) {
	files := make([]storage.File, storage.MaxSearchResults-1)
	for i := range files {
		files[i] = storage.File{Hash: []byte(fmt.Sprintf("ed2k-file-%06d", i))}
	}
	meta := metaRows(t, 3)
	meta = append(meta, storage.File{Hash: files[0].Hash, Name: "duplicate"})
	ch := make(chan []storage.File, 1)
	ch <- meta

	merged := mergeMetaResults(files, ch)
	t.Logf("input: %d eD2K + %d meta (one duplicate hash); output: %d rows", len(files), len(meta), len(merged))
	if len(merged) != storage.MaxSearchResults {
		t.Fatalf("merged %d rows, want the ceiling %d", len(merged), storage.MaxSearchResults)
	}
	if merged[len(merged)-1].Meta == nil {
		t.Fatal("the one free slot should hold the first meta row")
	}
	if got := mergeMetaResults(files[:2], nil); len(got) != 2 {
		t.Fatalf("a nil channel (no meta for this requester) changed the result: %d rows", len(got))
	}
}

// TestMetaRowsGatedOnLoginCapability: with advertiseToLegacyClients off, only a client
// that announced SrvCapMetaSearch in CT_SERVER_FLAGS is asked about at all.
func TestMetaRowsGatedOnLoginCapability(t *testing.T) {
	for _, capable := range []bool{false, true} {
		client, conn := searchPagingClient(t, 1)
		client.metaCapable = capable
		fake := &fakeMeta{rows: metaRows(t, 2)}
		client.server.SetMetaSearcher(fake, false)

		client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
		records := decodeSearchRecords(t, conn.takeWritten())
		t.Logf("input: advertiseToLegacyClients=false metaCapable=%t; output: records=%d searcherCalls=%d",
			capable, len(records), fake.callCount())

		want := 1
		if capable {
			want = 3
		}
		if len(records) != want {
			t.Fatalf("metaCapable=%t: %d records, want %d", capable, len(records), want)
		}
	}
}

// TestLoginRecordsMetaCapability: the SrvCapMetaSearch bit of CT_SERVER_FLAGS is what
// sets metaCapable, and its absence leaves it clear.
func TestLoginRecordsMetaCapability(t *testing.T) {
	for _, flags := range []uint32{0, SrvCapMetaSearch} {
		client, _ := searchPagingClient(t, 0)
		client.metaCapable = false
		items := loginItems(bytes.Repeat([]byte{0x6c}, 16), 0, 4662)
		items[len(items)-1] = PacketItem{Type: TypeTags, Value: []Tag{{Type: TypeUint32, Code: TagFlags, Data: flags}}}
		wire, err := MakePacket(PrED2K, items)
		if err != nil {
			t.Fatal(err)
		}
		p := NewPacket()
		if err := p.Init(NewBufferFromBytes(wire.Bytes())); err != nil {
			t.Fatal(err)
		}
		fresh := newTCPClient(client.server, &recordingConn{}, false)
		fresh.handlePacket(p)
		t.Logf("input: login CT_SERVER_FLAGS=0x%x; output: metaCapable=%t", flags, fresh.metaCapable)
		if fresh.metaCapable != (flags&SrvCapMetaSearch != 0) {
			t.Fatalf("flags 0x%x gave metaCapable=%t", flags, fresh.metaCapable)
		}
	}
}

// TestUDPGlobSearchMetaGating: with advertiseToLegacyClients off, OP_GLOBSEARCHREQ
// (no tag block) never gets meta rows, and OP_GLOBSEARCHREQ3 gets them only when its
// CT_SERVER_UDPSEARCH_FLAGS carries SrvCapUDPMetaSearch. Each row is its own datagram.
func TestUDPGlobSearchMetaGating(t *testing.T) {
	search := []byte{0x01, 0x04, 0x00, 'f', 'o', 'o', 'd'}
	req3 := func(flags uint32) []byte {
		b := NewBuffer(64)
		_ = b.PutTags([]Tag{{Type: TypeUint32, Code: TagSearchTree, Data: flags}})
		return append(b.Bytes()[:b.Pos()], search...)
	}
	cases := []struct {
		name      string
		payload   []byte
		req3      bool
		wantCalls int
	}{
		{"REQ no tag block", search, false, 0},
		{"REQ3 large-files only", req3(0x01), true, 0},
		{"REQ3 meta flag", req3(0x01 | SrvCapUDPMetaSearch), true, 1},
	}
	for _, tc := range cases {
		fake := &fakeMeta{rows: metaRows(t, 2)}
		rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, seededEngine(t))
		rt.SetMetaSearcher(fake, false)
		server, remote, gotReply := udpProbe(t)

		if tc.req3 {
			rt.udpGlobSearchReq3(NewBufferFromBytes(tc.payload), remote, server, nil, "udp")
		} else {
			rt.udpGlobSearchReq(NewBufferFromBytes(tc.payload), remote, server, nil, "udp")
		}
		datagrams := 0
		for gotReply() != nil {
			datagrams++
		}
		t.Logf("input: %s payload=% x; output: searcherCalls=%d udpArg=%v datagrams=%d",
			tc.name, tc.payload, fake.callCount(), fake.calls, datagrams)
		if fake.callCount() != tc.wantCalls {
			t.Fatalf("%s: %d searcher calls, want %d", tc.name, fake.callCount(), tc.wantCalls)
		}
		if tc.wantCalls > 0 && !fake.calls[0] {
			t.Fatalf("%s: searcher asked with udp=false", tc.name)
		}
		if want := 1 + 2*tc.wantCalls; datagrams != want {
			t.Fatalf("%s: %d datagrams, want %d (one per row)", tc.name, datagrams, want)
		}
	}
}

// TestAddFileEmitsMetaTags decodes a meta row back and checks every FT_META_* tag,
// and that the tag ids are the contract's — ed2k keeps its own constants so the wire
// encoder takes no dependency on the contract module, and this is what stops them
// drifting apart.
func TestAddFileEmitsMetaTags(t *testing.T) {
	ids := map[uint8]int{
		TagMetaKind: tags.FTMetaKind, TagMetaVersion: tags.FTMetaVersion, TagMetaFileIndex: tags.FTMetaFileIndex,
		TagMetaFilePath: tags.FTMetaFilePath, TagMetaTotalSize: tags.FTMetaTotalSize, TagMetaID: tags.FTMetaID,
		TagMetaSeeders: tags.FTMetaSeeders, TagMetaPeers: tags.FTMetaPeers, TagMetaAge: tags.FTMetaAge,
		TagMetaIndexer: tags.FTMetaIndexer, TagMetaFlags: tags.FTMetaFlags, TagMetaMagnet: tags.FTMetaMagnet,
	}
	for ours, contract := range ids {
		if int(ours) != contract {
			t.Fatalf("tag 0x%02x differs from the contract's 0x%02x", ours, contract)
		}
	}
	if FlagMetaSearch != tags.FlagMetaSearch || SrvCapMetaSearch != tags.SrvCapMetaSearch || SrvCapUDPMetaSearch != tags.SrvCapUDPMetaSearch {
		t.Fatal("capability bits differ from the contract's")
	}

	row := metaRows(t, 1)[0]
	packets, err := BuildGlobSearchResPackets([]storage.File{row})
	if err != nil {
		t.Fatal(err)
	}
	// A datagram is protocol, opcode, then one record; a count of 1 in front makes it
	// a file list the shared decoder reads.
	raw := append([]byte{1, 0, 0, 0}, packets[0].Bytes()[2:]...)
	records, err := NewBufferFromBytes(raw).GetFileList()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := records[0].Tags
	t.Logf("input: %+v", *row.Meta)
	t.Logf("output: tags=%v", got)

	m := row.Meta
	want := map[uint8]any{
		TagMetaKind: uint64(m.Kind), TagMetaVersion: uint64(m.Version), TagMetaFileIndex: uint64(m.FileIndex),
		TagMetaFilePath: m.FilePath, TagMetaTotalSize: m.TotalSize, TagMetaID: m.CatalogID,
		TagMetaSeeders: uint64(m.Seeders), TagMetaPeers: uint64(m.Peers), TagMetaAge: uint64(m.AgeDays),
		TagMetaIndexer: m.Indexer, TagMetaFlags: uint64(m.Flags), TagMetaMagnet: m.Magnet,
	}
	for code, v := range want {
		if g := got[tagName(code)]; g != v {
			t.Fatalf("tag 0x%02x = %v (%T), want %v (%T)", code, g, g, v, v)
		}
	}
	if got["name"] != row.Name {
		t.Fatalf("FT_FILENAME = %v, want %q", got["name"], row.Name)
	}
}

// TestOfferFilesRejectsMetaHash is the §9.1 guard: a modified client offering a file
// under a pseudo-hash must not attach itself as a source of an advertised meta row.
func TestOfferFilesRejectsMetaHash(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 0, 0)
	meta := testMetaHash(t, 0x77)

	offer := []PacketItem{
		{Type: TypeUint8, Value: OpOfferFiles},
		{Type: TypeUint32, Value: uint32(2)},
	}
	AddFile(&offer, SharedFile{Name: "real.bin", Size: 4096, Hash: offerHash(1),
		SourceID: ValCompleteID, SourcePort: ValCompletePort})
	AddFile(&offer, SharedFile{Name: "pseudo.mkv", Size: 4096, Hash: meta,
		SourceID: ValCompleteID, SourcePort: ValCompletePort})

	t.Logf("input: OP_OFFERFILES real.bin + pseudo.mkv under meta hash %x", meta)
	dispatchIncomingTCPPacket(t, client, offer)
	sources := engine.GetSources(meta, 4096)
	t.Logf("output: FilesCount=%d sourcesOfMetaHash=%d offeredFiles=%d closed=%d",
		engine.FilesCount(), len(sources), client.offeredFiles, conn.closed)

	if engine.FilesCount() != 1 || len(sources) != 0 {
		t.Fatalf("the meta-hash record was stored: FilesCount=%d sources=%d", engine.FilesCount(), len(sources))
	}
	if client.offeredFiles != 1 || conn.closed != 0 {
		t.Fatalf("offeredFiles=%d closed=%d, want 1/0: a refused record costs nothing", client.offeredFiles, conn.closed)
	}
}

// TestGetSourcesOnMetaHashIsEmpty pins what a stock client's download of a meta row
// gets from OP_GETSOURCES: nothing. It holds today because the hash is never stored; a
// future "helpfully return something" change would hand out sources that serve nothing.
func TestGetSourcesOnMetaHashIsEmpty(t *testing.T) {
	engine := seededEngine(t)
	meta := testMetaHash(t, 0x42)
	got := engine.GetSources(meta, 1<<20)
	t.Logf("input: GetSources(%x, 1 MiB); output: %d sources", meta, len(got))
	if len(got) != 0 {
		t.Fatalf("a meta hash returned %d sources", len(got))
	}
}

// fixedFilesEngine reports a fixed eD2K file count, so a status test can tell the
// eD2K share of the advertised total from the meta share.
type fixedFilesEngine struct {
	storage.Engine
	files int
}

func (e fixedFilesEngine) FilesCount() int { return e.files }

// TestServerStatusAddsMetaFiles covers countInServerStatus on the wire: both status
// packets carry eD2K + meta files, Counts() keeps the eD2K figure for the dashboard,
// the sum is clamped to the uint32 field, and no searcher changes nothing.
func TestServerStatusAddsMetaFiles(t *testing.T) {
	cases := []struct {
		name      string
		meta      *fakeMeta
		ed2kFiles int
		want      uint32
	}{
		{"no searcher", nil, 700, 700},
		{"searcher counting nothing", &fakeMeta{}, 700, 700},
		{"meta files added", &fakeMeta{files: 1234}, 700, 1934},
		{"clamped to uint32", &fakeMeta{files: math.MaxUint32}, 700, math.MaxUint32},
	}
	for _, tc := range cases {
		rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{},
			fixedFilesEngine{Engine: storage.NewMemoryEngine(), files: tc.ed2kFiles})
		if tc.meta != nil {
			rt.SetMetaSearcher(tc.meta, true)
		}

		packet, err := rt.buildStatRes(0x1122, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, b := payloadAfterOpcode(t, packet)
		udp, err := ParseGlobServStatRes(b)
		if err != nil {
			t.Fatal(err)
		}

		tcp := readServerStatusFiles(t, rt)
		_, dashboard := rt.Counts()
		t.Logf("input: %s, ed2k files=%d; output: OP_GLOBSERVSTATRES files=%d OP_SERVERSTATUS files=%d Counts()=%d AdvertisedFiles()=%d",
			tc.name, tc.ed2kFiles, udp.Files, tcp, dashboard, rt.AdvertisedFiles())

		if udp.Files != tc.want || tcp != tc.want || uint32(rt.AdvertisedFiles()) != tc.want {
			t.Errorf("%s: udp=%d tcp=%d advertised=%d, want %d", tc.name, udp.Files, tcp, rt.AdvertisedFiles(), tc.want)
		}
		if dashboard != tc.ed2kFiles {
			t.Errorf("%s: Counts() files=%d, want the eD2K figure %d alone", tc.name, dashboard, tc.ed2kFiles)
		}
	}
}

// readServerStatusFiles sends one OP_SERVERSTATUS over a pipe and returns its file count.
func readServerStatusFiles(t *testing.T, rt *ServerRuntime) uint32 {
	t.Helper()
	server, client := net.Pipe()
	defer client.Close()
	c := newTCPClient(rt, server, false)
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		n, _ := client.Read(buf)
		got <- buf[:n]
	}()
	c.sendServerStatus()
	server.Close()
	raw := <-got
	// protocol, uint32 length, opcode, users, files
	if len(raw) < 14 || raw[5] != OpServerStatus {
		t.Fatalf("not an OP_SERVERSTATUS: % x", raw)
	}
	return binary.LittleEndian.Uint32(raw[10:14])
}
