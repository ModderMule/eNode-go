package ed2k

import (
	"bytes"
	"context"
	"crypto/md5"
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

// fakeMeta is a MetaSearcher with a fixed answer that records how it was asked. Like
// the real searcher, a nativeOnly call answers with the native (Kad) rows alone.
type fakeMeta struct {
	mu          sync.Mutex
	rows        []storage.File
	calls       []bool // the udp argument of each call for every network
	nativeCalls int    // calls limited to the native networks
	files       int    // what AdvertisedFiles reports
}

func (f *fakeMeta) Search(_ context.Context, _ *storage.SearchExpr, udp, nativeOnly bool) []storage.File {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !nativeOnly {
		f.calls = append(f.calls, udp)
		return f.rows
	}
	f.nativeCalls++
	var native []storage.File
	for _, row := range f.rows {
		if row.Meta.Native() {
			native = append(native, row)
		}
	}
	return native
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

// kadRows returns n Kad rows as the meta package builds them: a real MD4 in the hash
// slot, the network prefix on the name, and Meta saying the row is native.
func kadRows(n int) []storage.File {
	rows := make([]storage.File, n)
	for i := range rows {
		hash := md5.Sum([]byte{'k', 'a', 'd', byte(i)})
		rows[i] = storage.File{
			Hash:    hash[:],
			Name:    fmt.Sprintf("[kad emule-qt.org] paging-kad-%02d.avi", i),
			Size:    uint64(700<<20 + i),
			Type:    "Video",
			Sources: 17, Completed: 0,
			Meta: &storage.MetaInfo{
				Kind: storage.MetaKindED2K, CatalogID: fmt.Sprintf("ed2k:%X", hash), Peers: 17, AgeDays: 2, Indexer: "kad",
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
// CT_SERVER_UDPSEARCH_FLAGS carries SrvCapUDPMetaSearch. Each row is its own record.
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
		records := 0
		for d := gotReply(); d != nil; d = gotReply() {
			records += countGlobSearchRecords(t, d)
		}
		t.Logf("input: %s payload=% x; output: searcherCalls=%d udpArg=%v records=%d",
			tc.name, tc.payload, fake.callCount(), fake.calls, records)
		if fake.callCount() != tc.wantCalls {
			t.Fatalf("%s: %d searcher calls, want %d", tc.name, fake.callCount(), tc.wantCalls)
		}
		if tc.wantCalls > 0 && !fake.calls[0] {
			t.Fatalf("%s: searcher asked with udp=false", tc.name)
		}
		if want := 1 + 2*tc.wantCalls; records != want {
			t.Fatalf("%s: %d records, want %d (one per row)", tc.name, records, want)
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
		TagMetaNetwork: tags.FTMetaNetwork,
	}
	if MetaNetworkKad != tags.MetaNetworkKad {
		t.Fatal("MetaNetworkKad differs from the contract's")
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

// countGlobSearchRecords walks a UDP search datagram's [E3 99 record] entries the way
// eMule's UDPSocket.cpp does and returns how many it holds.
func countGlobSearchRecords(t *testing.T, datagram []byte) int {
	t.Helper()
	b := NewBufferFromBytes(datagram)
	n := 0
	for b.Remaining() > 0 {
		proto, _ := b.GetUInt8()
		op, err := b.GetUInt8()
		if err != nil || proto != PrED2K || op != OpGlobSearchRes {
			t.Fatalf("record %d: bad header %#x %#x in % x", n, proto, op, datagram)
		}
		if len(b.Get(16)) != 16 {
			t.Fatalf("record %d: short hash", n)
		}
		if _, err := b.GetUInt32LE(); err != nil {
			t.Fatal(err)
		}
		if _, err := b.GetUInt16LE(); err != nil {
			t.Fatal(err)
		}
		if _, err := b.GetTags(); err != nil {
			t.Fatalf("record %d: %v", n, err)
		}
		n++
	}
	return n
}

// hasMetaTags reports whether a decoded record carries any FT_META_* tag of a
// pseudo-hash row (0x60-0x6c).
func hasMetaTags(r FileRecord) bool {
	for code := TagMetaKind; code <= TagMetaMagnet; code++ {
		if _, ok := r.Tags[tagName(code)]; ok {
			return true
		}
	}
	return false
}

// TestKadRowIsAnOrdinaryFileWithOneTag is what eMuleQt recognises a Kad result by:
// FT_META_NETWORK = 3 and nothing else of the meta block. FT_META_KIND in particular
// must be absent — a shipped eMuleQt drops a row whose kind tag its hash cannot back.
func TestKadRowIsAnOrdinaryFileWithOneTag(t *testing.T) {
	client, conn := searchPagingClient(t, 1)
	client.server.SetMetaSearcher(&fakeMeta{rows: kadRows(1)}, true)

	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	records := decodeSearchRecords(t, conn.takeWritten())
	t.Logf("input: 1 eD2K file + 1 Kad row, search \"paging-\"")
	for i, r := range records {
		t.Logf("output: record %d hash=%x id=%d port=%d tags=%v", i, r.Hash, r.ID, r.Port, r.Tags)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want the eD2K file and the Kad row", len(records))
	}
	local, kad := records[0], records[1]
	if _, marked := local.Tags[tagName(TagMetaNetwork)]; marked {
		t.Fatal("the server's own file carries FT_META_NETWORK")
	}
	want := kadRows(1)[0]
	if !bytes.Equal(kad.Hash, want.Hash) || metahash.IsMetaHash(kad.Hash) {
		t.Fatalf("Kad row hash %x, want the file's own MD4 %x", kad.Hash, want.Hash)
	}
	if kad.Tags[tagName(TagMetaNetwork)] != uint64(MetaNetworkKad) {
		t.Fatalf("FT_META_NETWORK = %v, want %d", kad.Tags[tagName(TagMetaNetwork)], MetaNetworkKad)
	}
	if hasMetaTags(kad) {
		t.Fatalf("the Kad row carries FT_META_* tags of a pseudo-hash row: %v", kad.Tags)
	}
	if kad.ID != 0 || kad.Port != 0 {
		t.Fatalf("Kad row source %d:%d, want 0:0", kad.ID, kad.Port)
	}
	if kad.Tags["name"] != want.Name || kad.Tags[tagName(TagSources)] != uint64(want.Sources) {
		t.Fatalf("Kad row name=%v sources=%v, want %q / %d", kad.Tags["name"], kad.Tags[tagName(TagSources)], want.Name, want.Sources)
	}
}

// TestLocalFileTakesPrecedenceOverKadRow: a file a user shares on this server is
// answered from the server's own database, whatever Kad says about the same hash. One
// record is sent, with the local name, sources and source address, and without the
// Kad prefix or tag — on a single page, on a later page and over UDP.
func TestLocalFileTakesPrecedenceOverKadRow(t *testing.T) {
	// Local file i has hash {i>>8, i, 0...}, name paging-%04d.bin and size 1024+i.
	kadFor := func(i int) storage.File {
		row := kadRows(1)[0]
		row.Hash = make([]byte, 16)
		row.Hash[0], row.Hash[1] = byte(i>>8), byte(i)
		row.Name = fmt.Sprintf("[kad emule-qt.org] kad name of paging-%04d.avi", i)
		row.Sources = 99
		return row
	}
	check := func(label string, records []FileRecord, local int) {
		t.Helper()
		hash := kadFor(local).Hash
		found := 0
		for _, r := range records {
			if !bytes.Equal(r.Hash, hash) {
				continue
			}
			found++
			t.Logf("output: %s record name=%v sources=%v id=%#x port=%d network=%v",
				label, r.Tags["name"], r.Tags[tagName(TagSources)], r.ID, r.Port, r.Tags[tagName(TagMetaNetwork)])
			if want := fmt.Sprintf("paging-%04d.bin", local); r.Tags["name"] != want {
				t.Fatalf("%s: name %v, want the local %q", label, r.Tags["name"], want)
			}
			if r.Tags[tagName(TagSources)] != uint64(1) {
				t.Fatalf("%s: sources %v, want the server's own count 1", label, r.Tags[tagName(TagSources)])
			}
			if r.ID != 0x0100007F || r.Port != 4662 {
				t.Fatalf("%s: source %#x:%d, want the sharing client's", label, r.ID, r.Port)
			}
			if _, marked := r.Tags[tagName(TagMetaNetwork)]; marked {
				t.Fatalf("%s: the local file carries FT_META_NETWORK", label)
			}
		}
		if found != 1 {
			t.Fatalf("%s: hash %x sent %d times, want once", label, hash, found)
		}
	}

	// One page: 3 local files, Kad knows file 1 too and one file the server lacks.
	client, conn := searchPagingClient(t, 3)
	client.server.SetMetaSearcher(&fakeMeta{rows: append([]storage.File{kadFor(1)}, kadRows(1)...)}, true)
	t.Logf("input: 3 local files, Kad rows for local file 1 and for one unknown file")
	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	records := decodeSearchRecords(t, conn.takeWritten())
	if len(records) != 4 {
		t.Fatalf("got %d records, want 3 local + 1 Kad-only", len(records))
	}
	check("single page", records, 1)

	// Two pages: the local file sits on page 2, the Kad row would have been appended
	// after it.
	localOnPage2 := storage.MaxSearchPage + 10
	client, conn = searchPagingClient(t, storage.MaxSearchPage+20)
	client.server.SetMetaSearcher(&fakeMeta{rows: []storage.File{kadFor(localOnPage2)}}, true)
	t.Logf("input: %d local files, a Kad row for local file %d (page 2)", storage.MaxSearchPage+20, localOnPage2)
	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	page1 := decodeSearchRecords(t, conn.takeWritten())
	client.handleED2K(OpQueryMoreResult, NewBuffer(0))
	page2 := decodeSearchRecords(t, conn.takeWritten())
	all := append(page1, page2...)
	if len(all) != storage.MaxSearchPage+20 {
		t.Fatalf("pages hold %d records, want the %d local files and no Kad row", len(all), storage.MaxSearchPage+20)
	}
	check("paged", all, localOnPage2)

	// UDP: the seeded file "food.bin" is local; Kad reports the same hash.
	kad := kadRows(1)[0]
	kad.Hash = []byte("fedcba9876543210")
	kad.Name = "[kad emule-qt.org] food from kad.bin"
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, seededEngine(t))
	rt.SetMetaSearcher(&fakeMeta{rows: []storage.File{kad}}, true)
	server, remote, gotReply := udpProbe(t)
	rt.udpGlobSearchReq(NewBufferFromBytes([]byte{0x01, 0x04, 0x00, 'f', 'o', 'o', 'd'}), remote, server, nil, "udp")
	var udp []FileRecord
	for d := gotReply(); d != nil; d = gotReply() {
		if countGlobSearchRecords(t, d) != 1 {
			t.Fatalf("udp datagram holds more than the one local record: % x", d)
		}
		recs, err := NewBufferFromBytes(append([]byte{1, 0, 0, 0}, d[2:]...)).GetFileList()
		if err != nil {
			t.Fatal(err)
		}
		udp = append(udp, recs...)
	}
	t.Logf("input: UDP search \"food\", local food.bin and a Kad row with its hash; output: %d records", len(udp))
	if len(udp) != 1 || udp[0].Tags["name"] != "food.bin" {
		t.Fatalf("udp answer %v, want the local food.bin alone", udp)
	}
	if _, marked := udp[0].Tags[tagName(TagMetaNetwork)]; marked {
		t.Fatal("udp: the local file carries FT_META_NETWORK")
	}
}

// TestKadRowsReachEveryClient: with advertiseToLegacyClients off a client that never
// announced SrvCapMetaSearch gets no torrent or Usenet row, which it could not act on,
// but still gets the Kad rows, which it can download. The pseudo-hash networks are not
// even asked. The same holds for the UDP opcodes without a tag block.
func TestKadRowsReachEveryClient(t *testing.T) {
	rows := append(metaRows(t, 2), kadRows(2)...)

	client, conn := searchPagingClient(t, 1)
	client.metaCapable = false
	fake := &fakeMeta{rows: rows}
	client.server.SetMetaSearcher(fake, false)
	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	records := decodeSearchRecords(t, conn.takeWritten())
	kad, pseudo := 0, 0
	for _, r := range records {
		if _, ok := r.Tags[tagName(TagMetaNetwork)]; ok {
			kad++
		}
		if hasMetaTags(r) {
			pseudo++
		}
	}
	t.Logf("input: TCP, advertiseToLegacyClients=false, metaCapable=false, 2 torrent + 2 Kad rows; output: records=%d kad=%d pseudo=%d fullCalls=%d nativeCalls=%d",
		len(records), kad, pseudo, fake.callCount(), fake.nativeCalls)
	if len(records) != 3 || kad != 2 || pseudo != 0 {
		t.Fatalf("records=%d kad=%d pseudo=%d, want 1 local + 2 Kad and no pseudo-hash row", len(records), kad, pseudo)
	}
	if fake.callCount() != 0 || fake.nativeCalls != 1 {
		t.Fatalf("fullCalls=%d nativeCalls=%d, want 0/1", fake.callCount(), fake.nativeCalls)
	}

	fake = &fakeMeta{rows: rows}
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, seededEngine(t))
	rt.SetMetaSearcher(fake, false)
	server, remote, gotReply := udpProbe(t)
	rt.udpGlobSearchReq(NewBufferFromBytes([]byte{0x01, 0x04, 0x00, 'f', 'o', 'o', 'd'}), remote, server, nil, "udp")
	udpRecords := 0
	for d := gotReply(); d != nil; d = gotReply() {
		udpRecords += countGlobSearchRecords(t, d)
	}
	t.Logf("input: UDP OP_GLOBSEARCHREQ, same rows; output: records=%d fullCalls=%d nativeCalls=%d",
		udpRecords, fake.callCount(), fake.nativeCalls)
	if udpRecords != 3 || fake.callCount() != 0 || fake.nativeCalls != 1 {
		t.Fatalf("udp records=%d fullCalls=%d nativeCalls=%d, want 3/0/1", udpRecords, fake.callCount(), fake.nativeCalls)
	}
}

// TestKadHashIsAnOrdinaryFileToTheServer: a Kad row's hash is a real MD4, so the
// pseudo-hash guards do not apply. A client may offer the file, and from then on
// OP_GETSOURCES answers with it; before that the answer is empty, and the client
// finds its sources on Kad.
func TestKadHashIsAnOrdinaryFileToTheServer(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, _ := newOfferLimitClient(t, engine, 0, 0)
	kad := kadRows(1)[0]

	before := engine.GetSources(kad.Hash, 4096)
	offer := []PacketItem{
		{Type: TypeUint8, Value: OpOfferFiles},
		{Type: TypeUint32, Value: uint32(1)},
	}
	AddFile(&offer, SharedFile{Name: "paging-kad-00.avi", Size: 4096, Hash: kad.Hash,
		SourceID: ValCompleteID, SourcePort: ValCompletePort})
	dispatchIncomingTCPPacket(t, client, offer)
	after := engine.GetSources(kad.Hash, 4096)

	t.Logf("input: OP_GETSOURCES for Kad hash %x, then OP_OFFERFILES of it, then OP_GETSOURCES again", kad.Hash)
	t.Logf("output: sources before=%d after=%d FilesCount=%d", len(before), len(after), engine.FilesCount())
	if len(before) != 0 {
		t.Fatalf("an unknown Kad hash returned %d sources", len(before))
	}
	if engine.FilesCount() != 1 || len(after) != 1 {
		t.Fatalf("the offered file was refused: FilesCount=%d sources=%d", engine.FilesCount(), len(after))
	}
}
