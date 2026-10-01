package storage

import (
	"testing"
)

// natPair connects two clients that share one HighID — two users behind one NAT with
// two forwarded ports — and has each offer its own file.
func natPair(t *testing.T) (m *MemoryEngine, a, b ClientInfo, fileA, fileB []byte) {
	t.Helper()
	m = NewMemoryEngine()
	const sharedID = 0x0a0b0c0d
	a = ClientInfo{ID: sharedID, Port: 4662, Hash: []byte("client-a-hash-01")}
	b = ClientInfo{ID: sharedID, Port: 4672, Hash: []byte("client-b-hash-01")}
	var err error
	if a.StoreID, err = m.Connect(a); err != nil {
		t.Fatal(err)
	}
	if b.StoreID, err = m.Connect(b); err != nil {
		t.Fatal(err)
	}
	fileA, fileB = []byte("file-a-hash-0001"), []byte("file-b-hash-0001")
	m.AddFile(File{Hash: fileA, Name: "a.iso", Size: 100}, a)
	m.AddFile(File{Hash: fileB, Name: "b.iso", Size: 200}, b)
	return m, a, b, fileA, fileB
}

// Two sessions with the same ed2k ID used to share one clients row: the second
// overwrote the first, and either one's Disconnect deleted the other's sources and
// orphaned its hash index, locking it out until restart.
func TestMemorySameIDSessionsAreIndependent(t *testing.T) {
	m, a, b, fileA, fileB := natPair(t)
	t.Logf("input: A{id=%#x port=%d store=%d} and B{id=%#x port=%d store=%d} each offer one file",
		a.ID, a.Port, a.StoreID, b.ID, b.Port, b.StoreID)

	if m.ClientsCount() != 2 {
		t.Fatalf("both sessions must be stored, ClientsCount=%d", m.ClientsCount())
	}

	m.Disconnect(b)
	t.Logf("output after B disconnects: clients=%d A connected=%t B connected=%t sources(a)=%d sources(b)=%d",
		m.ClientsCount(), m.IsConnected(a), m.IsConnected(b), len(m.GetSources(fileA, 100)), len(m.GetSources(fileB, 200)))
	if !m.IsConnected(a) || m.IsConnected(b) {
		t.Fatalf("B's disconnect must leave A connected and B gone")
	}
	if len(m.GetSources(fileA, 100)) != 1 {
		t.Fatal("B's disconnect removed A's source")
	}
	if len(m.GetSources(fileB, 200)) != 0 {
		t.Fatal("B's source outlived B")
	}

	m.Disconnect(a)
	t.Logf("output after A disconnects: clients=%d A connected=%t sources(a)=%d",
		m.ClientsCount(), m.IsConnected(a), len(m.GetSources(fileA, 100)))
	if m.IsConnected(a) {
		t.Fatal("A's hash stays indexed after its disconnect: every re-login would be refused")
	}
	if m.ClientsCount() != 0 || len(m.GetSources(fileA, 100)) != 0 {
		t.Fatalf("A's row or source outlived A")
	}
}

// A replaced session's Disconnect can land after the new session with the same hash
// connected. It must not unregister the live one or strip its sources.
func TestMemoryLateDisconnectOfReplacedSession(t *testing.T) {
	m := NewMemoryEngine()
	hash := []byte("same-user-hash-1")
	file := []byte("file-hash-000001")
	old := ClientInfo{ID: 0x01020304, Port: 4662, Hash: hash}
	old.StoreID, _ = m.Connect(old)
	m.AddFile(File{Hash: file, Name: "x.iso", Size: 10}, old)

	fresh := ClientInfo{ID: 0x01020304, Port: 4662, Hash: hash}
	fresh.StoreID, _ = m.Connect(fresh)
	m.AddFile(File{Hash: file, Name: "x.iso", Size: 10}, fresh)
	t.Logf("input: old store=%d and new store=%d share hash and address; old disconnects last", old.StoreID, fresh.StoreID)

	m.Disconnect(old)
	t.Logf("output: connected=%t clients=%d sources=%d", m.IsConnected(fresh), m.ClientsCount(), len(m.GetSources(file, 10)))
	if !m.IsConnected(fresh) {
		t.Fatal("late Disconnect of the replaced session unregistered the live one")
	}
	if len(m.GetSources(file, 10)) != 1 {
		t.Fatal("late Disconnect of the replaced session removed the live session's source")
	}
}

// Nothing kept the memory engine's counters current: Sources was whatever the offer
// claimed (eMule sends none) and Completed the last publisher's own flag. Search now
// reports the live counts, and filters on them.
func TestMemorySearchReportsLiveCounts(t *testing.T) {
	m := NewMemoryEngine()
	file := []byte("counted-file-001")
	for i, complete := range []uint32{1, 0, 1} {
		info := ClientInfo{ID: uint32(0x01000000 + i), Port: 4662, Hash: []byte{byte(i), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}}
		info.StoreID, _ = m.Connect(info)
		m.AddFile(File{Hash: file, Name: "counted.iso", Size: 1000, Sources: 99, Completed: complete}, info)
	}
	t.Logf("input: 3 sources (2 complete) offer counted.iso, each claiming sources=99")

	got := m.FindBySearch(&SearchExpr{Kind: SearchText, Text: "counted"})
	if len(got) != 1 {
		t.Fatalf("want 1 result, got %d", len(got))
	}
	t.Logf("output: Sources=%d Completed=%d", got[0].Sources, got[0].Completed)
	if got[0].Sources != 3 || got[0].Completed != 2 {
		t.Fatalf("want Sources=3 Completed=2, got %d/%d", got[0].Sources, got[0].Completed)
	}

	for _, tc := range []struct {
		tag   uint8
		value uint64
		want  int
	}{
		{SearchTagSources, 3, 1},
		{SearchTagSources, 4, 0},
		{SearchTagComplete, 2, 1},
		{SearchTagComplete, 3, 0},
	} {
		expr := &SearchExpr{Kind: SearchAnd,
			Left:  &SearchExpr{Kind: SearchText, Text: "counted"},
			Right: numericLeaf(tc.tag, SearchOpGreaterEqual, tc.value)}
		n := len(m.FindBySearch(expr))
		t.Logf("input: tag=%#x >= %d, output: %d result(s)", tc.tag, tc.value, n)
		if n != tc.want {
			t.Fatalf("tag=%#x >= %d: want %d results, got %d", tc.tag, tc.value, tc.want, n)
		}
	}
}

// An offer still being handled when its session was released lands after Disconnect.
// Stored, its sources would outlive the session for good: no second Disconnect comes.
func TestMemoryOfferAfterDisconnectIsDropped(t *testing.T) {
	m := NewMemoryEngine()
	info := ClientInfo{ID: 0x01020304, Port: 4662, Hash: []byte("late-offer-hash1")}
	info.StoreID, _ = m.Connect(info)
	m.Disconnect(info)

	file := []byte("late-file-hash01")
	m.AddFiles([]File{{Hash: file, Name: "late.iso", Size: 10}}, info)
	t.Logf("input: AddFiles from store=%d after its Disconnect, output: sources=%d files=%d",
		info.StoreID, len(m.GetSourcesByHash(file)), m.FilesCount())
	if len(m.GetSourcesByHash(file)) != 0 || m.FilesCount() != 0 {
		t.Fatal("an offer from a released session was stored")
	}
}

// GetSources hands out the newest offers first, as the DB engines' ORDER BY
// time_offer DESC does; it used to hand out the oldest 255 forever. A re-offer counts
// as new.
func TestMemoryGetSourcesNewestFirst(t *testing.T) {
	m := NewMemoryEngine()
	file := []byte("popular-file-001")
	var infos []ClientInfo
	for i := range MaxWireSources + 10 {
		info := ClientInfo{ID: uint32(0x01000000 + i), Port: 4662, Hash: []byte{byte(i), byte(i >> 8), 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}
		info.StoreID, _ = m.Connect(info)
		m.AddFile(File{Hash: file, Name: "popular.iso", Size: 10}, info)
		infos = append(infos, info)
	}
	m.AddFile(File{Hash: file, Name: "popular.iso", Size: 10}, infos[0]) // re-offer

	got := m.GetSources(file, 10)
	t.Logf("input: %d sources, the first re-offering last; output: %d returned, first id=%#x second id=%#x last id=%#x",
		len(infos), len(got), got[0].ID, got[1].ID, got[len(got)-1].ID)
	if len(got) != MaxWireSources {
		t.Fatalf("want %d sources, got %d", MaxWireSources, len(got))
	}
	if got[0].ID != infos[0].ID || got[1].ID != infos[len(infos)-1].ID {
		t.Fatalf("want the re-offer, then the newest source first")
	}
	if got[len(got)-1].ID != infos[11].ID {
		t.Fatalf("want the oldest sources dropped, last id=%#x", got[len(got)-1].ID)
	}
}

// A search result names one source by id/port. It was the last offerer's, kept after
// that session left, when its LowID may already belong to someone else.
func TestMemorySearchResultSourceIsLive(t *testing.T) {
	m := NewMemoryEngine()
	file := []byte("result-source-01")
	a := ClientInfo{ID: 0x0a000001, Port: 4662, Hash: []byte("result-src-a-001")}
	b := ClientInfo{ID: 0x0b000001, Port: 4663, Hash: []byte("result-src-b-001")}
	a.StoreID, _ = m.Connect(a)
	b.StoreID, _ = m.Connect(b)
	m.AddFile(File{Hash: file, Name: "result.iso", Size: 10}, a)
	m.AddFile(File{Hash: file, Name: "result.iso", Size: 10}, b)

	expr := &SearchExpr{Kind: SearchText, Text: "result"}
	steps := []struct {
		leave    ClientInfo
		wantID   uint32
		wantPort uint16
	}{{b, a.ID, a.Port}, {a, 0, 0}}
	for _, step := range steps {
		m.Disconnect(step.leave)
		got := m.FindBySearch(expr)
		if len(got) != 1 {
			t.Fatalf("want 1 result, got %d", len(got))
		}
		t.Logf("input: id=%#x disconnects, output: result source %#x:%d", step.leave.ID, got[0].SourceID, got[0].SourcePort)
		if got[0].SourceID != step.wantID || got[0].SourcePort != step.wantPort {
			t.Fatalf("want source %#x:%d", step.wantID, step.wantPort)
		}
	}
}

// numericLeaf builds a numeric leaf as the wire parser does: TagType is operator,
// a 2-byte tag-name length of 1, and the tag id, read as one little-endian uint32.
func numericLeaf(tag, op uint8, value uint64) *SearchExpr {
	return &SearchExpr{Kind: SearchUInt32, TagType: uint32(op) | 1<<8 | uint32(tag)<<24, ValueUint: value}
}
