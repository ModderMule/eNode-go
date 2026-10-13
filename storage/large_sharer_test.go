package storage

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// sharerHash is the hash of the i-th file of sharer who.
func sharerHash(who byte, i int) []byte {
	h := make([]byte, hashLen)
	h[0] = who
	binary.BigEndian.PutUint32(h[1:], uint32(i))
	h[15] = 0x5a
	return h
}

// sharerFiles is n files of sharer who, named with word so a search finds them.
func sharerFiles(who byte, first, n int, word string) []File {
	files := make([]File, n)
	for i := range files {
		files[i] = File{
			Hash: sharerHash(who, first+i), Size: uint64(1000 + first + i),
			Name: fmt.Sprintf("%s %c%06d.bin", word, who, first+i), Completed: 1,
		}
	}
	return files
}

func connectSharer(t *testing.T, m Engine, who byte) ClientInfo {
	t.Helper()
	info := ClientInfo{ID: 0x0a000000 + uint32(who), Port: 4662, Hash: []byte(fmt.Sprintf("sharer-hash-%04d", who))}
	id, err := m.Connect(info)
	if err != nil {
		t.Fatalf("connect %c: %v", who, err)
	}
	info.StoreID = id
	return info
}

// The record and the source are sized on purpose; a field added without thought
// costs every file on the server. See docs/memory-footprint.md.
func TestMemoryRecordSizes(t *testing.T) {
	rec, src := unsafe.Sizeof(memRec{}), unsafe.Sizeof(memSource{})
	t.Logf("input: memRec{}, memSource{} output: %d and %d bytes (File %d, Source %d)",
		rec, src, unsafe.Sizeof(File{}), unsafe.Sizeof(Source{}))
	if rec != 80 || src != 24 {
		t.Fatalf("memRec is %d bytes and memSource %d, want 80 and 24", rec, src)
	}
}

// A departing session's sources go in several lock acquisitions. Whatever was added
// or asked in between, nothing of the session may be left and every count must be
// what the remaining sessions make it.
func TestMemoryDisconnectInChunksLeavesNothing(t *testing.T) {
	m := NewMemoryEngine()
	big, other := connectSharer(t, m, 'a'), connectSharer(t, m, 'b')
	const bigFiles, shared, otherOwn = 2*disconnectChunk + 500, 300, 40
	own := sharerFiles('a', 0, bigFiles, "big")
	m.AddFiles(own, big)
	// other sources some of big's files too, one of them at a second size, and has
	// files of its own.
	m.AddFiles(own[:shared], other)
	second := own[shared]
	second.Size += 7
	m.AddFile(second, other)
	m.AddFiles(sharerFiles('b', 0, otherOwn, "small"), other)
	t.Logf("input: big offers %d files; other offers %d of them, one more at another size, and %d of its own",
		bigFiles, shared, otherOwn)
	if got := m.OfferedCount(big); got != bigFiles {
		t.Fatalf("setup: big sources %d files, want %d", got, bigFiles)
	}
	if got := m.OfferedCount(other); got != shared+1+otherOwn {
		t.Fatalf("setup: other sources %d files, want %d", got, shared+1+otherOwn)
	}

	m.Disconnect(big)

	left, wrong := 0, 0
	for i, f := range own {
		sources := m.GetSourcesByHash(f.Hash)
		for _, s := range sources {
			if s.ID == big.ID {
				left++
			}
		}
		want := 0
		if i <= shared {
			want = 1
		}
		if len(sources) != want {
			wrong++
		}
	}
	found := m.FindBySearch(&SearchExpr{Kind: SearchText, Text: "big"})
	withSource := 0
	for _, f := range found {
		if f.Sources > 0 {
			withSource++
			if f.Sources != 1 || f.SourceID != other.ID {
				t.Fatalf("%q reports %d source(s), named %#x: want other's one", f.Name, f.Sources, f.SourceID)
			}
		}
	}
	before := m.FilesCount()
	result, err := m.CleanupStale(time.Hour, CleanupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: sources of big left=%d files with a wrong source count=%d clients=%d connected(big)=%t offered(big)=%d offered(other)=%d files=%d, after cleanup removed=%d files=%d",
		left, wrong, m.ClientsCount(), m.IsConnected(big), m.OfferedCount(big), m.OfferedCount(other), before, result.Files, m.FilesCount())
	if left != 0 || wrong != 0 {
		t.Fatalf("%d source(s) of the departed session remain, %d file(s) have a wrong source count", left, wrong)
	}
	if m.ClientsCount() != 1 || m.IsConnected(big) || m.OfferedCount(big) != 0 {
		t.Fatalf("the session is still known: clients=%d connected=%t offered=%d", m.ClientsCount(), m.IsConnected(big), m.OfferedCount(big))
	}
	if got := m.OfferedCount(other); got != shared+1+otherOwn {
		t.Fatalf("other sources %d files after big left, want %d", got, shared+1+otherOwn)
	}
	// own[shared] is held at two sizes and other sources the hash, so both stay.
	if want := bigFiles - shared - 1; result.Files != want || m.FilesCount() != before-want {
		t.Fatalf("cleanup removed %d files leaving %d, want %d removed", result.Files, m.FilesCount(), want)
	}
	// Leaving again, or late, changes nothing.
	m.Disconnect(big)
	m.AddFiles(own[:5], big)
	if n := len(m.GetSourcesByHash(own[0].Hash)); n != 1 {
		t.Fatalf("a released session added a source: %d", n)
	}
}

// While a session with 100,000 files is released, a search must get its answer
// without waiting for the last file: the lock is given up between chunks. The
// observer below proves it by seeing the engine half way — the session gone, its last
// file still sourced — which it can only do while the disconnect is in progress.
func TestMemorySearchReturnsDuringLargeDisconnect(t *testing.T) {
	const files = 100_000
	expr := &SearchExpr{Kind: SearchText, Text: "needle"}
	// An attempt can miss the window if the observer is not scheduled during it;
	// that is the machine, not the engine, so it is tried again.
	for attempt := 1; attempt <= 5; attempt++ {
		m := NewMemoryEngine()
		big, other := connectSharer(t, m, 'a'), connectSharer(t, m, 'b')
		share := sharerFiles('a', 0, files, "bulk")
		m.AddFiles(share, big)
		m.AddFiles(sharerFiles('b', 0, 10, "needle"), other)
		last := share[files-1].Hash

		var midway, searches atomic.Int64
		running, done := make(chan struct{}), make(chan struct{})
		stop := atomic.Bool{}
		go func() {
			defer close(done)
			close(running)
			for !stop.Load() {
				gone := !m.IsConnected(big)
				hits := len(m.FindBySearch(expr))
				if gone && len(m.GetSourcesByHash(last)) == 1 {
					midway.Add(1)
					if hits == 10 {
						searches.Add(1)
					}
				}
			}
		}()
		<-running
		start := time.Now()
		m.Disconnect(big)
		took := time.Since(start)
		stop.Store(true)
		<-done

		t.Logf("input: attempt %d, one session with %d files disconnects while another goroutine searches", attempt, files)
		t.Logf("output: disconnect took %s; observer saw it half done %d time(s), %d search(es) answered in that state; sources left=%d",
			took, midway.Load(), searches.Load(), len(m.GetSourcesByHash(last)))
		if n := len(m.GetSourcesByHash(last)); n != 0 {
			t.Fatalf("the last file still has %d source(s) after the disconnect", n)
		}
		if midway.Load() > 0 {
			if searches.Load() == 0 {
				t.Fatal("a search during the disconnect did not return the other session's files")
			}
			return
		}
	}
	t.Fatal("no search was answered while the session was being released: the lock was held throughout")
}

// A renumbering of the records in the middle of a chunked disconnect leaves the
// departing session's list of ids meaningless; the fallback finds its sources anyway.
func TestMemoryRemoveAllSourcesOf(t *testing.T) {
	m := NewMemoryEngine()
	a, b := connectSharer(t, m, 'a'), connectSharer(t, m, 'b')
	files := sharerFiles('a', 0, 50, "x")
	m.AddFiles(files, a)
	m.AddFiles(files[:20], b)

	m.mu.Lock()
	m.removeAllSourcesOfLocked(a.StoreID)
	m.mu.Unlock()

	left := 0
	for _, f := range files {
		for _, s := range m.GetSourcesByHash(f.Hash) {
			if s.ID == a.ID {
				left++
			}
		}
	}
	t.Logf("input: a offers 50 files, b 20 of them; every source of a removed by scan output: sources of a left=%d, sources of file 0=%d, of file 30=%d",
		left, len(m.GetSourcesByHash(files[0].Hash)), len(m.GetSourcesByHash(files[30].Hash)))
	if left != 0 || len(m.GetSourcesByHash(files[0].Hash)) != 1 || len(m.GetSourcesByHash(files[30].Hash)) != 0 {
		t.Fatal("the scan left a source of the session, or took another session's")
	}
}

// OfferedCount is the distinct files a session sources now, and HasOffered says
// which. A re-offer adds nothing; a disconnect ends it.
func TestMemoryOfferedCount(t *testing.T) {
	m := NewMemoryEngine()
	a, b := connectSharer(t, m, 'a'), connectSharer(t, m, 'b')
	files := sharerFiles('a', 0, 200, "x")
	steps := []struct {
		name  string
		do    func()
		wantA int
		wantB int
	}{
		{"a offers 200 files", func() { m.AddFiles(files, a) }, 200, 0},
		{"a re-offers them 5 times", func() {
			for range 5 {
				m.AddFiles(files, a)
			}
		}, 200, 0},
		{"a re-offers one under a new name, incomplete", func() {
			f := files[3]
			f.Name, f.Completed = "renamed.bin", 0
			m.AddFile(f, a)
		}, 200, 0},
		{"b offers 50 of a's files and 10 of its own", func() {
			m.AddFiles(files[:50], b)
			m.AddFiles(sharerFiles('b', 0, 10, "y"), b)
		}, 200, 60},
		{"a offers one file twice in a packet, both new", func() {
			f := sharerFiles('a', 500, 1, "x")[0]
			m.AddFiles([]File{f, f}, a)
		}, 201, 60},
		{"b disconnects", func() { m.Disconnect(b) }, 201, 0},
	}
	for _, step := range steps {
		step.do()
		gotA, gotB := m.OfferedCount(a), m.OfferedCount(b)
		t.Logf("input: %s output: OfferedCount a=%d b=%d", step.name, gotA, gotB)
		if gotA != step.wantA || gotB != step.wantB {
			t.Fatalf("%s: a=%d b=%d, want %d and %d", step.name, gotA, gotB, step.wantA, step.wantB)
		}
	}
	ask := []File{files[0], sharerFiles('b', 0, 1, "y")[0], files[199], {Hash: sharerHash('z', 1), Size: 1}}
	got := m.HasOffered(a, ask)
	t.Logf("input: HasOffered(a) for its first file, a file of b, its last file, an unknown file output: %v", got)
	if fmt.Sprint(got) != "[true false true false]" {
		t.Fatalf("HasOffered = %v, want [true false true false]", got)
	}
	// Without the StoreID the session is found by its hash, as Disconnect finds it.
	bare := ClientInfo{Hash: a.Hash}
	if n := m.OfferedCount(bare); n != 201 {
		t.Fatalf("OfferedCount by hash = %d, want 201", n)
	}
	if n := m.OfferedCount(ClientInfo{Hash: []byte("nobody-at-all-00")}); n != 0 {
		t.Fatalf("OfferedCount of an unknown session = %d, want 0", n)
	}
}

// Rebuilding the index renumbers the records. Every session's list of what it
// sources is renumbered with them, or its disconnect would clean the wrong files.
func TestMemoryRebuildKeepsSessionsAndSources(t *testing.T) {
	m := NewMemoryEngine()
	gone, a, b := connectSharer(t, m, 'g'), connectSharer(t, m, 'a'), connectSharer(t, m, 'b')
	// Interleaved, so removing gone's files leaves holes everywhere.
	for i := range 300 {
		m.AddFiles(sharerFiles('g', i, 1, "gone"), gone)
		m.AddFiles(sharerFiles('a', i, 1, "keep"), a)
	}
	shared := sharerFiles('a', 0, 100, "keep")
	m.AddFiles(shared, b)
	twoSizes := shared[5]
	twoSizes.Size += 3
	m.AddFile(twoSizes, a)
	m.Disconnect(gone)
	if _, err := m.CleanupStale(time.Hour, CleanupOptions{}); err != nil {
		t.Fatal(err)
	}
	layout := m.layout

	m.mu.Lock()
	m.rebuildIndexLocked()
	m.mu.Unlock()

	t.Logf("input: 300 files of a session that left, 301 records of a (one hash at two sizes), 100 of them also from b; index rebuilt")
	t.Logf("output: layout %d -> %d records=%d files=%d offered a=%d b=%d sources(file 0)=%d sources(two sizes)=%d",
		layout, m.layout, m.recs.len(), m.FilesCount(), m.OfferedCount(a), m.OfferedCount(b),
		len(m.GetSourcesByHash(shared[0].Hash)), len(m.GetSourcesByHash(twoSizes.Hash)))
	if m.recs.len() != 301 || m.FilesCount() != 301 || m.layout == layout {
		t.Fatalf("records=%d files=%d, want 301 dense records in a new layout", m.recs.len(), m.FilesCount())
	}
	if m.OfferedCount(a) != 300 || m.OfferedCount(b) != 100 {
		t.Fatalf("offered a=%d b=%d, want 300 and 100", m.OfferedCount(a), m.OfferedCount(b))
	}
	if got := m.GetSources(twoSizes.Hash, twoSizes.Size); len(got) != 1 || got[0].ID != a.ID {
		t.Fatalf("the second size lost its source across the rebuild: %+v", got)
	}
	if got := m.GetSources(shared[5].Hash, shared[5].Size); len(got) != 1 || got[0].ID != b.ID {
		t.Fatalf("the first size of the two-size hash should now be b's alone: %+v", got)
	}
	checkPostings(t, m)

	m.Disconnect(a)
	left := 0
	for i := range 300 {
		for _, s := range m.GetSourcesByHash(sharerHash('a', i)) {
			if s.ID == a.ID {
				left++
			}
		}
	}
	t.Logf("output: after a disconnects, sources of a left=%d sources(file 0)=%d offered b=%d",
		left, len(m.GetSourcesByHash(shared[0].Hash)), m.OfferedCount(b))
	if left != 0 || len(m.GetSourcesByHash(shared[0].Hash)) != 1 || m.OfferedCount(b) != 100 {
		t.Fatal("a's disconnect after the rebuild left its sources, or took b's")
	}
}

// A session's sources share its user hash and IPv6 address rather than each holding
// a copy, and a caller that never connected still gets its own back.
func TestMemorySourcesShareTheSessionIdentity(t *testing.T) {
	m := NewMemoryEngine()
	v6 := []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	info := ClientInfo{ID: 0x0a000001, Port: 4662, Hash: []byte("identity-hash-01"), IPv6: v6, IPv6Reachable: true, CryptOptions: 3}
	info.StoreID, _ = m.Connect(info)
	files := sharerFiles('a', 0, 2, "x")
	m.AddFiles(files, info)
	loose := ClientInfo{ID: 0x0b000001, Port: 4663, Hash: []byte("never-connected1"), IPv6: v6}
	m.AddFile(files[0], loose)

	one, two := m.GetSourcesByHash(files[0].Hash), m.GetSourcesByHash(files[1].Hash)
	t.Logf("input: a session with IPv6 offers 2 files; a ClientInfo that never connected offers the first")
	t.Logf("output: file 0 sources=%d newest hash=%q, file 1 hash=%q ipv6=%x reachable=%t crypt=%d",
		len(one), one[0].UserHash, two[0].UserHash, two[0].IPv6, two[0].IPv6Reachable, two[0].CryptOptions)
	if len(one) != 2 || string(one[0].UserHash) != "never-connected1" || one[0].IPv6Reachable {
		t.Fatalf("the unconnected caller's source is wrong: %+v", one)
	}
	mine := one[1]
	if string(mine.UserHash) != "identity-hash-01" || string(mine.IPv6) != string(v6) || !mine.IPv6Reachable || mine.CryptOptions != 3 {
		t.Fatalf("the session's source lost its identity: %+v", mine)
	}
	if &mine.UserHash[0] != &two[0].UserHash[0] || &mine.IPv6[0] != &two[0].IPv6[0] {
		t.Fatal("two sources of one session hold separate copies of its hash or address")
	}
}

// With more matches than a search may return, the files with the most sources are
// returned, best first, whenever they were published; and the rest of the answer is
// not simply whoever published first.
func TestMemorySearchRanksBySources(t *testing.T) {
	m := NewMemoryEngine()
	first, second := connectSharer(t, m, 'a'), connectSharer(t, m, 'b')
	// Two large shares, one published entirely before the other, then a few files
	// that three sessions have.
	m.AddFiles(sharerFiles('a', 0, 3000, "common"), first)
	m.AddFiles(sharerFiles('b', 0, 3000, "common"), second)
	popular := sharerFiles('p', 0, 50, "common wanted")
	for _, who := range []byte{'x', 'y', 'z'} {
		m.AddFiles(popular, connectSharer(t, m, who))
	}
	expr := &SearchExpr{Kind: SearchText, Text: "common"}

	got := m.FindBySearch(expr)
	again := m.FindBySearch(expr)
	fromSecond, top := 0, 0
	for i, f := range got {
		if f.Sources == 3 {
			top++
			if i >= len(popular) {
				t.Fatalf("a file with 3 sources is at position %d, behind files with 1", i)
			}
		}
		if f.Hash[0] == 'b' {
			fromSecond++
		}
		if i > 0 && got[i-1].Sources < f.Sources {
			t.Fatalf("result %d has more sources than the one before it", i)
		}
	}
	same := len(got) == len(again)
	for i := 0; same && i < len(got); i++ {
		same = string(got[i].Hash) == string(again[i].Hash)
	}
	other := m.FindBySearch(&SearchExpr{Kind: SearchText, Text: "bin"})
	differs := false
	for i := len(popular); i < len(got) && i < len(other); i++ {
		if string(got[i].Hash) != string(other[i].Hash) {
			differs = true
			break
		}
	}
	t.Logf("input: 3000 one-source files of one session, then 3000 of another, then 50 files with 3 sources; search %q", expr.Text)
	t.Logf("output: results=%d with 3 sources=%d from the later share=%d same order on a second run=%t another query picks other ties=%t",
		len(got), top, fromSecond, same, differs)
	if len(got) != MaxSearchResults {
		t.Fatalf("got %d results, want the cap of %d", len(got), MaxSearchResults)
	}
	if top != len(popular) {
		t.Fatalf("%d of the %d best-sourced files were returned", top, len(popular))
	}
	if fromSecond < 300 {
		t.Fatalf("only %d results come from the share published second: the first publisher fills the answer", fromSecond)
	}
	if !same {
		t.Fatal("the same search gave two different answers")
	}
	if !differs {
		t.Fatal("a different query broke the ties the same way")
	}
}

// A search with no more matches than the cap is not ranked: it returns them all, in
// the order they were published, as it always did.
func TestMemorySearchUnderCapKeepsPublicationOrder(t *testing.T) {
	m := NewMemoryEngine()
	a := connectSharer(t, m, 'a')
	files := sharerFiles('a', 0, MaxSearchResults, "exact")
	m.AddFiles(files, a)
	m.AddFiles(files[900:], connectSharer(t, m, 'b')) // the last hundred have two sources

	got := m.FindBySearch(&SearchExpr{Kind: SearchText, Text: "exact"})
	ordered := len(got) == len(files)
	for i := 0; ordered && i < len(got); i++ {
		ordered = string(got[i].Hash) == string(files[i].Hash)
	}
	t.Logf("input: %d matching files, the last 100 with two sources output: results=%d in publication order=%t",
		len(files), len(got), ordered)
	if !ordered {
		t.Fatal("an answer that fits the cap was reordered or cut")
	}
}

// The ranking looks at searchRankScan matches and no further.
func TestMemorySearchRankScanIsBounded(t *testing.T) {
	m := NewMemoryEngine()
	a := connectSharer(t, m, 'a')
	m.AddFiles(sharerFiles('a', 0, searchRankScan+500, "wide"), a)
	// Past the bound, with more sources than anything before it.
	late := sharerFiles('l', 0, 1, "wide")
	m.AddFiles(late, a)
	m.AddFiles(late, connectSharer(t, m, 'b'))

	got := m.FindBySearch(&SearchExpr{Kind: SearchText, Text: "wide"})
	seen := false
	for _, f := range got {
		seen = seen || f.Hash[0] == 'l'
	}
	t.Logf("input: %d one-source matches, then one two-source match output: results=%d late file returned=%t",
		searchRankScan+500, len(got), seen)
	if len(got) != MaxSearchResults || seen {
		t.Fatalf("results=%d late=%t: the search read past its scan bound", len(got), seen)
	}
}
