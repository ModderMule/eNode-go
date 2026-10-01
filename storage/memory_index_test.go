package storage

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// indexWords is the name vocabulary of the random tests: substrings of one another,
// mixed case, non-ASCII (İ lowercases to two runes), and short words the trigram
// lookup cannot use.
var indexWords = []string{
	"cabinet", "bin", "Cabin", "binary", "robin", "Straße", "STRASSE", "İstanbul", "istanbul",
	"Ägypten", "x264", "x265", "mp3", "MP4", "a", "ab", "abc", "e", "m", "2024", "1080p", "720p",
	"the", "then", "other", "theme", "日本語", "本語",
}

var indexSeparators = []string{" ", ".", "-", "_", " - ", "(", ")", "  "}

// indexTerms are the query terms: words, pieces of words, terms with punctuation
// inside, and 1–2 character terms.
var indexTerms = []string{
	"bin", "abin", "cab", "CAB", "binet", "robin", "straße", "strasse", "İstanbul", "istanbul",
	"stan", "gypt", "x26", "x264", "mp", "mp3", "p4", "a", "ab", "e.m", "m.x", "e m", "1080p",
	"080", "20", "the", "hem", "ther", "日本", "本語", "zzz", ".", "-", "bin.mp3", "cabinet-2024",
}

// TestMemoryIndexMatchesScan is the index's contract: whatever files are stored,
// renamed or removed, FindBySearch returns what a full MatchSearchExpr scan returns.
func TestMemoryIndexMatchesScan(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	m := NewMemoryEngine()
	const users = 40
	clients := make([]ClientInfo, users)
	for u := range clients {
		ci := ClientInfo{ID: uint32(1000 + u), Port: 4662, Hash: userHash(u)}
		ci.StoreID, _ = m.Connect(ci)
		clients[u] = ci
	}
	queries := 0
	check := func(phase string, n int) {
		for range n {
			expr := randomExpr(rng, 3)
			checkAgainstScan(t, m, expr)
			queries++
		}
		checkPostings(t, m)
		t.Logf("phase %s: files=%d recs=%d free=%d words=%d entries=%d stale=%d, %d queries agree",
			phase, m.FilesCount(), m.recs.len(), len(m.free), len(m.names.words), m.names.entries, m.names.entries-m.names.live, n)
	}

	publish := func(from, to int) {
		for i := from; i < to; i++ {
			m.AddFile(File{Hash: fileHash(i), Size: uint64(i), Name: randomName(rng), Completed: 1},
				clients[rng.IntN(users)])
		}
	}
	publish(0, 5000)
	check("publish", 700)

	// Re-offers under other names, some flipping back to a name the file had before.
	for range 3000 {
		i := rng.IntN(5000)
		m.AddFile(File{Hash: fileHash(i), Size: uint64(i), Name: randomName(rng)}, clients[rng.IntN(users)])
	}
	check("rename", 700)

	// Half the users leave; files nobody serves are reaped and their ids freed.
	for u := 0; u < users/2; u++ {
		m.Disconnect(clients[u])
	}
	res, err := m.CleanupStale(time.Hour, CleanupOptions{})
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	t.Logf("cleanup removed %d files", res.Files)
	check("cleanup", 300)

	// New files take the freed ids, so their postings go in out of order.
	for u := 0; u < users/2; u++ {
		clients[u].StoreID, _ = m.Connect(clients[u])
	}
	publish(5000, 8000)
	check("reuse", 300)

	// A second round without renames, so the ids are purged and reused rather than
	// renumbered by a rebuild.
	for u := users / 2; u < users*3/4; u++ {
		m.Disconnect(clients[u])
	}
	if _, err := m.CleanupStale(time.Hour, CleanupOptions{}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	check("purge", 300)
	for u := users / 2; u < users*3/4; u++ {
		clients[u].StoreID, _ = m.Connect(clients[u])
	}
	publish(8000, 9000)
	check("reuse-purged", 300)
	t.Logf("output: %d random queries matched the full scan", queries)
}

func TestMemoryIndexSubstringInsideWord(t *testing.T) {
	m := NewMemoryEngine()
	c := connectOne(m)
	m.AddFile(File{Hash: fileHash(1), Size: 1, Name: "Old Oak Cabinet.jpg"}, c)
	m.AddFile(File{Hash: fileHash(2), Size: 2, Name: "robin_hood.e.mp4"}, c)
	for _, tc := range []struct {
		term string
		want int
	}{
		{"bin", 2}, {"CABINET", 1}, {"e.m", 1},
		// A separator inside a query word matches any separator, so "d.e" is the runs
		// "d" and "e": both names have them ("Old … Cabinet", "robin_hood.e").
		{"d.e", 2},
		{"oak cab", 1}, {"oak cab zzz", 0}, {"in", 2},
	} {
		got := m.FindBySearch(&SearchExpr{Kind: SearchText, Text: tc.term})
		t.Logf("input: %q output: %d file(s)", tc.term, len(got))
		if len(got) != tc.want {
			t.Errorf("%q: got %d files, want %d", tc.term, len(got), tc.want)
		}
	}
}

// TestMemoryIndexRenameFlipFlop re-offers one file under two alternating names, as
// clients naming the same file differently do; each word is listed once.
func TestMemoryIndexRenameFlipFlop(t *testing.T) {
	m := NewMemoryEngine()
	c := connectOne(m)
	for i := range 50 {
		name := "movie.one.avi"
		if i%2 == 1 {
			name = "film.two.avi"
		}
		m.AddFile(File{Hash: fileHash(1), Size: 1, Name: name}, c)
	}
	checkPostings(t, m)
	one := m.FindBySearch(&SearchExpr{Kind: SearchText, Text: "movie"})
	two := m.FindBySearch(&SearchExpr{Kind: SearchText, Text: "film"})
	t.Logf("input: 50 alternating offers, last film.two.avi output: movie=%d film=%d entries=%d stale=%d",
		len(one), len(two), m.names.entries, m.names.entries-m.names.live)
	if len(one) != 0 || len(two) != 1 {
		t.Fatalf("got movie=%d film=%d, want 0 and 1", len(one), len(two))
	}
	if m.names.entries != 5 || m.names.live != 3 {
		t.Fatalf("entries=%d live=%d, want 5 (avi film movie one two) and 3", m.names.entries, m.names.live)
	}
}

// TestMemoryIndexReusedID removes a file, lets a new one take its id, and checks the
// new file does not inherit the old one's words.
func TestMemoryIndexReusedID(t *testing.T) {
	m := NewMemoryEngine()
	a, b := connectOne(m), ClientInfo{ID: 2, Port: 2, Hash: userHash(2)}
	b.StoreID, _ = m.Connect(b)
	m.AddFile(File{Hash: fileHash(1), Size: 1, Name: "gone forever.mkv"}, a)
	m.AddFile(File{Hash: fileHash(2), Size: 2, Name: "stays.mkv"}, b)
	m.Disconnect(a)

	// Before the sweep the dead id is still listed; it must not be returned.
	m.mu.Lock()
	*m.recs.at(0) = File{}
	m.dead = append(m.dead, 0)
	delete(m.files, fileMapKey(fileHash(1), 1))
	m.mu.Unlock()
	if got := m.FindBySearch(&SearchExpr{Kind: SearchText, Text: "gone"}); len(got) != 0 {
		t.Fatalf("a removed file was returned: %+v", got)
	}
	if _, err := m.CleanupStale(time.Hour, CleanupOptions{}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	m.AddFile(File{Hash: fileHash(3), Size: 3, Name: "brand new.mkv"}, b)
	gone := m.FindBySearch(&SearchExpr{Kind: SearchText, Text: "gone"})
	fresh := m.FindBySearch(&SearchExpr{Kind: SearchText, Text: "brand"})
	t.Logf("input: file 1 removed, file 3 added output: recs=%d gone=%d brand=%d", m.recs.len(), len(gone), len(fresh))
	if m.recs.len() != 2 {
		t.Fatalf("the freed id was not reused: %d records", m.recs.len())
	}
	if len(gone) != 0 || len(fresh) != 1 {
		t.Fatalf("got gone=%d brand=%d, want 0 and 1", len(gone), len(fresh))
	}
	checkPostings(t, m)
}

func TestMemoryIndexAfterSnapshotLoad(t *testing.T) {
	src := NewMemoryEngine()
	c := connectOne(src)
	for i := range 20 {
		src.AddFile(File{Hash: fileHash(i), Size: uint64(i), Name: fmt.Sprintf("Cabinet %d.jpg", i)}, c)
	}
	path := filepath.Join(t.TempDir(), "storage.gob")
	if _, err := src.WriteSnapshot(path, false); err != nil {
		t.Fatalf("write: %v", err)
	}
	dst := NewMemoryEngine()
	if _, err := dst.LoadSnapshot(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	got := dst.FindBySearch(&SearchExpr{Kind: SearchText, Text: "abin"})
	one := dst.FindBySearch(&SearchExpr{Kind: SearchText, Text: "cabinet 17"})
	t.Logf("input: 20 files through a snapshot output: abin=%d \"cabinet 17\"=%d", len(got), len(one))
	if len(got) != 20 || len(one) != 1 {
		t.Fatalf("got %d and %d, want 20 and 1", len(got), len(one))
	}
	checkPostings(t, dst)
}

// checkAgainstScan compares FindBySearch with a full scan of the same records.
func checkAgainstScan(t *testing.T, m *MemoryEngine, expr *SearchExpr) {
	t.Helper()
	var want []string
	for _, f := range m.FindByNameContains("") {
		if MatchSearchExpr(expr, f) {
			want = append(want, fileMapKey(f.Hash, f.Size))
		}
	}
	got := m.FindBySearch(expr)
	keys := make([]string, 0, len(got))
	for _, f := range got {
		if !MatchSearchExpr(expr, f) {
			t.Fatalf("%s: returned %q, which does not match", indexExprString(expr), f.Name)
		}
		keys = append(keys, fileMapKey(f.Hash, f.Size))
	}
	if len(want) > MaxSearchResults {
		if len(keys) != MaxSearchResults {
			t.Fatalf("%s: %d results, want the cap of %d", indexExprString(expr), len(keys), MaxSearchResults)
		}
		return
	}
	sort.Strings(want)
	sort.Strings(keys)
	if !slices.Equal(want, keys) {
		t.Fatalf("%s: index returned %d files, scan %d", indexExprString(expr), len(keys), len(want))
	}
}

// checkPostings asserts each posting list and its tail are sorted, duplicate-free
// and disjoint, and that entries counts them.
func checkPostings(t *testing.T, m *MemoryEngine) {
	t.Helper()
	m.mu.RLock()
	defer m.mu.RUnlock()
	total := 0
	for wid, ids := range m.names.post {
		all := append(slices.Clone(ids), m.names.tails[uint32(wid)]...)
		total += len(all)
		for i := 1; i < len(ids); i++ {
			if ids[i-1] >= ids[i] {
				t.Fatalf("word %q: posting not strictly ascending", m.names.words[wid])
			}
		}
		slices.Sort(all)
		if hasDup(all) {
			t.Fatalf("word %q: an id is listed twice", m.names.words[wid])
		}
	}
	if total != m.names.entries {
		t.Fatalf("entries = %d, lists hold %d", m.names.entries, total)
	}
}

func hasDup(sorted []uint32) bool {
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return true
		}
	}
	return false
}

func randomName(rng *rand.Rand) string {
	var b strings.Builder
	for i := range 1 + rng.IntN(5) {
		if i > 0 {
			b.WriteString(indexSeparators[rng.IntN(len(indexSeparators))])
		}
		b.WriteString(indexWords[rng.IntN(len(indexWords))])
	}
	b.WriteString([]string{".avi", ".mp3", ".mkv", ""}[rng.IntN(4)])
	return b.String()
}

func randomExpr(rng *rand.Rand, depth int) *SearchExpr {
	if depth == 0 || rng.IntN(3) == 0 {
		switch rng.IntN(8) {
		case 0:
			return &SearchExpr{Kind: SearchUInt64, TagType: uint32(SearchTagSize)<<24 | 1<<8 | uint32(SearchOpGreater),
				ValueUint: uint64(rng.IntN(8000))}
		case 1:
			return &SearchExpr{Kind: SearchString, TagType: searchTypeExt, ValueString: "mp3"}
		case 2:
			return &SearchExpr{Kind: SearchString, TagType: 0xee0001, ValueString: "x"} // unsupported: pruned
		case 3:
			return &SearchExpr{Kind: SearchText, Text: "  "}
		case 4:
			return &SearchExpr{Kind: SearchString, TagType: searchTypeText, ValueString: randomTerm(rng)}
		default:
			text := randomTerm(rng)
			if rng.IntN(3) == 0 {
				text += " " + randomTerm(rng)
			}
			return &SearchExpr{Kind: SearchText, Text: text}
		}
	}
	kind := []SearchKind{SearchAnd, SearchOr, SearchAndNot}[rng.IntN(3)]
	return &SearchExpr{Kind: kind, Left: randomExpr(rng, depth-1), Right: randomExpr(rng, depth-1)}
}

func randomTerm(rng *rand.Rand) string { return indexTerms[rng.IntN(len(indexTerms))] }

func indexExprString(e *SearchExpr) string {
	if e == nil {
		return "nil"
	}
	switch e.Kind {
	case SearchText:
		return fmt.Sprintf("%q", e.Text)
	case SearchAnd, SearchOr, SearchAndNot:
		op := map[SearchKind]string{SearchAnd: "AND", SearchOr: "OR", SearchAndNot: "ANDNOT"}[e.Kind]
		return "(" + indexExprString(e.Left) + " " + op + " " + indexExprString(e.Right) + ")"
	default:
		return fmt.Sprintf("{kind %d tag %#x %q %d}", e.Kind, e.TagType, e.ValueString, e.ValueUint)
	}
}

func connectOne(m *MemoryEngine) ClientInfo {
	c := ClientInfo{ID: 1, Port: 1, Hash: userHash(1)}
	c.StoreID, _ = m.Connect(c)
	return c
}

func fileHash(i int) []byte {
	h := make([]byte, hashLen)
	binary.BigEndian.PutUint64(h, uint64(i)+1)
	return h
}

func userHash(u int) []byte {
	h := make([]byte, hashLen)
	binary.BigEndian.PutUint64(h[8:], uint64(u)+1)
	return h
}

// TestNameWordsMatchesAlnumRuns pins nameWords to the query side's splitter: a name
// word and a query run must come from the same rule, or the index misses files.
func TestNameWordsMatchesAlnumRuns(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	names := []string{"", "...", "İstanbul-2024", "a\xffb", "日本語 本語", "Straße_x264.MKV", "e.m"}
	for range 500 {
		names = append(names, randomName(rng))
	}
	for _, name := range names {
		want := alnumRuns(strings.ToLower(name))
		slices.Sort(want)
		want = slices.Compact(want)
		got := nameWords(name)
		if !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Fatalf("input: %q output: %q, alnumRuns gives %q", name, got, want)
		}
	}
	t.Logf("input: %d names output: nameWords agrees with alnumRuns on all", len(names))
}
