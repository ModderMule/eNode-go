package storage

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
)

const testHashHex = "D5CD3DE9DD2558D8268D4AD0FB41C23D"

func testHash(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(testHashHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseHashTerm(t *testing.T) {
	want := testHash(t)
	lower := strings.ToLower(testHashHex)
	cases := []struct {
		term string
		ok   bool
		size uint64
	}{
		{"ed2k::" + testHashHex, true, 0},
		{"ed2k::" + lower, true, 0},
		{"ED2K::" + testHashHex, true, 0},
		{"  ed2k::" + testHashHex + "  ", true, 0},
		{"ed2k::" + testHashHex + " trailing words", true, 0},
		{"ed2k:378234567:" + testHashHex, true, 378234567},
		{"ed2k:0:" + testHashHex, true, 0},
		{"ed2k://|file|Some%20Movie.avi|378234567|" + testHashHex + "|/", true, 378234567},
		{"ed2k://|file|name.avi|378234567|" + testHashHex + "|h=ABC|/", true, 378234567},
		{"<a href= ed2k://|file|name.avi|42|" + testHashHex + "|/", true, 42},
		{"magnet:?xt=ed2k:" + testHashHex, true, 0},
		{"magnet:?xt=urn:ed2k:" + testHashHex, true, 0},
		{"magnet:?xt=urn:ed2khash:" + testHashHex + "&dn=x", true, 0},
		// Not hash terms: they stay keywords.
		{"ed2k", false, 0},
		{"ed2k::" + testHashHex[:31], false, 0},
		{"ed2k::" + testHashHex[:30] + "zz", false, 0},
		{"ed2k:12" + testHashHex, false, 0},
		{"ed2k://|file|name.avi|" + testHashHex, false, 0},
		{"magnet:?xt=urn:btih:" + testHashHex, false, 0},
		{testHashHex, false, 0},
		{"some movie", false, 0},
	}
	for _, c := range cases {
		hash, size, ok := ParseHashTerm(c.term)
		t.Logf("input: %q -> output: hash=%x size=%d ok=%v", c.term, hash, size, ok)
		if ok != c.ok {
			t.Fatalf("ParseHashTerm(%q) ok=%v, want %v", c.term, ok, c.ok)
		}
		if !ok {
			continue
		}
		if !bytes.Equal(hash, want) || size != c.size {
			t.Fatalf("ParseHashTerm(%q) = %x/%d, want %x/%d", c.term, hash, size, want, c.size)
		}
	}
}

func TestParseRelatedTerm(t *testing.T) {
	h := testHashHex
	h2 := strings.Repeat("ab", 16)
	many := "related::" + h + strings.Repeat("::"+h, MaxRelatedSeeds+5)
	cases := []struct {
		term  string
		ok    bool
		seeds int
		size0 uint64
	}{
		{"related::" + h, true, 1, 0},
		{"related::" + h + "::" + h2, true, 2, 0},
		{"related:123:" + h, true, 1, 123},
		{"related:123:" + h + ":456:" + h2, true, 2, 123},
		{"RELATED::" + h, true, 1, 0},
		{"related::" + h + "::zz", true, 1, 0},
		{many, true, MaxRelatedSeeds, 0},
		{"related", false, 0, 0},
		{"related::", false, 0, 0},
		{"related::nothex", false, 0, 0},
		{"related files", false, 0, 0},
		{"ed2k::" + h, false, 0, 0},
	}
	for _, c := range cases {
		seeds, ok := ParseRelatedTerm(c.term)
		t.Logf("input: %.80q -> output: seeds=%d ok=%v", c.term, len(seeds), ok)
		if ok != c.ok || len(seeds) != c.seeds {
			t.Fatalf("ParseRelatedTerm(%q) = %d seed(s) ok=%v, want %d ok=%v", c.term, len(seeds), ok, c.seeds, c.ok)
		}
		if ok && seeds[0].Size != c.size0 {
			t.Fatalf("ParseRelatedTerm(%q) first size %d, want %d", c.term, seeds[0].Size, c.size0)
		}
	}
}

// sizeAtLeast is the numeric leaf eMule sends for a minimum size filter.
func sizeAtLeast(v uint64) *SearchExpr {
	return &SearchExpr{Kind: SearchUInt64, TagType: uint32(SearchOpGreaterEqual) | 1<<8 | uint32(SearchTagSize)<<24, ValueUint: v}
}

func hashLeaf(hash []byte, size uint64) *SearchExpr {
	return &SearchExpr{Kind: SearchHash, ValueString: string(hash), ValueUint: size}
}

func TestMatchSearchExprHash(t *testing.T) {
	h := testHash(t)
	other := bytes.Repeat([]byte{1}, 16)
	file := File{Hash: h, Name: "Some Movie.avi", Size: 1000}
	cases := []struct {
		name string
		expr *SearchExpr
		want bool
	}{
		{"hash", hashLeaf(h, 0), true},
		{"hash and size", hashLeaf(h, 1000), true},
		{"hash, other size", hashLeaf(h, 999), false},
		{"other hash", hashLeaf(other, 0), false},
		{"hash AND size>=500", &SearchExpr{Kind: SearchAnd, Left: hashLeaf(h, 0), Right: sizeAtLeast(500)}, true},
		{"hash AND size>=5000", &SearchExpr{Kind: SearchAnd, Left: hashLeaf(h, 0), Right: sizeAtLeast(5000)}, false},
		{"other hash OR movie", &SearchExpr{Kind: SearchOr, Left: hashLeaf(other, 0), Right: &SearchExpr{Kind: SearchText, Text: "movie"}}, true},
		{"movie ANDNOT hash", &SearchExpr{Kind: SearchAndNot, Left: &SearchExpr{Kind: SearchText, Text: "movie"}, Right: hashLeaf(h, 0)}, false},
	}
	for _, c := range cases {
		got := MatchSearchExpr(c.expr, file)
		t.Logf("input: %s -> output: %v", c.name, got)
		if got != c.want {
			t.Fatalf("%s: matched %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBuildSearchWhereHash(t *testing.T) {
	h := testHash(t)
	for _, dialect := range []string{DialectMariaDB, DialectMySQL} {
		where, args := BuildSearchWhere(hashLeaf(h, 0), dialect)
		t.Logf("input: hash leaf dialect=%s -> output: %s %x", dialect, where, args)
		if where != "(f.hash = ?)" || len(args) != 1 || !bytes.Equal(args[0].([]byte), h) {
			t.Fatalf("dialect %s: where %q args %v", dialect, where, args)
		}
		where, args = BuildSearchWhere(hashLeaf(h, 42), dialect)
		t.Logf("input: hash+size leaf dialect=%s -> output: %s %v", dialect, where, args)
		if where != "(f.hash = ? AND f.size = ?)" || len(args) != 2 || args[1] != uint64(42) {
			t.Fatalf("dialect %s: where %q args %v", dialect, where, args)
		}
	}
	// A hash narrows like an indexed keyword: never dropped as a scan, even
	// with a short keyword beside it.
	expr := &SearchExpr{Kind: SearchAnd, Left: hashLeaf(h, 0), Right: &SearchExpr{Kind: SearchText, Text: "x"}}
	scan := SearchNeedsScan(expr, 3)
	t.Logf("input: hash AND x -> output: needsScan=%v", scan)
	if scan || SearchNeedsScan(hashLeaf(h, 0), 3) {
		t.Fatal("a hash search must not count as a scan")
	}
}

func TestRelatedLeafIsPrunedByEngines(t *testing.T) {
	rel := &SearchExpr{Kind: SearchRelated, Related: []FileKey{{Hash: testHash(t)}}}
	where, _ := BuildSearchWhere(rel, DialectMariaDB)
	file := File{Hash: testHash(t), Name: "a.avi", Size: 10}
	t.Logf("input: related leaf -> output: where=%q match=%v", where, MatchSearchExpr(rel, file))
	if where != "" || MatchSearchExpr(rel, file) {
		t.Fatal("a related leaf on its own must match nothing in FindBySearch")
	}
	seeds, ok := FindRelated(&SearchExpr{Kind: SearchAnd, Left: rel, Right: sizeAtLeast(5)})
	t.Logf("input: related AND size>=5 -> output: seeds=%d ok=%v", len(seeds), ok)
	if !ok || len(seeds) != 1 {
		t.Fatal("the related leaf on the AND path was not found")
	}
	if _, ok := FindRelated(&SearchExpr{Kind: SearchOr, Left: rel, Right: sizeAtLeast(5)}); ok {
		t.Fatal("a related leaf under OR is not a related search")
	}
	if !MatchRelatedFilter(rel, file) {
		t.Fatal("a related leaf alone must let every related file through")
	}
	and := &SearchExpr{Kind: SearchAnd, Left: rel, Right: sizeAtLeast(50)}
	if MatchRelatedFilter(and, file) {
		t.Fatal("the size filter AND-ed with the related leaf was not applied")
	}
	if got := NewMemoryEngine().FindBySearch(rel); len(got) != 0 {
		t.Fatalf("memory FindBySearch answered a related leaf with %d file(s)", len(got))
	}
}

// hashSearchScenario is the hash search contract for any engine: a hash leaf finds
// the files with that hash, at one size or all, and combines with the other leaves.
func hashSearchScenario(t *testing.T, engine Engine) {
	t.Helper()
	a := ClientInfo{ID: 0x0a000003, IPv4: 0x0300000a, Port: 4662, Hash: []byte("hash-search-a-01")}
	b := ClientInfo{ID: 0x0b000003, IPv4: 0x0300000b, Port: 4663, Hash: []byte("hash-search-b-01")}
	c := ClientInfo{ID: 0x0c000003, IPv4: 0x0300000c, Port: 4664, Hash: []byte("hash-search-c-01")}
	for _, c := range []*ClientInfo{&a, &b, &c} {
		id, err := engine.Connect(*c)
		if err != nil {
			t.Fatal(err)
		}
		c.StoreID = id
	}
	hx := testHash(t)
	hy := []byte("hash-search-y-01")
	engine.AddFile(File{Hash: hx, Name: "hashsmall.avi", Size: 10, Type: "Video"}, a)
	engine.AddFile(File{Hash: hx, Name: "hashsmall.avi", Size: 10, Type: "Video"}, b)
	// A client sources a hash at one size; another one offers it at a second size.
	engine.AddFile(File{Hash: hx, Name: "hashlarge.avi", Size: 20, Type: "Video"}, c)
	engine.AddFile(File{Hash: hy, Name: "keyword.avi", Size: 30, Type: "Video"}, b)

	list := func(files []File) []string {
		out := make([]string, 0, len(files))
		for _, f := range files {
			out = append(out, fmt.Sprintf("%s/%d", f.Name, f.Size))
		}
		slices.Sort(out)
		return out
	}
	cases := []struct {
		name string
		expr *SearchExpr
		want []string
	}{
		{"ed2k::hx", hashLeaf(hx, 0), []string{"hashlarge.avi/20", "hashsmall.avi/10"}},
		{"ed2k:20:hx", hashLeaf(hx, 20), []string{"hashlarge.avi/20"}},
		{"hx AND size>=15", &SearchExpr{Kind: SearchAnd, Left: hashLeaf(hx, 0), Right: sizeAtLeast(15)}, []string{"hashlarge.avi/20"}},
		{"ed2k:10:hx OR keyword", &SearchExpr{Kind: SearchOr, Left: hashLeaf(hx, 10), Right: &SearchExpr{Kind: SearchText, Text: "keyword"}},
			[]string{"hashsmall.avi/10", "keyword.avi/30"}},
		{"unknown hash", hashLeaf(bytes.Repeat([]byte{7}, 16), 0), []string{}},
	}
	for _, c := range cases {
		files := engine.FindBySearch(c.expr)
		got := list(files)
		t.Logf("input: %s -> output: %v", c.name, got)
		if !slices.Equal(got, c.want) {
			t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
		}
		for _, f := range files {
			if f.Name == "hashsmall.avi" && f.Sources != 2 {
				t.Fatalf("%s: hashsmall.avi has %d source(s), want 2", c.name, f.Sources)
			}
		}
	}
}

func TestMemoryHashSearch(t *testing.T) {
	hashSearchScenario(t, NewMemoryEngine())
}

func TestMySQLHashSearch(t *testing.T) {
	requireIntegration(t)
	engine, _ := startMySQL(t, "enode")
	hashSearchScenario(t, engine)
}

func TestMariaDBHashSearch(t *testing.T) {
	requireIntegration(t)
	hashSearchScenario(t, startMariaDB(t, "enode"))
}

func TestMongoHashSearch(t *testing.T) {
	requireIntegration(t)
	hashSearchScenario(t, startMongoEngine(t, "enode_hash_search"))
}

func TestManticoreHashSearch(t *testing.T) {
	requireIntegration(t)
	hashSearchScenario(t, wrapManticore(t, startMariaDB(t, "enode"), startManticore(t)))
}

func TestMirrorHashSearch(t *testing.T) {
	m := NewMirror(100)
	hx := testHash(t)
	m.Put(1, 1, []File{
		{Hash: hx, Name: "mirrorsmall.avi", Size: 10, Sources: 3},
		{Hash: hx, Name: "mirrorlarge.avi", Size: 20, Sources: 1},
		{Hash: []byte("mirror-other-001"), Name: "other.avi", Size: 30, Sources: 1},
	})
	names := func(files []File) []string {
		out := []string{}
		for _, f := range files {
			out = append(out, f.Name)
		}
		slices.Sort(out)
		return out
	}
	got := names(m.Search(hashLeaf(hx, 0), 10))
	t.Logf("input: ed2k::hx over a mirror -> output: %v", got)
	if !slices.Equal(got, []string{"mirrorlarge.avi", "mirrorsmall.avi"}) {
		t.Fatalf("mirror hash search %v", got)
	}
	got = names(m.Search(hashLeaf(hx, 20), 10))
	t.Logf("input: ed2k:20:hx -> output: %v", got)
	if !slices.Equal(got, []string{"mirrorlarge.avi"}) {
		t.Fatalf("mirror hash+size search %v", got)
	}
	// The origin's next walk no longer lists the large one: it leaves the hash index too.
	m.Put(1, 2, []File{{Hash: hx, Name: "mirrorsmall.avi", Size: 10, Sources: 3}})
	m.Sweep(1, 2)
	got = names(m.Search(hashLeaf(hx, 0), 10))
	t.Logf("input: after a sweep dropped mirrorlarge.avi -> output: %v", got)
	if !slices.Equal(got, []string{"mirrorsmall.avi"}) {
		t.Fatalf("after the sweep the mirror hash search is %v", got)
	}
	m.Drop(1)
	if got := m.Search(hashLeaf(hx, 0), 10); len(got) != 0 || len(m.byHash) != 0 {
		t.Fatalf("after Drop: %d result(s), %d hash entr(ies)", len(got), len(m.byHash))
	}
}
