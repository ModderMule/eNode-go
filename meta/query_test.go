package meta

import (
	"reflect"
	"testing"

	"enode/storage"
)

func text(s string) *storage.SearchExpr {
	return &storage.SearchExpr{Kind: storage.SearchText, Text: s}
}

func node(kind storage.SearchKind, left, right *storage.SearchExpr) *storage.SearchExpr {
	return &storage.SearchExpr{Kind: kind, Left: left, Right: right}
}

func tagString(tag uint32, v string) *storage.SearchExpr {
	return &storage.SearchExpr{Kind: storage.SearchString, TagType: tag, ValueString: v}
}

func tagUint(tag uint32, v uint64) *storage.SearchExpr {
	return &storage.SearchExpr{Kind: storage.SearchUInt64, TagType: tag, ValueUint: v}
}

func TestBuildQuery(t *testing.T) {
	cases := []struct {
		name string
		expr *storage.SearchExpr
		want Query
		ok   bool
	}{
		{"single keyword", text("ubuntu"), Query{Terms: []string{"ubuntu"}}, true},
		{"multi-word leaf", text("ubuntu  24.04 iso"), Query{Terms: []string{"ubuntu", "24.04", "iso"}}, true},
		{"and of leaves", node(storage.SearchAnd, text("ubuntu"), tagString(storage.SearchTermTag, "desktop")),
			Query{Terms: []string{"ubuntu", "desktop"}}, true},
		{"duplicates folded", node(storage.SearchAnd, text("Ubuntu"), text("ubuntu")), Query{Terms: []string{"Ubuntu"}}, true},
		{"type and size bounds", node(storage.SearchAnd, text("movie"),
			node(storage.SearchAnd, tagString(storage.SearchFileTypeTag, "Video"),
				node(storage.SearchAnd, tagUint(storage.SearchSizeGtTag, 100), tagUint(storage.SearchSizeLtTag, 1000)))),
			Query{Terms: []string{"movie"}, FileType: "Video", MinSize: 101, MaxSize: 999}, true},
		// eMule's search window sends >= and <= (ops 3 and 4), which map onto the
		// daemon's inclusive bounds unshifted.
		{"inclusive size bounds", node(storage.SearchAnd, text("movie"),
			node(storage.SearchAnd, tagUint(sizeLeaf(storage.SearchOpGreaterEqual), 100), tagUint(sizeLeaf(storage.SearchOpLessEqual), 1000))),
			Query{Terms: []string{"movie"}, MinSize: 100, MaxSize: 1000}, true},
		{"exact size", node(storage.SearchAnd, text("movie"), tagUint(sizeLeaf(storage.SearchOpEqual), 500)),
			Query{Terms: []string{"movie"}, MinSize: 500, MaxSize: 500}, true},
		{"not-equal size left to post-filter", node(storage.SearchAnd, text("movie"), tagUint(sizeLeaf(storage.SearchOpNotEqual), 500)),
			Query{Terms: []string{"movie"}}, true},
		{"not single word excluded", node(storage.SearchAndNot, text("linux"), text("beta")),
			Query{Terms: []string{"linux"}, Exclude: []string{"beta"}}, true},
		{"not of or excluded", node(storage.SearchAndNot, text("linux"), node(storage.SearchOr, text("beta"), text("rc"))),
			Query{Terms: []string{"linux"}, Exclude: []string{"beta", "rc"}}, true},
		{"not of and left to post-filter", node(storage.SearchAndNot, text("linux"), node(storage.SearchAnd, text("beta"), text("rc"))),
			Query{Terms: []string{"linux"}}, true},
		{"not of phrase left to post-filter", node(storage.SearchAndNot, text("linux"), text("release candidate")),
			Query{Terms: []string{"linux"}}, true},
		{"or branch dropped", node(storage.SearchAnd, text("linux"), node(storage.SearchOr, text("iso"), text("img"))),
			Query{Terms: []string{"linux"}}, true},
		{"or at root forwards nothing", node(storage.SearchOr, text("a"), text("b")), Query{}, false},
		{"type only forwards nothing", tagString(storage.SearchFileTypeTag, "Audio"), Query{FileType: "Audio"}, false},
		{"extension is post-filter only", node(storage.SearchAnd, text("song"), tagString(storage.SearchExtTag, "mp3")),
			Query{Terms: []string{"song"}}, true},
		{"nil", nil, Query{}, false},
	}
	for _, tc := range cases {
		got, ok := BuildQuery(tc.expr)
		t.Logf("input: %s; output: %+v ok=%t", tc.name, got, ok)
		if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %+v ok=%t, want %+v ok=%t", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestQueryRequestAndKey(t *testing.T) {
	q := Query{Terms: []string{"Ubuntu", "iso"}, Exclude: []string{"beta"}, FileType: "Iso", MinSize: 10, MaxSize: 20}
	req := q.Request(50)
	t.Logf("input: %+v; output: request=%v key=%q", q, req, q.Key())
	if req.GetQuery() != "Ubuntu iso" || req.GetLimit() != 50 || req.GetType() != "Iso" ||
		req.GetMinSize() != 10 || req.GetMaxSize() != 20 || len(req.GetExclude()) != 1 {
		t.Fatalf("request %v does not carry the query", req)
	}

	reordered := Query{Terms: []string{"ISO", "ubuntu"}, Exclude: []string{"BETA"}, FileType: "iso", MinSize: 10, MaxSize: 20}
	if q.Key() != reordered.Key() {
		t.Fatalf("keys differ for the same query in another order/case: %q vs %q", q.Key(), reordered.Key())
	}
	for _, other := range []Query{
		{Terms: []string{"ubuntu", "iso"}, FileType: "Iso", MinSize: 10, MaxSize: 20},
		{Terms: []string{"ubuntu", "iso"}, Exclude: []string{"beta"}, FileType: "Iso", MinSize: 11, MaxSize: 20},
		{Terms: []string{"ubuntu", "iso"}, Exclude: []string{"beta"}, FileType: "Video", MinSize: 10, MaxSize: 20},
	} {
		if other.Key() == q.Key() {
			t.Fatalf("a different query %+v shares the cache key", other)
		}
	}
}

// TestBuildQueryForwardsAvailability: eMule's availability floor on an AND path
// becomes Search.min_seeders and is part of the cache key; one under an OR, an upper
// bound and NotEqual are left to the post-filter.
func TestBuildQueryForwardsAvailability(t *testing.T) {
	cases := []struct {
		name string
		expr *storage.SearchExpr
		want uint32
	}{
		{"at least 5", node(storage.SearchAnd, text("ubuntu"), tagUint(sourcesLeaf(storage.SearchOpGreaterEqual), 5)), 5},
		{"more than 4", node(storage.SearchAnd, text("ubuntu"), tagUint(sourcesLeaf(storage.SearchOpGreater), 4)), 5},
		{"exactly 3", node(storage.SearchAnd, text("ubuntu"), tagUint(sourcesLeaf(storage.SearchOpEqual), 3)), 3},
		{"the higher of two floors", node(storage.SearchAnd,
			node(storage.SearchAnd, text("ubuntu"), tagUint(sourcesLeaf(storage.SearchOpGreaterEqual), 2)),
			tagUint(sourcesLeaf(storage.SearchOpGreaterEqual), 7)), 7},
		{"an upper bound", node(storage.SearchAnd, text("ubuntu"), tagUint(sourcesLeaf(storage.SearchOpLess), 9)), 0},
		{"not equal", node(storage.SearchAnd, text("ubuntu"), tagUint(sourcesLeaf(storage.SearchOpNotEqual), 1)), 0},
		{"under an OR", node(storage.SearchAnd, text("ubuntu"),
			node(storage.SearchOr, text("iso"), tagUint(sourcesLeaf(storage.SearchOpGreaterEqual), 5))), 0},
	}
	for _, tc := range cases {
		q, _ := BuildQuery(tc.expr)
		req := q.Request(10)
		t.Logf("input: %s; output: MinSources=%d min_seeders=%d", tc.name, q.MinSources, req.GetMinSeeders())
		if q.MinSources != tc.want || req.GetMinSeeders() != tc.want {
			t.Errorf("%s: got %d / %d, want %d", tc.name, q.MinSources, req.GetMinSeeders(), tc.want)
		}
	}

	a := Query{Terms: []string{"ubuntu"}, MinSources: 1}
	b := Query{Terms: []string{"ubuntu"}, MinSources: 2}
	t.Logf("input: %+v vs %+v; output: keys %q / %q", a, b, a.Key(), b.Key())
	if a.Key() == b.Key() {
		t.Fatalf("queries with different availability floors share a cache key")
	}
}

// sizeLeaf is the TagType of an FT_FILESIZE leaf with operator op: op, a tag-name
// length of 1, and the tag id, as one little-endian uint32.
func sizeLeaf(op uint8) uint32 {
	return uint32(op) | 1<<8 | uint32(storage.SearchTagSize)<<24
}

// sourcesLeaf is the TagType of an FT_SOURCES leaf with operator op.
func sourcesLeaf(op uint8) uint32 {
	return uint32(op) | 1<<8 | uint32(storage.SearchTagSources)<<24
}
