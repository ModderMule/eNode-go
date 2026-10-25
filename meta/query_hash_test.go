package meta

import (
	"slices"
	"testing"

	"enode/storage"
)

// A hash or related search asks the catalogue daemons nothing on its own; AND-ed
// with words, only the words are forwarded and the hash is left to the post-filter.
func TestBuildQueryIgnoresHashAndRelatedLeaves(t *testing.T) {
	hash := &storage.SearchExpr{Kind: storage.SearchHash, ValueString: string(make([]byte, 16))}
	related := &storage.SearchExpr{Kind: storage.SearchRelated, Related: []storage.FileKey{{Hash: make([]byte, 16)}}}
	for name, expr := range map[string]*storage.SearchExpr{"hash": hash, "related": related} {
		q, ok := BuildQuery(expr)
		t.Logf("input: %s leaf -> output: terms=%v ok=%t", name, q.Terms, ok)
		if ok {
			t.Fatalf("a %s leaf alone built a daemon query: %+v", name, q)
		}
	}
	and := &storage.SearchExpr{Kind: storage.SearchAnd, Left: hash, Right: &storage.SearchExpr{Kind: storage.SearchText, Text: "movie"}}
	q, ok := BuildQuery(and)
	t.Logf("input: hash AND movie -> output: terms=%v ok=%t", q.Terms, ok)
	if !ok || !slices.Equal(q.Terms, []string{"movie"}) {
		t.Fatalf("hash AND movie built %+v ok=%t", q, ok)
	}
}
