package storage

import (
	"testing"
)

// TestSearchNeedsScan pins which search trees the SQL and MongoDB engines drop
// because no full-text lookup anchors them. The check is per tree, not per leaf:
// a short run next to an indexable one (x-men, AND(x, men)) still runs, while a
// short run that alone decides the rows (x, OR(x, men)) is dropped.
func TestSearchNeedsScan(t *testing.T) {
	and := func(l, r *SearchExpr) *SearchExpr { return &SearchExpr{Kind: SearchAnd, Left: l, Right: r} }
	or := func(l, r *SearchExpr) *SearchExpr { return &SearchExpr{Kind: SearchOr, Left: l, Right: r} }
	andNot := func(l, r *SearchExpr) *SearchExpr { return &SearchExpr{Kind: SearchAndNot, Left: l, Right: r} }

	cases := []struct {
		name        string
		expr        *SearchExpr
		wantMySQL   bool // ngram, minTok 2 (also MongoDB's cutoff)
		wantMariaDB bool // word index, minTok 3
	}{
		{"single letter", textExpr("x"), true, true},
		{"two letters is mariadb-only", textExpr("hi"), false, true},
		{"short run beside an indexable run", textExpr("x-men"), false, false},
		{"only short words in one leaf", textExpr("x y"), true, true},
		{"punctuation only", textExpr("%_"), true, true},
		{"long punctuation only", textExpr("%%%"), true, true},
		{"AND anchored by its sibling", and(textExpr("x"), textExpr("men")), false, false},
		{"OR with a short branch", or(textExpr("x"), textExpr("men")), true, true},
		{"OR of indexable branches", or(textExpr("star"), textExpr("wars")), false, false},
		{"short word with only a type filter", and(typeExpr("Video"), textExpr("x")), true, true},
		{"indexable word with a type filter", and(typeExpr("Video"), textExpr("men")), false, false},
		{"short word negated", andNot(textExpr("men"), textExpr("x")), false, false},
		{"short word as the positive side", andNot(textExpr("x"), textExpr("men")), true, true},
		{"unsupported tag is pruned", and(unsupportedLeaf(), textExpr("x")), true, true},
		{"whitespace contradiction absorbed by OR", or(textExpr("   "), textExpr("men")), false, false},
		{"type filter alone is unchanged", typeExpr("Video"), false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotMySQL := SearchNeedsScan(tc.expr, ftMinTokenSize(DialectMySQL))
			gotMariaDB := SearchNeedsScan(tc.expr, ftMinTokenSize(DialectMariaDB))
			t.Logf("input: %s", describeExpr(tc.expr))
			t.Logf("output: needsScan mysql=%v mariadb=%v", gotMySQL, gotMariaDB)

			if gotMySQL != tc.wantMySQL {
				t.Fatalf("mysql needsScan = %v, want %v", gotMySQL, tc.wantMySQL)
			}
			if gotMariaDB != tc.wantMariaDB {
				t.Fatalf("mariadb needsScan = %v, want %v", gotMariaDB, tc.wantMariaDB)
			}
		})
	}
}

// TestMongoSearchPipelineDropsUnanchored confirms the MongoDB engine applies the
// guard before building a pipeline, and still builds one for a short run that
// rides along with an indexable one.
func TestMongoSearchPipelineDropsUnanchored(t *testing.T) {
	cases := []struct {
		text   string
		wantOK bool
	}{
		{"x", false},
		{"x-men", true},
		{"men", true},
	}
	for _, tc := range cases {
		_, ok := mongoSearchPipeline(textExpr(tc.text))
		t.Logf("input: text=%q output: pipeline ok=%v", tc.text, ok)
		if ok != tc.wantOK {
			t.Fatalf("mongoSearchPipeline(%q) ok = %v, want %v", tc.text, ok, tc.wantOK)
		}
	}
}
