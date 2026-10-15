package storage

import (
	"math"
	"math/rand/v2"
	"reflect"
	"testing"
)

func extLeaf(ext string) *SearchExpr {
	return &SearchExpr{Kind: SearchString, TagType: searchTypeExt, ValueString: ext}
}

func artistLeaf(v string) *SearchExpr {
	return &SearchExpr{Kind: SearchString, TagType: searchTypeArtist, ValueString: v}
}

// TestBuildManticoreQuery pins what a tree renders to: which part each leaf goes
// into, how the operators join them, and which trees are sent to the database.
func TestBuildManticoreQuery(t *testing.T) {
	sizeGt := numericLeaf(SearchTagSize, SearchOpGreater, 100)
	sourcesGe := numericLeaf(SearchTagSources, SearchOpGreaterEqual, 5)
	completeGe := numericLeaf(SearchTagComplete, SearchOpGreaterEqual, 1)
	cases := []struct {
		name       string
		expr       *SearchExpr
		outcome    manticoreOutcome
		match      string
		filter     string
		args       []any
		having     string
		postFilter bool
	}{
		{name: "one word", expr: textLeaf("Spider"), match: "(@name *spider*)"},
		{name: "words and separators split into runs", expr: textLeaf("spider-man 2002"),
			match: "(@name *spider* *man* *2002*)"},
		{name: "a one-letter run is a whole word", expr: textLeaf("x-men"), match: "(@name x *men*)"},
		{name: "CJK is a phrase", expr: textLeaf("東京ラブ"), match: `(@name "東京ラブ")`},
		{name: "mixed script splits where the tokenizer does", expr: textLeaf("abc東京"),
			match: `(@name *abc* "東京")`},
		{name: "AND", expr: &SearchExpr{Kind: SearchAnd, Left: textLeaf("a1"), Right: textLeaf("b2")},
			match: "(@name *a1*) (@name *b2*)"},
		{name: "OR is bracketed both sides", expr: &SearchExpr{Kind: SearchOr, Left: textLeaf("a1"), Right: textLeaf("b2")},
			match: "(((@name *a1*)) | ((@name *b2*)))"},
		{name: "AND NOT of a keyword", expr: &SearchExpr{Kind: SearchAndNot, Left: textLeaf("a1"), Right: textLeaf("b2")},
			match: "(@name *a1*) -((@name *b2*))"},
		{name: "artist is field limited", expr: artistLeaf("Foo Fighters"), match: "(@artist *foo* *fighters*)"},
		{name: "type is normalized", expr: typeExpr("Iso"), filter: "type = ?", args: []any{"Pro"}},
		{name: "keyword AND attributes",
			expr:  &SearchExpr{Kind: SearchAnd, Left: textLeaf("abc"), Right: &SearchExpr{Kind: SearchAnd, Left: extLeaf("avi"), Right: sizeGt}},
			match: "(@name *abc*)", filter: "(ext = ? AND size > ?)", args: []any{"avi", uint64(100)}},
		{name: "attributes OR-ed",
			expr:  &SearchExpr{Kind: SearchAnd, Left: textLeaf("abc"), Right: &SearchExpr{Kind: SearchOr, Left: extLeaf("avi"), Right: extLeaf("mkv")}},
			match: "(@name *abc*)", filter: "(ext = ? OR ext = ?)", args: []any{"avi", "mkv"}},
		{name: "attribute negated",
			expr:  &SearchExpr{Kind: SearchAndNot, Left: textLeaf("abc"), Right: extLeaf("avi")},
			match: "(@name *abc*)", filter: "NOT (ext = ?)", args: []any{"avi"}},
		{name: "one counter goes to HAVING",
			expr:  &SearchExpr{Kind: SearchAnd, Left: textLeaf("abc"), Right: sourcesGe},
			match: "(@name *abc*)", having: "sources >= ?"},
		{name: "two counters are checked in Go",
			expr:  &SearchExpr{Kind: SearchAnd, Left: textLeaf("abc"), Right: &SearchExpr{Kind: SearchAnd, Left: sourcesGe, Right: completeGe}},
			match: "(@name *abc*)", postFilter: true},
		{name: "a size above int64 is clamped", expr: &SearchExpr{Kind: SearchAnd, Left: textLeaf("abc"),
			Right: numericLeaf(SearchTagSize, SearchOpLess, math.MaxUint64)},
			match: "(@name *abc*)", filter: "size < ?", args: []any{uint64(math.MaxInt64)}},
		{name: "keyword OR attribute is unsupported",
			expr: &SearchExpr{Kind: SearchOr, Left: textLeaf("abc"), Right: extLeaf("avi")}, outcome: manticoreUnsupported},
		{name: "negated keyword with no keyword to subtract from is unsupported",
			expr: &SearchExpr{Kind: SearchAndNot, Left: extLeaf("avi"), Right: textLeaf("abc")}, outcome: manticoreUnsupported},
		{name: "punctuation-only term is unsupported", expr: textLeaf("abc ."), outcome: manticoreUnsupported},
		{name: "empty artist is unsupported", expr: artistLeaf(" "), outcome: manticoreUnsupported},
		{name: "unsupported pruned by an AND NOT", expr: &SearchExpr{Kind: SearchAndNot, Left: textLeaf("abc"), Right: textLeaf("  ")},
			match: "(@name *abc*)"},
		{name: "all-whitespace keyword is empty", expr: textLeaf("   "), outcome: manticoreEmpty},
		{name: "unknown tag alone is empty", expr: unsupportedLeaf(), outcome: manticoreEmpty},
		{name: "unknown tag is pruned beside a keyword",
			expr: &SearchExpr{Kind: SearchAnd, Left: unsupportedLeaf(), Right: textLeaf("abc")}, match: "(@name *abc*)"},
		{name: "contradiction wins over unsupported under AND",
			expr: &SearchExpr{Kind: SearchAnd, Left: textLeaf(" "), Right: textLeaf(".")}, outcome: manticoreEmpty},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("input: %s", indexExprString(tc.expr))
			q, outcome := buildManticoreQuery(tc.expr)
			having, _ := q.having()
			t.Logf("output: outcome=%d match=%q filter=%q args=%v having=%q agg=%v", outcome, q.match, q.filter, q.args, having, q.agg != nil)
			if outcome != tc.outcome {
				t.Fatalf("outcome %d, want %d", outcome, tc.outcome)
			}
			if outcome != manticoreRun {
				return
			}
			if q.match != tc.match || q.filter != tc.filter {
				t.Fatalf("match %q filter %q, want %q %q", q.match, q.filter, tc.match, tc.filter)
			}
			if len(q.args) != 0 || len(tc.args) != 0 {
				if !reflect.DeepEqual(q.args, tc.args) {
					t.Fatalf("args %#v, want %#v", q.args, tc.args)
				}
			}
			if having != tc.having {
				t.Fatalf("having %q, want %q", having, tc.having)
			}
			if got := q.agg != nil && having == ""; got != tc.postFilter {
				t.Fatalf("post-filter %v, want %v", got, tc.postFilter)
			}
		})
	}
}

// TestManticoreAggMatches checks the counter constraints evaluated in Go against
// MatchSearchExpr, which evaluates the same leaves on a File.
func TestManticoreAggMatches(t *testing.T) {
	sourcesGe := numericLeaf(SearchTagSources, SearchOpGreaterEqual, 3)
	completeLt := numericLeaf(SearchTagComplete, SearchOpLess, 2)
	trees := []*SearchExpr{
		{Kind: SearchAnd, Left: sourcesGe, Right: completeLt},
		{Kind: SearchOr, Left: sourcesGe, Right: completeLt},
		{Kind: SearchAndNot, Left: sourcesGe, Right: completeLt},
		{Kind: SearchAndNot, Left: textLeaf("abc"), Right: completeLt},
	}
	for _, expr := range trees {
		q, outcome := buildManticoreQuery(expr)
		if outcome != manticoreRun || q.agg == nil {
			t.Fatalf("%s: outcome %d agg %v", indexExprString(expr), outcome, q.agg)
		}
		for sources := uint64(0); sources < 5; sources++ {
			for completed := uint64(0); completed <= sources; completed++ {
				file := File{Name: "abc", Sources: uint32(sources), Completed: uint32(completed)}
				want := MatchSearchExpr(expr, file)
				got := q.agg.matches(sources, completed)
				if got != want {
					t.Fatalf("%s sources=%d completed=%d: got %v, want %v", indexExprString(expr), sources, completed, got, want)
				}
			}
		}
		t.Logf("input: %s, output: agg agrees with MatchSearchExpr on every count", indexExprString(expr))
	}
}

// TestManticorePrunesLikeSQL holds the Manticore builder to the SQL builder's
// prune and contradiction rules: over random trees, a tree is empty for one
// exactly when it is empty for the other.
func TestManticorePrunesLikeSQL(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	counts := map[manticoreOutcome]int{}
	for range 5000 {
		expr := randomExpr(rng, 4)
		_, outcome := buildManticoreQuery(expr)
		counts[outcome]++
		if outcome == manticoreUnsupported {
			continue
		}
		where, _ := BuildSearchWhere(expr, DialectMySQL)
		if (outcome == manticoreEmpty) != (where == "") {
			t.Fatalf("%s: manticore outcome %d, sql where %q", indexExprString(expr), outcome, where)
		}
	}
	t.Logf("output: run=%d empty=%d unsupported=%d", counts[manticoreRun], counts[manticoreEmpty], counts[manticoreUnsupported])
}
