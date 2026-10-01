package storage

import (
	"reflect"
	"testing"
)

// TestFtLeafDialects pins the SQL each dialect emits for name search. It is the
// discriminating test for the full-text change: against the pre-fix build (plain
// `s.name LIKE '%term%'` for every term) none of the MATCH expectations hold.
//
//	mariadb — word-prefix `+run*`, indexed, no residual LIKE for indexable terms.
//	mysql   — ngram phrase `+"run"`, indexed, plus a residual LIKE per term that
//	          pins the exact substring.
//
// A term below the dialect's token size (mariadb 3, mysql 2) has no indexable
// run and falls back to a lone `LIKE` — the only sanctioned leading-`%`.
func TestFtLeafDialects(t *testing.T) {
	cases := []struct {
		name     string
		dialect  string
		text     string
		wantSQL  string
		wantArgs []any
	}{
		{
			"mariadb single word is a prefix MATCH, no LIKE",
			DialectMariaDB, "star",
			"(MATCH(s.name) AGAINST (? IN BOOLEAN MODE))",
			[]any{"+star*"},
		},
		{
			"mariadb splits punctuation into required prefixes",
			DialectMariaDB, "star-wars",
			"(MATCH(s.name) AGAINST (? IN BOOLEAN MODE))",
			[]any{"+star* +wars*"},
		},
		{
			"mariadb sub-token term falls back to a LIKE scan",
			DialectMariaDB, "hi",
			"(s.name LIKE ?)",
			[]any{"%hi%"},
		},
		{
			"mariadb mixes an indexed prefix with a short-term LIKE",
			DialectMariaDB, "hi star",
			"(MATCH(s.name) AGAINST (? IN BOOLEAN MODE) AND s.name LIKE ?)",
			[]any{"+star*", "%hi%"},
		},
		{
			"mysql single word is an ngram phrase plus exact LIKE",
			DialectMySQL, "star",
			"(MATCH(s.name) AGAINST (? IN BOOLEAN MODE) AND s.name LIKE ?)",
			[]any{`+"star"`, "%star%"},
		},
		{
			"mysql two words share one MATCH and get one LIKE each",
			DialectMySQL, "star wars",
			"(MATCH(s.name) AGAINST (? IN BOOLEAN MODE) AND s.name LIKE ? AND s.name LIKE ?)",
			[]any{`+"star" +"wars"`, "%star%", "%wars%"},
		},
		{
			"mariadb short run is filtered by the indexed run",
			DialectMariaDB, "x-men",
			"(MATCH(s.name) AGAINST (? IN BOOLEAN MODE) AND s.name LIKE ?)",
			[]any{"+men*", "%x%"},
		},
		{
			"mysql short run keeps its LIKE beside the indexed run",
			DialectMySQL, "x-men",
			"(MATCH(s.name) AGAINST (? IN BOOLEAN MODE) AND s.name LIKE ? AND s.name LIKE ?)",
			[]any{`+"men"`, "%x%", "%men%"},
		},
		{
			"mariadb long punctuation-only term keeps its literal LIKE",
			DialectMariaDB, "%%%",
			"(s.name LIKE ?)",
			[]any{`%\%\%\%%`},
		},
		{
			"mysql single char is below ngram size, LIKE only",
			DialectMySQL, "a",
			"(s.name LIKE ?)",
			[]any{"%a%"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expr := &SearchExpr{Kind: SearchText, Text: tc.text}
			sql, args := BuildSearchWhere(expr, tc.dialect)
			t.Logf("input: dialect=%s text=%q", tc.dialect, tc.text)
			t.Logf("output: sql=%q args=%v", sql, args)

			if sql != tc.wantSQL {
				t.Fatalf("sql = %q, want %q", sql, tc.wantSQL)
			}
			if !reflect.DeepEqual(args, tc.wantArgs) {
				t.Fatalf("args = %v, want %v", args, tc.wantArgs)
			}
			// Placeholders and args must stay in step.
			placeholders := 0
			for _, c := range sql {
				if c == '?' {
					placeholders++
				}
			}
			if placeholders != len(args) {
				t.Fatalf("%d placeholders but %d args", placeholders, len(args))
			}
		})
	}
}

// TestFtLeafEmptyDialectIsMariaDB confirms the zero value routes to the portable
// word-based path rather than emitting no MATCH at all.
func TestFtLeafEmptyDialectIsMariaDB(t *testing.T) {
	expr := &SearchExpr{Kind: SearchText, Text: "star"}
	sql, args := BuildSearchWhere(expr, "")
	t.Logf("input: dialect=\"\" text=%q", "star")
	t.Logf("output: sql=%q args=%v", sql, args)
	if sql != "(MATCH(s.name) AGAINST (? IN BOOLEAN MODE))" || !reflect.DeepEqual(args, []any{"+star*"}) {
		t.Fatalf("empty dialect did not behave as mariadb: sql=%q args=%v", sql, args)
	}
}

// TestShortRunNotDropped pins that the `x` of `x-men` still constrains the match
// instead of being dropped for being too short to index. Dropping it used to
// widen `x-men` to any name containing `men`.
func TestShortRunNotDropped(t *testing.T) {
	expr := &SearchExpr{Kind: SearchText, Text: "x-men"}
	cases := []struct {
		name string
		want bool
	}{
		{"X-Men.avi", true},
		{"x.men.2000.mkv", true},
		{"Men.in.Black.avi", false},
	}
	for _, tc := range cases {
		got := MatchSearchExpr(expr, File{Name: tc.name})
		t.Logf("input: search=%q name=%q output: match=%v", "x-men", tc.name, got)
		if got != tc.want {
			t.Fatalf("match(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
