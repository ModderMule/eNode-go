package storage

import (
	"strings"
	"testing"
)

// TestEscapeLike pins L13's escaping helper: %, _ and the escape backslash itself
// are backslash-escaped so a search term matches them literally.
func TestEscapeLike(t *testing.T) {
	cases := []struct{ in, want string }{
		{`a%b_c\d`, `a\%b\_c\\d`},
		{`plain`, `plain`},
		{`100%`, `100\%`},
		{`a_b`, `a\_b`},
		{``, ``},
	}
	for _, c := range cases {
		got := escapeLike(c.in)
		t.Logf("input=%q output=%q", c.in, got)
		if got != c.want {
			t.Fatalf("escapeLike(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestBuildSearchWhereEscapesWildcards pins that a % inside a search term reaches
// MySQL as an escaped literal, not a wildcard — so the three engines agree, the
// memory and Mongo engines already treating it literally. A term is matched by its
// alphanumeric runs, so only a term with no run at all ("100%" splits into "100")
// is bound literally; that literal must be escaped. Against the pre-fix build the
// bound argument is the raw "%%_%".
func TestBuildSearchWhereEscapesWildcards(t *testing.T) {
	expr := &SearchExpr{Kind: SearchText, Text: "%_"}
	sql, args := BuildSearchWhere(expr, DialectMariaDB)
	t.Logf("input: text search %q", "%_")
	t.Logf("output: sql=%q args=%v", sql, args)

	if len(args) != 1 {
		t.Fatalf("want 1 bound arg, got %d: %v", len(args), args)
	}
	got, _ := args[0].(string)
	if got != `%\%\_%` {
		t.Fatalf("bound arg = %q, want %q", got, `%\%\_%`)
	}
}

// A wildcard between two runs is a separator like any other: "a%b" must match
// "a.b" on every engine, and neither LIKE argument may carry a raw wildcard.
func TestBuildSearchWhereWildcardSeparatesRuns(t *testing.T) {
	expr := &SearchExpr{Kind: SearchText, Text: "a%b"}
	sql, args := BuildSearchWhere(expr, DialectMariaDB)
	t.Logf("input: text search %q", "a%b")
	t.Logf("output: sql=%q args=%v", sql, args)

	if len(args) != 2 || args[0] != "%a%" || args[1] != "%b%" {
		t.Fatalf("args = %v, want [%%a%% %%b%%]", args)
	}
	for _, a := range args {
		if strings.Count(a.(string), "%") != 2 {
			t.Fatalf("bound arg %q carries a wildcard from the term", a)
		}
	}
}
