package storage

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// eMule sends a quoted string with its quotes (MFC GetSearchPacket). The words of a
// phrase must follow each other, with only separators between them.
func TestTextPhrases(t *testing.T) {
	for _, tc := range []struct {
		text string
		want [][]string
	}{
		{`matrix reloaded`, nil},
		{`"Matrix Reloaded"`, [][]string{{"matrix", "reloaded"}}},
		{`"matrix reloaded" dvd`, [][]string{{"matrix", "reloaded"}}},
		{`"spider-man" "the  dark knight"`, [][]string{{"spider", "man"}, {"the", "dark", "knight"}}},
		{`"matrix" dvd`, nil},     // one run: the plain match covers it
		{`"matrix reloaded`, nil}, // unpaired quote is ignored
		{`""`, nil},
	} {
		got := textPhrases(tc.text)
		t.Logf("input: %q output: %v", tc.text, got)
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%q: got %v, want %v", tc.text, got, tc.want)
		}
	}
}

func TestContainsPhrase(t *testing.T) {
	ph := []string{"matrix", "reloaded"}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"The.Matrix.Reloaded.2003.mkv", true},
		{"matrix_reloaded.avi", true},
		{"Matrix - Reloaded", true},
		{"TheMatrixReloadedX.avi", true}, // substring at both ends, as a plain run
		{"Reloaded.Matrix.avi", false},
		{"Matrix.2.Reloaded.avi", false},
		{"Matrix Revolutions (Reloaded edit)", false},
		{"matrix matrix reloaded", true},  // second occurrence of the first run
		{"Ünïcode Matrix–Reloaded", true}, // en dash separator
		{"", false},
	} {
		lower := strings.ToLower(tc.name)
		got := containsPhrase(lower, ph)
		t.Logf("input: %q output: %v", tc.name, got)
		if got != tc.want {
			t.Fatalf("%q: got %v, want %v", tc.name, got, tc.want)
		}
		// The database regexp follows the same rule (checked here with Go's engine).
		re := regexp.MustCompile(phraseRegexp(ph))
		if re.MatchString(tc.name) != tc.want {
			t.Fatalf("%q: regexp %q disagrees", tc.name, re)
		}
	}
}

func TestMemorySearchQuotedPhrase(t *testing.T) {
	m := NewMemoryEngine()
	c := connectOne(m)
	for i, name := range []string{"The.Matrix.Reloaded.2003.mkv", "Reloaded.Matrix.avi", "Matrix.2.Reloaded.dvd.avi", "matrix reloaded dvd.iso"} {
		m.AddFile(File{Hash: fileHash(i + 1), Size: uint64(i + 1), Name: name}, c)
	}
	for _, tc := range []struct {
		expr *SearchExpr
		want []string
	}{
		{&SearchExpr{Kind: SearchString, TagType: searchTypeText, ValueString: `"matrix reloaded"`},
			[]string{"The.Matrix.Reloaded.2003.mkv", "matrix reloaded dvd.iso"}},
		{&SearchExpr{Kind: SearchText, Text: `matrix reloaded`},
			[]string{"The.Matrix.Reloaded.2003.mkv", "Reloaded.Matrix.avi", "Matrix.2.Reloaded.dvd.avi", "matrix reloaded dvd.iso"}},
		{&SearchExpr{Kind: SearchText, Text: `"matrix reloaded" dvd`},
			[]string{"matrix reloaded dvd.iso"}},
		// NOT "phrase" drops only the names holding the phrase
		{&SearchExpr{Kind: SearchAndNot,
			Left:  &SearchExpr{Kind: SearchText, Text: `matrix`},
			Right: &SearchExpr{Kind: SearchText, Text: `"matrix reloaded"`}},
			[]string{"Reloaded.Matrix.avi", "Matrix.2.Reloaded.dvd.avi"}},
	} {
		var got []string
		for _, f := range m.FindBySearch(tc.expr) {
			got = append(got, f.Name)
		}
		t.Logf("input: %+v output: %v", tc.expr, got)
		if !sameNames(got, tc.want) {
			t.Fatalf("got %v, want %v", got, tc.want)
		}
	}
}

func TestBuildSearchWhereQuotedPhrase(t *testing.T) {
	re := `(?i)matrix[^\p{L}\p{N}]*reloaded`
	for _, tc := range []struct {
		dialect, wantSQL string
		wantArgs         []any
	}{
		{DialectMariaDB,
			"(MATCH(s.name) AGAINST (? IN BOOLEAN MODE) AND s.name REGEXP ?)",
			[]any{"+matrix* +reloaded*", re}},
		{DialectMySQL,
			"(MATCH(s.name) AGAINST (? IN BOOLEAN MODE) AND s.name LIKE ? AND s.name LIKE ? AND s.name REGEXP ?)",
			[]any{`+"matrix" +"reloaded"`, "%matrix%", "%reloaded%", re}},
	} {
		sql, args := BuildSearchWhere(&SearchExpr{Kind: SearchText, Text: `"matrix reloaded"`}, tc.dialect)
		t.Logf("input: dialect=%s output: sql=%q args=%v", tc.dialect, sql, args)
		if sql != tc.wantSQL || !reflect.DeepEqual(args, tc.wantArgs) {
			t.Fatalf("got %q %v, want %q %v", sql, args, tc.wantSQL, tc.wantArgs)
		}
	}
}

func TestMongoSearchQuotedPhrase(t *testing.T) {
	leaf := &SearchExpr{Kind: SearchText, Text: `"matrix reloaded"`}
	filter, _, _ := mongoFilterNode(leaf)
	want := bson.M{"$and": []bson.M{
		{"$and": []bson.M{
			{"name": bson.M{"$regex": "matrix", "$options": "i"}},
			{"name": bson.M{"$regex": "reloaded", "$options": "i"}},
		}},
		{"name": bson.M{"$regex": `(?i)matrix[^\p{L}\p{N}]*reloaded`}},
	}}
	t.Logf("input: %q output: %v", leaf.Text, filter)
	if !reflect.DeepEqual(filter, want) {
		t.Fatalf("filter = %v, want %v", filter, want)
	}
	// $text finds the words; the leaf stays behind for the regex stage.
	search, rest, ok := hoistTextLeaf(leaf)
	if !ok || search != `"matrix" "reloaded"` || rest != leaf {
		t.Fatalf("hoist = %q %v %v", search, rest, ok)
	}
	if _, rest, ok := hoistTextLeaf(&SearchExpr{Kind: SearchText, Text: "matrix reloaded"}); !ok || rest != nil {
		t.Fatalf("unquoted leaf must hoist whole, rest=%v", rest)
	}
}

// Manticore runs the phrase itself: no fallback to the database.
func TestManticorePhraseMatch(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{`"matrix reloaded"`, `(@name *matrix* *reloaded* "*matrix reloaded*")`},
		{`"the dark knight" dvd`, `(@name *the* *dark* *knight* *dvd* "*the dark knight*")`},
		{`"x men"`, `(@name x *men* "x men*")`},
		{`"東京 matrix"`, `(@name "東京" *matrix* "東京 matrix*")`},
		{`"matrix reloaded`, `(@name *matrix* *reloaded*)`},
	} {
		n := manticoreTextLeaf("name", tc.text)
		t.Logf("input: %q output: %+v", tc.text, n)
		if n.unsupported || n.match != tc.want {
			t.Fatalf("%q: got %+v, want match %q", tc.text, n, tc.want)
		}
	}
}

func sameNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		if seen[s]--; seen[s] < 0 {
			return false
		}
	}
	return true
}
