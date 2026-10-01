package storage

import (
	"reflect"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// eMule keeps `spider-man` as one keyword (its lexer only splits on blanks, quotes
// and parentheses), so a separator inside a word reached every engine literally and
// `spider-man` missed `Spider.Man.2002.avi` while `spider man` found it.
func TestMemorySearchSeparatorInsideWord(t *testing.T) {
	m := NewMemoryEngine()
	c := connectOne(m)
	for i, name := range []string{"Spider.Man.2002.avi", "X-Men.2000.mkv", "Mad Men S01.mkv", "Conan O_Brien.mp4", "AC DC - Thunderstruck.mp3"} {
		m.AddFile(File{Hash: fileHash(i + 1), Size: uint64(i + 1), Name: name}, c)
	}
	for _, tc := range []struct {
		term string
		want []string
	}{
		{"spider-man", []string{"Spider.Man.2002.avi"}},
		{"x-men", []string{"X-Men.2000.mkv"}},
		{"o'brien", []string{"Conan O_Brien.mp4"}},
		{"ac/dc", []string{"AC DC - Thunderstruck.mp3"}},
		{"spider-woman", nil},
	} {
		var got []string
		for _, f := range m.FindBySearch(&SearchExpr{Kind: SearchText, Text: tc.term}) {
			got = append(got, f.Name)
		}
		t.Logf("input: %q output: %v", tc.term, got)
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%q: got %v, want %v", tc.term, got, tc.want)
		}
	}
}

// Both SQL dialects match a word run by run. The mariadb word index used to drop a
// run shorter than its token size, so `x-men` became `+men*` and found "Mad Men".
func TestBuildSearchWhereSeparatorInsideWord(t *testing.T) {
	for _, tc := range []struct {
		dialect, text, wantSQL string
		wantArgs               []any
	}{
		{DialectMySQL, "spider-man",
			"(MATCH(s.name) AGAINST (? IN BOOLEAN MODE) AND s.name LIKE ? AND s.name LIKE ?)",
			[]any{`+"spider" +"man"`, "%spider%", "%man%"}},
		{DialectMariaDB, "spider-man",
			"(MATCH(s.name) AGAINST (? IN BOOLEAN MODE))",
			[]any{"+spider* +man*"}},
		{DialectMariaDB, "x-men",
			"(MATCH(s.name) AGAINST (? IN BOOLEAN MODE) AND s.name LIKE ?)",
			[]any{"+men*", "%x%"}},
		{DialectMySQL, "x-men",
			"(MATCH(s.name) AGAINST (? IN BOOLEAN MODE) AND s.name LIKE ? AND s.name LIKE ?)",
			[]any{`+"men"`, "%x%", "%men%"}},
	} {
		sql, args := BuildSearchWhere(&SearchExpr{Kind: SearchText, Text: tc.text}, tc.dialect)
		t.Logf("input: dialect=%s text=%q output: sql=%q args=%v", tc.dialect, tc.text, sql, args)
		if sql != tc.wantSQL || !reflect.DeepEqual(args, tc.wantArgs) {
			t.Fatalf("got %q %v, want %q %v", sql, args, tc.wantSQL, tc.wantArgs)
		}
	}
}

// Mongo's regex fallback and its $text phrases split the word the same way; a
// `"spider-man"` phrase is matched literally by MongoDB.
func TestMongoSearchSeparatorInsideWord(t *testing.T) {
	expr := &SearchExpr{Kind: SearchText, Text: "spider-man"}

	filter := mongoNameRegexFilter(splitTerms(expr.Text))
	want := bson.M{"$and": []bson.M{
		{"name": bson.M{"$regex": "spider", "$options": "i"}},
		{"name": bson.M{"$regex": "man", "$options": "i"}},
	}}
	t.Logf("input: %q output: regex filter=%v", expr.Text, filter)
	if !reflect.DeepEqual(filter, want) {
		t.Fatalf("regex filter = %v, want %v", filter, want)
	}

	text, ok := textLeafSearch(expr)
	t.Logf("input: %q output: $text=%q ok=%t", expr.Text, text, ok)
	if !ok || text != `"spider" "man"` {
		t.Fatalf(`$text = %q, want "spider" "man"`, text)
	}
}

// Offers of type Arc or Iso are stored as Pro. MFC maps the search value the same
// way before sending, eMuleQt does not, so its Archive and CD-image searches found
// nothing on any engine.
func TestFileTypeSearchAcceptsArcAndIso(t *testing.T) {
	m := NewMemoryEngine()
	c := connectOne(m)
	m.AddFile(File{Hash: fileHash(1), Size: 1, Name: "debian.iso", Type: "Iso"}, c)
	m.AddFile(File{Hash: fileHash(2), Size: 2, Name: "debian.mp3", Type: "Audio"}, c)
	for _, value := range []string{"Iso", "Arc", "arc", "Pro"} {
		expr := &SearchExpr{Kind: SearchAnd,
			Left:  &SearchExpr{Kind: SearchText, Text: "debian"},
			Right: &SearchExpr{Kind: SearchString, TagType: searchTypeFileType, ValueString: value}}
		got := m.FindBySearch(expr)
		sql, args := BuildSearchWhere(expr.Right, DialectMariaDB)
		filter, _, _ := mongoFilterNode(expr.Right)
		t.Logf("input: type=%q, output: memory=%d sql=%s %v mongo=%v", value, len(got), sql, args, filter)
		if len(got) != 1 || got[0].Name != "debian.iso" {
			t.Fatalf("type %q: memory found %d files", value, len(got))
		}
		if args[0] != "Pro" || filter["type"] != "Pro" {
			t.Fatalf("type %q: SQL arg %v / Mongo %v, want Pro", value, args[0], filter["type"])
		}
	}
}
