package storage

import (
	"strings"
	"testing"
)

func TestManticoreCreateStatement(t *testing.T) {
	got := manticoreCreateStatement("enode_sources", DefaultManticoreTableOptions)
	t.Logf("output: %s", got)
	if !strings.HasPrefix(got, "CREATE TABLE IF NOT EXISTS enode_sources (name text, title text, ") ||
		!strings.HasSuffix(got, "pass bigint) "+DefaultManticoreTableOptions) {
		t.Fatalf("unexpected statement %q", got)
	}
}

func TestCompareManticoreTable(t *testing.T) {
	want := manticoreShape{Columns: map[string]manticoreDescribed{}, Settings: map[string]string{"min_infix_len": "2"}}
	for _, c := range manticoreColumns {
		d := manticoreDescribed{Type: c.decl}
		if c.fullText() {
			d.Properties = []string{"indexed", "stored"}
		}
		want.Columns[c.name] = d
	}
	clone := func() manticoreShape {
		got := manticoreShape{Columns: map[string]manticoreDescribed{}, Settings: map[string]string{}}
		for k, v := range want.Columns {
			got.Columns[k] = v
		}
		for k, v := range want.Settings {
			got.Settings[k] = v
		}
		return got
	}

	same := clone()
	same.Columns["extra"] = manticoreDescribed{Type: "uint"}
	if add, problems := compareManticoreTable(want, same); len(add) != 0 || len(problems) != 0 {
		t.Fatalf("an extra column is not drift: add=%v problems=%v", add, problems)
	}

	missingAttr := clone()
	delete(missingAttr.Columns, "pass")
	add, problems := compareManticoreTable(want, missingAttr)
	t.Logf("output: missing attribute add=%v problems=%v", add, problems)
	if len(add) != 1 || add[0].name != "pass" || len(problems) != 0 {
		t.Fatal("a missing attribute is added in place")
	}

	broken := clone()
	delete(broken.Columns, "name")
	broken.Columns["size"] = manticoreDescribed{Type: "uint"}
	broken.Columns["title"] = manticoreDescribed{Type: "text", Properties: []string{"indexed"}}
	broken.Settings["min_infix_len"] = "3"
	_, problems = compareManticoreTable(want, broken)
	t.Logf("output: problems=%v", problems)
	if len(problems) != 4 {
		t.Fatalf("got %d problems, want 4: %v", len(problems), problems)
	}
}

func TestParseManticoreSettings(t *testing.T) {
	got := parseManticoreSettings("min_infix_len = 2\nngram_len = 1\n\nngram_chars = cont")
	t.Logf("output: %v", got)
	if got["min_infix_len"] != "2" || got["ngram_chars"] != "cont" || len(got) != 3 {
		t.Fatalf("parsed %v", got)
	}
}
