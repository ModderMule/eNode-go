package contentfilter

import (
	"errors"
	"testing"
)

// TestMatcherMatch is torrent-crawler's filter table: the two implementations must
// agree, since one keyword list is meant to be shared between them.
func TestMatcherMatch(t *testing.T) {
	cases := []struct {
		keywords, text string
		want           bool
	}{
		{"xxx", "Movie.XXX.1080p", true},
		{"xxx", "[XXX]_clip_01", true},
		{"xxx", "xxxl.shirt.catalogue", false},
		{"xxx", "xx.release", false},
		{"18", "Some.Show.18.Plus.mkv", true},
		{"18", "Some.Show.S01E18.mkv", false},
		{"18", "Release2018", false},
		{"foo|xxx", "Other.XXX.Thing", true},
		{"foo bar", "Foo.Bar.2026", true},
		{"foo bar", "Foo.Baz.Bar", false},
		{"foo-bar", "foo_bar", true},
		{"xxx", "ＸＸＸ.Collection", true},
		{"成人", "新作成人映画", true},
		{"xxx", "成人xxx合集", true},
		{"av女優", "新作AV女優集", true},
		{"av女優", "新作NAV女優集", false},
		{"ビデオ", "アダルトビデオー集", true},
		{"café", "Le.Café.Noir", true},
		{"cafe", "Le.Café.Noir", false},
		{"", "anything.at.all", false},
		{"xxx", "", false},
	}
	for _, tc := range cases {
		m, err := NewMatcher(tc.keywords)
		if err != nil {
			t.Fatalf("NewMatcher(%q): %v", tc.keywords, err)
		}
		got := m.Match(tc.text)
		t.Logf("input: keywords=%q text=%q output: match=%t", tc.keywords, tc.text, got)
		if got != tc.want {
			t.Errorf("keywords %q on %q = %t, want %t", tc.keywords, tc.text, got, tc.want)
		}
	}
}

func TestNewMatcherParsing(t *testing.T) {
	cases := []struct {
		keywords string
		wantLen  int
		wantErr  error
	}{
		{"", 0, nil},
		{" | || ", 0, nil},
		{"xxx|foo bar", 2, nil},
		{"  xxx  |  yyy ", 2, nil},
		{"XXX|xxx|X.X.X", 2, nil}, // de-duplicated once normalised; X.X.X is the phrase "x x x"
		{"xxx|--", 0, ErrNoWord},
	}
	for _, tc := range cases {
		m, err := NewMatcher(tc.keywords)
		t.Logf("input: %q output: len=%d err=%v", tc.keywords, m.Len(), err)
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("NewMatcher(%q) error = %v, want %v", tc.keywords, err, tc.wantErr)
			continue
		}
		if m.Len() != tc.wantLen {
			t.Errorf("NewMatcher(%q) holds %d keyword(s), want %d", tc.keywords, m.Len(), tc.wantLen)
		}
		if m.Empty() != (m.Len() == 0) {
			t.Errorf("NewMatcher(%q): Empty()=%t disagrees with Len()=%d", tc.keywords, m.Empty(), m.Len())
		}
	}
}

func TestNilMatcherMatchesNothing(t *testing.T) {
	var m *Matcher
	t.Logf("input: nil matcher output: empty=%t len=%d match=%t", m.Empty(), m.Len(), m.Match("xxx"))
	if !m.Empty() || m.Len() != 0 || m.Match("xxx") {
		t.Fatal("a nil matcher must be empty and match nothing")
	}
}
