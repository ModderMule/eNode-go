package token

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The examples of Protocol.md §10.1 and the edge cases of tests/vectors-v1.md.

func TestTables(t *testing.T) {
	err := CheckTables()
	t.Logf("tables check: %v", err)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSplitVectors(t *testing.T) {
	cases := []struct {
		name, words, keywords string
	}{
		{"The.Big_Sleep (1946) [1080p].mkv", "the big sleep 1946 1080p mkv", "the big sleep 1946 1080p"},
		{"Ça-va_ÉTÉ.MP3", "ça va été mp3", "ça va été"},
		{"Straße.ﬁnal.txt", "strasse final txt", "strasse final"},
		{"東京物語 Tokyo Story.avi", "東京 京物 物語 tokyo story avi", "東京 京物 物語 tokyo story"},
		{"Avi.Love.avi", "avi love", "love"},
		{"AC/DC", "ac dc", "ac dc"},
		{"a.b", "a b", ""},
		{"notes.", "notes", "notes"},
		{"archive.tar.backup123", "archive tar backup123", "archive tar backup123"},
		{"co­op.TXT", "coop txt", "coop"},
		{"été à la carte", "été à la carte", "été à la carte"},
		{"ＦＵＬＬ　Ｗｉｄｔｈ", "full width", "full width"},
		{"İstanbul", "i̇stanbul", "i̇stanbul"},
		{"x² ½", "x2 1 2", "x2"},
		{"don't", "don t", "don"},
		{"abc東京物def.mkv", "abc 東京 京物 def mkv", "abc 東京 京物 def"},
		{"x東y", "x 東 y", "東"},
		{"ｶﾞｰﾄﾞ", "ガー ード", "ガー ード"},
		{"映画.日本語", "映画 日本 本語", "映画"},
		{"ab.x日本", "ab x 日本", "ab"},
		{"น้ำ", "น้ ้ํ ํา", "น้ ้ํ ํา"},
	}
	for _, c := range cases {
		sp := SplitName(c.name)
		gotW := strings.Join(sp.Words, " ")
		gotK := strings.Join(sp.Keywords, " ")
		t.Logf("%q -> words=%q keywords=%q ext=%q", c.name, gotW, gotK, sp.Ext)
		if gotW != c.words {
			t.Errorf("%q: words %q want %q", c.name, gotW, c.words)
		}
		if gotK != c.keywords {
			t.Errorf("%q: keywords %q want %q", c.name, gotK, c.keywords)
		}
	}
}

func TestKeywordTargets(t *testing.T) {
	cases := map[string]string{
		"the":       "ebac9c8ff16567f5ea601eb083446933",
		"été":       "aa5038d6eb60080247c35b751a004695",
		"strasse":   "6fbd6277e369c70ebb8f1ed7f00c02af",
		"物語":        "bbcb1d1e2730b4a844019e9d9d67e705",
		"i̇stanbul": "e3ee3b59a82510462b54b9831ed8fdc4",
		"ガー":        "e032996bbf74f08c39b8f940a356e148",
		"ํา":        "ca09fb4602c9a001b290474ccb41deac",
	}
	for w, want := range cases {
		got := KeywordTarget(0, w)
		t.Logf("%q (%x) -> %x", w, w, got)
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("%q: got %x want %s", w, got, want)
		}
	}
}

func TestHasKeywordFor(t *testing.T) {
	sp := SplitName("The.Big_Sleep (1946) [1080p].mkv")
	ok := HasKeywordFor(sp, 0, KeywordTarget(0, "sleep"))
	ext := HasKeywordFor(sp, 0, KeywordTarget(0, "mkv"))
	lvl := HasKeywordFor(sp, 1, KeywordTarget(0, "sleep"))
	t.Logf("sleep=%v mkv=%v sleep@level1=%v", ok, ext, lvl)
	if !ok || ext || lvl {
		t.Fatal("keyword target check")
	}
}
