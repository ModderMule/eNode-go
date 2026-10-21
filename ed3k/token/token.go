// Package token splits names into ed3k words and keywords (Protocol.md §10.1)
// and derives keyword targets. Publisher, searcher and storing node must split
// alike, so this follows the spec step by step: NFKC, full case folding, NFKC,
// drop Cf; words are runs of L, M and N; unspaced scripts become overlapping
// pairs; the extension's words are no keywords.
package token

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"enode/ed3k/ident"
)

// MinUnicode is the oldest Unicode table version §10.1 allows.
const MinUnicode = 16

// CheckTables returns an error when the Unicode tables this binary carries are
// older than §10.1 requires. x/text uses its 17.0 tables only with Go ≥ 1.27.
func CheckTables() error {
	for name, v := range map[string]string{"x/text norm": norm.Version, "unicode": unicode.Version} {
		var major int
		if _, err := fmt.Sscanf(v, "%d", &major); err != nil || major < MinUnicode {
			return fmt.Errorf("ed3k: %s tables are Unicode %s, need %d.0.0 or later", name, v, MinUnicode)
		}
	}
	return nil
}

// Normalize is step 1 of §10.1: NFKC, full case folding, NFKC, then every code
// point of category Cf removed. A text is normalised once.
func Normalize(s string) string {
	s = norm.NFKC.String(s)
	s = cases.Fold().String(s)
	s = norm.NFKC.String(s)
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// Split is a name split into its words, keywords and extension.
type Split struct {
	// Words are the distinct words of the name, in the order they first occur.
	Words []string
	// Keywords are the words of 2 bytes or more that the extension does not
	// give, in order.
	Keywords []string
	// Ext is the extension without the '.', or "".
	Ext string
}

// SplitName applies steps 1 to 4 of §10.1 to a name.
func SplitName(name string) Split {
	n := Normalize(name)
	var sp Split
	sp.Words = distinct(wordsOf(n))
	sp.Ext = extension(n)
	extWords := map[string]bool{}
	if sp.Ext != "" {
		for _, w := range wordsOf(sp.Ext) {
			extWords[w] = true
		}
	}
	for _, w := range sp.Words {
		if len(w) >= 2 && !extWords[w] {
			sp.Keywords = append(sp.Keywords, w)
		}
	}
	return sp
}

// Words splits an already normalised text (a search term list) into words by
// steps 2 and 3, without normalising it again.
func Words(normalised string) []string {
	return distinct(wordsOf(normalised))
}

// KeywordTarget is H("ed3k v1 keyword", level(1) ‖ word)[0..16).
func KeywordTarget(level uint8, word string) [16]byte {
	return ident.H16("ed3k v1 keyword", []byte{level}, []byte(word))
}

// HasKeywordFor reports whether one keyword of name gives target at level, the
// storing node's check of §10.7.
func HasKeywordFor(sp Split, level uint8, target [16]byte) bool {
	for _, k := range sp.Keywords {
		if KeywordTarget(level, k) == target {
			return true
		}
	}
	return false
}

// wordsOf is steps 2 and 3: runs of L, M and N, with unspaced runs replaced by
// their overlapping pairs.
func wordsOf(s string) []string {
	var out []string
	var run []rune
	flush := func() {
		if len(run) > 0 {
			out = append(out, unspace(run)...)
			run = run[:0]
		}
	}
	for _, r := range s {
		if isWordRune(r) {
			run = append(run, r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

// unspace splits one word at its unspaced runs (step 3).
func unspace(word []rune) []string {
	var out []string
	i := 0
	for i < len(word) {
		j := i
		un := isUnspaced(word[i])
		for j < len(word) && isUnspaced(word[j]) == un {
			j++
		}
		seg := word[i:j]
		switch {
		case !un:
			out = append(out, string(seg))
		case len(seg) == 1:
			out = append(out, string(seg))
		default:
			for k := 0; k+1 < len(seg); k++ {
				out = append(out, string(seg[k:k+2]))
			}
		}
		i = j
	}
	return out
}

// extension is step 4: the text after the last '.', when it is 1 to 8 code
// points of category L or N.
func extension(n string) string {
	i := strings.LastIndexByte(n, '.')
	if i < 0 {
		return ""
	}
	ext := n[i+1:]
	c := utf8.RuneCountInString(ext)
	if c < 1 || c > 8 {
		return ""
	}
	for _, r := range ext {
		if !unicode.In(r, unicode.L, unicode.N) {
			return ""
		}
	}
	return ext
}

func isWordRune(r rune) bool {
	return unicode.In(r, unicode.L, unicode.M, unicode.N)
}

// isUnspaced is the table of step 3 and nothing else.
func isUnspaced(r rune) bool {
	switch {
	case r >= 0x3005 && r <= 0x3007,
		r >= 0x3040 && r <= 0x30FF,
		r >= 0x31F0 && r <= 0x31FF,
		r >= 0x3400 && r <= 0x4DBF,
		r >= 0x4E00 && r <= 0x9FFF,
		r >= 0x20000 && r <= 0x323AF,
		r >= 0x0E00 && r <= 0x0E7F,
		r >= 0x0E80 && r <= 0x0EFF,
		r >= 0x1780 && r <= 0x17FF,
		r >= 0x1000 && r <= 0x109F,
		r >= 0xA9E0 && r <= 0xA9FF,
		r >= 0xAA60 && r <= 0xAA7F:
		return true
	}
	return false
}

func distinct(ws []string) []string {
	seen := make(map[string]bool, len(ws))
	out := ws[:0:0]
	for _, w := range ws {
		if !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	return out
}
