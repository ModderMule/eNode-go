package contentfilter

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// KeywordSeparator splits the configured keywords.
const KeywordSeparator = "|"

// ErrNoWord is a keyword with nothing left to match once its punctuation is taken away.
var ErrNoWord = errors.New("a keyword needs at least one letter or digit")

// Matcher holds the compiled keywords of filter.keywords. A nil Matcher is valid and
// matches nothing, which is what "no keywords configured" means everywhere.
//
// Matching is by whole words, case-insensitively, and literal: a keyword is a word to
// find, not a pattern. Both sides are normalised the same way (see normalize) and a
// match is a substring test on the results, which is what makes "xxx" find
// "Movie.XXX.1080p" but not "xxxl", and "foo bar" find "Foo.Bar". The rules are those
// of torrent-crawler's filter.keywords, so one keyword list means the same thing on
// the crawlers and on this server.
type Matcher struct {
	// patterns are the normalised keywords, each with a space at either end that has
	// to meet a word boundary in the text — see pattern.
	patterns []string
}

// NewMatcher parses the configured keywords, separated by a vertical bar.
//
// Empty entries are skipped, so "a||b" and a trailing bar are harmless. An entry that
// is nothing but punctuation is an error rather than skipped: it would match nothing,
// and silently ignoring what the operator wrote would leave them believing something
// is filtered that is not.
func NewMatcher(keywords string) (*Matcher, error) {
	var patterns []string
	for keyword := range strings.SplitSeq(keywords, KeywordSeparator) {
		keyword = strings.TrimSpace(keyword)
		if keyword == "" {
			continue
		}
		p := pattern(keyword)
		if p == "" {
			return nil, fmt.Errorf("%w: %q", ErrNoWord, keyword)
		}
		if !slices.Contains(patterns, p) {
			patterns = append(patterns, p)
		}
	}
	if len(patterns) == 0 {
		return nil, nil
	}
	slices.Sort(patterns)
	return &Matcher{patterns: patterns}, nil
}

// Empty reports whether the matcher matches nothing.
func (m *Matcher) Empty() bool {
	return m == nil || len(m.patterns) == 0
}

// Len is how many distinct keywords the matcher holds.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.patterns)
}

// Match reports whether text contains one of the keywords as a whole word.
func (m *Matcher) Match(text string) bool {
	if m.Empty() || text == "" {
		return false
	}
	normalised := normalize(text)
	for _, p := range m.patterns {
		if strings.Contains(normalised, p) {
			return true
		}
	}
	return false
}

// Rune classes normalize distinguishes.
const (
	classSpace = iota
	classWord
	classCont
)

// contScripts are the scripts written without spaces between words.
var contScripts = []*unicode.RangeTable{
	unicode.Han,
	unicode.Hiragana,
	unicode.Katakana,
	unicode.Hangul,
	unicode.Thai,
	unicode.Lao,
	unicode.Khmer,
	unicode.Myanmar,
}

// pattern normalises one keyword into the string a normalised text has to contain. It
// is empty when the keyword holds no word at all.
//
// normalize pads with a space at both ends, which is what makes the match whole-word:
// " xxx " is not in " xxxl ". A continuous-script end drops its space, because a text
// in such a script has no word gaps to meet it — " 成人" has to be found inside
// " 新作成人映画 ".
func pattern(keyword string) string {
	p := normalize(keyword)
	if strings.TrimSpace(p) == "" {
		return ""
	}
	if first, _ := utf8.DecodeRuneInString(p[1:]); isCont(first) {
		p = p[1:]
	}
	if last, _ := utf8.DecodeLastRuneInString(p[:len(p)-1]); isCont(last) {
		p = p[:len(p)-1]
	}
	return p
}

// normalize reduces text to lower-case words separated by single spaces, with a space
// at each end.
//
// A word is a run of letters, digits and combining marks; everything else — dots,
// underscores, brackets, dashes — is a gap. NFKC first, so a full-width "ＸＸＸ" is the
// same word as "xxx". A switch between a continuous script (CJK, Thai and their
// neighbours) and any other letter is a gap too: "成人xxx" holds the word "xxx".
func normalize(text string) string {
	text = norm.NFKC.String(text)

	var sb strings.Builder
	sb.Grow(len(text) + 2)
	sb.WriteByte(' ')

	prev := classSpace
	for _, r := range text {
		class := classOf(r)

		// A combining mark belongs to the rune before it, whatever its own script: a
		// Latin accent or a Japanese voicing mark is part of the letter it sits on,
		// not the start of a new word.
		if unicode.Is(unicode.M, r) && prev != classSpace {
			sb.WriteRune(r)
			continue
		}

		switch class {
		case classSpace:
			if prev != classSpace {
				sb.WriteByte(' ')
			}
		default:
			if prev != classSpace && prev != class {
				sb.WriteByte(' ')
			}
			sb.WriteRune(unicode.ToLower(r))
		}
		prev = class
	}
	if prev != classSpace {
		sb.WriteByte(' ')
	}
	return sb.String()
}

func classOf(r rune) int {
	switch {
	case isCont(r):
		return classCont
	case unicode.IsLetter(r), unicode.IsNumber(r), unicode.Is(unicode.M, r):
		return classWord
	default:
		return classSpace
	}
}

func isCont(r rune) bool {
	// The prolonged sound mark is Common script, but it only ever appears inside
	// Katakana words.
	if r == 'ー' {
		return true
	}
	return unicode.In(r, contScripts...)
}
