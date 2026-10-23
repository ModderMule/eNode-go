package spamfilter

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// badSignalTokens are the words a name uses to say the file is broken or fake, as in
// eMuleQt's FakeFileRules::defaults. No bare "password": it is in the name of every
// password recovery tool.
var badSignalTokens = []string{"fake", "corrupt", "wrong file", "password protected", "virus", "trojan", "malware"}

// badSignalPatterns are the names that hide a program behind a media extension.
var badSignalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\.mp4\.exe$`),
	regexp.MustCompile(`(?i)\.avi\.scr$`),
}

// assessNames checks the name for what eMuleQt calls a bad signal. Words that put a
// file on a blocklist are filter.keywords' job, not this package's.
func assessNames(r Record, v *Verdict) {
	if matchesBadSignal(r.Name) {
		v.add(ReasonBadSignalName, pointsBadSignalName)
	}
}

func matchesBadSignal(name string) bool {
	if name == "" {
		return false
	}
	words := paddedWords(name)
	for _, token := range badSignalTokens {
		if strings.Contains(words, " "+token+" ") {
			return true
		}
	}
	for _, re := range badSignalPatterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// foldName is the name in lower case with its accents taken off: "Fäke" is "fake".
func foldName(name string) string {
	decomposed := strings.ToLower(norm.NFKD.String(name))
	var sb strings.Builder
	sb.Grow(len(decomposed))
	for _, c := range decomposed {
		if !unicode.Is(unicode.Mn, c) {
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

// paddedWords is the folded name as words separated by single spaces, with a space at
// each end, so a token is found as " token ".
func paddedWords(name string) string {
	words := strings.FieldsFunc(foldName(name), func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c)
	})
	return " " + strings.Join(words, " ") + " "
}
