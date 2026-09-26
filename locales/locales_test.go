package locales

import (
	"strings"
	"testing"
)

// TestEveryLanguageHasEveryCode fails when a MsgCode was added to one language file
// but not the others: the fallback would hide it at run time.
func TestEveryLanguageHasEveryCode(t *testing.T) {
	want := Codes(Default)
	t.Logf("input: %d codes in %s.json, languages %v", len(want), Default, Languages())
	for _, lang := range Languages() {
		have := map[string]bool{}
		for _, c := range Codes(lang) {
			have[c] = true
		}
		for _, c := range want {
			if !have[c] {
				t.Errorf("%s.json is missing %q", lang, c)
			}
		}
		for c := range have {
			if !Has(c) {
				t.Errorf("%s.json has %q, which %s.json lacks", lang, c, Default)
			}
		}
		for _, c := range Codes(lang) {
			if strings.TrimSpace(T(lang, c)) == "" {
				t.Errorf("%s.json has an empty text for %q", lang, c)
			}
		}
		t.Logf("output: %s has %d codes", lang, len(have))
	}
}

func TestTFallsBack(t *testing.T) {
	cases := []struct{ lang, code, want string }{
		{"de", "auth.required", T("de", "auth.required")},
		{"xx", "auth.required", T(Default, "auth.required")},
		{"de", "no.such.code", "no.such.code"},
	}
	for _, c := range cases {
		got := T(c.lang, c.code)
		t.Logf("input: lang=%q code=%q output: %q", c.lang, c.code, got)
		if got != c.want {
			t.Errorf("T(%q,%q) = %q, want %q", c.lang, c.code, got, c.want)
		}
	}
	if T("de", "auth.required") == T(Default, "auth.required") {
		t.Errorf("de translation of auth.required equals the English text")
	}
}

func TestNegotiate(t *testing.T) {
	cases := map[string]string{
		"":                            Default,
		"de-DE,de;q=0.9,en;q=0.8":     "de",
		"fr-FR,fr;q=0.9":              Default,
		"fr-FR, en-US;q=0.8, de;q=.5": "en",
		"DE":                          "de",
	}
	for header, want := range cases {
		got := Negotiate(header)
		t.Logf("input: Accept-Language=%q output: %q", header, got)
		if got != want {
			t.Errorf("Negotiate(%q) = %q, want %q", header, got, want)
		}
	}
}
