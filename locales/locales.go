// Package locales translates MsgCodes: the stable, dotted codes (such as
// "auth.required") that the Meta API returns in errors and status replies and that
// the account website shows. A client may translate a code itself; the text here is
// what the server shows on its own pages and puts in error messages.
//
// Each language is one flat JSON file, code → text. English is the fallback for a
// missing language and for a code missing from a language. Every code must exist in
// en.json; locales_test.go checks that every language has the same codes.
package locales

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Default is the fallback language.
const Default = "en"

//go:embed *.json
var files embed.FS

// catalog is language → code → text, loaded once at init.
var catalog = mustLoad()

// T returns the text for code in lang, falling back to English, then to the code
// itself so a missing translation is visible rather than blank.
func T(lang, code string) string {
	if text, ok := catalog[lang][code]; ok {
		return text
	}
	if text, ok := catalog[Default][code]; ok {
		return text
	}
	return code
}

// Has reports whether code exists in the default language.
func Has(code string) bool {
	_, ok := catalog[Default][code]
	return ok
}

// Languages returns the available languages, sorted.
func Languages() []string {
	out := make([]string, 0, len(catalog))
	for lang := range catalog {
		out = append(out, lang)
	}
	sort.Strings(out)
	return out
}

// Codes returns every code of one language, sorted.
func Codes(lang string) []string {
	out := make([]string, 0, len(catalog[lang]))
	for code := range catalog[lang] {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

// Negotiate picks the best available language for an Accept-Language header,
// honouring the order the client listed them in (q-values are not weighed: browsers
// list languages in preference order already).
func Negotiate(acceptLanguage string) string {
	for _, part := range strings.Split(acceptLanguage, ",") {
		tag := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		base := strings.ToLower(strings.SplitN(tag, "-", 2)[0])
		if _, ok := catalog[base]; ok {
			return base
		}
	}
	return Default
}

func mustLoad() map[string]map[string]string {
	entries, err := files.ReadDir(".")
	if err != nil {
		panic(fmt.Sprintf("locales: %v", err))
	}
	out := map[string]map[string]string{}
	for _, e := range entries {
		b, err := files.ReadFile(e.Name())
		if err != nil {
			panic(fmt.Sprintf("locales: %v", err))
		}
		var m map[string]string
		if err := json.Unmarshal(b, &m); err != nil {
			panic(fmt.Sprintf("locales: %s: %v", e.Name(), err))
		}
		out[strings.TrimSuffix(e.Name(), ".json")] = m
	}
	if _, ok := out[Default]; !ok {
		panic("locales: " + Default + ".json is missing")
	}
	return out
}
