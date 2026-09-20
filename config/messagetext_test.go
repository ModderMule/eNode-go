package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMessageTextNewlineStyles pins that every YAML style an operator might reach for
// lands on the same LF-separated string. The double-quoted and single-quoted forms are
// the interesting pair: YAML honours \n escapes only inside double quotes, so without
// normalizeMessageText the single-quoted form would ship a literal backslash-n.
func TestMessageTextNewlineStyles(t *testing.T) {
	const wantLogin = "Welcome to eNode!\nSecond line."

	cases := []struct {
		name string
		yaml string
	}{
		{"literal block scalar", "messageLogin: |-\n  Welcome to eNode!\n  Second line."},
		{"literal block scalar, trailing newline kept by |", "messageLogin: |\n  Welcome to eNode!\n  Second line.\n"},
		{"double-quoted, YAML decodes the escape", `messageLogin: "Welcome to eNode!\nSecond line."`},
		{"single-quoted, we decode the escape", `messageLogin: 'Welcome to eNode!\nSecond line.'`},
		{"double-quoted CRLF escape", `messageLogin: "Welcome to eNode!\r\nSecond line."`},
		{"single-quoted CRLF escape", `messageLogin: 'Welcome to eNode!\r\nSecond line.'`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("input: %s", tc.yaml)

			cfg := loadFromYAML(t, tc.yaml)

			t.Logf("output: MessageLogin = %q", cfg.MessageLogin)
			if cfg.MessageLogin != wantLogin {
				t.Errorf("MessageLogin is %q, want %q", cfg.MessageLogin, wantLogin)
			}
		})
	}
}

// TestMessageTextTrimsTrailingNewlines guards the blank line a naive client would draw.
// Both eMule trees skip empty tokens when splitting, so a trailing newline is invisible
// there, but a client splitting on the literal separator would render it.
func TestMessageTextTrimsTrailingNewlines(t *testing.T) {
	const in = "messageLogin: \"Welcome!\\n\\n\"\nmessageLowID: \"You have LowID.\\r\\n\""
	t.Logf("input: %s", in)

	cfg := loadFromYAML(t, in)

	t.Logf("output: MessageLogin = %q, MessageLowID = %q", cfg.MessageLogin, cfg.MessageLowID)
	if cfg.MessageLogin != "Welcome!" {
		t.Errorf("MessageLogin is %q, want %q", cfg.MessageLogin, "Welcome!")
	}
	if cfg.MessageLowID != "You have LowID." {
		t.Errorf("MessageLowID is %q, want %q", cfg.MessageLowID, "You have LowID.")
	}
}

// TestShippedConfigsCarryMultiLineLogin reads the two YAMLs actually shipped, so the
// documented multi-line form cannot rot into a single line unnoticed. enode.local.yaml
// is gitignored and skipped when absent, matching config_parity_test.go.
func TestShippedConfigsCarryMultiLineLogin(t *testing.T) {
	for _, path := range []string{shippedConfigPath, localConfigPath} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				t.Skipf("%s absent (gitignored)", path)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load(%s): %v", path, err)
			}
			t.Logf("input: %s", path)
			t.Logf("output: MessageLogin = %q", cfg.MessageLogin)

			lines := 1
			for _, r := range cfg.MessageLogin {
				if r == '\n' {
					lines++
				}
			}
			if lines < 2 {
				t.Errorf("messageLogin in %s is a single line (%q); the multi-line block "+
					"documented in that file has been lost", path, cfg.MessageLogin)
			}
			if cfg.MessageLogin != normalizeMessageText(cfg.MessageLogin) {
				t.Errorf("messageLogin in %s is not normalized after Load: %q", path, cfg.MessageLogin)
			}
		})
	}
}

// TestShippedLoginMessageIsClientSafe guards the rules a server message has to obey to
// reach the user's info pane intact, for both shipped configs. It asserts RULES, never the
// wording: the promo link in messageLogin is free to be reworded, but it cannot silently
// stop being a link. See docs/server-client-communication.md, "Multi-line server messages".
//
// enode.local.yaml is gitignored and skipped when absent, matching config_parity_test.go.
func TestShippedLoginMessageIsClientSafe(t *testing.T) {
	for _, path := range []string{shippedConfigPath, localConfigPath} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				t.Skipf("%s absent (gitignored)", path)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load(%s): %v", path, err)
			}
			t.Logf("input: %s", path)

			for _, field := range []struct {
				key   string
				value string
			}{
				{"messageLogin", cfg.MessageLogin},
				{"messageLowID", cfg.MessageLowID},
			} {
				t.Logf("output: %s = %q", field.key, field.value)
				for i, line := range strings.Split(field.value, "\n") {
					for _, problem := range clientSafetyProblems(line) {
						t.Errorf("%s line %d %s: %q", field.key, i+1, problem, line)
					}
				}
			}
		})
	}
}

// TestClientSafeLineRules is the negative half of TestShippedLoginMessageIsClientSafe: it
// proves each rule actually fires, so the shipped-config check cannot pass by doing nothing.
func TestClientSafeLineRules(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantBad bool
	}{
		{"the shipped promo line", "Get eMule-Qt, the modern open-source ed2k client: https://emule-qt.org/", false},
		{"plain ASCII prose", "An experimental ed2k server written in Go.", false},
		{"URL with no trailing slash", "Download at https://emule-qt.org", false},
		{"ed2k link last on the line", "Try ed2k://|server|127.0.0.1|4661|/", false},
		{"non-ASCII dash", "Get eMule-Qt \u2014 the modern client", true},
		{"tab is a control char", "Welcome\tto eNode-go", true},
		{"reserved prefix, server version", "server version 17.14 is what we speak", true},
		{"reserved prefix, mixed case", "Server Version 17.14 is what we speak", true},
		{"reserved prefix, ERROR", "ERROR is a word we cannot open with", true},
		{"reserved prefix, WARNING", "WARNING: read this", true},
		{"text after the URL", "Visit https://emule-qt.org/ for the client", true},
		{"URL with a trailing period", "Visit https://emule-qt.org/.", true},
		{"URL with a trailing comma", "Visit https://emule-qt.org/,", true},
		{"reserved word mid-sentence is fine", "This is not an ERROR, just a note", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("input: %q", tc.line)
			problems := clientSafetyProblems(tc.line)
			t.Logf("output: %d problem(s) %v", len(problems), problems)
			if got := len(problems) > 0; got != tc.wantBad {
				t.Errorf("clientSafetyProblems(%q) flagged=%t, want %t", tc.line, got, tc.wantBad)
			}
		})
	}
}

func loadFromYAML(t *testing.T, body string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enode.config.yaml")
	if err := os.WriteFile(path, []byte(body+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// clientLinkSchemes are the URL prefixes both eMule trees turn into a clickable link in the
// server-info pane: s_apszSchemes (srchybrid/OtherFunctions.cpp:89-100, consumed by
// CHTRichEditCtrl::AppendText) and kSchemes (eMuleQt/src/gui/utils/TextLinks.h:47-52,
// consumed by linkify). Matching is case-insensitive here, which is the Qt tree's rule and a
// superset of the MFC tree's _tcsncmp.
var clientLinkSchemes = []string{
	"ed2k://", "http://", "https://", "ftp://", "www.", "ftp.", "mailto:", "magnet:?",
}

// clientSafetyProblems returns one message per way the line would be mangled by the client
// that renders it, empty when the line is safe. Returning the problems rather than failing
// in place is what lets TestClientSafeLineRules check that each rule actually fires.
func clientSafetyProblems(line string) []string {
	var problems []string

	// Rule 1: ASCII only. The text is decoded as UTF-8 only once the client knows our
	// SRV_TCPFLG_UNICODE bit, and that bit arrives in OP_IDCHANGE — which handShake sends
	// *after* both messages (srchybrid/ServerSocket.cpp:159, :291). On a first-ever connect
	// the flag is still 0 and anything outside printable ASCII is read as ANSI.
	for _, r := range line {
		if r < 0x20 || r > 0x7e {
			problems = append(problems, fmt.Sprintf("holds %q, outside printable ASCII; the client "+
				"decodes the message before SRV_TCPFLG_UNICODE reaches it in OP_IDCHANGE, so it "+
				"renders as ANSI", r))
			break
		}
	}

	// Rule 2: three leading words are reserved, anchored at the start of the line. A
	// "server version" line overwrites the version the client displays for us; ERROR and
	// WARNING are diverted to the log with bOutputMessage = false and never shown as message
	// text (srchybrid/ServerSocket.cpp:176-201,
	// eMuleQt/src/core/server/ServerConnect.cpp:1183-1211).
	if strings.HasPrefix(strings.ToLower(line), "server version") {
		problems = append(problems, `opens with "server version" (matched case-insensitively by the `+
			`client's _tcsnicmp); the client reads the rest as our version string instead of showing it`)
	}
	for _, prefix := range []string{"ERROR", "WARNING"} {
		if strings.HasPrefix(line, prefix) {
			problems = append(problems, fmt.Sprintf("opens with %q; both trees divert such a line to "+
				"the log with bOutputMessage = false, so the user never sees it in the server-info pane",
				prefix))
		}
	}

	// Rule 3: a URL has to be the last thing on its line. Both trees run the link from the
	// scheme to the next whitespace, but only the Qt tree then chops trailing ".,;:!?)"
	// (TextLinks.h:118-120) — the MFC tree does not, so punctuation touching the URL there
	// becomes part of the href. Ending the line with the URL makes the two agree.
	start := -1
	lower := strings.ToLower(line)
	for _, scheme := range clientLinkSchemes {
		if at := strings.Index(lower, scheme); at >= 0 && (start < 0 || at < start) {
			start = at
		}
	}
	if start < 0 {
		return problems
	}
	url := line[start:]
	if cut := strings.IndexAny(url, " \t"); cut >= 0 {
		return append(problems, fmt.Sprintf("continues after the URL %q; put the URL last so the MFC "+
			"tree, which does not strip trailing punctuation the way TextLinks.h:118-120 does, cannot "+
			"fold the following text into the link", url[:cut]))
	}
	if strings.ContainsAny(url[len(url)-1:], ".,;:!?)") {
		problems = append(problems, fmt.Sprintf("ends the URL %q with sentence punctuation; the MFC "+
			"tree keeps it inside the href and the link resolves to the wrong address", url))
	}
	return problems
}
