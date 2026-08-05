package config

import (
	"os"
	"path/filepath"
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
