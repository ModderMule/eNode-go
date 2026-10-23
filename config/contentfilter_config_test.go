package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContentFilterDefaults(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\n")
	f := cfg.Filter
	t.Logf("output: keywords=%q banlist=%+v filter=%+v whitelist=%+v reload=%d threshold=%d banMinutes=%d update=%+v",
		f.Keywords, f.HashBanlist, f.HashFilter, f.HashWhitelist, f.ReloadMinutesOrDefault(), f.BanThresholdOrDefault(), f.BanMinutes, f.Update)

	if f.ContentEnabled() || f.Update.Enabled {
		t.Fatal("the content filter and its updater must default to off")
	}
	for name, got := range map[string]string{
		"filter.hashBanlist.file":   f.HashBanlist.File,
		"filter.hashFilter.file":    f.HashFilter.File,
		"filter.hashWhitelist.file": f.HashWhitelist.File,
	} {
		if !strings.HasPrefix(got, DataDir+"/") && !strings.HasPrefix(got, DataDir+string(filepath.Separator)) {
			t.Errorf("%s = %q, want it under %s/ — the updater writes it", name, got, DataDir)
		}
	}
	if f.ReloadMinutesOrDefault() != 30 || f.BanThresholdOrDefault() != 3 || f.BanMinutes != 1440 {
		t.Errorf("reload=%d threshold=%d banMinutes=%d, want 30/3/1440", f.ReloadMinutesOrDefault(), f.BanThresholdOrDefault(), f.BanMinutes)
	}
	t.Logf("output: spam=%+v localLists=%+v", f.Spam, f.LocalLists)
	if f.Spam.Enabled || f.Spam.EnableScore || f.Spam.EnableLog || f.LocalLists.Enabled {
		t.Error("filter.spam, its switches and filter.localLists must default to off")
	}
	for name, got := range map[string]string{
		"filter.spam.logFile":             f.Spam.LogFile,
		"filter.localLists.banlistFile":   f.LocalLists.BanlistFile,
		"filter.localLists.filterFile":    f.LocalLists.FilterFile,
		"filter.localLists.whitelistFile": f.LocalLists.WhitelistFile,
	} {
		if filepath.Dir(got) != DataDir {
			t.Errorf("%s = %q, want it under %s/", name, got, DataDir)
		}
	}
	t.Logf("output: keywordBanThreshold=%d banFile=%q", f.KeywordBanThresholdOrDefault(), f.BanFile)
	if f.KeywordBanThresholdOrDefault() != 5 || f.BanFile != filepath.Join(DataDir, "bans.txt") {
		t.Errorf("keywordBanThreshold=%d banFile=%q, want 5 and %s", f.KeywordBanThresholdOrDefault(), f.BanFile, filepath.Join(DataDir, "bans.txt"))
	}
	if f.Update.IntervalHours != 168 || f.Update.MinKeepRatio != 0.5 || f.Update.PublicKey != DefaultFilterUpdatePublicKey {
		t.Errorf("update defaults = %+v, want weekly, 0.5 and the service's key", f.Update)
	}
	if !strings.HasSuffix(f.Update.BanlistURL, "/files/hash_banlist.txt") ||
		!strings.HasSuffix(f.Update.FilterURL, "/files/hash_filter.txt") ||
		!strings.HasSuffix(f.Update.WhitelistURL, "/files/whitelist_hashes.txt") {
		t.Errorf("update URLs = %q %q %q", f.Update.BanlistURL, f.Update.FilterURL, f.Update.WhitelistURL)
	}
}

func TestSpamSwitchesParse(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\nfilter:\n  spam:\n    enabled: true\n    enableScore: true\n    enableLog: false\n")
	t.Logf("input: spam enabled, enableScore true, enableLog false; output: spam=%+v", cfg.Filter.Spam)
	if s := cfg.Filter.Spam; !s.Enabled || !s.EnableScore || s.EnableLog {
		t.Errorf("spam = %+v, want enabled and scoring on, the log off", s)
	}
}

func TestContentFilterExplicitZeroIsKept(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\nfilter:\n  reloadMinutes: 0\n  banThreshold: 0\n  keywords: \"xxx|foo bar\"\n")
	t.Logf("input: reloadMinutes 0, banThreshold 0; output: reload=%d threshold=%d enabled=%t",
		cfg.Filter.ReloadMinutesOrDefault(), cfg.Filter.BanThresholdOrDefault(), cfg.Filter.ContentEnabled())
	if cfg.Filter.ReloadMinutesOrDefault() != 0 || cfg.Filter.BanThresholdOrDefault() != 0 {
		t.Fatal("an explicit 0 turns the timer and the sanction off; it must not be replaced by the default")
	}
	if !cfg.Filter.ContentEnabled() {
		t.Fatal("keywords alone enable the content filter")
	}
}

func TestContentFilterValidation(t *testing.T) {
	const lists = "  hashBanlist:\n    enabled: true\n"
	cases := []struct {
		name, body, want string
	}{
		{"keyword without a word", "  keywords: \"ok|--\"\n", "filter.keywords"},
		{"negative threshold", "  banThreshold: -1\n", "filter.banThreshold"},
		{"negative keyword threshold", "  keywordBanThreshold: -1\n", "filter.keywordBanThreshold"},
		{"negative reload", "  reloadMinutes: -5\n", "filter.reloadMinutes"},
		{"ratio above one", "  update:\n    minKeepRatio: 1.5\n", "filter.update.minKeepRatio"},
		{"reference IP is a hostname", lists + "  update:\n    enabled: true\n    referenceIP: \"peer.example\"\n", "filter.update.referenceIP"},
		{"reference IP is IPv6", lists + "  update:\n    enabled: true\n    referenceIP: \"2001:db8::1\"\n", "filter.update.referenceIP"},
		{"short public key", lists + "  update:\n    enabled: true\n    referenceIP: \"203.0.113.9\"\n    publicKey: \"abcd\"\n", "filter.update.publicKey"},
		{"update with no list on", "  update:\n    enabled: true\n    referenceIP: \"203.0.113.9\"\n", "filter.update.enabled"},
	}
	for _, tc := range cases {
		path := filepath.Join(t.TempDir(), "enode.config.yaml")
		if err := os.WriteFile(path, []byte("address: 127.0.0.1\nfilter:\n"+tc.body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		t.Logf("input: %s; output: err=%v", tc.name, err)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err=%v, want one naming %s", tc.name, err, tc.want)
		}
	}

	path := filepath.Join(t.TempDir(), "enode.config.yaml")
	if err := os.WriteFile(path, []byte("address: 127.0.0.1\nfilter:\n"+lists+"  update:\n    enabled: true\n    referenceIP: \"203.0.113.9\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	t.Logf("input: a complete update section; output: err=%v", err)
	if err != nil {
		t.Fatalf("a complete update section must load: %v", err)
	}

	// referenceIP is optional: empty stands for this server's own primary IPv4.
	if err := os.WriteFile(path, []byte("address: 127.0.0.1\nfilter:\n"+lists+"  update:\n    enabled: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	t.Logf("input: update section without referenceIP; output: referenceIP=%q err=%v", cfg.Filter.Update.ReferenceIP, err)
	if err != nil {
		t.Fatalf("an update section without referenceIP must load: %v", err)
	}
}
