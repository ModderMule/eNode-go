package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadYAML(t *testing.T, body string) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enode.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

// TestMetaSearchDefaults: an absent section is off, and every knob gets a usable
// default, including the per-network URL and prefix.
func TestMetaSearchDefaults(t *testing.T) {
	cfg, err := loadYAML(t, "name: test\n")
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.MetaSearch
	t.Logf("input: no metaSearch section; output: %+v", m)
	if m.AnyEnabled() {
		t.Fatal("meta search must be off by default")
	}
	if !m.AdvertiseToLegacyClientsOrDefault() || m.UDPMaxConcurrent != 16 {
		t.Fatalf("advertise=%t udpMaxConcurrent=%d", m.AdvertiseToLegacyClientsOrDefault(), m.UDPMaxConcurrent)
	}
	if m.Torrent.URL != DefaultTorrentURL || m.Usenet.URL != DefaultUsenetURL {
		t.Fatalf("urls %q / %q", m.Torrent.URL, m.Usenet.URL)
	}
	if m.Torrent.NamePrefixOrDefault(DefaultTorrentNamePrefix) != "[torrent] " ||
		m.Usenet.NamePrefixOrDefault(DefaultUsenetNamePrefix) != "[usenet] " {
		t.Fatal("default prefixes wrong")
	}
	if !m.Torrent.LiveSearchOrDefault() || m.Torrent.SearchTimeoutMs != 1500 || m.Torrent.UDPSearchTimeoutMs != 800 ||
		m.Torrent.MaxResults != 50 || m.Torrent.MaxUDPResults != 10 || m.Torrent.Feed.MaxRows != 250000 {
		t.Fatalf("torrent defaults %+v", m.Torrent)
	}
	if m.Torrent.CountInServerStatus || m.Usenet.CountInServerStatus {
		t.Fatal("countInServerStatus must be off by default")
	}
	if m.Cache.MaxEntries != 1000 || m.Cache.MaxRowsPerEntry != 100 || m.Cache.TTLSeconds != 600 {
		t.Fatalf("cache defaults %+v", m.Cache)
	}
}

// TestMetaSearchExplicitEmptyPrefix: "" means no prefix, not "use the default".
func TestMetaSearchExplicitEmptyPrefix(t *testing.T) {
	cfg, err := loadYAML(t, "metaSearch:\n  usenet:\n    enabled: true\n    namePrefix: \"\"\n")
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.MetaSearch.Usenet.NamePrefixOrDefault(DefaultUsenetNamePrefix)
	t.Logf("input: namePrefix \"\"; output: %q", got)
	if got != "" {
		t.Fatalf("prefix %q, want none", got)
	}
}

func TestMetaSearchValidation(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{"bad url on enabled network", "metaSearch:\n  torrent:\n    enabled: true\n    url: \"127.0.0.1:9701\"\n", "metaSearch.torrent.url"},
		{"bad url on disabled network is fine", "metaSearch:\n  torrent:\n    url: \"nonsense\"\n", ""},
		{"udp cap", "metaSearch:\n  usenet:\n    maxUDPResults: 51\n", "maxUDPResults"},
		{"result cap", "metaSearch:\n  usenet:\n    maxResults: 1001\n", "maxResults"},
		{"backoff order", "metaSearch:\n  torrent:\n    feed:\n      reconnectMinSeconds: 60\n      reconnectMaxSeconds: 10\n", "reconnectMaxSeconds"},
	}
	for _, tc := range cases {
		_, err := loadYAML(t, tc.yaml)
		t.Logf("input: %s; output: err=%v", tc.name, err)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: err=%v, want one naming %q", tc.name, err, tc.wantErr)
		}
	}
}
