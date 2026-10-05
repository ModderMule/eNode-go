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
	if m.Torrent.URL != DefaultTorrentURL || m.Usenet.URL != DefaultUsenetURL || m.Kad.URL != DefaultKadURL {
		t.Fatalf("urls %q / %q / %q", m.Torrent.URL, m.Usenet.URL, m.Kad.URL)
	}
	if m.Torrent.NamePrefixOrDefault(DefaultTorrentNamePrefix) != "[torrent] " ||
		m.Usenet.NamePrefixOrDefault(DefaultUsenetNamePrefix) != "[usenet] " ||
		m.Kad.NamePrefixOrDefault(DefaultKadNamePrefix) != "[kad] " {
		t.Fatal("default prefixes wrong")
	}
	if m.Kad.Enabled || m.Kad.MaxResults != 50 || m.Kad.MaxUDPResults != 10 {
		t.Fatalf("kad defaults %+v, want off with the shared limits", m.Kad)
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

// TestMetaSearchKad: the Kad network is a setting of its own, off unless enabled, with
// a configurable prefix like the other networks.
func TestMetaSearchKad(t *testing.T) {
	body := "metaSearch:\n  kad:\n    enabled: true\n    namePrefix: \"[kad emule-qt.org] \"\n"
	cfg, err := loadYAML(t, body)
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.MetaSearch
	prefix := m.Kad.NamePrefixOrDefault(DefaultKadNamePrefix)
	t.Logf("input: %q; output: kad.enabled=%t url=%q prefix=%q anyEnabled=%t torrent=%t usenet=%t",
		body, m.Kad.Enabled, m.Kad.URL, prefix, m.AnyEnabled(), m.Torrent.Enabled, m.Usenet.Enabled)
	if !m.Kad.Enabled || !m.AnyEnabled() || m.Torrent.Enabled || m.Usenet.Enabled {
		t.Fatal("enabling kad must turn on kad alone")
	}
	if m.Kad.URL != DefaultKadURL || prefix != "[kad emule-qt.org] " {
		t.Fatalf("url %q prefix %q", m.Kad.URL, prefix)
	}

	_, err = loadYAML(t, "metaSearch:\n  kad:\n    enabled: true\n    url: \"127.0.0.1:9703\"\n")
	t.Logf("input: kad url without a scheme; output: err=%v", err)
	if err == nil || !strings.Contains(err.Error(), "metaSearch.kad.url") {
		t.Fatalf("err = %v, want metaSearch.kad.url", err)
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
