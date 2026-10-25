package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRelatedSearchDefaults covers tcp.relatedSearch: on with a floor of 5 users when
// absent, off when said so, and a floor of 0 or less falling back to 5.
func TestRelatedSearchDefaults(t *testing.T) {
	ptr := func(v int) *int { return &v }
	off := false
	cases := []struct {
		name        string
		in          RelatedSearchConfig
		wantEnabled bool
		wantMin     int
	}{
		{"absent", RelatedSearchConfig{}, true, 5},
		{"off", RelatedSearchConfig{Enabled: &off}, false, 5},
		{"floor 10", RelatedSearchConfig{MinClients: ptr(10)}, true, 10},
		{"floor 1", RelatedSearchConfig{MinClients: ptr(1)}, true, 1},
		{"floor 0", RelatedSearchConfig{MinClients: ptr(0)}, true, 5},
		{"negative floor", RelatedSearchConfig{MinClients: ptr(-2)}, true, 5},
	}
	for _, c := range cases {
		enabled, minClients := c.in.EnabledOrDefault(), c.in.MinClientsOrDefault()
		t.Logf("case=%q -> enabled=%t minClients=%d", c.name, enabled, minClients)
		if enabled != c.wantEnabled || minClients != c.wantMin {
			t.Errorf("%s: got %t/%d, want %t/%d", c.name, enabled, minClients, c.wantEnabled, c.wantMin)
		}
	}
}

// TestRelatedSearchFromYAML reads the keys as an operator writes them.
func TestRelatedSearchFromYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enode.config.yaml")
	yaml := "tcp:\n  port: 5555\n  relatedSearch:\n    enabled: false\n    minClients: 8\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	rs := cfg.TCP.RelatedSearch
	t.Logf("input: %q -> output: enabled=%t minClients=%d", yaml, rs.EnabledOrDefault(), rs.MinClientsOrDefault())
	if rs.EnabledOrDefault() || rs.MinClientsOrDefault() != 8 {
		t.Fatalf("got enabled=%t minClients=%d", rs.EnabledOrDefault(), rs.MinClientsOrDefault())
	}
}
