package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLowIDAndConnectionTimeoutDefaults covers a short config: absent keys must admit
// LowID clients and give the dial-back a timeout, and an explicit false must stay off.
func TestLowIDAndConnectionTimeoutDefaults(t *testing.T) {
	cases := []struct {
		name        string
		yaml        string
		wantAllow   bool
		wantTimeout int
	}{
		{"absent", "name: short\n", true, DefaultConnectionTimeoutMs},
		{"zero timeout", "tcp:\n  connectionTimeout: 0\n", true, DefaultConnectionTimeoutMs},
		{"negative timeout", "tcp:\n  connectionTimeout: -5\n", true, DefaultConnectionTimeoutMs},
		{"explicit values", "tcp:\n  allowLowIDs: true\n  connectionTimeout: 750\n", true, 750},
		{"LowIDs off", "tcp:\n  allowLowIDs: false\n", false, DefaultConnectionTimeoutMs},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "enode.yaml")
		if err := os.WriteFile(path, []byte(c.yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		allow, timeout := cfg.TCP.AllowLowIDsOrDefault(), cfg.TCP.ConnectionTimeout
		t.Logf("case=%q input=%q -> allowLowIDs=%v connectionTimeout=%d", c.name, c.yaml, allow, timeout)
		if allow != c.wantAllow || timeout != c.wantTimeout {
			t.Errorf("%s: got %v/%d, want %v/%d", c.name, allow, timeout, c.wantAllow, c.wantTimeout)
		}
	}
}
