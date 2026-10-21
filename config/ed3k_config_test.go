package config

import (
	"path/filepath"
	"testing"
)

func TestEd3kDefaults(t *testing.T) {
	var c Ed3kConfig
	if err := setEd3kDefaults(&c); err != nil {
		t.Fatal(err)
	}
	t.Logf("input: empty ed3k section output: %+v", c)
	if c.Enabled || c.Port != 0 || c.KeyFile != filepath.Join(DataDir, "ed3k.key") || c.RequestsPerMinute != 120 ||
		c.Limits.MaxConnections != 50000 || c.Bridge.Enabled != nil || c.Bridge.MaxPerAnswer != 20 {
		t.Fatalf("defaults %+v", c)
	}
}

// TestEd3kBridgeActive: the bridge is on by default, can be turned off, and never
// runs while ed3k itself is off.
func TestEd3kBridgeActive(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name    string
		enabled bool
		bridge  *bool
		want    bool
	}{
		{"ed3k on, bridge absent", true, nil, true},
		{"ed3k on, bridge true", true, &yes, true},
		{"ed3k on, bridge false", true, &no, false},
		{"ed3k off, bridge absent", false, nil, false},
		{"ed3k off, bridge true", false, &yes, false},
	}
	for _, c := range cases {
		cfg := Ed3kConfig{Enabled: c.enabled, Bridge: Ed3kBridgeConfig{Enabled: c.bridge}}
		got := cfg.BridgeActive()
		t.Logf("input: %s output: %v", c.name, got)
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestEd3kValidation(t *testing.T) {
	cases := []struct {
		name string
		c    Ed3kConfig
		ok   bool
	}{
		{"off, anything goes", Ed3kConfig{Advertise: "nonsense"}, true},
		{"advertise IPv4", Ed3kConfig{Enabled: true, Advertise: "81.2.3.4"}, true},
		{"advertise an IPv6 as IPv4", Ed3kConfig{Enabled: true, Advertise: "2a00::1"}, false},
		{"advertiseIPv6 an IPv4", Ed3kConfig{Enabled: true, AdvertiseIPv6: "81.2.3.4"}, false},
		{"listen not an IP", Ed3kConfig{Enabled: true, Listen: "eth0"}, false},
		{"network of 33 bytes", Ed3kConfig{Enabled: true, Network: "123456789012345678901234567890123"}, false},
	}
	for _, c := range cases {
		err := setEd3kDefaults(&c.c)
		t.Logf("%s -> %v", c.name, err)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
}
