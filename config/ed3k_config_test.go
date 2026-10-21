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
		c.Limits.MaxConnections != 50000 || c.Bridge.Enabled || c.Bridge.MaxPerAnswer != 20 {
		t.Fatalf("defaults %+v", c)
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
