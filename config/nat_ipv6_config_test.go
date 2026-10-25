package config

import "testing"

func TestNATIPv6DefaultsEnabled(t *testing.T) {
	// natTraversal.ipv6 omitted must default to true (the *bool absent-key pattern).
	cfg, err := Load(writeTempConfig(t, "name: t\nnatTraversal:\n  enabled: true\n  port: 2004\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("natTraversal.ipv6 omitted -> IPv6OrDefault()=%v", cfg.NAT.IPv6OrDefault())
	if !cfg.NAT.IPv6OrDefault() {
		t.Fatal("natTraversal.ipv6 should default to enabled")
	}
}

func TestNATIPv6HonoursExplicitFalse(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, "name: t\nnatTraversal:\n  enabled: true\n  port: 2004\n  ipv6: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("natTraversal.ipv6: false -> IPv6OrDefault()=%v", cfg.NAT.IPv6OrDefault())
	if cfg.NAT.IPv6OrDefault() {
		t.Fatal("natTraversal.ipv6: false must disable IPv6 hole-punching")
	}
}

// natTraversal.serverIndependent is retired: an old config that sets it still loads.
func TestNATServerIndependentKeyIgnored(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, "name: t\nnatTraversal:\n  enabled: true\n  port: 2004\n  serverIndependent: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: serverIndependent: false, output: loaded, key set=%t", cfg.NAT.ServerIndependent != nil)
	if cfg.NAT.ServerIndependent == nil || !cfg.NAT.Enabled {
		t.Fatal("old config with serverIndependent must still load")
	}
}

func TestNATForeignCallbackDefault(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, "name: t\nnatTraversal:\n  enabled: true\n  port: 2004\n"))
	if err != nil {
		t.Fatal(err)
	}
	off, err := Load(writeTempConfig(t, "name: t\nnatTraversal:\n  foreignCallback: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: omitted / false, output: %t / %t", cfg.NAT.ForeignCallbackOrDefault(), off.NAT.ForeignCallbackOrDefault())
	if !cfg.NAT.ForeignCallbackOrDefault() || off.NAT.ForeignCallbackOrDefault() {
		t.Fatal("natTraversal.foreignCallback must default on and honour false")
	}
}
