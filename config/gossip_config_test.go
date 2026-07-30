package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests use the writeConfig helper from cleanup_config_test.go: it writes a
// throwaway YAML and loads it through the real Load path, so setDefaults runs exactly
// as it does at boot.

// TestGossipPortDefaultsToTCPPlus12 pins the port derivation, and the value is forced by
// the reference implementation rather than chosen.
//
// This test previously required tcp+14 — eserver's own portUDPOBF default — and that was
// wrong. Measured against the real binary on a shared Docker network: eserver recovers a
// peer's *TCP* port from the UDP source port of an obfuscated frame by subtracting 12, so a
// frame sent from tcp+14 is booked against a server two ports above the real one. It then
// logs "received a pong from unknown server", its ping bookkeeping never confirms, and the
// peer never appears in its server.met. From tcp+12 the same frame is booked correctly.
//
// The port therefore collapses onto portObfuscated deliberately; main.go shares that one
// socket rather than binding it twice. See tests/interop and docs/server-gossip.md §8.
func TestGossipPortDefaultsToTCPPlus12(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\n")
	t.Logf("input: config with no udp port keys")
	t.Logf("output: tcp=%d portObfuscated=%d portGossip=%d",
		cfg.TCP.Port, cfg.UDP.PortObfuscated, cfg.UDP.PortGossip)

	if cfg.UDP.PortGossip != cfg.TCP.Port+12 {
		t.Fatalf("portGossip = %d, want tcp.port+12 = %d", cfg.UDP.PortGossip, cfg.TCP.Port+12)
	}
	if cfg.UDP.PortGossip != cfg.UDP.PortObfuscated {
		t.Fatalf("portGossip (%d) and portObfuscated (%d) must be the same socket by default",
			cfg.UDP.PortGossip, cfg.UDP.PortObfuscated)
	}
}

// TestGossipPortDerivesFromCustomTCPPort makes sure the offset is computed from tcp.port,
// not the literal 5567 the shipped config happens to carry.
func TestGossipPortDerivesFromCustomTCPPort(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\ntcp:\n  port: 4661\n")
	t.Logf("input: tcp.port=4661; output: portObfuscated=%d portGossip=%d",
		cfg.UDP.PortObfuscated, cfg.UDP.PortGossip)
	if cfg.UDP.PortObfuscated != 4673 {
		t.Fatalf("portObfuscated = %d, want 4673 (4661+12)", cfg.UDP.PortObfuscated)
	}
	if cfg.UDP.PortGossip != 4673 {
		t.Fatalf("portGossip = %d, want 4673: gossip shares the tcp+12 socket", cfg.UDP.PortGossip)
	}
}

// TestGossipExplicitPortGossipIsHonoured covers the operator override. It is kept even
// though the default is the only value that interoperates with Lugdunum: portUDPOBF is a
// donkey.ini parameter, so a future peer implementation may want a separate socket, and
// setting this binds one and advertises it. Against a real eserver it breaks the ping
// bookkeeping — see TestGossipPortDefaultsToTCPPlus12.
func TestGossipExplicitPortGossipIsHonoured(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\nudp:\n  portGossip: 9999\n")
	t.Logf("input: udp.portGossip=9999; output: %d", cfg.UDP.PortGossip)
	if cfg.UDP.PortGossip != 9999 {
		t.Fatalf("portGossip = %d, want the configured 9999", cfg.UDP.PortGossip)
	}
}

// TestGossipTogglesDefaultOn pins the *bool defaults. A plain bool would make an
// absent key mean false — the opposite of the intended default — silently disabling
// gossip and persistence for anyone whose YAML predates these keys.
func TestGossipTogglesDefaultOn(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\n")
	t.Logf("input: config with no gossip block")
	t.Logf("output: enabled=%v publishIPv6=%v persist=%v",
		cfg.Gossip.EnabledOrDefault(), cfg.Gossip.PublishIPv6OrDefault(), cfg.Gossip.PersistOrDefault())
	if !cfg.Gossip.EnabledOrDefault() {
		t.Error("gossip.enabled must default to true")
	}
	if !cfg.Gossip.PublishIPv6OrDefault() {
		t.Error("gossip.publishIPv6 must default to true")
	}
	if !cfg.Gossip.PersistOrDefault() {
		t.Error("gossip.persist must default to true")
	}
}

// TestGossipExplicitFalseSurvivesSetDefaults is the discriminating half of the *bool
// pattern: enode.local.yaml relies on `enabled: false` actually sticking, since that
// config binds loopback and must never gossip with third parties.
func TestGossipExplicitFalseSurvivesSetDefaults(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\ngossip:\n  enabled: false\n  publishIPv6: false\n  persist: false\n")
	t.Logf("input: gossip.enabled/publishIPv6/persist all explicitly false")
	t.Logf("output: enabled=%v publishIPv6=%v persist=%v",
		cfg.Gossip.EnabledOrDefault(), cfg.Gossip.PublishIPv6OrDefault(), cfg.Gossip.PersistOrDefault())
	if cfg.Gossip.EnabledOrDefault() {
		t.Fatal("an explicit gossip.enabled=false must be honoured, not overwritten by the default")
	}
	if cfg.Gossip.PublishIPv6OrDefault() {
		t.Error("an explicit publishIPv6=false must be honoured")
	}
	if cfg.Gossip.PersistOrDefault() {
		t.Error("an explicit persist=false must be honoured")
	}
}

// TestGossipCadenceDefaults pins the timing and cap constants against eserver's.
func TestGossipCadenceDefaults(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\n")
	t.Logf("output: interval=%ds maxServers=%d maxFailures=%d persistInterval=%ds",
		cfg.Gossip.IntervalSeconds, cfg.Gossip.MaxServers,
		cfg.Gossip.MaxFailures, cfg.Gossip.PersistIntervalSeconds)
	if cfg.Gossip.IntervalSeconds != 150 {
		t.Errorf("intervalSeconds = %d, want 150 (inside Lugdunum's ~165s keepalive)", cfg.Gossip.IntervalSeconds)
	}
	if cfg.Gossip.MaxServers != 4096 {
		t.Errorf("maxServers = %d, want 4096 (eserver's maxservers default)", cfg.Gossip.MaxServers)
	}
	if cfg.Gossip.MaxFailures != 5 {
		t.Errorf("maxFailures = %d, want 5", cfg.Gossip.MaxFailures)
	}
	if cfg.Gossip.PersistIntervalSeconds != 225 {
		t.Errorf("persistIntervalSeconds = %d, want 225 (eserver's autoservlist cadence)", cfg.Gossip.PersistIntervalSeconds)
	}
}

// TestAllowPrivatePeersDefaultsOff guards the one gossip toggle that is deliberately
// a plain bool: its default is off, which is what an absent key already yields, and
// turning it on admits loopback/LAN peers.
func TestAllowPrivatePeersDefaultsOff(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\n")
	t.Logf("output: allowPrivatePeers=%v", cfg.Gossip.AllowPrivatePeers)
	if cfg.Gossip.AllowPrivatePeers {
		t.Fatal("allowPrivatePeers must default to off")
	}
}

// TestAppWrittenFilesDefaultUnderDataDir pins the layout split: things the server
// writes go under data/ (gitignored), operator-supplied inputs stay in the root.
func TestAppWrittenFilesDefaultUnderDataDir(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\n")
	t.Logf("output: serverMetFile=%q geoipDatabase=%q ipfilterFile=%q",
		cfg.Gossip.ServerMetFile, cfg.Filter.GeoIP.Database, cfg.Filter.IPFilter.File)

	for name, got := range map[string]string{
		"gossip.serverMetFile":  cfg.Gossip.ServerMetFile,
		"filter.geoip.database": cfg.Filter.GeoIP.Database,
	} {
		if !strings.HasPrefix(got, DataDir+string(filepath.Separator)) && !strings.HasPrefix(got, DataDir+"/") {
			t.Errorf("%s = %q, want it under %s/ — the server writes this file", name, got, DataDir)
		}
	}
	// The range list is supplied by the operator, so it must NOT be forced under data/.
	if strings.Contains(cfg.Filter.IPFilter.File, DataDir) {
		t.Errorf("filter.ipfilter.file = %q, want it outside %s/ — it is operator-supplied, not written by us",
			cfg.Filter.IPFilter.File, DataDir)
	}
}

// TestResolveDataPathIsWorkingDirectoryIndependent is the reason ResolveDataPath
// exists: these tests run with config/ as the working directory, so a bare
// "data/server.met" would otherwise mean config/data/server.met here and
// ed2k/data/server.met in another package.
func TestResolveDataPathIsWorkingDirectoryIndependent(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\n")
	resolved := cfg.ServerMetPath()
	wd, _ := os.Getwd()
	t.Logf("input: %q with working directory %s", cfg.Gossip.ServerMetFile, wd)
	t.Logf("output: %q", resolved)

	if resolved == "" {
		t.Fatal("ServerMetPath returned empty")
	}
	// Resolved against the module root, so from config/ it must climb out of the
	// package directory rather than naming config/data/server.met.
	abs, err := filepath.Abs(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(abs, filepath.Join("config", DataDir)) {
		t.Fatalf("resolved to %s: a package-relative path, not the module-root data/", abs)
	}
	if filepath.Base(abs) != "server.met" {
		t.Errorf("resolved basename = %q, want server.met", filepath.Base(abs))
	}
	// An empty config value must stay empty rather than resolving to the module root.
	if got := ResolveDataPath(""); got != "" {
		t.Errorf("ResolveDataPath(\"\") = %q, want \"\"", got)
	}
}

// TestGossipSeedsFallBackToServersList covers the compatibility path: an existing
// config with only `servers:` participates in gossip without gaining a new key, while
// an explicit gossip.seeds list wins when the operator wants the two to differ.
func TestGossipSeedsFallBackToServersList(t *testing.T) {
	fallback := writeConfig(t, "address: 127.0.0.1\nservers:\n  - ip: \"192.0.2.10\"\n    port: 4661\n")
	seeds := fallback.GossipSeeds()
	t.Logf("input: servers=[192.0.2.10:4661], no gossip.seeds")
	t.Logf("output: seeds=%v", seeds)
	if len(seeds) != 1 || seeds[0].IP != "192.0.2.10" {
		t.Fatalf("expected the servers list to be used as seeds, got %v", seeds)
	}

	explicit := writeConfig(t, "address: 127.0.0.1\n"+
		"servers:\n  - ip: \"192.0.2.10\"\n    port: 4661\n"+
		"gossip:\n  seeds:\n    - ip: \"198.51.100.5\"\n      port: 4242\n")
	seeds = explicit.GossipSeeds()
	t.Logf("input: servers=[192.0.2.10], gossip.seeds=[198.51.100.5:4242]")
	t.Logf("output: seeds=%v", seeds)
	if len(seeds) != 1 || seeds[0].IP != "198.51.100.5" || seeds[0].Port != 4242 {
		t.Fatalf("explicit gossip.seeds must win over servers, got %v", seeds)
	}
}

// TestGeoIPHasCredentialsRequiresBoth pins why HasCredentials is not a simple
// non-empty check: a half-filled config must mean "local file only", not "download
// with a broken account", which would fail on every weekly tick.
func TestGeoIPHasCredentialsRequiresBoth(t *testing.T) {
	cases := []struct {
		account, key string
		want         bool
	}{
		{"", "", false},
		{"12345", "", false},
		{"", "somekey", false},
		{"12345", "somekey", true},
	}
	for _, c := range cases {
		got := GeoIPConfig{AccountID: c.account, LicenseKey: c.key}.HasCredentials()
		t.Logf("accountID=%q licenseKey=%q -> HasCredentials=%v", c.account, c.key, got)
		if got != c.want {
			t.Errorf("HasCredentials(%q,%q) = %v, want %v", c.account, c.key, got, c.want)
		}
	}
}
