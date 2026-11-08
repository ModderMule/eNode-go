package main

import (
	"testing"
	"time"

	"enode/config"
	"enode/ed2k"
)

// tcp.relatedSearch reaches the advertised TCP word and the runtime: on by default
// with a floor of 5 users.
func TestServerListenConfigsRelatedSearch(t *testing.T) {
	off := false
	seven := 7
	cases := []struct {
		name    string
		rs      config.RelatedSearchConfig
		wantOn  bool
		wantMin int
	}{
		{"defaults", config.RelatedSearchConfig{}, true, 5},
		{"off", config.RelatedSearchConfig{Enabled: &off}, false, 5},
		{"floor 7", config.RelatedSearchConfig{MinClients: &seven}, true, 7},
	}
	for _, tc := range cases {
		cfg := config.Config{TCP: config.TCPConfig{RelatedSearch: tc.rs}}
		tcpRT, _ := buildRuntimeConfigs(cfg, bootDerived{})
		t.Logf("input: %s, output: tcp flags=0x%x related=%t minClients=%d", tc.name, tcpRT.Flags, tcpRT.RelatedSearch, tcpRT.RelatedMinClients)
		if (tcpRT.Flags&ed2k.FlagRelatedSearch != 0) != tc.wantOn || tcpRT.RelatedSearch != tc.wantOn || tcpRT.RelatedMinClients != tc.wantMin {
			t.Fatalf("%s: flags 0x%x related=%t minClients=%d, want on=%t min=%d",
				tc.name, tcpRT.Flags, tcpRT.RelatedSearch, tcpRT.RelatedMinClients, tc.wantOn, tc.wantMin)
		}
	}
}

// tcp.firewallRecheck reaches the advertised TCP word (0x800000) and the runtime: on by
// default, every 120 s.
func TestServerListenConfigsFirewallRecheck(t *testing.T) {
	off := false
	thirty := 30
	cases := []struct {
		name         string
		tcp          config.TCPConfig
		wantOn       bool
		wantInterval time.Duration
	}{
		{"defaults", config.TCPConfig{}, true, 120 * time.Second},
		{"off", config.TCPConfig{FirewallRecheck: &off}, false, 120 * time.Second},
		{"every 30s", config.TCPConfig{FirewallRecheckInterval: &thirty}, true, 30 * time.Second},
	}
	for _, tc := range cases {
		tcpRT, _ := buildRuntimeConfigs(config.Config{TCP: tc.tcp}, bootDerived{})
		t.Logf("input: %s, output: tcp flags=0x%x recheck=%t interval=%s", tc.name, tcpRT.Flags, tcpRT.FirewallRecheck, tcpRT.FirewallRecheckInterval)
		if (tcpRT.Flags&ed2k.FlagFirewallRecheck != 0) != tc.wantOn || tcpRT.FirewallRecheck != tc.wantOn || tcpRT.FirewallRecheckInterval != tc.wantInterval {
			t.Fatalf("%s: flags 0x%x recheck=%t interval=%s, want on=%t interval=%s",
				tc.name, tcpRT.Flags, tcpRT.FirewallRecheck, tcpRT.FirewallRecheckInterval, tc.wantOn, tc.wantInterval)
		}
	}
}
