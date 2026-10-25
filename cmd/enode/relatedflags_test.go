package main

import (
	"testing"

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
