package main

import (
	"testing"

	"enode/config"
	"enode/ed2k"
)

// The PR_NAT bits reach both flag words, and the NAT port is advertised whenever a
// client may use PR_NAT here.
func TestServerListenConfigsNatFlags(t *testing.T) {
	off := false
	cases := []struct {
		name                 string
		nat                  config.NATConfig
		wantRendezvous, wake bool
	}{
		{"defaults", config.NATConfig{Enabled: true, Port: 2004}, true, true},
		{"restricted", config.NATConfig{Enabled: true, Port: 2004, ServerIndependent: &off}, false, true},
		{"no wake", config.NATConfig{Enabled: true, Port: 2004, TCPWake: &off}, true, false},
		{"service off", config.NATConfig{Port: 2004}, false, false},
	}
	for _, tc := range cases {
		cfg := config.Config{NAT: tc.nat}
		tcpRT, udpRT := buildRuntimeConfigs(cfg, bootDerived{})
		t.Logf("input: %s, output: tcp=0x%x udp=0x%x natPort=%d", tc.name, tcpRT.Flags, udpRT.UDPFlags, tcpRT.NatRendezvousPort)
		for word, flags := range map[string]uint32{"tcp": tcpRT.Flags, "udp": udpRT.UDPFlags} {
			if (flags&ed2k.FlagNatRendezvous != 0) != tc.wantRendezvous || (flags&ed2k.FlagNatWake != 0) != tc.wake {
				t.Fatalf("%s: %s flags 0x%x, want rendezvous=%t wake=%t", tc.name, word, flags, tc.wantRendezvous, tc.wake)
			}
		}
		if wantPort := tc.wantRendezvous || tc.wake; (tcpRT.NatRendezvousPort != 0) != wantPort {
			t.Fatalf("%s: NAT port %d, want advertised=%t", tc.name, tcpRT.NatRendezvousPort, wantPort)
		}
	}
}
