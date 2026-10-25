package main

import (
	"testing"

	"enode/config"
	"enode/ed2k"
)

// The PR_NAT bits: 0x40000 on the TCP word only (logged-in clients), the wake on
// both words, and the NAT port advertised whenever a client may use PR_NAT here.
// serverIndependent is ignored.
func TestServerListenConfigsNatFlags(t *testing.T) {
	off := false
	cases := []struct {
		name                 string
		nat                  config.NATConfig
		wantRendezvous, wake bool
	}{
		{"defaults", config.NATConfig{Enabled: true, Port: 2004}, true, true},
		{"serverIndependent ignored", config.NATConfig{Enabled: true, Port: 2004, ServerIndependent: &off}, true, true},
		{"no wake", config.NATConfig{Enabled: true, Port: 2004, TCPWake: &off}, true, false},
		{"service off", config.NATConfig{Port: 2004}, false, false},
	}
	for _, tc := range cases {
		cfg := config.Config{NAT: tc.nat}
		tcpRT, udpRT := buildRuntimeConfigs(cfg, bootDerived{})
		t.Logf("input: %s, output: tcp=0x%x udp=0x%x natPort=%d", tc.name, tcpRT.Flags, udpRT.UDPFlags, tcpRT.NatRendezvousPort)
		if (tcpRT.Flags&ed2k.FlagNatRendezvous != 0) != tc.wantRendezvous || udpRT.UDPFlags&ed2k.FlagNatRendezvous != 0 {
			t.Fatalf("%s: rendezvous tcp=0x%x udp=0x%x, want tcp=%t udp=false", tc.name, tcpRT.Flags, udpRT.UDPFlags, tc.wantRendezvous)
		}
		for word, flags := range map[string]uint32{"tcp": tcpRT.Flags, "udp": udpRT.UDPFlags} {
			if (flags&ed2k.FlagNatWake != 0) != tc.wake {
				t.Fatalf("%s: %s flags 0x%x, want wake=%t", tc.name, word, flags, tc.wake)
			}
		}
		if wantPort := tc.wantRendezvous || tc.wake; (tcpRT.NatRendezvousPort != 0) != wantPort {
			t.Fatalf("%s: NAT port %d, want advertised=%t", tc.name, tcpRT.NatRendezvousPort, wantPort)
		}
	}
}

// The foreign callback flag (UDP 0x400000) follows natTraversal.foreignCallback, and
// only where the Lugdunum callback itself is effective.
func TestServerListenConfigsForeignCallback(t *testing.T) {
	off := false
	cases := []struct {
		name string
		cfg  config.Config
		want bool
	}{
		{"defaults", config.Config{SupportCrypt: true, TCP: config.TCPConfig{AllowLowIDs: true}}, true},
		{"foreignCallback off", config.Config{SupportCrypt: true, TCP: config.TCPConfig{AllowLowIDs: true}, NAT: config.NATConfig{ForeignCallback: &off}}, false},
		{"lugdunum callback off", config.Config{SupportCrypt: true, TCP: config.TCPConfig{AllowLowIDs: true}, NAT: config.NATConfig{LugdunumCallback: &off}}, false},
		{"no crypt", config.Config{TCP: config.TCPConfig{AllowLowIDs: true}}, false},
		{"no LowIDs", config.Config{SupportCrypt: true}, false},
	}
	for _, tc := range cases {
		tcpRT, udpRT := buildRuntimeConfigs(tc.cfg, bootDerived{})
		t.Logf("input: %s, output: udp=0x%x", tc.name, udpRT.UDPFlags)
		if (udpRT.UDPFlags&ed2k.FlagForeignCallback != 0) != tc.want || tcpRT.Flags&ed2k.FlagForeignCallback != 0 {
			t.Fatalf("%s: udp=0x%x tcp=0x%x, want foreign=%t on UDP only", tc.name, udpRT.UDPFlags, tcpRT.Flags, tc.want)
		}
	}
}
