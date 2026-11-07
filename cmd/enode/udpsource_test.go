package main

import (
	"net"
	"testing"

	"enode/ed2k"
)

// TestUDPSourceIPv4 covers the choice of the listeners' IPv4 source at startup: the
// advertised IP, only on a wildcard bind and only when an interface holds it.
func TestUDPSourceIPv4(t *testing.T) {
	if !ed2k.IPv4SourcePinning {
		t.Skip("IPv4 source pinning is Linux only")
	}
	local := []net.IP{net.ParseIP("176.116.0.51"), net.ParseIP("176.116.0.62"), net.ParseIP("2a0f:5f40:0:9::133")}
	cases := []struct {
		bind, advertised, want string
	}{
		{"", "176.116.0.62", "176.116.0.62"},
		{"0.0.0.0", "176.116.0.62", "176.116.0.62"},
		{"::", "176.116.0.62", "176.116.0.62"},
		{"176.116.0.62", "176.116.0.62", "<nil>"}, // a bound socket sends from its address
		{"", "203.0.113.7", "<nil>"},              // behind 1:1 NAT: not ours to send from
		{"", "", "<nil>"},
	}
	for _, c := range cases {
		got := udpSourceIPv4(c.bind, c.advertised, local).String()
		t.Logf("udpSourceIPv4(bind=%q, advertised=%q) = %s", c.bind, c.advertised, got)
		if got != c.want {
			t.Errorf("udpSourceIPv4(bind=%q, advertised=%q) = %s, want %s", c.bind, c.advertised, got, c.want)
		}
	}
}
