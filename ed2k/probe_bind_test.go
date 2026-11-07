package ed2k

import (
	"net"
	"testing"
)

func TestLocalBindForNetwork(t *testing.T) {
	cases := []struct {
		network string
		address string
		wantNil bool
		wantIP  string
	}{
		{"tcp4", "192.0.2.9", false, "192.0.2.9"},
		{"tcp6", "2001:db8::9", false, "2001:db8::9"},
		{"tcp4", "2001:db8::9", true, ""}, // family mismatch
		{"tcp6", "192.0.2.9", true, ""},   // family mismatch
		{"tcp4", "0.0.0.0", true, ""},     // wildcard
		{"tcp6", "::", true, ""},          // wildcard
		{"tcp4", "", true, ""},            // empty
		{"tcp4", "not-an-ip", true, ""},   // unparsable
	}
	for _, c := range cases {
		got := localBindForNetwork(c.network, c.address)
		if c.wantNil {
			if got != nil {
				t.Errorf("localBindForNetwork(%q, %q) = %v, want nil", c.network, c.address, got)
			}
			continue
		}
		if got == nil || got.String() != c.wantIP {
			t.Errorf("localBindForNetwork(%q, %q) = %v, want %s", c.network, c.address, got, c.wantIP)
		}
	}
	t.Logf("family-aware local bind selection verified for %d cases", len(cases))
}

// TestDialBackSource: on a wildcard bind the dial-back leaves from the address the
// client connected to, since eMule ignores a probe from another IP than its server's.
func TestDialBackSource(t *testing.T) {
	v4In := &net.TCPAddr{IP: net.ParseIP("176.116.0.62"), Port: 7555}
	mappedIn := &net.TCPAddr{IP: net.ParseIP("::ffff:176.116.0.62"), Port: 7555}
	v6In := &net.TCPAddr{IP: net.ParseIP("2a0f:5f40:0:9::133"), Port: 7555}
	cases := []struct {
		network string
		address string
		inbound net.Addr
		want    string
	}{
		{"tcp4", "", v4In, "176.116.0.62"},
		{"tcp4", "", mappedIn, "176.116.0.62"},
		{"tcp4", "0.0.0.0", v4In, "176.116.0.62"},
		{"tcp4", "192.0.2.9", v4In, "192.0.2.9"}, // the bind address wins
		{"tcp6", "", v6In, "2a0f:5f40:0:9::133"},
		{"tcp6", "", v4In, "<nil>"},     // the client came over IPv4
		{"tcp6", "", mappedIn, "<nil>"}, // likewise, on the dual-stack listener
		{"tcp4", "", v6In, "<nil>"},
		{"tcp4", "", nil, "<nil>"},
		{"tcp4", "", &net.TCPAddr{IP: net.IPv4zero}, "<nil>"},
	}
	for _, c := range cases {
		got := dialBackSource(c.network, c.address, c.inbound).String()
		t.Logf("dialBackSource(%q, %q, %v) = %s", c.network, c.address, c.inbound, got)
		if got != c.want {
			t.Errorf("dialBackSource(%q, %q, %v) = %s, want %s", c.network, c.address, c.inbound, got, c.want)
		}
	}
}
