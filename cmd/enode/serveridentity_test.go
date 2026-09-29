package main

import (
	"fmt"
	"os"
	"testing"

	"enode/ed2k"
)

func TestFirstRoutableIP(t *testing.T) {
	cases := []struct {
		name       string
		candidates []string
		want       string
	}{
		{"a configured address wins", []string{"203.0.113.7", "198.51.100.4"}, "203.0.113.7"},
		{"the wildcard falls through to dynIp", []string{"0.0.0.0", "198.51.100.4"}, "198.51.100.4"},
		{"an empty address falls through", []string{"", "198.51.100.4"}, "198.51.100.4"},
		{"nothing routable", []string{"0.0.0.0", ""}, ""},
		{"wildcard dynIp is not routable either", []string{"0.0.0.0", "0.0.0.0"}, ""},
		// The OP_SERVERIDENT server-IP field is a uint32: an IPv6 bind address has no
		// form there, and picking it made every ident fail to build.
		{"the v6 wildcard falls through to dynIp", []string{"::", "198.51.100.4"}, "198.51.100.4"},
		{"a bracketed v6 wildcard falls through", []string{"[::]", "198.51.100.4"}, "198.51.100.4"},
		{"a global v6 bind falls through", []string{"2001:db8::1", "198.51.100.4"}, "198.51.100.4"},
		{"v6 wildcard and no dynIp", []string{"::", ""}, ""},
		{"a v4-mapped address is advertised as plain IPv4", []string{"::ffff:203.0.113.7", "198.51.100.4"}, "203.0.113.7"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := firstRoutableIP(tc.candidates...)
			t.Logf("input: %v -> output: %q", tc.candidates, got)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Deriving the hash from cfg.Address alone meant every deployment that did not
// set `address` computed MD5("0.0.0.0" + port) — one identity shared by every
// unconfigured server on the network.
func TestServerHashDistinguishesUnconfiguredServers(t *testing.T) {
	hash := func(seed string, port uint16) string {
		return fmt.Sprintf("%x", ed2k.MD5([]byte(fmt.Sprintf("%s%d", seed, port))))
	}

	withIP := hash(serverIdentitySeed("203.0.113.7", "0.0.0.0"), 4661)
	otherIP := hash(serverIdentitySeed("198.51.100.4", "0.0.0.0"), 4661)
	t.Logf("output: two configured servers -> %s vs %s", withIP[:16], otherIP[:16])
	if withIP == otherIP {
		t.Fatal("two servers with different addresses share a hash")
	}

	// With no routable address the seed is the hostname, so the value is stable
	// across calls — a random seed would produce a new identity on every boot.
	unconfigured1 := hash(serverIdentitySeed("", "0.0.0.0"), 4661)
	unconfigured2 := hash(serverIdentitySeed("", "0.0.0.0"), 4661)
	t.Logf("output: unconfigured, twice -> %s vs %s", unconfigured1[:16], unconfigured2[:16])
	if unconfigured1 != unconfigured2 {
		t.Fatal("the unconfigured server hash is not stable across calls")
	}

	// And it must not be the value every unconfigured deployment used to share.
	wildcard := hash("0.0.0.0", 4661)
	t.Logf("output: unconfigured=%s vs the old shared value=%s", unconfigured1[:16], wildcard[:16])
	if host, err := os.Hostname(); err == nil && host != "" {
		if unconfigured1 == wildcard {
			t.Fatal("unconfigured servers still derive the same hash from the wildcard")
		}
	}

	// The port still participates, so two servers on one host differ by port.
	byPort := hash(serverIdentitySeed("", "0.0.0.0"), 4665)
	t.Logf("output: same host, port 4665 -> %s", byPort[:16])
	if byPort == unconfigured1 {
		t.Fatal("the port does not affect the server hash")
	}
}

func TestServerIdentitySeedFallbackOrder(t *testing.T) {
	if got := serverIdentitySeed("203.0.113.7", "0.0.0.0"); got != "203.0.113.7" {
		t.Fatalf("a routable IP must win: got %q", got)
	}
	t.Logf("output: routable IP is preferred")

	host, err := os.Hostname()
	if err != nil || host == "" {
		t.Skip("hostname unavailable on this machine")
	}
	if got := serverIdentitySeed("", "0.0.0.0"); got != host {
		t.Fatalf("expected the hostname %q, got %q", host, got)
	}
	t.Logf("output: falls back to hostname %q", host)
}
