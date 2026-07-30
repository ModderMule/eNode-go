package storage

import "testing"

// TestServerAddrKeyIdentity pins the identity rule the eMule server list uses:
// (address, TCP port), with the address canonicalized. The IPv6 cases are the ones
// that matter — advertisableServers used to key configured entries on the raw
// config string while gossip supplied net.IP.String(), so the same peer written
// "2001:DB8::1" in the config and reported as 2001:db8::1 by a peer appeared twice
// in OP_SERVERLIST.
func TestServerAddrKeyIdentity(t *testing.T) {
	cases := []struct {
		name  string
		a, b  Server
		equal bool
		why   string
	}{
		{
			name:  "identical ipv4",
			a:     Server{IP: "192.0.2.10", Port: 4661},
			b:     Server{IP: "192.0.2.10", Port: 4661},
			equal: true,
			why:   "same address and port",
		},
		{
			name:  "ipv6 compressed vs expanded",
			a:     Server{IP: "2001:db8::1", Port: 4661},
			b:     Server{IP: "2001:db8:0:0:0:0:0:1", Port: 4661},
			equal: true,
			why:   "net.IP canonicalization collapses the two spellings",
		},
		{
			name:  "ipv6 case difference",
			a:     Server{IP: "2001:DB8::1", Port: 4661},
			b:     Server{IP: "2001:db8::1", Port: 4661},
			equal: true,
			why:   "comparison is case-insensitive, as ServerList::findByAddress is",
		},
		{
			name:  "ipv4 surrounding whitespace",
			a:     Server{IP: " 192.0.2.10 ", Port: 4661},
			b:     Server{IP: "192.0.2.10", Port: 4661},
			equal: true,
			why:   "trimmed before parsing",
		},
		{
			name:  "same address different port",
			a:     Server{IP: "192.0.2.10", Port: 4661},
			b:     Server{IP: "192.0.2.10", Port: 5661},
			equal: false,
			why:   "two ports on one host are two servers, as in eMule",
		},
		{
			name:  "different address same port",
			a:     Server{IP: "192.0.2.10", Port: 4661},
			b:     Server{IP: "192.0.2.11", Port: 4661},
			equal: false,
			why:   "different hosts",
		},
		{
			name:  "unparsable address falls back to lowercase",
			a:     Server{IP: "Peer.Example.COM", Port: 4661},
			b:     Server{IP: "peer.example.com", Port: 4661},
			equal: true,
			why:   "non-literal addresses compare case-insensitively too",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ka, kb := ServerAddrKey(tc.a), ServerAddrKey(tc.b)
			t.Logf("input:  a=%q:%d b=%q:%d", tc.a.IP, tc.a.Port, tc.b.IP, tc.b.Port)
			t.Logf("output: keyA=%q keyB=%q equal=%t (want %t: %s)", ka, kb, ka == kb, tc.equal, tc.why)
			if (ka == kb) != tc.equal {
				t.Fatalf("key equality = %t, want %t (%s)", ka == kb, tc.equal, tc.why)
			}
		})
	}
}

// TestAppendUniqueServerRejectsPortZero mirrors IsGoodServerIP
// (srchybrid/ServerList.cpp:322-325), which rejects a zero port before it ever
// looks for a duplicate. A port of 0 is not contactable, so storing it would only
// publish an unusable entry.
func TestAppendUniqueServerRejectsPortZero(t *testing.T) {
	list, added := appendUniqueServer(nil, Server{IP: "192.0.2.10", Port: 0})
	t.Logf("input:  192.0.2.10:0")
	t.Logf("output: added=%t len=%d", added, len(list))
	if added || len(list) != 0 {
		t.Fatalf("port 0 must be rejected, got added=%t len=%d", added, len(list))
	}
}

// TestAppendUniqueServerKeepsExisting checks the "existing wins" rule: eMule's
// AddServer discards the incoming duplicate and keeps the record it already has
// (srchybrid/ServerList.cpp:230-234).
func TestAppendUniqueServerKeepsExisting(t *testing.T) {
	var list []Server
	list, first := appendUniqueServer(list, Server{IP: "192.0.2.10", Port: 4661})
	list, second := appendUniqueServer(list, Server{IP: "192.0.2.10", Port: 4661})
	list, third := appendUniqueServer(list, Server{IP: "192.0.2.10", Port: 5661})

	t.Logf("input:  192.0.2.10:4661 twice, then 192.0.2.10:5661")
	t.Logf("output: added=%t,%t,%t list=%v", first, second, third, list)

	if !first || second || !third {
		t.Fatalf("want added=true,false,true; got %t,%t,%t", first, second, third)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 entries, got %d: %v", len(list), list)
	}
}

// TestAddServerDeduplicatesAcrossEngines asserts the rule holds for every engine,
// not just the default one. All three keep the peer list as a plain in-RAM slice —
// no database is involved — so the MySQL and MongoDB engines can be exercised here
// without a container.
func TestAddServerDeduplicatesAcrossEngines(t *testing.T) {
	engines := map[string]Engine{
		"memory":  NewMemoryEngine(),
		"mysql":   &MySQLEngine{},
		"mongodb": &MongoDBEngine{},
	}

	for name, engine := range engines {
		t.Run(name, func(t *testing.T) {
			in := []Server{
				{IP: "192.0.2.10", Port: 4661},
				{IP: "192.0.2.10", Port: 4661},  // exact duplicate
				{IP: "2001:DB8::1", Port: 4661}, // same peer as the next, different spelling
				{IP: "2001:db8::1", Port: 4661}, //
				{IP: "192.0.2.10", Port: 5661},  // same host, other port: distinct
				{IP: "192.0.2.11", Port: 0},     // invalid port
			}
			for _, s := range in {
				engine.AddServer(s)
			}

			got := engine.ServersAll()
			t.Logf("input:  %d entries %v", len(in), in)
			t.Logf("output: %d stored %v", len(got), got)

			if len(got) != 3 {
				t.Fatalf("want 3 unique servers, got %d: %v", len(got), got)
			}
			if engine.ServersCount() != 3 {
				t.Fatalf("ServersCount = %d, want 3", engine.ServersCount())
			}
		})
	}
}
