package main

import (
	"testing"

	"enode/config"
	"enode/storage"
)

// TestServerListSeededFromConfig pins L1: seedServers loads the configured peer
// servers into storage (the only caller of AddServer outside tests), and skips an
// entry with an unparseable IP rather than aborting the whole list. Against a build
// with the seeding removed, ServersAll() is empty.
func TestServerListSeededFromConfig(t *testing.T) {
	engine := storage.NewMemoryEngine()
	entries := []config.ServerEntry{
		{IP: "111.222.111.222", Port: 1234},
		{IP: "123.123.234.234", Port: 2345},
		{IP: "not-an-ip", Port: 9999}, // invalid → skipped, must not drop the rest
	}
	t.Logf("input: %d entries (one with an invalid IP)", len(entries))
	seedServers(engine, entries)

	got := engine.ServersAll()
	t.Logf("output: %d server(s) seeded: %+v", len(got), got)
	if len(got) != 2 {
		t.Fatalf("want 2 valid servers seeded, got %d", len(got))
	}
	if got[0].IP != "111.222.111.222" || got[0].Port != 1234 {
		t.Fatalf("entry 0 mismatch: %+v", got[0])
	}
	if got[1].IP != "123.123.234.234" || got[1].Port != 2345 {
		t.Fatalf("entry 1 mismatch: %+v", got[1])
	}
}

// TestServerListSeedsPublicIPv6 pins that a public IPv6 peer server is seeded (it
// is advertised in the trailing v6 block of OP_SERVERLIST), while a non-public v6
// (link-local) and garbage are still skipped.
func TestServerListSeedsPublicIPv6(t *testing.T) {
	engine := storage.NewMemoryEngine()
	entries := []config.ServerEntry{
		{IP: "111.222.111.222", Port: 1234}, // v4 kept
		{IP: "2001:db8::1", Port: 4661},     // public v6 kept
		{IP: "fe80::1", Port: 4662},         // link-local v6 skipped
		{IP: "garbage", Port: 9999},         // invalid skipped
	}
	t.Logf("input: %d entries (v4, public v6, link-local v6, garbage)", len(entries))
	seedServers(engine, entries)

	got := engine.ServersAll()
	t.Logf("output: %d server(s) seeded: %+v", len(got), got)
	if len(got) != 2 {
		t.Fatalf("want 2 seeded (v4 + public v6), got %d", len(got))
	}
	var haveV6 bool
	for _, s := range got {
		if s.IP == "2001:db8::1" && s.Port == 4661 {
			haveV6 = true
		}
	}
	if !haveV6 {
		t.Fatalf("public IPv6 server not seeded: %+v", got)
	}
}

// TestServerListSeedSkipsDuplicates covers a peer listed more than once under
// `servers:`. eMule's AddServer keeps the entry it already has and discards the
// incoming duplicate (srchybrid/ServerList.cpp:230-234); we do the same, and the
// two IPv6 spellings here are one peer, not two.
func TestServerListSeedSkipsDuplicates(t *testing.T) {
	engine := storage.NewMemoryEngine()
	entries := []config.ServerEntry{
		{IP: "111.222.111.222", Port: 1234},
		{IP: "111.222.111.222", Port: 1234}, // exact duplicate
		{IP: "2001:db8::1", Port: 4661},
		{IP: "2001:DB8::1", Port: 4661},     // same peer, different spelling
		{IP: "111.222.111.222", Port: 4661}, // same host, other port: kept
	}
	t.Logf("input: %d entries, 2 of them duplicates", len(entries))
	seedServers(engine, entries)

	got := engine.ServersAll()
	t.Logf("output: %d server(s) seeded: %+v", len(got), got)
	if len(got) != 3 {
		t.Fatalf("want 3 unique servers, got %d: %+v", len(got), got)
	}
}

// TestServerListEmptyByDefault confirms an omitted `servers:` seeds nothing — the
// unchanged default, and correct where the Node original shipped invalid dummies.
func TestServerListEmptyByDefault(t *testing.T) {
	engine := storage.NewMemoryEngine()
	seedServers(engine, nil)
	if n := engine.ServersCount(); n != 0 {
		t.Fatalf("want empty server list by default, got %d", n)
	}
	t.Logf("output: no servers seeded for empty config")
}
