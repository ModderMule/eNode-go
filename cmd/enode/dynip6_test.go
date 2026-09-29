package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"enode/ed2k"
)

func TestResolveDynIP6ValueExplicitAndEmpty(t *testing.T) {
	// Empty means "no v6 advertisement".
	ip, by, err := resolveDynIP6Value("", nil, time.Second)
	if err != nil || ip != "" || by != "" {
		t.Fatalf("empty dynIp6: got ip=%q by=%q err=%v", ip, by, err)
	}
	// An explicit value is returned verbatim.
	ip, by, err = resolveDynIP6Value("2001:db8::5", nil, time.Second)
	if err != nil || ip != "2001:db8::5" || by != "" {
		t.Fatalf("explicit dynIp6: got ip=%q by=%q err=%v", ip, by, err)
	}
	t.Logf("empty and explicit dynIp6 handled")
}

// TestFetchIPFromURLRejectsWrongFamily confirms the v6 validator rejects an IPv4
// body and accepts a v6 one (the trace/bare parsing is shared with the v4 path).
func TestFetchIPFromURLValidatesFamily(t *testing.T) {
	v4srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "192.0.2.7")
	}))
	defer v4srv.Close()
	v6srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "2001:db8::7\n")
	}))
	defer v6srv.Close()

	client := newDynIPClient(2 * time.Second) // tcp4 to reach the httptest 127.0.0.1 listener

	if _, err := fetchIPFromURL(client, v4srv.URL, ed2k.IsPublicIPv6); err == nil {
		t.Fatal("v6 validator must reject an IPv4 body")
	}
	got, err := fetchIPFromURL(client, v6srv.URL, ed2k.IsPublicIPv6)
	if err != nil || got != "2001:db8::7" {
		t.Fatalf("v6 body: got %q err %v", got, err)
	}
	t.Logf("family validation: v4 body rejected, v6 body -> %s", got)
}

func TestPickStableIPv6(t *testing.T) {
	cand := func(ip string, temp, depr, tent bool) ipv6Candidate {
		return ipv6Candidate{IP: net.ParseIP(ip), Temporary: temp, Deprecated: depr, Tentative: tent, FlagsKnown: true}
	}
	stableA := cand("2001:db8:1::10", false, false, false)
	tempA := cand("2001:db8:1::abcd:1234", true, false, false)
	stableB := cand("2001:db8:2::20", false, false, false)
	deprB := cand("2001:db8:2::dead", false, true, false)
	tentC := cand("2001:db8:3::30", false, false, true)
	unknown := ipv6Candidate{IP: net.ParseIP("2001:db8:4::40")}

	cases := []struct {
		name         string
		probed       string
		cands        []ipv6Candidate
		wantIP       string
		wantUnstable bool
		wantNote     bool
	}{
		{"probed stable kept", "2001:db8:1::10", []ipv6Candidate{tempA, stableA}, "2001:db8:1::10", false, false},
		{"probed not local kept", "2001:db8:9::1", []ipv6Candidate{tempA, stableA}, "2001:db8:9::1", false, false},
		{"probed temporary replaced", "2001:db8:1::abcd:1234", []ipv6Candidate{tempA, stableA}, "2001:db8:1::10", false, true},
		{"replacement prefers same /64", "2001:db8:2::dead", []ipv6Candidate{stableA, deprB, stableB}, "2001:db8:2::20", false, true},
		{"replacement falls back to other /64", "2001:db8:1::abcd:1234", []ipv6Candidate{tempA, stableB}, "2001:db8:2::20", false, true},
		{"probed temporary, nothing stable", "2001:db8:1::abcd:1234", []ipv6Candidate{tempA, tentC}, "2001:db8:1::abcd:1234", true, false},
		{"unknown flags treated as usable", "2001:db8:4::40", []ipv6Candidate{unknown}, "2001:db8:4::40", false, false},
		{"no probe, first stable", "", []ipv6Candidate{tempA, deprB, stableB, stableA}, "2001:db8:2::20", false, false},
		{"no probe, unknown flags", "", []ipv6Candidate{unknown}, "2001:db8:4::40", false, false},
		{"no probe, only unstable prefers non-tentative", "", []ipv6Candidate{tentC, tempA}, "2001:db8:1::abcd:1234", true, false},
		{"no probe, only tentative", "", []ipv6Candidate{tentC}, "2001:db8:3::30", true, false},
		{"no probe, no candidates", "", nil, "", false, false},
	}
	for _, tc := range cases {
		got := pickStableIPv6(tc.probed, tc.cands)
		t.Logf("%s: probed=%q -> ip=%q note=%q unstable=%v stableCount=%d", tc.name, tc.probed, got.IP, got.Note, got.Unstable, got.StableCount)
		if got.IP != tc.wantIP || got.Unstable != tc.wantUnstable || (got.Note != "") != tc.wantNote {
			t.Errorf("%s: got %+v, want ip=%q unstable=%v note=%v", tc.name, got, tc.wantIP, tc.wantUnstable, tc.wantNote)
		}
	}
}

// TestLocalIPv6Candidates is a smoke test of the platform enumerator: whatever this
// host has, every entry must be a public IPv6.
func TestLocalIPv6Candidates(t *testing.T) {
	cands := localIPv6Candidates()
	if len(cands) == 0 {
		t.Skip("no public IPv6 on this host")
	}
	for _, c := range cands {
		t.Logf("candidate %s temporary=%v deprecated=%v tentative=%v flagsKnown=%v", c.IP, c.Temporary, c.Deprecated, c.Tentative, c.FlagsKnown)
		if !ed2k.IsPublicIPv6(c.IP) {
			t.Errorf("non-public candidate %s", c.IP)
		}
	}
}
