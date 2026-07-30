package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testServer builds a Server over an httptest.Server so the real mux, template and
// JSON handler are exercised end-to-end without binding a fixed port. It returns
// the base URL and the live snapshot the handlers will serve.
func testServer(t *testing.T) (string, LiveStats) {
	t.Helper()
	static := StaticInfo{
		Name:              "(TESTING!!!) eNode",
		Description:       "unit-test server",
		Version:           "v0.1.0",
		Engine:            "memory",
		TCPPort:           5555,
		TCPPortObf:        5565,
		UDPPort:           5559,
		UDPPortObf:        5567,
		NATPort:           2004,
		Crypt:             true,
		IPv6:              true,
		NAT:               true,
		ServerIndependent: true,
	}
	live := LiveStats{
		Clients:          42,
		Files:            1337,
		LowIDs:           7,
		Servers:          3,
		UptimeSeconds:    90,
		Time:             "2026-07-22T10:00:00Z",
		GossipKnown:      5,
		GossipVerified:   2,
		GossipParked:     1,
		GossipAdmitted:   19,
		FilterBlockedIP:  64,
		FilterBlockedGeo: 8,
	}
	s := New(Config{}, static, func() LiveStats { return live })
	ts := httptest.NewServer(s.http.Handler)
	t.Cleanup(ts.Close)
	return ts.URL, live
}

func TestStatsJSONReturnsSnapshot(t *testing.T) {
	base, want := testServer(t)

	resp, err := http.Get(base + "/stats.json")
	if err != nil {
		t.Fatalf("GET /stats.json: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	t.Logf("GET /stats.json -> %d %s", resp.StatusCode, strings.TrimSpace(string(body)))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type=%q, want application/json", ct)
	}

	var got LiveStats
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode LiveStats: %v", err)
	}
	if got != want {
		t.Errorf("stats=%+v, want %+v", got, want)
	}

	// The JSON key names are a consumed contract, not an internal detail: the dashboard
	// script reads them, and tests/interop polls gossipVerified to decide when a handshake
	// has completed. Round-tripping through LiveStats above would keep passing after a
	// rename, so the wire names are asserted against the raw object.
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode raw JSON: %v", err)
	}
	for _, key := range []string{
		"clients", "files", "lowIDs", "servers", "uptimeSeconds", "time",
		"gossipKnown", "gossipVerified", "gossipParked", "gossipAdmitted",
		"filterBlockedIP", "filterBlockedGeo",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("stats.json missing key %q", key)
		}
	}
	t.Logf("output: %d keys, gossipVerified=%v servers=%v", len(raw), raw["gossipVerified"], raw["servers"])
}

func TestIndexRendersStaticOnly(t *testing.T) {
	base, live := testServer(t)

	resp, err := http.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	t.Logf("GET / -> %d, %d bytes", resp.StatusCode, len(html))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}

	// Static fields are rendered by the template.
	for _, want := range []string{"(TESTING!!!) eNode", "v0.1.0", "5555", "/stats.json"} {
		if !strings.Contains(html, want) {
			t.Errorf("index HTML missing static content %q", want)
		}
	}
	// Placeholder elements the script fills must be present.
	for _, id := range []string{
		`id="clients"`, `id="files"`, `id="lowIDs"`, `id="servers"`, `id="uptime"`,
		`id="gossip"`, `id="blocked"`, `id="blockedBreak"`,
	} {
		if !strings.Contains(html, id) {
			t.Errorf("index HTML missing placeholder element %s", id)
		}
	}
	// The live counters must NOT be baked into the served HTML — they arrive only
	// via /stats.json. 1337 (files) and 42 (clients) are distinctive enough that
	// their absence proves the page shipped no dynamic values.
	for _, baked := range []string{">1337<", ">42<"} {
		if strings.Contains(html, baked) {
			t.Errorf("index HTML unexpectedly baked in live value %q", baked)
		}
	}
	t.Logf("confirmed live counts (clients=%d files=%d) absent from static HTML", live.Clients, live.Files)
}

func TestUnknownPathIs404(t *testing.T) {
	base, _ := testServer(t)
	resp, err := http.Get(base + "/nope")
	if err != nil {
		t.Fatalf("GET /nope: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("GET /nope -> %d", resp.StatusCode)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d, want 404", resp.StatusCode)
	}
}
