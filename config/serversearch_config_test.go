package config

import (
	"strings"
	"testing"
)

// TestServerSearchDefaults: an absent section is off, and enabling it with nothing
// else serves search and browse in allowlist mode on the default port.
func TestServerSearchDefaults(t *testing.T) {
	off, err := ApplyServerSearchDefaults(ServerSearchConfig{}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input:  no serverSearch section")
	t.Logf("output: %+v", off)
	if off.Enabled || off.Consumes() || off.Mode != ServerSearchModeAllowlist || off.Listen != DefaultServerSearchListen {
		t.Errorf("unexpected defaults: %+v", off)
	}

	on, err := ApplyServerSearchDefaults(ServerSearchConfig{Enabled: true, Listen: "127.0.0.1:4673"}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input:  enabled: true")
	t.Logf("output: %+v", on)
	if !on.ServeSearch() || !on.ServeBrowse() || on.GossipMode() || on.Consumes() ||
		on.Serve.MaxBrowseLimit != 1000 || on.Mirror.MaxFiles != 500000 || on.Mirror.IntervalMinutes != 60 {
		t.Errorf("unexpected enabled defaults: %+v", on)
	}

	no := false
	served, err := ApplyServerSearchDefaults(ServerSearchConfig{Enabled: true, Listen: "127.0.0.1:4673",
		Serve: ServerSearchServe{Browse: &no}, Mirror: ServerSearchMirror{Enabled: true}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if served.ServeBrowse() || !served.ServeSearch() || !served.Consumes() {
		t.Errorf("browse: false and mirror.enabled: true gave %+v", served)
	}
}

// TestServerSearchRefusesToStart lists the configurations Load rejects, each with
// the part of the message an operator needs.
func TestServerSearchRefusesToStart(t *testing.T) {
	peer := func(url, token, fp string) []ServerSearchPeer {
		return []ServerSearchPeer{{URL: url, Token: token, Fingerprint: fp}}
	}
	cases := []struct {
		name   string
		cfg    ServerSearchConfig
		gossip bool
		want   string // "" means it must load
	}{
		{"unknown mode", ServerSearchConfig{Mode: "open"}, true, "serverSearch.mode"},
		{"gossip mode without gossip", ServerSearchConfig{Mode: ServerSearchModeGossip}, false, "needs gossip.enabled"},
		{"gossip mode with gossip", ServerSearchConfig{Mode: ServerSearchModeGossip}, true, ""},
		{"bad listen", ServerSearchConfig{Listen: "4673"}, true, "serverSearch.listen"},
		{"half a certificate", ServerSearchConfig{TLS: ServerSearchTLSConfig{CertFile: "c.pem"}}, true, "both certFile and keyFile"},
		{"bad advertise url", ServerSearchConfig{AdvertiseURL: "server.example.org"}, true, "serverSearch.advertiseURL"},
		{"allowlist peer without a token", ServerSearchConfig{Listen: "127.0.0.1:4673", Peers: peer("https://a.example.org", "", "")}, true, "has no token"},
		{"gossip peer without a token", ServerSearchConfig{Mode: ServerSearchModeGossip, Peers: peer("https://a.example.org", "", "")}, true, ""},
		{"empty peer", ServerSearchConfig{Peers: peer("", "", "")}, true, "needs a url, a token, or both"},
		{"bad peer url", ServerSearchConfig{Listen: "127.0.0.1:4673", Peers: peer("a.example.org:4673", "t", "")}, true, ".url"},
		{"bad fingerprint", ServerSearchConfig{Listen: "127.0.0.1:4673", Peers: peer("https://a.example.org", "t", "abc")}, true, "fingerprint"},
		{"fingerprint without https", ServerSearchConfig{Listen: "127.0.0.1:4673", Peers: peer("http://127.0.0.1:4673", "t", "sha256/abc=")}, true, "not https"},
		{"token sent in clear text", ServerSearchConfig{Listen: "127.0.0.1:4673", Peers: peer("http://a.example.org:4673", "t", "")}, true, "in clear text"},
		{"token sent to loopback", ServerSearchConfig{Listen: "127.0.0.1:4673", Peers: peer("http://127.0.0.1:4700", "t", "")}, true, ""},
		{"token received in clear text", ServerSearchConfig{Listen: "0.0.0.0:4673", Peers: peer("https://a.example.org", "t", "")}, true, "needs serverSearch.tls"},
		{"token received behind a proxy", ServerSearchConfig{Listen: "0.0.0.0:4673", AllowInsecureAuth: true, Peers: peer("https://a.example.org", "t", "")}, true, ""},
		{"token received over tls", ServerSearchConfig{Listen: "0.0.0.0:4673", TLS: ServerSearchTLSConfig{CertFile: "c.pem", KeyFile: "k.pem"},
			Peers: peer("https://a.example.org", "t", "")}, true, ""},
		{"two peers, one token", ServerSearchConfig{Listen: "127.0.0.1:4673", Peers: []ServerSearchPeer{
			{URL: "https://a.example.org", Token: "t"}, {URL: "https://b.example.org", Token: "t"}}}, true, "shares its token"},
		{"browse limit too large", ServerSearchConfig{Serve: ServerSearchServe{MaxBrowseLimit: 5000}}, true, "maxBrowseLimit"},
		{"negative rate limit", ServerSearchConfig{Serve: ServerSearchServe{RateLimit: ServerSearchRateLimitConfig{PerIPPerMinute: -1}}}, true, "rateLimit"},
	}
	for _, c := range cases {
		c.cfg.Enabled = true
		_, err := ApplyServerSearchDefaults(c.cfg, c.gossip)
		t.Logf("input:  %s", c.name)
		t.Logf("output: %v", err)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.want != "" && err == nil:
			t.Errorf("%s: loaded, want an error naming %q", c.name, c.want)
		case c.want != "" && !strings.Contains(err.Error(), c.want):
			t.Errorf("%s: error %q does not name %q", c.name, err, c.want)
		}
	}

	// Off, none of it is checked: a half-written section must not stop the server.
	if _, err := ApplyServerSearchDefaults(ServerSearchConfig{Mode: "open", Listen: "4673"}, false); err != nil {
		t.Errorf("a disabled section was validated: %v", err)
	}
}

// TestServerSearchLoadsFromYAML: the section reaches the struct under its keys, and
// a peer's URL loses its trailing slash.
func TestServerSearchLoadsFromYAML(t *testing.T) {
	cfg, err := loadYAML(t, `
serverSearch:
  enabled: true
  mode: gossip
  listen: "127.0.0.1:4700"
  serve:
    browse: false
    maxSearchLimit: 50
  peers:
    - url: "https://peer.example.org:4673/"
      token: "shared"
      fingerprint: "sha256/abc="
  search:
    enabled: true
    timeoutMs: 800
  mirror:
    enabled: true
    intervalMinutes: 15
    maxFiles: 1000
`)
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.ServerSearch
	t.Logf("output: %+v", s)
	if !s.Enabled || !s.GossipMode() || s.Listen != "127.0.0.1:4700" || s.ServeBrowse() || s.Serve.MaxSearchLimit != 50 ||
		len(s.Peers) != 1 || s.Peers[0].URL != "https://peer.example.org:4673" || s.Peers[0].Token != "shared" ||
		!s.Search.Enabled || s.Search.TimeoutMs != 800 || !s.Mirror.Enabled || s.Mirror.IntervalMinutes != 15 || s.Mirror.MaxFiles != 1000 {
		t.Errorf("unexpected section: %+v", s)
	}
}
