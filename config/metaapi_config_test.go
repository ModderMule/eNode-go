package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMetaAPIDefaults(t *testing.T) {
	c, err := ApplyMetaAPIDefaults(MetaAPIConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: empty metaApi output: grpc=%s http=%s cache=%d fetch=%dms max=%d session=%dh",
		c.GRPC.Listen, c.HTTP.Listen, c.MetafileCache.MaxBytes, c.FetchTimeoutMs, c.MaxMetafileBytes, c.Accounts.SessionTTLHours)
	if c.GRPC.Listen != DefaultMetaAPIGRPCListen || c.HTTP.Listen != DefaultMetaAPIHTTPListen {
		t.Errorf("listen defaults: %s %s", c.GRPC.Listen, c.HTTP.Listen)
	}
	if c.GRPCEnabled() || c.HTTPAPIEnabled() || c.HTTPListenerEnabled() {
		t.Errorf("a disabled API runs a listener")
	}
	c.Enabled = true
	if !c.GRPCEnabled() || c.HTTPAPIEnabled() || c.HTTPListenerEnabled() {
		t.Errorf("enabled API: grpc=%v httpAPI=%v httpListener=%v, want true false false",
			c.GRPCEnabled(), c.HTTPAPIEnabled(), c.HTTPListenerEnabled())
	}
	c.Accounts.Enabled = true
	if !c.HTTPListenerEnabled() || c.HTTPAPIEnabled() {
		t.Errorf("accounts on: the HTTP listener must run for the website, without the API")
	}
	if !c.Accounts.AllowRegistrationOrDefault() {
		t.Errorf("allowRegistration must default on")
	}
}

func TestMetaAPIValidation(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string // substring of the error; "" = valid
	}{
		{"disabled is always valid", "enabled: false\naccounts: {enabled: true}", ""},
		{"public API", "enabled: true", ""},
		{"bad listen", "enabled: true\ngrpc: {listen: nope}", "metaApi.grpc.listen"},
		{"half tls", "enabled: true\ntls: {certFile: a.pem}", "both certFile and keyFile"},
		{"fingerprint without tls", "enabled: true\ntls: {advertiseFingerprint: true}", "advertiseFingerprint"},
		{"bad advertise url", "enabled: true\nadvertiseURL: ftp://x", "metaApi.advertiseURL"},
		{"accounts without tls", "enabled: true\naccounts: {enabled: true, publicURL: 'https://e.org'}", "allowInsecureAuth"},
		{"accounts without publicURL", "enabled: true\nallowInsecureAuth: true\naccounts: {enabled: true}", "publicURL"},
		{"accounts ok", "enabled: true\nallowInsecureAuth: true\naccounts: {enabled: true, publicURL: 'https://e.org/'}", ""},
		{"duplicate step id", "accounts:\n  steps:\n    - {id: pay, type: payment}\n    - {id: pay, type: payment}", "used twice"},
		{"bad step id", "accounts:\n  steps:\n    - {id: 'Pay Now', type: payment}", "is invalid"},
		{"step without type", "accounts:\n  steps:\n    - {id: pay}", "has no type"},
		{"negative rate", "rateLimit: {perIPPerMinute: -1}", "negative"},
		{"negative search rate", "search: {rateLimit: {perAccountPerMinute: -1}}", "metaApi.search.rateLimit"},
		{"search limit too high", "search: {maxLimit: 501}", "metaApi.search.maxLimit"},
		{"search window too deep", "search: {window: 20000}", "metaApi.search.window"},
		{"search window below limit", "search: {maxLimit: 100, window: 50}", "smaller than maxLimit"},
	}
	for _, tc := range cases {
		var c MetaAPIConfig
		if err := yaml.Unmarshal([]byte(tc.yaml), &c); err != nil {
			t.Fatalf("%s: yaml: %v", tc.name, err)
		}
		_, err := ApplyMetaAPIDefaults(c)
		t.Logf("input: %s output: err=%v", tc.name, err)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err=%v, want one mentioning %q", tc.name, err, tc.want)
		}
	}
}

func TestMetaAPISearchDefaults(t *testing.T) {
	c, err := ApplyMetaAPIDefaults(MetaAPIConfig{})
	if err != nil {
		t.Fatal(err)
	}
	s := c.Search
	t.Logf("input: empty metaApi output: search timeout=%dms maxLimit=%d window=%d cache=%d/%ds",
		s.TimeoutMs, s.MaxLimit, s.Window, s.Cache.MaxEntries, s.Cache.TTLSeconds)
	if s.TimeoutMs != 5000 || s.MaxLimit != 100 || s.Window != 1000 || s.Cache.MaxEntries != 2000 || s.Cache.TTLSeconds != 600 {
		t.Errorf("search defaults %+v", s)
	}
	if c.SearchEnabled() {
		t.Errorf("search on while the API is off")
	}
	c.Enabled = true
	if !c.SearchEnabled() || c.SearchRequiresAccount() {
		t.Errorf("public API: search=%v requiresAccount=%v, want true false", c.SearchEnabled(), c.SearchRequiresAccount())
	}
	c.Accounts.Enabled = true
	if !c.SearchRequiresAccount() {
		t.Errorf("accounts on: search must require an account by default")
	}
	off := false
	c.Search.RequireAccount = &off
	if c.SearchRequiresAccount() {
		t.Errorf("requireAccount: false ignored")
	}
	c.Search.Enabled = &off
	if c.SearchEnabled() {
		t.Errorf("search.enabled: false ignored")
	}
}

// TestAccountStepKeepsItsOwnKeys checks a step entry's type-specific keys survive
// decoding for the step to read, and that disabled steps are left out.
func TestAccountStepKeepsItsOwnKeys(t *testing.T) {
	src := `
steps:
  - id: payment
    type: payment
    enabled: true
    plans:
      - {id: monthly, periodDays: 30}
  - id: email
    type: email_verification
    enabled: false
`
	var a AccountsConfig
	if err := yaml.Unmarshal([]byte(src), &a); err != nil {
		t.Fatal(err)
	}
	steps := a.EnabledSteps()
	if len(steps) != 1 || steps[0].ID != "payment" || steps[0].Type != "payment" {
		t.Fatalf("EnabledSteps = %+v", steps)
	}
	var own struct {
		Plans []struct {
			ID         string `yaml:"id"`
			PeriodDays int    `yaml:"periodDays"`
		} `yaml:"plans"`
	}
	if err := steps[0].Decode(&own); err != nil {
		t.Fatal(err)
	}
	t.Logf("input: payment step with one plan output: %+v", own)
	if len(own.Plans) != 1 || own.Plans[0].ID != "monthly" || own.Plans[0].PeriodDays != 30 {
		t.Fatalf("step keys lost: %+v", own)
	}
}

// TestShippedConfigMetaAPI loads the tracked config: the Meta API must ship off, and
// its example payment step must decode.
func TestShippedConfigMetaAPI(t *testing.T) {
	cfg, err := Load(shippedConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.MetaAPI
	t.Logf("output: enabled=%v grpc=%v http=%v accounts=%v steps=%d", c.Enabled, c.GRPCEnabled(), c.HTTPAPIEnabled(), c.Accounts.Enabled, len(c.Accounts.Steps))
	if c.Enabled || c.Accounts.Enabled || c.HTTPAPIEnabled() {
		t.Fatalf("the shipped config enables the Meta API")
	}
	if len(c.Accounts.Steps) == 0 || c.Accounts.Steps[0].Type != "payment" {
		t.Fatalf("the shipped config lost its example payment step")
	}
	if len(c.Accounts.EnabledSteps()) != 0 {
		t.Fatalf("the shipped config enables a registration step")
	}
	if c.Search.Enabled == nil || !*c.Search.Enabled || c.Search.RequireAccount == nil || !*c.Search.RequireAccount ||
		c.Search.RateLimit.PerIPPerMinute != 30 {
		t.Fatalf("the shipped search block: %+v", c.Search)
	}
}

func TestMetaAPIPublicStatus(t *testing.T) {
	off, on := false, true
	cases := []struct {
		name string
		cfg  MetaAPIConfig
		want bool
	}{
		{"api off", MetaAPIConfig{HTTP: MetaAPIHTTPConfig{Enabled: &on}}, false},
		{"api on, no http listener", MetaAPIConfig{Enabled: true}, false},
		{"http listener, key absent", MetaAPIConfig{Enabled: true, HTTP: MetaAPIHTTPConfig{Enabled: &on}}, true},
		{"website-only listener", MetaAPIConfig{Enabled: true, Accounts: AccountsConfig{Enabled: true}}, true},
		{"status: false", MetaAPIConfig{Enabled: true, HTTP: MetaAPIHTTPConfig{Enabled: &on, Status: &off}}, false},
	}
	for _, tc := range cases {
		got := tc.cfg.PublicStatusEnabled()
		t.Logf("input: %s output: PublicStatusEnabled=%t", tc.name, got)
		if got != tc.want {
			t.Errorf("%s: PublicStatusEnabled=%t, want %t", tc.name, got, tc.want)
		}
	}
}
