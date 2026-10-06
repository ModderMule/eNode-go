package config

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// MetaAPIConfig is the client-facing Meta API (enode.meta.v1 MetaApi and AccountApi):
// how an eMuleQt client downloads the .torrent or .nzb behind a meta search row, and
// optionally logs in to an account first. Off by default. See docs/meta-api.md.
//
// Two listeners serve it. The gRPC listener is on whenever the API is; the plain
// HTTP listener (Connect protocol, raw metafile route, and the account website) is
// off unless the operator enables it — or accounts are on, whose registration website
// needs somewhere to live.
type MetaAPIConfig struct {
	Enabled bool `yaml:"enabled"`
	// AdvertiseURL is the base URL sent to clients as ST_META_API (0x9E) in
	// OP_SERVERIDENT, e.g. https://enode.example.org:4671. Empty derives it from the
	// advertised server IP and the gRPC port.
	AdvertiseURL string `yaml:"advertiseURL"`
	// HTTPAdvertiseURL is the HTTP endpoint's base URL as reported in GetCaps. Empty
	// derives it like AdvertiseURL, from the HTTP port.
	HTTPAdvertiseURL string `yaml:"httpAdvertiseURL"`
	// AllowInsecureAuth permits accounts without tls: passwords and session tokens
	// then cross the network in clear text unless a TLS proxy sits in front, which is
	// the one case this is for.
	AllowInsecureAuth bool `yaml:"allowInsecureAuth"`
	// TrustForwardedFor takes the client address from X-Forwarded-For, for rate
	// limits and logs. Only safe behind a reverse proxy that sets the header;
	// otherwise a client picks its own address and escapes every per-IP limit.
	TrustForwardedFor bool `yaml:"trustForwardedFor"`

	TLS  MetaAPITLSConfig      `yaml:"tls"`
	GRPC MetaAPIListenerConfig `yaml:"grpc"`
	HTTP MetaAPIHTTPConfig     `yaml:"http"`

	MetafileCache MetaAPICacheConfig `yaml:"metafileCache"`
	// FetchTimeoutMs bounds one FetchMetaFile call to a catalogue daemon.
	FetchTimeoutMs int `yaml:"fetchTimeoutMs"`
	// MaxMetafileBytes is the largest metafile served; bigger ones are refused.
	MaxMetafileBytes int `yaml:"maxMetafileBytes"`

	RateLimit MetaAPIRateLimitConfig `yaml:"rateLimit"`
	Search    MetaAPISearchConfig    `yaml:"search"`
	Accounts  AccountsConfig         `yaml:"accounts"`
}

// MetaAPISearchConfig is MetaApi.Search: a paged search of the torrent, Usenet
// and Kad catalogues behind metaSearch, for clients that browse them directly.
type MetaAPISearchConfig struct {
	// Enabled serves MetaApi.Search whenever the API is on. *bool, defaults on. It
	// needs at least one metaSearch network with liveSearch on.
	Enabled *bool `yaml:"enabled"`
	// RequireAccount asks for an active account, as metafile downloads do. It only
	// applies with metaApi.accounts.enabled. *bool, defaults on; false lets anyone
	// search while downloads still need an account.
	RequireAccount *bool `yaml:"requireAccount"`
	// TimeoutMs bounds the daemon calls behind one page.
	TimeoutMs int `yaml:"timeoutMs"`
	// MaxLimit caps the releases on one page.
	MaxLimit int `yaml:"maxLimit"`
	// Window is the deepest release paging reaches.
	Window int `yaml:"window"`

	Cache MetaAPISearchCacheConfig `yaml:"cache"`
	// RateLimit caps searches, separately from metafile downloads. 0 disables a limit.
	RateLimit MetaAPIRateLimitConfig `yaml:"rateLimit"`
}

// MetaAPISearchCacheConfig caches daemon answers in chunks of 100 releases per
// network and search, so paging forward and repeated searches cost no daemon call.
type MetaAPISearchCacheConfig struct {
	MaxEntries int `yaml:"maxEntries"`
	TTLSeconds int `yaml:"ttlSeconds"`
}

// MetaAPITLSConfig serves both listeners over TLS when CertFile and KeyFile are set.
type MetaAPITLSConfig struct {
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
	// AdvertiseFingerprint sends the certificate's SPKI pin as ST_META_API_FP (0x9C),
	// so a client can trust a self-signed certificate on a bare-IP server.
	AdvertiseFingerprint bool `yaml:"advertiseFingerprint"`
}

// MetaAPIListenerConfig is one listener. Enabled is *bool because the two listeners
// default differently: gRPC on, HTTP off.
type MetaAPIListenerConfig struct {
	Enabled *bool  `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

// MetaAPIHTTPConfig is the plain HTTP listener: a listener, plus what only it serves.
type MetaAPIHTTPConfig struct {
	Enabled *bool  `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	// Status serves the public GET /status whenever this listener runs. *bool,
	// defaults on. GET /healthz is served either way.
	Status *bool `yaml:"status"`
}

// MetaAPICacheConfig bounds the metafile cache by bytes rather than entries: a .nzb
// can be a hundred times the size of a .torrent.
type MetaAPICacheConfig struct {
	MaxBytes           int64 `yaml:"maxBytes"`
	TTLSeconds         int   `yaml:"ttlSeconds"`
	NegativeTTLSeconds int   `yaml:"negativeTtlSeconds"`
}

// MetaAPIRateLimitConfig caps metafile downloads. 0 disables that limit.
type MetaAPIRateLimitConfig struct {
	PerIPPerMinute      int `yaml:"perIPPerMinute"`
	PerAccountPerMinute int `yaml:"perAccountPerMinute"`
}

// AccountsConfig is optional username/password authentication. Off means the API is
// public. On, a user registers on the server's website first; Steps are what that
// registration takes beyond a username and password (payment, and later others).
type AccountsConfig struct {
	Enabled bool `yaml:"enabled"`
	// PublicURL is the website's base URL as users reach it, e.g.
	// https://enode.example.org. Registration links sent to clients are built from it.
	PublicURL string `yaml:"publicURL"`
	// AllowRegistration lets new users sign up on the website. *bool, defaults on.
	AllowRegistration *bool `yaml:"allowRegistration"`
	SessionTTLHours   int   `yaml:"sessionTtlHours"`
	MinPasswordLength int   `yaml:"minPasswordLength"`
	// PollSeconds is how often open steps are reconciled in the background, e.g. a
	// payment whose provider never called back.
	PollSeconds int `yaml:"pollSeconds"`
	// Steps run in order. Empty means registering activates the account at once.
	Steps []AccountStepConfig `yaml:"steps"`
}

// AccountStepConfig is one registration step. ID, Type and Enabled are common to
// every step; everything else in the entry is that step type's own configuration,
// kept as a raw node for the step to decode, so a new step type needs no change here.
type AccountStepConfig struct {
	ID      string
	Type    string
	Enabled bool
	// Raw is the whole YAML mapping of the entry, common keys included.
	Raw yaml.Node
}

// GRPCEnabled reports whether the gRPC listener runs, defaulting to on.
func (c MetaAPIConfig) GRPCEnabled() bool { return c.Enabled && boolOrDefault(c.GRPC.Enabled, true) }

// HTTPAPIEnabled reports whether the HTTP listener serves the API, defaulting to off.
func (c MetaAPIConfig) HTTPAPIEnabled() bool {
	return c.Enabled && boolOrDefault(c.HTTP.Enabled, false)
}

// HTTPListenerEnabled reports whether the HTTP listener runs at all: for the API, or
// for the account website.
func (c MetaAPIConfig) HTTPListenerEnabled() bool {
	return c.HTTPAPIEnabled() || (c.Enabled && c.Accounts.Enabled)
}

// PublicStatusEnabled reports whether the HTTP listener serves GET /status,
// defaulting to on whenever that listener runs.
func (c MetaAPIConfig) PublicStatusEnabled() bool {
	return c.HTTPListenerEnabled() && boolOrDefault(c.HTTP.Status, true)
}

// TLSEnabled reports whether the listeners serve TLS.
func (c MetaAPIConfig) TLSEnabled() bool { return c.TLS.CertFile != "" && c.TLS.KeyFile != "" }

// SearchEnabled reports whether MetaApi.Search is served, defaulting to on with the API.
func (c MetaAPIConfig) SearchEnabled() bool {
	return c.Enabled && boolOrDefault(c.Search.Enabled, true)
}

// SearchRequiresAccount reports whether MetaApi.Search needs an active account: only
// with accounts on, and then by default.
func (c MetaAPIConfig) SearchRequiresAccount() bool {
	return c.Accounts.Enabled && boolOrDefault(c.Search.RequireAccount, true)
}

// AllowRegistrationOrDefault reports whether new users may sign up, defaulting to true.
func (c AccountsConfig) AllowRegistrationOrDefault() bool {
	return boolOrDefault(c.AllowRegistration, true)
}

// EnabledSteps returns the steps that are switched on, in order.
func (c AccountsConfig) EnabledSteps() []AccountStepConfig {
	var out []AccountStepConfig
	for _, s := range c.Steps {
		if s.Enabled {
			out = append(out, s)
		}
	}
	return out
}

// UnmarshalYAML reads the common keys and keeps the whole node for the step.
func (s *AccountStepConfig) UnmarshalYAML(node *yaml.Node) error {
	var common struct {
		ID      string `yaml:"id"`
		Type    string `yaml:"type"`
		Enabled bool   `yaml:"enabled"`
	}
	if err := node.Decode(&common); err != nil {
		return err
	}
	s.ID, s.Type, s.Enabled = common.ID, common.Type, common.Enabled
	s.Raw = *node
	return nil
}

// Decode decodes the step's own keys into out.
func (s AccountStepConfig) Decode(out any) error {
	if s.Raw.Kind == 0 {
		return nil
	}
	return s.Raw.Decode(out)
}

// ApplyMetaAPIDefaults returns c with the defaults Load would fill in, or the error
// Load would report. For callers that build the section without a file.
func ApplyMetaAPIDefaults(c MetaAPIConfig) (MetaAPIConfig, error) {
	err := setMetaAPIDefaults(&c)
	return c, err
}

// Meta API defaults.
const (
	DefaultMetaAPIGRPCListen = "0.0.0.0:4671"
	DefaultMetaAPIHTTPListen = "0.0.0.0:4672"
)

// stepIDPattern keeps step ids usable as URL path segments.
var stepIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func setMetaAPIDefaults(c *MetaAPIConfig) error {
	if c.GRPC.Listen == "" {
		c.GRPC.Listen = DefaultMetaAPIGRPCListen
	}
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = DefaultMetaAPIHTTPListen
	}
	if c.MetafileCache.MaxBytes <= 0 {
		c.MetafileCache.MaxBytes = 256 << 20
	}
	if c.MetafileCache.TTLSeconds <= 0 {
		c.MetafileCache.TTLSeconds = 3600
	}
	if c.MetafileCache.NegativeTTLSeconds <= 0 {
		c.MetafileCache.NegativeTTLSeconds = 60
	}
	if c.FetchTimeoutMs <= 0 {
		c.FetchTimeoutMs = 3000
	}
	if c.MaxMetafileBytes <= 0 {
		c.MaxMetafileBytes = 16 << 20
	}
	if c.RateLimit.PerIPPerMinute < 0 || c.RateLimit.PerAccountPerMinute < 0 {
		return fmt.Errorf("metaApi.rateLimit values must not be negative; 0 disables a limit")
	}
	if err := setMetaAPISearchDefaults(&c.Search); err != nil {
		return err
	}
	a := &c.Accounts
	if a.SessionTTLHours <= 0 {
		a.SessionTTLHours = 720
	}
	if a.MinPasswordLength <= 0 {
		a.MinPasswordLength = 8
	}
	if a.PollSeconds <= 0 {
		a.PollSeconds = 300
	}
	if err := validateAccountSteps(a.Steps); err != nil {
		return err
	}
	if !c.Enabled {
		return nil
	}
	for key, addr := range map[string]string{"metaApi.grpc.listen": c.GRPC.Listen, "metaApi.http.listen": c.HTTP.Listen} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("%s %q is invalid: use host:port: %w", key, addr, err)
		}
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return fmt.Errorf("metaApi.tls needs both certFile and keyFile, or neither")
	}
	if c.TLS.AdvertiseFingerprint && !c.TLSEnabled() {
		return fmt.Errorf("metaApi.tls.advertiseFingerprint needs certFile and keyFile")
	}
	for key, u := range map[string]string{"metaApi.advertiseURL": c.AdvertiseURL, "metaApi.httpAdvertiseURL": c.HTTPAdvertiseURL} {
		if u != "" && !isHTTPURL(u) {
			return fmt.Errorf("%s %q is invalid: use http(s)://host[:port]", key, u)
		}
	}
	if !a.Enabled {
		return nil
	}
	if !c.TLSEnabled() && !c.AllowInsecureAuth {
		return fmt.Errorf("metaApi.accounts needs metaApi.tls, or allowInsecureAuth: true when a TLS proxy terminates in front: passwords would otherwise cross the network in clear text")
	}
	if !isHTTPURL(a.PublicURL) {
		return fmt.Errorf("metaApi.accounts.publicURL %q is invalid: it is the website users register on, e.g. https://enode.example.org", a.PublicURL)
	}
	a.PublicURL = strings.TrimRight(a.PublicURL, "/")
	return nil
}

// Search limits. maxSearchWindow matches the daemons' own paging depth.
const (
	maxSearchLimit  = 500
	maxSearchWindow = 10000
)

func setMetaAPISearchDefaults(c *MetaAPISearchConfig) error {
	if c.TimeoutMs <= 0 {
		c.TimeoutMs = 5000
	}
	if c.MaxLimit <= 0 {
		c.MaxLimit = 100
	}
	if c.Window <= 0 {
		c.Window = 1000
	}
	if c.Cache.MaxEntries <= 0 {
		c.Cache.MaxEntries = 2000
	}
	if c.Cache.TTLSeconds <= 0 {
		c.Cache.TTLSeconds = 600
	}
	switch {
	case c.RateLimit.PerIPPerMinute < 0 || c.RateLimit.PerAccountPerMinute < 0:
		return fmt.Errorf("metaApi.search.rateLimit values must not be negative")
	case c.MaxLimit > maxSearchLimit:
		return fmt.Errorf("metaApi.search.maxLimit (%d) exceeds %d", c.MaxLimit, maxSearchLimit)
	case c.Window > maxSearchWindow:
		return fmt.Errorf("metaApi.search.window (%d) exceeds %d", c.Window, maxSearchWindow)
	case c.Window < c.MaxLimit:
		return fmt.Errorf("metaApi.search.window (%d) is smaller than maxLimit (%d)", c.Window, c.MaxLimit)
	}
	return nil
}

// validateAccountSteps checks what every step has in common. A step's own keys are
// validated by the step when it is built at startup.
func validateAccountSteps(steps []AccountStepConfig) error {
	seen := map[string]bool{}
	for i, s := range steps {
		if !stepIDPattern.MatchString(s.ID) {
			return fmt.Errorf("metaApi.accounts.steps[%d].id %q is invalid: use 1-32 of a-z, 0-9, _ and -", i, s.ID)
		}
		if seen[s.ID] {
			return fmt.Errorf("metaApi.accounts.steps[%d].id %q is used twice", i, s.ID)
		}
		seen[s.ID] = true
		if s.Type == "" {
			return fmt.Errorf("metaApi.accounts.steps[%d] (%s) has no type", i, s.ID)
		}
	}
	return nil
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
