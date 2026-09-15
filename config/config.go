package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"enode/storage"
	"enode/tests"
	"gopkg.in/yaml.v3"
)

// DataDir holds everything the server *writes* — the gossip server.met, the
// downloaded GeoIP database. Config files, the MySQL DDL and operator-supplied
// filter lists stay in the repo root, so a `git status` is never noisy with runtime
// state and `data/` can be gitignored wholesale.
//
// Paths under it are resolved through tests.FixRelativeTestingPath (see
// ResolveDataPath), which walks up to the go.mod directory. That makes a relative
// path mean the same thing whether the server was started from the repo root or a
// test is running from a package subdirectory.
const DataDir = "data"

type Config struct {
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	Address      string   `yaml:"address"`
	DynIP        string   `yaml:"dynIp"`
	TestURLs     []string `yaml:"testUrls"`
	MessageLowID string   `yaml:"messageLowID"`
	MessageLogin string   `yaml:"messageLogin"`
	// NoAssert is accepted for config compatibility with the Node original but is
	// an intentional no-op: Go bounds-checks every slice/array access, so there is
	// no assertion layer to disable. Kept so an existing YAML with the key loads.
	NoAssert bool   `yaml:"noAssert"`
	LogLevel string `yaml:"logLevel"`
	LogFile  string `yaml:"logFile"`

	// Servers seeds OP_SERVERLIST — the other servers this node advertises to
	// clients (never itself; a server's own identity travels in OP_SERVERIDENT).
	// Empty by default: an empty list is valid and correct, unlike the Node
	// original's two hard-coded invalid placeholder IPs.
	Servers []ServerEntry `yaml:"servers"`

	SupportCrypt bool `yaml:"supportCrypt"`
	RequestCrypt bool `yaml:"requestCrypt"`
	RequireCrypt bool `yaml:"requireCrypt"`
	AuxiliarPort bool `yaml:"auxiliarPort"`
	IPInLogin    bool `yaml:"IPinLogin"`

	TCP    TCPConfig    `yaml:"tcp"`
	UDP    UDPConfig    `yaml:"udp"`
	Files  FilesConfig  `yaml:"files"`
	NAT    NATConfig    `yaml:"natTraversal"`
	IPv6   IPv6Config   `yaml:"ipv6"`
	Admin  AdminConfig  `yaml:"admin"`
	Gossip GossipConfig `yaml:"gossip"`
	Filter FilterConfig `yaml:"filter"`

	Storage StorageConfig `yaml:"storage"`
	Debug   DebugConfig   `yaml:"debug"`
}

// DebugConfig gates debug-only development aids. SeedFixtures injects the dummy
// peers and files described by FixturesFile into the chosen storage engine at
// startup, so the search / source-list paths can be exercised without live clients.
//
// SeedFixtures is a plain bool, not a *bool: its default is OFF, which is exactly
// what a missing key yields, so the *bool "tell absent from explicit-false" pattern
// used by the default-on toggles is unnecessary here. Never enable on a public
// server — it advertises fabricated sources.
type DebugConfig struct {
	SeedFixtures bool   `yaml:"seedFixtures"`
	FixturesFile string `yaml:"fixturesFile"`
}

// ServerEntry is one advertised peer server in OP_SERVERLIST. IP may be an IPv4
// dotted-quad or a public IPv6 literal; a v6 entry is advertised in the trailing
// IPv6 block (see ed2k.BuildServerListPacket) to v6-aware clients only.
type ServerEntry struct {
	IP   string `yaml:"ip"`
	Port uint16 `yaml:"port"`
}

type TCPConfig struct {
	Port              uint16 `yaml:"port"`
	PortObfuscated    uint16 `yaml:"portObfuscated"`
	MaxConnections    int    `yaml:"maxConnections"`
	ConnectionTimeout int    `yaml:"connectionTimeout"`
	DisconnectTimeout int    `yaml:"disconnectTimeout"`
	AllowLowIDs       bool   `yaml:"allowLowIDs"`
	MinLowID          uint32 `yaml:"minLowID"`
	MaxLowID          uint32 `yaml:"maxLowID"`
}

// FilesConfig caps how many files a single client may publish to this server.
//
// Both are per-client publish caps, not statements about server capacity, and both
// are Lugdunum's own concepts. From its documentation, vendored at
// lugdunum-eserver/docs/kiten-20071012.txt:462 — "softLimit: If a client tries to
// publish more than softLimit files, the server sends him a WARNING message and
// ignores files in excess" — and :349 — "hardLimit: If a client tries to publish
// more than hardLimit files, the server disconnects him (before receiving the whole
// list)". eserver's defaults are 1000 and 4000; ours stay at the values eNode-go has
// always advertised, so enabling enforcement does not also change what clients are
// told. Both are enforced per TCP session in handleOfferFiles and advertised at
// OP_GLOBSERVSTATRES offsets +16/+20. See docs/file-publish-limits.md.
//
// Pointers, not plain ints, for the same reason the *bool toggles are pointers: zero
// is a meaningful value here (it means unlimited), so an absent key has to be
// distinguishable from an explicit 0. tcp.maxConnections gets away with a plain int
// only because it is never defaulted at all.
type FilesConfig struct {
	SoftLimit *int `yaml:"softLimit"`
	HardLimit *int `yaml:"hardLimit"`
}

// DefaultSoftFileLimit and DefaultHardFileLimit are the values eNode-go has published
// at OP_GLOBSERVSTATRES +16/+20 since it was written (previously hard-coded in
// BuildGlobServStatResPacket). Kept rather than adopting eserver's 1000/4000 so that
// turning enforcement on is a change of behaviour only, not of what we advertise.
const (
	DefaultSoftFileLimit = 10000
	DefaultHardFileLimit = 20000
)

// SoftLimitOrDefault and HardLimitOrDefault resolve the configured caps. Zero is
// returned as zero — unlimited — and is not replaced by the default.
func (c FilesConfig) SoftLimitOrDefault() int { return intOrDefault(c.SoftLimit, DefaultSoftFileLimit) }
func (c FilesConfig) HardLimitOrDefault() int { return intOrDefault(c.HardLimit, DefaultHardFileLimit) }

type UDPConfig struct {
	Port           uint16 `yaml:"port"`
	PortObfuscated uint16 `yaml:"portObfuscated"`
	// PortGossip is the socket obfuscated server-to-server frames are sent from, and the
	// portUDPOBF value published to peers.
	//
	// It defaults to tcp.Port + 12 — the same socket as PortObfuscated, which is then
	// shared rather than bound twice. tcp+12 is not a free choice: Lugdunum derives a
	// peer's TCP port from the UDP source port of an obfuscated frame by subtracting 12,
	// so a frame we send from any other port is attributed to a server that does not
	// exist. Measured, see docs/server-gossip.md §8.
	//
	// Setting it to anything else binds a separate socket and advertises that port. Only
	// do so for a peer implementation known to want it: against a real eserver it breaks
	// the ping bookkeeping that decides whether we count as a "working" server.
	PortGossip uint16 `yaml:"portGossip"`
	GetSources bool   `yaml:"getSources"`
	GetFiles   bool   `yaml:"getFiles"`
	// ServerKey is a server-wide secret seed, not the key sent to clients: each
	// client's UDP obfuscation key is derived from it plus the client's IP
	// (ed2k.deriveUDPKey). See docs/server-udp-crypt-ping.md.
	ServerKey uint32 `yaml:"serverKey"`
}

type NATConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    uint16 `yaml:"port"`
	// IPv6 enables dual-stack hole-punching (OP_NAT_*_IPV6). *bool so an absent key
	// defaults on; effective only when NAT and top-level ipv6 are also enabled. See
	// docs/ipv6-client-implementation-spec.md §9.
	IPv6 *bool `yaml:"ipv6"`
	// ServerIndependent enables cross-server / serverless LowID↔LowID rendezvous: the
	// server pairs two registered clients regardless of which eD2K server (if any)
	// they are logged into, and advertises the capability. *bool so an absent key
	// defaults on. When off, pairing is restricted to clients currently logged into
	// this server. See docs/ipv6-client-implementation-spec.md §9.
	ServerIndependent      *bool `yaml:"serverIndependent"`
	RegistrationTTLSeconds int   `yaml:"registrationTTLSeconds"`
}

// IPv6OrDefault reports whether IPv6 hole-punching is enabled, defaulting to true
// (subject to the top-level ipv6.enabled and natTraversal.enabled gates).
func (c NATConfig) IPv6OrDefault() bool { return boolOrDefault(c.IPv6, true) }

// ServerIndependentOrDefault reports whether server-independent (cross-server /
// serverless) rendezvous is enabled, defaulting to true.
func (c NATConfig) ServerIndependentOrDefault() bool { return boolOrDefault(c.ServerIndependent, true) }

// IPv6Config controls dual-stack listening and IPv6 source publication. When
// disabled the server behaves exactly as before: IPv4-only listeners, no IPv6
// parsed, stored or emitted.
//
// Enabled/PublishSources/ProbeReachability are *bool so an absent key can be told
// from an explicit false — the intended default is on, and a plain bool would
// default a missing key to off (see CleanupConfig.KeepZeroSourceFiles).
type IPv6Config struct {
	Enabled *bool `yaml:"enabled"`
	// Address is an explicit IPv6 bind. Empty means the top-level `address` governs
	// the bind (an empty top-level address is the dual-stack wildcard).
	Address string `yaml:"address"`
	// DynIP6 is the server's public IPv6, or "auto" to resolve it via TestURLs6 /
	// local interface enumeration. Empty disables self-advertisement of a v6.
	DynIP6            string   `yaml:"dynIp6"`
	TestURLs6         []string `yaml:"testUrls6"`
	PublishSources    *bool    `yaml:"publishSources"`
	ProbeReachability *bool    `yaml:"probeReachability"`
}

// EnabledOrDefault reports whether IPv6 is enabled, defaulting to true.
func (c IPv6Config) EnabledOrDefault() bool { return boolOrDefault(c.Enabled, true) }

// PublishSourcesOrDefault reports whether IPv6 sources are emitted, defaulting to
// true (subject to EnabledOrDefault).
func (c IPv6Config) PublishSourcesOrDefault() bool { return boolOrDefault(c.PublishSources, true) }

// ProbeReachabilityOrDefault reports whether the server probes a client's IPv6
// before publishing it as a source, defaulting to true.
func (c IPv6Config) ProbeReachabilityOrDefault() bool {
	return boolOrDefault(c.ProbeReachability, true)
}

// AdminConfig controls the local HTTP status dashboard (see admin.Server). Enabled
// is *bool so an absent key defaults on rather than off; BindIP defaults to
// 127.0.0.1 so the dashboard is reachable out of the box but never off-box unless
// the operator widens it deliberately.
type AdminConfig struct {
	Enabled *bool  `yaml:"enabled"`
	BindIP  string `yaml:"bindIP"`
	Port    uint16 `yaml:"port"`
}

// EnabledOrDefault reports whether the admin dashboard is served, defaulting to true.
func (c AdminConfig) EnabledOrDefault() bool { return boolOrDefault(c.Enabled, true) }

// GossipConfig controls server-to-server peer exchange — the Lugdunum
// OP_SERVER_LIST_REQ/RES handshake. When enabled the server registers itself with
// each seed, harvests their peer lists, and answers other servers' requests, so
// OP_SERVERLIST is populated from the live network instead of from `servers:`.
//
// Enabled and Persist are *bool so an absent key can be told from an explicit false;
// both default on. See docs/server-gossip.md for the wire protocol.
type GossipConfig struct {
	Enabled *bool `yaml:"enabled"`
	// Seeds are the servers to bootstrap from. Empty falls back to the top-level
	// `servers:` list, so an existing config needs no new keys to participate.
	Seeds []ServerEntry `yaml:"seeds"`
	// IntervalSeconds is how often each peer is re-contacted. Lugdunum's own keepalive
	// is ~165 s; the default 150 s stays just inside that so our entry never expires
	// on a peer between rounds.
	IntervalSeconds int `yaml:"intervalSeconds"`
	// MaxServers caps the peer table, matching eserver's maxservers default of 4096.
	// A cap is a DoS guard, not a tuning knob: without it a hostile peer can grow the
	// table without bound by echoing fabricated entries.
	MaxServers int `yaml:"maxServers"`
	// MaxFailures parks a peer after this many consecutive failed rounds.
	MaxFailures int `yaml:"maxFailures"`
	// PublishIPv6 emits and consumes the OP_SERVER_LIST_*_IPV6 (0xa7/0xa8) extension.
	// *bool, defaults on; only effective when the top-level ipv6 is also enabled.
	PublishIPv6 *bool `yaml:"publishIPv6"`
	// AllowPrivatePeers permits LAN/loopback peer addresses, the equivalent of eMule's
	// FilterLANIPs preference being off. Default false. Needed to gossip with a server
	// on the same host or LAN — including the Lugdunum reference container — because
	// ed2k.IsGoodIP otherwise rejects those addresses outright.
	AllowPrivatePeers bool `yaml:"allowPrivatePeers"`
	// Persist writes verified peers to ServerMetFile so a restart does not have to
	// re-earn the mesh. *bool, defaults on. Mirrors eserver's autoservlist.
	Persist *bool `yaml:"persist"`
	// ServerMetFile is the eMule-format server.met written by the persistence loop.
	// Under ./data because the server writes it; see docs/server-gossip.md.
	ServerMetFile string `yaml:"serverMetFile"`
	// PersistIntervalSeconds is the write cadence, eserver's ~225 s.
	PersistIntervalSeconds int `yaml:"persistIntervalSeconds"`
}

// EnabledOrDefault reports whether gossip runs, defaulting to true.
func (c GossipConfig) EnabledOrDefault() bool { return boolOrDefault(c.Enabled, true) }

// PublishIPv6OrDefault reports whether the 0xa7/0xa8 IPv6 extension is used,
// defaulting to true (subject to the top-level ipv6.enabled gate).
func (c GossipConfig) PublishIPv6OrDefault() bool { return boolOrDefault(c.PublishIPv6, true) }

// PersistOrDefault reports whether the peer table is written to disk, defaulting to true.
func (c GossipConfig) PersistOrDefault() bool { return boolOrDefault(c.Persist, true) }

// FilterConfig controls who may talk to the server at all. Both halves are
// independently optional and both default off: they need operator-supplied data
// (a range list, MaxMind credentials) that no default can invent.
//
// A blocked address is dropped before any wire parsing on both TCP and UDP.
// See docs/access-filters.md.
type FilterConfig struct {
	IPFilter IPFilterConfig `yaml:"ipfilter"`
	GeoIP    GeoIPConfig    `yaml:"geoip"`
}

// IPFilterConfig is the static range list: an eMule/guarding.p2p ipfilter.dat or an
// eserver ipfilter.srv. Operator-supplied, so File is not under ./data.
type IPFilterConfig struct {
	Enabled bool   `yaml:"enabled"`
	File    string `yaml:"file"`
	// MinLevel blocks a range whose level is strictly *below* this value. The
	// convention is inverted from what the name suggests — a low level means high
	// confidence the range is bad — so raising it blocks more. Zero uses eMule's
	// default of 100.
	MinLevel int `yaml:"minLevel"`
	// ReloadMinutes re-reads the file on a timer so a range list can be updated
	// without a restart. Zero disables reloading.
	ReloadMinutes int `yaml:"reloadMinutes"`
}

// GeoIPConfig is country-based blocking from a MaxMind GeoLite2 country database.
//
// A deny-list, deliberately: that is how operators use eserver's obfcountries, and an
// allow-list on a public eD2K server would refuse most of the network the moment a
// code was mistyped. An address that resolves to no country is never blocked.
type GeoIPConfig struct {
	Enabled bool `yaml:"enabled"`
	// Database is the .mmdb path. Downloaded and refreshed by the server, so under
	// ./data rather than the repo root.
	Database string `yaml:"database"`
	// BlockedCountries are ISO 3166-1 alpha-2 codes, case-insensitive.
	BlockedCountries []string `yaml:"blockedCountries"`
	// AccountID and LicenseKey are MaxMind download credentials. Leave both empty to
	// use only an existing local database and never contact MaxMind. Keep real values
	// out of the committed config — enode.local.yaml is gitignored.
	AccountID  string `yaml:"accountID"`
	LicenseKey string `yaml:"licenseKey"`
	// UpdateDays is how often to check for a newer database. GeoLite2-Country is
	// republished weekly, and the check is conditional on the current file's MD5 —
	// an unchanged database transfers nothing. Zero uses 7.
	UpdateDays int `yaml:"updateDays"`
}

// HasCredentials reports whether MaxMind download credentials were supplied. Both
// halves are required: an account ID without a licence key cannot authenticate, and
// treating that as "configured" would turn a half-filled config into a download error
// on every refresh instead of the intended local-file-only mode.
func (c GeoIPConfig) HasCredentials() bool {
	return c.AccountID != "" && c.LicenseKey != ""
}

// boolOrDefault returns *p, or def when p is nil. The *bool pattern lets an absent
// YAML key be told from an explicit false (see the IPv6 and cleanup toggles).
func boolOrDefault(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// intOrDefault returns *p, or def when p is nil. The *int counterpart of
// boolOrDefault, for a key whose zero value means something (files.softLimit /
// files.hardLimit: 0 is "unlimited", not "unset").
func intOrDefault(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

type StorageConfig struct {
	Engine   string         `yaml:"engine"`
	Cleanup  CleanupConfig  `yaml:"cleanup"`
	Snapshot SnapshotConfig `yaml:"snapshot"`
	MySQL    MySQLConfig    `yaml:"mysql"`
	MongoDB  MongoDBConfig  `yaml:"mongodb"`
}

// SnapshotConfig persists the memory engine's index to disk so a restart does not
// start empty. It applies to the memory engine only — mysql and mongodb already
// persist, and enabling it under those is a logged no-op rather than an error.
//
// Enabled is a plain bool, not a *bool: the default is off, which is exactly what
// an absent key already yields, so there is nothing for the pointer to disambiguate
// (unlike CleanupConfig.KeepZeroSourceFiles, whose default is on).
type SnapshotConfig struct {
	Enabled         bool   `yaml:"enabled"`
	File            string `yaml:"file"`
	IntervalMinutes int    `yaml:"intervalMinutes"`
	// Compress gzip-wraps the gob stream, roughly halving a file that is dominated
	// by filenames. The reader sniffs the gzip magic rather than trusting this, so
	// flipping it does not orphan the snapshot already on disk.
	Compress bool `yaml:"compress"`
}

type CleanupConfig struct {
	Enabled         bool `yaml:"enabled"`
	StaleAfterHours int  `yaml:"staleAfterHours"`
	IntervalMinutes int  `yaml:"intervalMinutes"`
	// KeepZeroSourceFiles is a *bool, not a bool, so setDefaults can tell an
	// absent key from an explicit false. A plain bool would default to false when
	// the key is missing — the opposite of the intended default — and would
	// silently start deleting files for anyone whose config predates this option.
	KeepZeroSourceFiles *bool `yaml:"keepZeroSourceFiles"`
	BatchSize           int   `yaml:"batchSize"`
}

// KeepZeroSourceFilesOrDefault reports whether files with no remaining sources
// are retained, defaulting to true.
//
// Kept by default because the server's source list is not the only way a client
// finds peers: Kad and source exchange can locate sources for a file the server
// knows about but currently has none online for. The search result is how a user
// discovers the hash at all, so deleting it removes discovery for no gain.
func (c CleanupConfig) KeepZeroSourceFilesOrDefault() bool {
	return boolOrDefault(c.KeepZeroSourceFiles, true)
}

type MySQLConfig struct {
	Database      string `yaml:"database"`
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	User          string `yaml:"user"`
	Pass          string `yaml:"pass"`
	Connections   int    `yaml:"connections"`
	DeadlockDelay int    `yaml:"deadlockDelay"`
	// SchemaFile is the DDL applied on first connect when the tables are missing.
	// Relative to the working directory; defaults to misc/enode.sql.
	SchemaFile string `yaml:"schemaFile"`
	// Dialect selects the full-text search strategy, since MariaDB and MySQL do
	// not share one. "mariadb" (the default) uses a plain word-based FULLTEXT
	// index and word-prefix matching, portable to both servers. "mysql" uses the
	// ngram parser (MySQL 5.7.6+ only) for true substring matching. See
	// storage.DialectMariaDB / storage.DialectMySQL and docs/database-engines.local.md.
	Dialect string `yaml:"dialect"`
}

type MongoDBConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
	URI      string `yaml:"uri"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	if err := setDefaults(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func setDefaults(cfg *Config) error {
	// Client-facing message text is stored LF-separated whatever the YAML style. The
	// wire layer converts to CRLF on the way out — see ed2k.BuildServerMessagePacket.
	cfg.MessageLogin = normalizeMessageText(cfg.MessageLogin)
	cfg.MessageLowID = normalizeMessageText(cfg.MessageLowID)

	// With IPv6 disabled, an empty bind pins to the IPv4 wildcard exactly as
	// before. With IPv6 enabled, an empty bind is left empty so the listener binds
	// the dual-stack wildcard ([::]) and accepts both families; an operator who
	// wants IPv4-only sets address: "0.0.0.0" explicitly.
	if cfg.Address == "" && !cfg.IPv6.EnabledOrDefault() {
		cfg.Address = "0.0.0.0"
	}
	if len(cfg.IPv6.TestURLs6) == 0 {
		// Ordered literal-IP first (the address pins the family, immune to DNS /
		// Happy Eyeballs), then v6-only hostnames, then dual-stack hosts. Verified
		// live 2026-07-20. 6.ipw.cn is included last but returned empty on probe.
		cfg.IPv6.TestURLs6 = []string{
			"https://[2606:4700:4700::1111]/cdn-cgi/trace",
			"https://v6.ident.me",
			"https://ipv6.icanhazip.com",
			"https://api64.ipify.org",
			"https://www.cloudflare.com/cdn-cgi/trace",
			"https://6.ipw.cn",
		}
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.LogFile == "" {
		cfg.LogFile = "logs/enode.log"
	}
	if len(cfg.TestURLs) == 0 {
		cfg.TestURLs = []string{
			"https://4.ipw.cn",
			"https://ip.3322.net",
			"https://api.ipify.org",
			"https://checkip.amazonaws.com",
		}
	}
	// Ports match the Node original (enode.config.js) and both shipped YAMLs:
	// TCP 5555/5565 and plaintext UDP 5559 (tcp+4, the port eMule pings for the
	// unencrypted stat — srchybrid/UDPSocket.cpp:771-772).
	// The port previously fell back to the classic eDonkey 4661/4662/4665/4666,
	// which no config in the repo uses — so a YAML omitting the port keys bound
	// different ports than every sample config.
	if cfg.TCP.Port == 0 {
		cfg.TCP.Port = 5555
	}
	if cfg.TCP.PortObfuscated == 0 {
		cfg.TCP.PortObfuscated = 5565
	}
	if cfg.TCP.DisconnectTimeout <= 0 {
		cfg.TCP.DisconnectTimeout = 3600
	}
	if cfg.UDP.Port == 0 {
		cfg.UDP.Port = 5559
	}
	// eMule hardwires the server-UDP crypt-ping to tcp+12 and, on first contact,
	// only accepts the reply from that same port (srchybrid/ServerList.cpp:294,
	// GetServerByIPUDP :563-576). So the obfuscated UDP listener must sit at
	// tcp.port+12 (5567) — not tcp.portObfuscated+4 — or the crypt-ping bootstrap
	// is unreachable and clients fall back to the plaintext stat. See
	// docs/server-udp-crypt-ping.md.
	if cfg.UDP.PortObfuscated == 0 {
		cfg.UDP.PortObfuscated = cfg.TCP.Port + 12
	}
	// The obfuscated server-to-server channel shares the tcp+12 socket above, and tcp+12
	// is forced by the reference implementation rather than chosen.
	//
	// Two of eserver's constraints have to hold at once. It skips a peer whose obfuscated
	// frames do not arrive from the portUDPOBF that peer advertised ("continue because
	// portUDPobf(%d) != sin_port(%d)"), so the port we send from must be the port we
	// publish. And it recovers a peer's *TCP* port from the UDP source port of an
	// obfuscated frame by subtracting 12 — measured directly: a frame from our 5567 was
	// booked to 5555, one from 5569 to a nonexistent 5557, after which its ping
	// bookkeeping never confirmed and we stayed out of its "working servers" list and
	// therefore out of its server.met.
	//
	// tcp+14 (eserver's own portUDPOBF default) satisfies the first constraint and breaks
	// the second, so it cannot be used. See docs/server-gossip.md §8.
	if cfg.UDP.PortGossip == 0 {
		cfg.UDP.PortGossip = cfg.UDP.PortObfuscated
	}
	if cfg.NAT.Port == 0 {
		cfg.NAT.Port = 2004
	}
	if cfg.NAT.RegistrationTTLSeconds <= 0 {
		cfg.NAT.RegistrationTTLSeconds = 30
	}
	// Localhost-only by default: the dashboard is on out of the box but reachable
	// only from the same machine until an operator sets a wider bindIP.
	if cfg.Admin.BindIP == "" {
		cfg.Admin.BindIP = "127.0.0.1"
	}
	if cfg.Admin.Port == 0 {
		cfg.Admin.Port = 4560
	}
	// Gossip cadence. 150 s sits just inside Lugdunum's own ~165 s keepalive, so our
	// entry never lapses on a peer between rounds; 4096 is eserver's maxservers.
	if cfg.Gossip.IntervalSeconds <= 0 {
		cfg.Gossip.IntervalSeconds = 150
	}
	if cfg.Gossip.MaxServers <= 0 {
		cfg.Gossip.MaxServers = 4096
	}
	if cfg.Gossip.MaxFailures <= 0 {
		cfg.Gossip.MaxFailures = 5
	}
	if cfg.Gossip.PersistIntervalSeconds <= 0 {
		cfg.Gossip.PersistIntervalSeconds = 225
	}
	// Under DataDir because the server writes it, unlike the operator-supplied
	// ipfilter and schema files which stay where the operator put them.
	if cfg.Gossip.ServerMetFile == "" {
		cfg.Gossip.ServerMetFile = filepath.Join(DataDir, "server.met")
	}
	if cfg.Filter.IPFilter.MinLevel <= 0 {
		cfg.Filter.IPFilter.MinLevel = 100
	}
	if cfg.Filter.IPFilter.File == "" {
		cfg.Filter.IPFilter.File = "ipfilter.dat"
	}
	if cfg.Filter.GeoIP.Database == "" {
		cfg.Filter.GeoIP.Database = filepath.Join(DataDir, "GeoLite2-Country.mmdb")
	}
	if cfg.Filter.GeoIP.UpdateDays <= 0 {
		cfg.Filter.GeoIP.UpdateDays = 7
	}
	if cfg.Storage.Engine == "" {
		cfg.Storage.Engine = "memory"
	}
	if cfg.Storage.Cleanup.StaleAfterHours <= 0 {
		cfg.Storage.Cleanup.StaleAfterHours = 24
	}
	if cfg.Storage.Cleanup.IntervalMinutes <= 0 {
		cfg.Storage.Cleanup.IntervalMinutes = 60
	}
	// Fifteen minutes bounds how much of the index a crash can cost while keeping
	// the write off the hot path; an orderly shutdown flushes regardless, so this
	// only matters for a kill.
	if cfg.Storage.Snapshot.IntervalMinutes <= 0 {
		cfg.Storage.Snapshot.IntervalMinutes = 15
	}
	// Under DataDir for the same reason as server.met: the server writes it, unlike
	// the operator-supplied ipfilter and schema files.
	if cfg.Storage.Snapshot.File == "" {
		cfg.Storage.Snapshot.File = filepath.Join(DataDir, "storage.gob")
	}
	if cfg.Storage.MySQL.Port == 0 {
		cfg.Storage.MySQL.Port = 3306
	}
	if cfg.Storage.MySQL.SchemaFile == "" {
		cfg.Storage.MySQL.SchemaFile = "misc/enode.sql"
	}
	// Default to the portable word-based dialect; an operator on real MySQL opts
	// into the ngram substring path explicitly. Fail fast on a typo rather than
	// silently picking a strategy the operator did not intend.
	if cfg.Storage.MySQL.Dialect == "" {
		cfg.Storage.MySQL.Dialect = storage.DialectMariaDB
	}
	if cfg.Storage.MySQL.Dialect != storage.DialectMariaDB && cfg.Storage.MySQL.Dialect != storage.DialectMySQL {
		return fmt.Errorf("storage.mysql.dialect %q is invalid: use %q or %q",
			cfg.Storage.MySQL.Dialect, storage.DialectMariaDB, storage.DialectMySQL)
	}
	// The publish caps are rejected rather than clamped, on the same reasoning as the
	// dialect above: both mistakes below are typos with a silent, wrong-behaviour
	// outcome, and this package has no logger to warn through.
	//
	// hardLimit below softLimit is the interesting one. The two are checked in that
	// order per record, so the session is closed before the soft warning could ever be
	// sent — the operator has written a soft limit that can never fire and would have
	// no way to tell.
	softFiles, hardFiles := cfg.Files.SoftLimitOrDefault(), cfg.Files.HardLimitOrDefault()
	if softFiles < 0 || hardFiles < 0 {
		return fmt.Errorf("files.softLimit (%d) and files.hardLimit (%d) must not be negative; 0 means unlimited",
			softFiles, hardFiles)
	}
	if softFiles > 0 && hardFiles > 0 && hardFiles < softFiles {
		return fmt.Errorf("files.hardLimit (%d) is below files.softLimit (%d): a client would be disconnected before the soft-limit warning could be sent",
			hardFiles, softFiles)
	}
	if cfg.Storage.MongoDB.Port == 0 {
		cfg.Storage.MongoDB.Port = 27017
	}
	if cfg.Storage.MongoDB.Database == "" {
		cfg.Storage.MongoDB.Database = "enode"
	}
	// Default the fixtures path even when seeding is off, so the shipped config can
	// document the key without an operator having to invent a path. Working-directory
	// relative, like storage.mysql.schemaFile above.
	if cfg.Debug.FixturesFile == "" {
		cfg.Debug.FixturesFile = "tests/data/debug_fixtures.yaml"
	}
	return nil
}

// ResolveDataPath makes a config path usable from any working directory by resolving
// it against the module root (the directory holding go.mod).
//
// This matters for two different callers. A server started from somewhere other than
// the repo root would otherwise create a second `data/` beside wherever it was
// launched. And a test in ed2k/ or netfilter/ runs with its own package directory as
// the working directory, so a bare "data/server.met" would resolve differently in
// every package. An absolute path is returned unchanged, and a deployed binary with no
// go.mod above it gets the path back as-is — the correct fallback in both cases.
func ResolveDataPath(path string) string {
	if path == "" {
		return ""
	}
	return tests.FixRelativeTestingPath(path)
}

// ServerMetPath is the resolved location of the gossip peer file.
func (c Config) ServerMetPath() string { return ResolveDataPath(c.Gossip.ServerMetFile) }

// StorageSnapshotPath is the resolved location of the memory-engine snapshot.
func (c Config) StorageSnapshotPath() string { return ResolveDataPath(c.Storage.Snapshot.File) }

// GeoIPDatabasePath is the resolved location of the MaxMind country database.
func (c Config) GeoIPDatabasePath() string { return ResolveDataPath(c.Filter.GeoIP.Database) }

// IPFilterPath is the resolved location of the operator-supplied range list. It is
// resolved the same way even though it is not under DataDir, so that naming
// "ipfilter.dat" works from a subdirectory too.
func (c Config) IPFilterPath() string { return ResolveDataPath(c.Filter.IPFilter.File) }

// GossipSeeds returns the servers to bootstrap from: gossip.seeds when set, otherwise
// the top-level `servers:` list. Falling back means an existing config participates in
// gossip without gaining a single new key, and an operator who wants the two lists to
// differ — advertise these, bootstrap from those — can still say so explicitly.
func (c Config) GossipSeeds() []ServerEntry {
	if len(c.Gossip.Seeds) > 0 {
		return c.Gossip.Seeds
	}
	return c.Servers
}

func (c Config) StorageEngineConfig() storage.Config {
	mysqlCfg := storage.MySQLConfig{
		Host:            c.Storage.MySQL.Host,
		Port:            c.Storage.MySQL.Port,
		User:            c.Storage.MySQL.User,
		Pass:            c.Storage.MySQL.Pass,
		Database:        c.Storage.MySQL.Database,
		MaxOpenConns:    c.Storage.MySQL.Connections,
		MaxIdleConns:    c.Storage.MySQL.Connections / 2,
		ConnMaxLifetime: 5 * time.Minute,
		// deadlockDelay was parsed from YAML and then dropped here, so the option
		// had no effect anywhere in the program.
		DeadlockDelay: time.Duration(c.Storage.MySQL.DeadlockDelay) * time.Millisecond,
		SchemaFile:    c.Storage.MySQL.SchemaFile,
		Dialect:       c.Storage.MySQL.Dialect,
	}
	mongoURI := c.Storage.MongoDB.URI
	if mongoURI == "" {
		mongoURI = fmt.Sprintf("mongodb://%s:%d", c.Storage.MongoDB.Host, c.Storage.MongoDB.Port)
	}
	mongoCfg := storage.MongoConfig{
		URI:      mongoURI,
		Database: c.Storage.MongoDB.Database,
		Timeout:  10 * time.Second,
	}
	return storage.Config{
		Engine:  c.Storage.Engine,
		MySQL:   mysqlCfg,
		MongoDB: mongoCfg,
	}
}

// normalizeMessageText canonicalises a client-facing message to LF line endings, so
// everything downstream — the wire builder, the logs, the admin page — sees one
// representation regardless of how the operator wrote it.
//
// Three input styles are accepted and all mean the same thing:
//
//	messageLogin: |-          # block scalar: real newlines
//	  first
//	  second
//	messageLogin: "first\nsecond"   # double-quoted: YAML decodes \n itself
//	messageLogin: 'first\nsecond'   # single-quoted/plain: YAML does NOT, so we do
//
// The last case is the reason the backslash forms are decoded here. YAML only honours
// escapes inside double quotes, so without this an operator who reached for single
// quotes would ship the literal two characters `\` `n` to every client and see no
// error. The cost is that a message wanting a literal backslash-n cannot have one,
// which no welcome banner has ever needed.
//
// Trailing newlines are trimmed. They add nothing a client displays — both eMule
// trees skip empty tokens when splitting the message — but a naive third-party
// splitter would render one as a blank line.
func normalizeMessageText(s string) string {
	if s == "" {
		return ""
	}
	// Backslash escapes first: decoding them can only introduce more line endings,
	// and doing it before the CR/LF pass means \r\n written either way converges.
	s = strings.ReplaceAll(s, `\r\n`, "\n")
	s = strings.ReplaceAll(s, `\n`, "\n")
	// Real line endings second. CRLF before lone CR, so a CRLF does not become two.
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Trim(s, "\n")
}
