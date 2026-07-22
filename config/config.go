package config

import (
	"fmt"
	"os"
	"time"

	"enode/storage"
	"gopkg.in/yaml.v3"
)

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

	TCP   TCPConfig   `yaml:"tcp"`
	UDP   UDPConfig   `yaml:"udp"`
	NAT   NATConfig   `yaml:"natTraversal"`
	IPv6  IPv6Config  `yaml:"ipv6"`
	Admin AdminConfig `yaml:"admin"`

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

type UDPConfig struct {
	Port           uint16 `yaml:"port"`
	PortObfuscated uint16 `yaml:"portObfuscated"`
	GetSources     bool   `yaml:"getSources"`
	GetFiles       bool   `yaml:"getFiles"`
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

// boolOrDefault returns *p, or def when p is nil. The *bool pattern lets an absent
// YAML key be told from an explicit false (see the IPv6 and cleanup toggles).
func boolOrDefault(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

type StorageConfig struct {
	Engine  string        `yaml:"engine"`
	Cleanup CleanupConfig `yaml:"cleanup"`
	MySQL   MySQLConfig   `yaml:"mysql"`
	MongoDB MongoDBConfig `yaml:"mongodb"`
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
	if cfg.Storage.Engine == "" {
		cfg.Storage.Engine = "memory"
	}
	if cfg.Storage.Cleanup.StaleAfterHours <= 0 {
		cfg.Storage.Cleanup.StaleAfterHours = 24
	}
	if cfg.Storage.Cleanup.IntervalMinutes <= 0 {
		cfg.Storage.Cleanup.IntervalMinutes = 60
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
