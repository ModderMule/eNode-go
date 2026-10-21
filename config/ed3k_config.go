package config

import (
	"fmt"
	"net"
	"path/filepath"
)

// Ed3kConfig runs an ed3k index node (Protocol.md §11 of the ed3k spec) beside the
// eD2K server: the QUIC successor network's equivalent of a server, without Kad
// router duty. Off unless Enabled. Its records live in the configured storage
// engine. See docs/ed3k-index-node.md.
type Ed3kConfig struct {
	Enabled bool `yaml:"enabled"`
	// Port is the node's UDP port. 0 takes the number of the eD2K TCP port, as the
	// spec's port rule asks (§14.1); the eD2K server's own UDP port is tcp+4, so the
	// two do not collide.
	Port uint16 `yaml:"port"`
	// Listen is the bind address; empty binds every address of both families.
	Listen string `yaml:"listen"`
	// Advertise and AdvertiseIPv6 are the addresses in the node's link (ST_ED3K)
	// and Hello. Empty takes the server's advertised IPv4, and its IPv6 when
	// ipv6.dynIp6 names one.
	Advertise     string `yaml:"advertise"`
	AdvertiseIPv6 string `yaml:"advertiseIPv6"`
	// KeyFile holds the node's Ed25519 seed, created on first start. The node ID
	// derives from it: keep it, or clients must learn a new link.
	KeyFile string `yaml:"keyFile"`
	// Network is the name of a test or closed network (1 to 32 bytes); empty is
	// the public network. A closed network's name is its secret.
	Network string `yaml:"network"`
	// Nick is sent in Hello; empty sends none.
	Nick string `yaml:"nick"`
	// RequestsPerMinute bounds KadRequests per host group, kind and operation.
	RequestsPerMinute int              `yaml:"requestsPerMinute"`
	Limits            Ed3kLimitConfig  `yaml:"limits"`
	Bridge            Ed3kBridgeConfig `yaml:"bridge"`
}

// Ed3kLimitConfig bounds connections, the relay service and the records held.
// Zero takes the default.
type Ed3kLimitConfig struct {
	MaxConnections      int `yaml:"maxConnections"`
	ConnectionsPerHost  int `yaml:"connectionsPerHost"`
	ConnectionsPerSite  int `yaml:"connectionsPerSite"`
	NewPerHostPerMinute int `yaml:"newPerHostPerMinute"`
	RelayLeaves         int `yaml:"relayLeaves"`
	RelayPerHost        int `yaml:"relayPerHost"`
	RelayPerSite        int `yaml:"relayPerSite"`
	// RecordsPerHost and RecordsPerSite bound what one publisher address or site
	// holds over all targets (the spec's §11 MUST); MaxRecords bounds the store.
	RecordsPerHost int `yaml:"recordsPerHost"`
	RecordsPerSite int `yaml:"recordsPerSite"`
	MaxRecords     int `yaml:"maxRecords"`
}

// Ed3kBridgeConfig lists ed3k nodes as eD2K sources (spec docs/ed2k-tags.md §6).
// The server tests each node's eD2K TCP port before listing it. It is on by
// default, but runs only when ed3k.enabled is on too.
type Ed3kBridgeConfig struct {
	// Enabled is a pointer so an absent key means on.
	Enabled *bool `yaml:"enabled"`
	// MaxPerAnswer bounds the ed3k sources added to one OP_FOUNDSOURCES.
	MaxPerAnswer int `yaml:"maxPerAnswer"`
	// TCPTestMinutes is how long a TCP test result is kept.
	TCPTestMinutes int `yaml:"tcpTestMinutes"`
}

// Defaults of the ed3k section.
const (
	DefaultEd3kKeyFile           = "ed3k.key"
	DefaultEd3kRequestsPerMinute = 120
)

// BridgeActive reports whether the bridge runs: on unless bridge.enabled is false, and
// never while ed3k.enabled is off.
func (c Ed3kConfig) BridgeActive() bool { return c.Enabled && boolOrDefault(c.Bridge.Enabled, true) }

// Ed3kKeyPath is the resolved location of the ed3k node key.
func (c Config) Ed3kKeyPath() string { return ResolveDataPath(c.Ed3k.KeyFile) }

func setEd3kDefaults(c *Ed3kConfig) error {
	if c.KeyFile == "" {
		c.KeyFile = filepath.Join(DataDir, DefaultEd3kKeyFile)
	}
	if c.RequestsPerMinute <= 0 {
		c.RequestsPerMinute = DefaultEd3kRequestsPerMinute
	}
	l := &c.Limits
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&l.MaxConnections, 50000)
	def(&l.ConnectionsPerHost, 256)
	def(&l.ConnectionsPerSite, 1024)
	def(&l.NewPerHostPerMinute, 120)
	def(&l.RelayLeaves, 1024)
	def(&l.RelayPerHost, 8)
	def(&l.RelayPerSite, 32)
	def(&l.RecordsPerHost, 50000)
	def(&l.RecordsPerSite, 200000)
	def(&l.MaxRecords, 50_000_000)
	def(&c.Bridge.MaxPerAnswer, 20)
	def(&c.Bridge.TCPTestMinutes, 30)
	if !c.Enabled {
		return nil
	}
	if len(c.Network) > 32 {
		return fmt.Errorf("ed3k.network: at most 32 bytes")
	}
	for key, v := range map[string]string{"ed3k.listen": c.Listen, "ed3k.advertise": c.Advertise, "ed3k.advertiseIPv6": c.AdvertiseIPv6} {
		if v != "" && net.ParseIP(v) == nil {
			return fmt.Errorf("%s: %q is not an IP address", key, v)
		}
	}
	if c.Advertise != "" && net.ParseIP(c.Advertise).To4() == nil {
		return fmt.Errorf("ed3k.advertise: %q is not an IPv4 address", c.Advertise)
	}
	if c.AdvertiseIPv6 != "" && net.ParseIP(c.AdvertiseIPv6).To4() != nil {
		return fmt.Errorf("ed3k.advertiseIPv6: %q is not an IPv6 address", c.AdvertiseIPv6)
	}
	return nil
}
