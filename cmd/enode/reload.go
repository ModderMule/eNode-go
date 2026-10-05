package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"enode/admin"
	"enode/config"
	"enode/ed2k"
	"enode/logging"
	"enode/storage"
)

// Config reload: re-read the config file while the server runs and apply every key
// that can change without a restart. No listener is closed and no client connection is
// touched; keys that need a restart are reported and left alone. The reloadable keys
// are listed in config.reloadableKeys.

// bootDerived holds what the runtime configs need beyond the config file. All of it is
// computed once at startup and stays fixed across reloads.
type bootDerived struct {
	advertisedIP string
	serverIPv6   []byte
	serverHash   []byte
	udpSecret    []byte
	// metaSearch is whether a catalogue daemon is configured, which sets FlagMetaSearch
	// in both advertised flag words.
	metaSearch bool
	metaAPI    ed2k.MetaAPIAdvert
}

// reloader applies config reloads. One exists per process; run() creates it once every
// socket is bound.
type reloader struct {
	// mu serialises reloads and guards the fields below it.
	mu  sync.Mutex
	ctx context.Context
	// path is the config file given on the command line.
	path string
	// bootFile is the config as the file had it at startup, the reference for "needs a
	// restart". boot is the same with dynIp resolved. applied is what is in effect now.
	bootFile config.Config
	boot     config.Config
	applied  config.Config
	derived  bootDerived

	runtime  *ed2k.ServerRuntime
	engine   storage.Engine
	adminSrv *admin.Server

	// udpCfg is the main UDP listener's config, the template for a separate gossip
	// socket. mainConn and obfConn are the sockets gossip sends from; obfConn is nil
	// when obfuscation is off.
	udpCfg   ed2k.UDPServerConfig
	mainConn *net.UDPConn
	obfConn  *net.UDPConn

	// gossip is the attached handler, nil while gossip is off. ownGossipConn is the
	// separate gossip socket when one had to be bound, and stopLoops halts the round
	// loop and the server.met timer.
	gossip        *ed2k.GossipHandler
	gossipConn    *net.UDPConn
	ownGossipConn *net.UDPConn
	stopLoops     func()
}

// Reload re-reads the config file and applies the reloadable keys. A file that does not
// load, or a change that cannot be applied, leaves the running server as it was and
// returns the error.
func (r *reloader) Reload() (admin.ReloadResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	next, err := config.Load(r.path)
	if err != nil {
		return admin.ReloadResult{}, fmt.Errorf("config load failed: %w", err)
	}
	effective := config.OverlayReloadable(r.boot, next)
	old := r.applied

	var res admin.ReloadResult
	for _, p := range config.Diff(old, effective) {
		if config.Reloadable(p) {
			res.Applied = append(res.Applied, p)
		}
	}
	for _, p := range config.Diff(r.bootFile, next) {
		if !config.Reloadable(p) {
			res.RestartRequired = append(res.RestartRequired, p)
		}
	}
	// Storage can add a server list entry but not take one back.
	if len(missingServers(effective.Servers, old.Servers)) > 0 {
		res.RestartRequired = append(res.RestartRequired, "servers (removed entries)")
	}

	// The two steps that can fail run first, and the first is undone if the second
	// fails, so an error leaves nothing half-applied.
	if err := applyLogging(old, effective); err != nil {
		return admin.ReloadResult{}, err
	}
	if err := r.applyGossip(old, effective); err != nil {
		_ = applyLogging(effective, old)
		return admin.ReloadResult{}, err
	}

	r.runtime.ApplyRuntimeConfig(buildRuntimeConfigs(effective, r.derived))
	r.runtime.SetStatsBoost(statsBoostFromConfig(effective))
	if added := missingServers(old.Servers, effective.Servers); len(added) > 0 {
		seedServers(r.engine, added)
	}
	if r.adminSrv != nil {
		r.adminSrv.SetStatic(buildAdminStatic(effective, r.derived))
		r.adminSrv.SetCredentials(effective.Admin.Username, effective.Admin.Password)
	}
	r.applied = effective

	logging.Infof("config reload: applied=%v restartRequired=%v (config=%s)", res.Applied, res.RestartRequired, r.path)
	return res, nil
}

// startGossipIO starts the gossip round loop and the server.met timer for the attached
// handler, binding a separate gossip socket when the obfuscated one cannot be shared.
// Called at startup and by a reload that turns gossip on.
func (r *reloader) startGossipIO(cfg config.Config) error {
	gossipConn := r.obfConn
	if gossipConn == nil || cfg.UDP.PortGossip != cfg.UDP.PortObfuscated {
		gossipUDPCfg := r.udpCfg
		gossipUDPCfg.Port = cfg.UDP.PortGossip
		conn, err := ed2k.RunUDPServer(gossipUDPCfg, r.runtime.UDPHandler(true))
		if err != nil {
			return fmt.Errorf("gossip udp server failed: %w", err)
		}
		r.ownGossipConn = conn
		gossipConn = conn
		logging.Infof("listening: udp-gossip %s:%d", gossipUDPCfg.Address, gossipUDPCfg.Port)
	} else {
		logging.Infof("gossip shares the obfuscated udp socket on port %d (Lugdunum reads a peer's TCP port as this minus 12)",
			cfg.UDP.PortGossip)
	}
	r.gossipConn = gossipConn
	r.stopLoops = startGossipLoops(r.ctx, cfg, r.gossip, r.mainConn, gossipConn)
	return nil
}

// close stops gossip on shutdown. The final server.met write happens here.
func (r *reloader) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopGossipIO()
}

// applyGossip moves gossip from the old config to the new one: on, off, or reconfigured
// in place with its peer table kept.
func (r *reloader) applyGossip(old, cfg config.Config) error {
	wasOn, on := r.gossip != nil, cfg.Gossip.EnabledOrDefault()
	switch {
	case !wasOn && on:
		r.gossip = buildGossipHandler(cfg, r.derived.advertisedIP, r.derived.serverIPv6)
		r.runtime.SetGossipHandler(r.gossip)
		if err := r.startGossipIO(cfg); err != nil {
			r.runtime.SetGossipHandler(nil)
			r.gossip = nil
			return err
		}
	case wasOn && !on:
		r.stopGossipIO()
		r.runtime.SetGossipHandler(nil)
		r.gossip = nil
		logging.Infof("gossip: disabled by config reload")
	case wasOn && on:
		r.gossip.UpdateConfig(buildGossipConfig(cfg, r.derived.advertisedIP, r.derived.serverIPv6))
		added := r.gossip.AddSeeds(ed2k.GossipSeedsFromServers(configSeedsToServers(cfg.GossipSeeds())))
		if added > 0 {
			logging.Infof("gossip: %d new seed(s) from config reload", added)
		}
		if gossipTimersChanged(old, cfg) {
			r.stopLoops()
			r.stopLoops = startGossipLoops(r.ctx, cfg, r.gossip, r.mainConn, r.gossipConn)
		}
	}
	return nil
}

// stopGossipIO halts the gossip loops and closes the separate gossip socket if one was
// bound. Safe to call when gossip is not running.
func (r *reloader) stopGossipIO() {
	r.stopLoops()
	r.stopLoops = func() {}
	if r.ownGossipConn != nil {
		_ = r.ownGossipConn.Close()
		r.ownGossipConn = nil
	}
	r.gossipConn = nil
}

// serverListenConfigs builds the listener configs for the plain TCP and main UDP sockets.
// The advertised flag words are derived from them.
func serverListenConfigs(cfg config.Config) (ed2k.TCPServerConfig, ed2k.UDPServerConfig) {
	dualStack := cfg.IPv6.EnabledOrDefault()
	tcpCfg := ed2k.TCPServerConfig{
		Address:        cfg.Address,
		Port:           cfg.TCP.Port,
		MaxConnections: cfg.TCP.MaxConnections,
		AuxiliarPort:   cfg.AuxiliarPort,
		RequireCrypt:   cfg.RequireCrypt,
		RequestCrypt:   cfg.RequestCrypt,
		SupportCrypt:   cfg.SupportCrypt,
		IPInLogin:      cfg.IPInLogin,
		DualStack:      dualStack,
		// Server-independent (cross-server / serverless) PR_NAT rendezvous is effective
		// only when the NAT service itself is enabled. It drives both the
		// FlagNatRendezvous advertisement and the OP_SERVERIDENT NAT-port tag.
		NatRendezvous: cfg.NAT.Enabled && cfg.NAT.ServerIndependentOrDefault(),
	}
	udpCfg := ed2k.UDPServerConfig{
		Address:      cfg.Address,
		Port:         cfg.UDP.Port,
		GetSources:   cfg.UDP.GetSources,
		GetFiles:     cfg.UDP.GetFiles,
		SupportCrypt: cfg.SupportCrypt,
		DualStack:    dualStack,
	}
	return tcpCfg, udpCfg
}

// buildRuntimeConfigs builds the settings every connection and datagram reads. Used at
// startup and again on each config reload.
func buildRuntimeConfigs(cfg config.Config, d bootDerived) (ed2k.TCPRuntimeConfig, ed2k.UDPRuntimeConfig) {
	tcpCfg, udpCfg := serverListenConfigs(cfg)
	tcpFlags := ed2k.BuildTCPFlags(tcpCfg)
	udpFlags := ed2k.BuildUDPFlags(udpCfg)
	if d.metaSearch {
		tcpFlags |= ed2k.FlagMetaSearch
		udpFlags |= ed2k.FlagMetaSearch
	}
	dualStack := cfg.IPv6.EnabledOrDefault()
	natRendezvousPort := uint16(0)
	if tcpCfg.NatRendezvous {
		natRendezvousPort = cfg.NAT.Port
	}
	tcp := ed2k.TCPRuntimeConfig{
		Name:        cfg.Name,
		Description: cfg.Description,
		// Address stays the bind address: probeClient uses it as its
		// LocalAddr and special-cases the wildcard. AdvertisedIP is what goes
		// out in OP_SERVERIDENT.
		Address:           cfg.Address,
		AdvertisedIP:      d.advertisedIP,
		Port:              cfg.TCP.Port,
		Flags:             tcpFlags,
		Hash:              d.serverHash,
		MessageLogin:      cfg.MessageLogin,
		MessageLowID:      cfg.MessageLowID,
		ConnectionTimeout: time.Duration(cfg.TCP.ConnectionTimeout) * time.Millisecond,
		DisconnectTimeout: time.Duration(cfg.TCP.DisconnectTimeout) * time.Second,
		LoginTimeout:      time.Duration(cfg.TCP.LoginTimeout) * time.Second,
		MaxConnsPerIP:     cfg.TCP.MaxConnectionsPerIPOrDefault(),
		AllowLowIDs:       cfg.TCP.AllowLowIDs,
		SupportCrypt:      cfg.SupportCrypt,
		MinLowID:          cfg.TCP.MinLowID,
		MaxLowID:          cfg.TCP.MaxLowID,
		IPv6:              dualStack,
		PublishV6Sources:  dualStack && cfg.IPv6.PublishSourcesOrDefault(),
		ProbeIPv6:         dualStack && cfg.IPv6.ProbeReachabilityOrDefault(),
		ServerIPv6:        d.serverIPv6,
		NatRendezvousPort: natRendezvousPort,
		MetaAPI:           d.metaAPI,
		SoftFileLimit:     cfg.Files.SoftLimitOrDefault(),
		HardFileLimit:     cfg.Files.HardLimitOrDefault(),
	}
	udp := ed2k.UDPRuntimeConfig{
		Name:        cfg.Name,
		Description: cfg.Description,
		DynIP:       cfg.DynIP,
		UDPFlags:    udpFlags,
		// The same two options BuildUDPFlags advertises. They must reach the
		// dispatcher too, or the server clears the flag and keeps answering.
		GetSources:     cfg.UDP.GetSources,
		GetFiles:       cfg.UDP.GetFiles,
		UDPPortObf:     advertisedUDPObfPort(cfg),
		TCPPortObf:     cfg.TCP.PortObfuscated,
		UDPSecret:      d.udpSecret,
		MaxConnections: uint32(cfg.TCP.MaxConnections),
		// Read from the same accessors as the TCP half above. Advertising a cap we
		// do not apply is the state this feature exists to end, so the two must
		// come from one source or not be separate fields at all.
		SoftFiles: uint32(cfg.Files.SoftLimitOrDefault()),
		HardFiles: uint32(cfg.Files.HardLimitOrDefault()),

		RateLimitPerIPPerMinute: cfg.UDP.RateLimitPerIPPerMinuteOrDefault(),
	}
	return tcp, udp
}

// buildGossipConfig builds the gossip handler's settings, at startup and on reload.
func buildGossipConfig(cfg config.Config, advertisedIP string, serverIPv6 []byte) ed2k.GossipConfig {
	gossipCfg := ed2k.GossipConfig{
		SelfPort:          cfg.TCP.Port,
		Name:              cfg.Name,
		Desc:              cfg.Description,
		MaxServers:        cfg.Gossip.MaxServers,
		MaxFailures:       cfg.Gossip.MaxFailures,
		AllowPrivatePeers: cfg.Gossip.AllowPrivatePeers,
		PublishIPv6:       cfg.IPv6.EnabledOrDefault() && cfg.Gossip.PublishIPv6OrDefault(),
		UDPPortObf:        cfg.UDP.PortGossip,
		TCPPortObf:        cfg.TCP.PortObfuscated,
	}
	if ip := net.ParseIP(advertisedIP); ip != nil {
		gossipCfg.SelfIPv4 = ip
	}
	if len(serverIPv6) == 16 {
		gossipCfg.SelfIPv6 = net.IP(serverIPv6)
	}
	return gossipCfg
}

// buildAdminStatic builds the facts the dashboard pages render, at startup and on reload.
func buildAdminStatic(cfg config.Config, d bootDerived) admin.StaticInfo {
	tcpObf, udpObf := uint16(0), uint16(0)
	if cfg.SupportCrypt {
		tcpObf, udpObf = cfg.TCP.PortObfuscated, cfg.UDP.PortObfuscated
	}
	natPort := uint16(0)
	if cfg.NAT.Enabled {
		natPort = cfg.NAT.Port
	}
	return admin.StaticInfo{
		Name:              cfg.Name,
		Description:       cfg.Description,
		Version:           ed2k.ENodeVersionStr,
		Engine:            cfg.Storage.Engine,
		AdvertisedIP:      d.advertisedIP,
		AdvertisedIPv6:    ipv6String(d.serverIPv6),
		TCPPort:           cfg.TCP.Port,
		TCPPortObf:        tcpObf,
		UDPPort:           cfg.UDP.Port,
		UDPPortObf:        udpObf,
		NATPort:           natPort,
		Crypt:             cfg.SupportCrypt,
		IPv6:              cfg.IPv6.EnabledOrDefault(),
		NAT:               cfg.NAT.Enabled,
		ServerIndependent: cfg.NAT.Enabled && cfg.NAT.ServerIndependentOrDefault(),
	}
}

// statsBoostFromConfig converts the local-only statsBoost section.
func statsBoostFromConfig(cfg config.Config) ed2k.StatsBoost {
	return ed2k.StatsBoost{
		Users:      cfg.StatsBoost.Users,
		LowIDUsers: cfg.StatsBoost.LowIDUsers,
		Files:      cfg.StatsBoost.Files,
	}
}

// applyLogging switches the log file and level when they changed. A failure restores
// the old log file, so a bad value leaves logging as it was.
func applyLogging(old, cfg config.Config) error {
	if cfg.LogFile != old.LogFile {
		if err := logging.SetOutputFile(cfg.LogFile); err != nil {
			return fmt.Errorf("config logFile invalid: %w", err)
		}
	}
	if cfg.LogLevel != old.LogLevel {
		if err := logging.SetLevelFromString(cfg.LogLevel); err != nil {
			if cfg.LogFile != old.LogFile {
				_ = logging.SetOutputFile(old.LogFile)
			}
			return fmt.Errorf("config logLevel invalid: %w", err)
		}
	}
	return nil
}

// gossipTimersChanged reports whether a setting baked into the gossip loops changed, so
// they have to be restarted to pick it up.
func gossipTimersChanged(old, cfg config.Config) bool {
	return old.Gossip.IntervalSeconds != cfg.Gossip.IntervalSeconds ||
		old.Gossip.PersistOrDefault() != cfg.Gossip.PersistOrDefault() ||
		old.Gossip.PersistIntervalSeconds != cfg.Gossip.PersistIntervalSeconds ||
		old.ServerMetPath() != cfg.ServerMetPath()
}

// missingServers returns the entries of want that are absent from have.
func missingServers(have, want []config.ServerEntry) []config.ServerEntry {
	present := make(map[config.ServerEntry]struct{}, len(have))
	for _, e := range have {
		present[e] = struct{}{}
	}
	var out []config.ServerEntry
	for _, e := range want {
		if _, ok := present[e]; !ok {
			out = append(out, e)
		}
	}
	return out
}
