package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"enode/admin"
	"enode/config"
	"enode/ed2k"
	"enode/logging"
	"enode/netfilter"
	"enode/storage"
)

const backgroundEnvKey = "ENODE_BACKGROUND"

func main() {
	configPath := flag.String("config", "enode.config.yaml", "path to YAML config")
	daemon := flag.Bool("daemon", false, "run in background")
	flag.Parse()

	if *daemon && os.Getenv(backgroundEnvKey) != "1" {
		pid, err := startBackgroundProcess(filterDaemonArgs(os.Args[1:]))
		if err != nil {
			log.Fatalf("start background process failed: %v", err)
		}
		log.Printf("enode started in background, pid=%d", pid)
		return
	}

	// SIGINT/SIGTERM cancel the context, which returns run() and lets its defers
	// execute. Previously main ended in `select {}`, so every defer below —
	// engine.Close(), the listener closes, the cleanup stoppers — was unreachable
	// and only gave the appearance of a graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *configPath); err != nil {
		logging.Errorf("enode exiting: %v", err)
		os.Exit(1)
	}
	logging.Infof("enode stopped cleanly")
}

// run holds the whole server lifetime. It returns when ctx is cancelled, so the
// defers registered inside it actually run.
//
// Errors after this point are returned rather than passed to logging.Fatalf:
// that is zap's Fatalf, which calls os.Exit(1) and therefore skips every defer
// already registered — including engine.Close(). A signal handler alone would
// not have fixed those paths.
func run(ctx context.Context, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config load failed: %w", err)
	}
	// Logging is configured before the dynIp probe so its warnings survive. The
	// probe used to run first and exit via the stdlib logger on failure, and
	// -daemon wires stderr to /dev/null — so a daemonized server that could not
	// reach the internet died with no diagnostic anywhere.
	if err := logging.SetOutputFile(cfg.LogFile); err != nil {
		return fmt.Errorf("config logFile invalid: %w", err)
	}
	if err := logging.SetLevelFromString(cfg.LogLevel); err != nil {
		return fmt.Errorf("config logLevel invalid: %w", err)
	}
	logging.Infof("welcome: enode starting (config=%s)", configPath)

	resolvedDynIP, resolvedByURL, err := resolveDynIPValue(cfg.DynIP, cfg.TestURLs, 0)
	if err != nil {
		// Not fatal. Every consumer of DynIP already degrades: firstRoutableIP
		// prefers cfg.Address, serverIdentitySeed falls back to the hostname, and
		// the NAT endpoint has its own fallback. Refusing to boot because a
		// third-party echo service is unreachable is far harsher than warranted.
		logging.Warnf("dynIp auto resolve failed, continuing without it: %v", err)
		resolvedDynIP = ""
	}
	if resolvedByURL != "" {
		logging.Infof("dynIp auto resolved: %s (url=%s)", resolvedDynIP, resolvedByURL)
	}
	cfg.DynIP = resolvedDynIP

	// The server's own public IPv6 (advertised via CT_MOD_SVR_IP_V6). Only resolved
	// when IPv6 is enabled; failure is non-fatal, exactly like the IPv4 path.
	var serverIPv6 []byte
	if cfg.IPv6.EnabledOrDefault() {
		resolvedV6, resolvedV6By, err := resolveDynIP6Value(cfg.IPv6.DynIP6, cfg.IPv6.TestURLs6, 0)
		if err != nil {
			logging.Warnf("dynIp6 auto resolve failed, continuing without a server IPv6: %v", err)
		} else if resolvedV6 != "" {
			if b, ok := ed2k.ParsePublicIPv6(resolvedV6); ok {
				serverIPv6 = b[:]
				if resolvedV6By != "" {
					logging.Infof("dynIp6 resolved: %s (via=%s)", resolvedV6, resolvedV6By)
				} else {
					logging.Infof("server public IPv6: %s", resolvedV6)
				}
			} else {
				logging.Warnf("dynIp6 value %q is not a usable public IPv6, ignoring", resolvedV6)
			}
		}
	}

	engine, err := storage.NewEngine(cfg.StorageEngineConfig())
	if err != nil {
		return fmt.Errorf("storage engine create failed: %w", err)
	}
	if err := engine.Init(); err != nil {
		return fmt.Errorf("storage init failed: %w", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			logging.Warnf("storage close error: %v", err)
		}
	}()

	// Restore the persisted index before anything can serve it, and start the
	// writer. The stopper is deferred after engine.Close() was registered above, so
	// LIFO unwinding flushes the final snapshot while the engine is still alive.
	if cfg.Storage.Snapshot.Enabled {
		snapshotPath := cfg.StorageSnapshotPath()
		if loader, ok := engine.(*storage.MemoryEngine); ok {
			stats, err := loader.LoadSnapshot(snapshotPath)
			switch {
			case err != nil:
				// Not fatal. A corrupt or half-written snapshot must not stop the
				// server from booting; it starts empty and rebuilds from re-offers.
				logging.Warnf("storage snapshot: cannot read %s, starting with an empty index: %v",
					snapshotPath, err)
			case stats.Files > 0:
				logging.Infof("storage snapshot: restored %d file(s) from %s in %s "+
					"(%d source(s) and %d client(s) in the file were not restored: they are offline after a restart)",
					stats.Files, snapshotPath, stats.Took.Round(time.Millisecond), stats.Sources, stats.Clients)
			default:
				// Covers both a first start with no file yet and a snapshot that
				// held nothing, which are the same thing from here.
				logging.Infof("storage snapshot: no usable snapshot at %s, starting with an empty index",
					snapshotPath)
			}
		}
		stopSnapshot := storage.StartSnapshot(
			engine,
			snapshotPath,
			time.Duration(cfg.Storage.Snapshot.IntervalMinutes)*time.Minute,
			cfg.Storage.Snapshot.Compress,
		)
		defer stopSnapshot()
	}

	seedServers(engine, cfg.Servers)

	// Debug-only: pre-populate the engine with dummy peers and files so the search /
	// source-list paths can be exercised without live clients. Off by default; a
	// failure here is never fatal — it is a development aid, not part of serving.
	if cfg.Debug.SeedFixtures {
		if err := seedDebugFixtures(engine, cfg.Debug.FixturesFile); err != nil {
			logging.Warnf("debug fixtures: %v", err)
		}
	}

	if cfg.Storage.Cleanup.Enabled {
		keepZeroSourceFiles := cfg.Storage.Cleanup.KeepZeroSourceFilesOrDefault()
		stopStorageCleanup := storage.StartCleanup(
			engine,
			time.Duration(cfg.Storage.Cleanup.IntervalMinutes)*time.Minute,
			time.Duration(cfg.Storage.Cleanup.StaleAfterHours)*time.Hour,
			storage.CleanupOptions{
				KeepZeroSourceFiles: keepZeroSourceFiles,
				BatchSize:           cfg.Storage.Cleanup.BatchSize,
			},
		)
		defer stopStorageCleanup()
		logging.Infof("storage cleanup enabled: every %dm, stale after %dh, keepZeroSourceFiles=%t",
			cfg.Storage.Cleanup.IntervalMinutes, cfg.Storage.Cleanup.StaleAfterHours, keepZeroSourceFiles)
	}

	dualStack := cfg.IPv6.EnabledOrDefault()
	// Server-independent (cross-server / serverless) PR_NAT rendezvous is effective
	// only when the NAT service itself is enabled. It drives both the FlagNatRendezvous
	// advertisement and the OP_SERVERIDENT NAT-port tag.
	natServerIndependent := cfg.NAT.Enabled && cfg.NAT.ServerIndependentOrDefault()
	natRendezvousPort := uint16(0)
	if natServerIndependent {
		natRendezvousPort = cfg.NAT.Port
	}
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
		NatRendezvous:  natServerIndependent,
	}
	udpCfg := ed2k.UDPServerConfig{
		Address:      cfg.Address,
		Port:         cfg.UDP.Port,
		GetSources:   cfg.UDP.GetSources,
		GetFiles:     cfg.UDP.GetFiles,
		SupportCrypt: cfg.SupportCrypt,
		DualStack:    dualStack,
	}
	tcpFlags := ed2k.BuildTCPFlags(tcpCfg)
	udpFlags := ed2k.BuildUDPFlags(udpCfg)

	// The address clients are told to reach us on. cfg.Address is the *bind*
	// address and defaults to 0.0.0.0, which IPv4ToInt32LE encodes as 0 — so
	// OP_SERVERIDENT advertised server IP 0.0.0.0 to everyone. The UDP path
	// already falls back to DynIP; this gives the TCP ident path the same.
	advertisedIP := firstRoutableIP(cfg.Address, cfg.DynIP)
	if advertisedIP == "" {
		logging.Warnf("advertised server IP unresolved: address=%q dynIp=%q, clients will receive serverIP=0.0.0.0",
			cfg.Address, cfg.DynIP)
	} else if advertisedIP != cfg.Address {
		logging.Infof("advertising server IP %s (address=%q is not routable)", advertisedIP, cfg.Address)
	}

	serverHash := ed2k.MD5([]byte(fmt.Sprintf("%s%d", serverIdentitySeed(advertisedIP, cfg.Address), cfg.TCP.Port)))

	runtime := ed2k.NewServerRuntime(
		ed2k.TCPRuntimeConfig{
			Name:        cfg.Name,
			Description: cfg.Description,
			// Address stays the bind address: probeClient uses it as its
			// LocalAddr and special-cases the wildcard. AdvertisedIP is what goes
			// out in OP_SERVERIDENT.
			Address:           cfg.Address,
			AdvertisedIP:      advertisedIP,
			Port:              cfg.TCP.Port,
			Flags:             tcpFlags,
			Hash:              serverHash,
			MessageLogin:      cfg.MessageLogin,
			MessageLowID:      cfg.MessageLowID,
			ConnectionTimeout: time.Duration(cfg.TCP.ConnectionTimeout) * time.Millisecond,
			DisconnectTimeout: time.Duration(cfg.TCP.DisconnectTimeout) * time.Second,
			AllowLowIDs:       cfg.TCP.AllowLowIDs,
			SupportCrypt:      cfg.SupportCrypt,
			MinLowID:          cfg.TCP.MinLowID,
			MaxLowID:          cfg.TCP.MaxLowID,
			IPv6:              dualStack,
			PublishV6Sources:  dualStack && cfg.IPv6.PublishSourcesOrDefault(),
			ProbeIPv6:         dualStack && cfg.IPv6.ProbeReachabilityOrDefault(),
			ServerIPv6:        serverIPv6,
			NatRendezvousPort: natRendezvousPort,
		},
		ed2k.UDPRuntimeConfig{
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
			UDPServerKey:   cfg.UDP.ServerKey,
			MaxConnections: uint32(cfg.TCP.MaxConnections),
		},
		engine,
	)

	// Access filters: ipfilter.dat ranges and MaxMind country blocking. A blocked address
	// is dropped before any wire parsing on both transports.
	//
	// A missing ipfilter file is fatal — the operator named it, and silently serving
	// everyone they meant to block is the wrong failure mode. A missing GeoIP database is
	// not: it depends on a download from a third party, so it degrades to "no country
	// matching" and says so in the log. See docs/access-filters.md.
	accessFilter, err := netfilter.New(ctx, netfilter.Config{
		IPFilterEnabled:       cfg.Filter.IPFilter.Enabled,
		IPFilterFile:          cfg.IPFilterPath(),
		IPFilterMinLevel:      cfg.Filter.IPFilter.MinLevel,
		IPFilterReloadMinutes: cfg.Filter.IPFilter.ReloadMinutes,
		GeoIPEnabled:          cfg.Filter.GeoIP.Enabled,
		GeoIPDatabase:         cfg.GeoIPDatabasePath(),
		BlockedCountries:      cfg.Filter.GeoIP.BlockedCountries,
		Account:               maxmindAccount(cfg.Filter.GeoIP),
		UpdateDays:            cfg.Filter.GeoIP.UpdateDays,
	})
	if err != nil {
		return fmt.Errorf("access filter: %w", err)
	}
	if accessFilter != nil {
		defer accessFilter.Close()
		runtime.SetAccessFilter(accessFilter)
	} else {
		logging.Infof("access filters: disabled")
	}

	// The gossip peer table is attached here, before any listener binds: ServerRuntime's
	// Gossip field is read without a lock by every accept and every datagram, so writing it
	// once the listeners are live is a data race. Its sockets and timers start further
	// down, once the main UDP socket the outbound loop sends from exists.
	gossipHandler := buildGossipHandler(cfg, advertisedIP, serverIPv6)
	if gossipHandler != nil {
		runtime.SetGossipHandler(gossipHandler)
	}

	// Local admin status dashboard. Default on and bound to loopback; a bind
	// failure is fatal because the operator asked for it. Static server facts are
	// captured once; the live counters come from a snapshot read per request.
	if cfg.Admin.EnabledOrDefault() {
		startTime := time.Now()
		tcpObf, udpObf := uint16(0), uint16(0)
		if cfg.SupportCrypt {
			tcpObf, udpObf = cfg.TCP.PortObfuscated, cfg.UDP.PortObfuscated
		}
		natPort := uint16(0)
		if cfg.NAT.Enabled {
			natPort = cfg.NAT.Port
		}
		adminSrv := admin.New(
			admin.Config{BindIP: cfg.Admin.BindIP, Port: cfg.Admin.Port},
			admin.StaticInfo{
				Name:              cfg.Name,
				Description:       cfg.Description,
				Version:           ed2k.ENodeVersionStr,
				Engine:            cfg.Storage.Engine,
				TCPPort:           cfg.TCP.Port,
				TCPPortObf:        tcpObf,
				UDPPort:           cfg.UDP.Port,
				UDPPortObf:        udpObf,
				NATPort:           natPort,
				Crypt:             cfg.SupportCrypt,
				IPv6:              dualStack,
				NAT:               cfg.NAT.Enabled,
				ServerIndependent: natServerIndependent,
			},
			func() admin.LiveStats {
				clients, files := runtime.Counts()
				// Gossip.Stats() and accessFilter.Stats() are both nil-receiver safe and
				// return zero values when the subsystem is off, so neither needs a branch.
				gossip := gossipHandler.Stats()
				blockedIP, blockedGeo := accessFilter.Stats()
				return admin.LiveStats{
					Clients: clients,
					Files:   files,
					LowIDs:  int(runtime.LowIDs.Count()),
					// What a client is actually sent, not Storage.ServersCount(): the latter
					// counts only configured peers and reads 0 for everything gossip learns.
					Servers:          runtime.AdvertisedServerCount(),
					UptimeSeconds:    int64(time.Since(startTime).Seconds()),
					Time:             time.Now().Format(time.RFC3339),
					GossipKnown:      gossip.Known,
					GossipVerified:   gossip.Verified,
					GossipParked:     gossip.Parked,
					GossipAdmitted:   gossip.Admitted,
					FilterBlockedIP:  blockedIP,
					FilterBlockedGeo: blockedGeo,
				}
			},
		)
		if err := adminSrv.Start(); err != nil {
			return fmt.Errorf("admin dashboard failed to bind %s:%d: %w", cfg.Admin.BindIP, cfg.Admin.Port, err)
		}
		defer adminSrv.Close()
		logging.Infof("admin dashboard: http://%s:%d/", adminDisplayHost(cfg.Admin.BindIP), cfg.Admin.Port)
		if !adminBindIsLoopback(cfg.Admin.BindIP) {
			logging.Warnf("admin dashboard bound to %s: it has no authentication and is reachable off-box", cfg.Admin.BindIP)
		}
	} else {
		logging.Infof("admin dashboard: disabled")
	}

	// Obfuscation is enabled on the *plaintext* listener too, which is what eserver does:
	// its portTCPOBF defaults to the value of `port`, so obfuscated TCP shares the
	// plaintext socket and is detected from the first bytes on the wire. Running the real
	// binary, `print` reports portTCPOBF=4661 against port=4661, and eMule agrees —
	// srchybrid/UDPSocket.cpp:394 falls back to nTCPObfuscationPort = pServer->GetPort().
	//
	// Additive, not a behaviour change for existing clients: handleBytes sniffs the first
	// byte with IsProtocol and falls through to normal parsing for a plaintext frame (the
	// H4 fix), so a plaintext login on this port still works exactly as before. The
	// separate tcp.portObfuscated listener stays bound for clients pinned to it.
	ln, err := ed2k.RunTCPServer(tcpCfg, runtime.TCPHandler(cfg.SupportCrypt))
	if err != nil {
		return fmt.Errorf("tcp server failed: %w", err)
	}
	defer ln.Close()
	logging.Infof("listening: tcp %s:%d (obfuscation accepted: %t)", tcpCfg.Address, tcpCfg.Port, cfg.SupportCrypt)

	udpMainHandler := runtime.UDPHandler(false)
	if cfg.NAT.Enabled {
		natTTL := time.Duration(cfg.NAT.RegistrationTTLSeconds) * time.Second
		natHandler := ed2k.NewNATTraversalHandler(natTTL)
		natHandler.ConfigureRegisterEndpointFromConfig(cfg.DynIP, cfg.Address, cfg.UDP.Port)
		natHandler.SetRegisterEndpointForLocalPort(cfg.NAT.Port, cfg.UDP.Port)
		// Dual-stack hole-punching: enabled when v6 is up and natTraversal.ipv6 is on.
		// serverIPv6 (resolved above) is the endpoint returned in the v6 REGISTER ack.
		if dualStack && cfg.NAT.IPv6OrDefault() {
			natHandler.SetIPv6Enabled(true)
			if len(serverIPv6) == 16 {
				natHandler.SetRegisterEndpointV6(serverIPv6)
			}
		}
		if cfg.SupportCrypt && cfg.UDP.PortObfuscated != 0 {
			natHandler.SetRegisterEndpointForLocalPort(cfg.UDP.PortObfuscated, cfg.UDP.PortObfuscated)
		}
		// Server-independent (cross-server / serverless) rendezvous. When off, the
		// membership predicate restricts SYNC2 pairing to user hashes currently logged
		// into this server (Storage.IsConnected, backed by a by-hash index).
		natHandler.SetServerIndependent(cfg.NAT.ServerIndependentOrDefault())
		natHandler.SetLocalMembership(func(h [16]byte) bool {
			return runtime.Storage.IsConnected(storage.ClientInfo{Hash: h[:]})
		})
		runtime.SetNATHandler(natHandler)
		effectiveIP := cfg.DynIP
		if effectiveIP == "" {
			effectiveIP = cfg.Address
		}
		if effectiveIP == "" || effectiveIP == "0.0.0.0" {
			logging.Warnf("nat register endpoint unresolved: dynIp=%q address=%q, clients may receive serverIP=0.0.0.0", cfg.DynIP, cfg.Address)
		}
		cleanupInterval := natTTL / 2
		if cleanupInterval < 5*time.Second {
			cleanupInterval = 5 * time.Second
		} else if cleanupInterval > time.Minute {
			cleanupInterval = time.Minute
		}
		stopCleanup := natHandler.StartCleanup(cleanupInterval)
		defer stopCleanup()

		natConn, err := ed2k.RunUDPServer(ed2k.UDPServerConfig{
			Address: cfg.Address,
			Port:    cfg.NAT.Port,
			// Bind the dual-stack wildcard when IPv6 is enabled, matching the main
			// UDP/TCP listeners; otherwise the NAT socket stays IPv4-only while the
			// rest of the server serves both families.
			DualStack: dualStack,
		}, udpMainHandler)
		if err != nil {
			return fmt.Errorf("nat traversal udp server failed: %w", err)
		}
		defer natConn.Close()
		logging.Infof("listening: nat-udp %s:%d", cfg.Address, cfg.NAT.Port)
	}

	udpConn, err := ed2k.RunUDPServer(udpCfg, udpMainHandler)
	if err != nil {
		return fmt.Errorf("udp server failed: %w", err)
	}
	defer udpConn.Close()
	logging.Infof("listening: udp %s:%d", udpCfg.Address, udpCfg.Port)

	// obfUDPConn is the tcp+12 obfuscated socket, kept in scope because gossip sends from
	// it (see the gossip block below).
	var obfUDPConn *net.UDPConn
	if cfg.SupportCrypt {
		tcpCryptCfg := tcpCfg
		tcpCryptCfg.Port = cfg.TCP.PortObfuscated
		udpCryptCfg := udpCfg
		udpCryptCfg.Port = cfg.UDP.PortObfuscated

		lnCrypt, err := ed2k.RunTCPServer(tcpCryptCfg, runtime.TCPHandler(true))
		if err != nil {
			return fmt.Errorf("obfuscated tcp server failed: %w", err)
		}
		defer lnCrypt.Close()
		logging.Infof("listening: tcp-obfuscated %s:%d", tcpCryptCfg.Address, tcpCryptCfg.Port)

		udpConnCrypt, err := ed2k.RunUDPServer(udpCryptCfg, runtime.UDPHandler(true))
		if err != nil {
			return fmt.Errorf("obfuscated udp server failed: %w", err)
		}
		defer udpConnCrypt.Close()
		obfUDPConn = udpConnCrypt
		logging.Infof("listening: udp-obfuscated %s:%d", udpCryptCfg.Address, udpCryptCfg.Port)
	}

	// Server-to-server gossip normally sends from the tcp+12 obfuscated socket above
	// rather than a socket of its own, because two of eserver's rules have to hold
	// together: the source port of our obfuscated frames must equal the portUDPOBF we
	// advertise ("continue because portUDPobf(%d) != sin_port(%d)"), and it recovers our
	// TCP port from that source port by subtracting 12. Only tcp+12 satisfies both — from
	// tcp+14 it books our frames against a server that does not exist and never counts us
	// as working. See config.setDefaults and docs/server-gossip.md §8.
	//
	// A separate socket is still bound when the operator sets a different udp.portGossip,
	// or when obfuscation is off and there is therefore no tcp+12 socket to share.
	//
	// The handler itself was attached to the runtime before any listener bound (see
	// buildGossipHandler above); only the sockets and timers start here. Nothing below
	// writes a ServerRuntime field.
	if gossipHandler != nil {
		gossipConn := obfUDPConn
		if gossipConn == nil || cfg.UDP.PortGossip != cfg.UDP.PortObfuscated {
			gossipUDPCfg := udpCfg
			gossipUDPCfg.Port = cfg.UDP.PortGossip
			conn, err := ed2k.RunUDPServer(gossipUDPCfg, runtime.UDPHandler(true))
			if err != nil {
				return fmt.Errorf("gossip udp server failed: %w", err)
			}
			defer conn.Close()
			gossipConn = conn
			logging.Infof("listening: udp-gossip %s:%d", gossipUDPCfg.Address, gossipUDPCfg.Port)
		} else {
			logging.Infof("gossip shares the obfuscated udp socket on port %d (Lugdunum reads a peer's TCP port as this minus 12)",
				cfg.UDP.PortGossip)
		}

		stopGossip := startGossipLoops(ctx, cfg, gossipHandler, udpConn, gossipConn)
		defer stopGossip()
	}

	<-ctx.Done()
	logging.Infof("shutdown signal received, stopping")
	return nil
}

// buildGossipHandler creates the peer table and seeds it, or returns nil when gossip is
// disabled.
//
// Separate from startGossipLoops, and called before any listener binds, because
// ServerRuntime's Gossip field is read by every accept and every datagram without a lock.
// Attaching it after the listeners are live is a genuine data race — the race detector
// catches it — and the same pre-bind ordering is what SetNATHandler and SetAccessFilter
// already rely on. The loops cannot start this early because phase 1 sends from the main
// UDP socket, which does not exist yet.
//
// Seeding order mirrors eserver's: a persisted server.met wins, and the configured seeds
// are the fallback for when that file is absent or empty. eserver documents
// seedIP/seedPort as "used if no serverList.met file is present (or if it's empty)" for
// the same reason — once a mesh is known, the operator's original bootstrap list is stale.
func buildGossipHandler(cfg config.Config, advertisedIP string, serverIPv6 []byte) *ed2k.GossipHandler {
	if !cfg.Gossip.EnabledOrDefault() {
		logging.Infof("gossip: disabled, OP_SERVERLIST is served from the static servers list")
		return nil
	}

	seeds := ed2k.GossipSeedsFromServers(configSeedsToServers(cfg.GossipSeeds()))
	from := "config"
	if cfg.Gossip.PersistOrDefault() {
		metPath := cfg.ServerMetPath()
		persisted, err := ed2k.ReadServerMet(metPath)
		if err != nil {
			// Not fatal. A corrupt or half-written peer file must not stop the server from
			// booting — the configured seeds are a perfectly good starting point, and the
			// next persistence tick overwrites the bad file.
			logging.Warnf("gossip: cannot read %s, falling back to the configured seeds: %v", metPath, err)
		} else if len(persisted) > 0 {
			converted := make([]ed2k.PeerAddr, 0, len(persisted))
			for _, e := range persisted {
				converted = append(converted, ed2k.PeerAddr{IP: e.IP, Port: e.Port})
			}
			seeds, from = converted, metPath
		}
	}

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

	handler := ed2k.NewGossipHandler(gossipCfg, seeds)
	// Register every address a peer could observe us on, so an echoed self-entry is
	// recognised as us even when it is not the advertised IP — on a multi-homed or NATed
	// host those differ, and re-ingesting the observed one is what recreates phantom
	// self-entries.
	handler.AddLocalIP(gossipCfg.SelfIPv4)
	handler.AddLocalIP(gossipCfg.SelfIPv6)
	for _, ip := range localInterfaceIPs() {
		handler.AddLocalIP(ip)
	}
	logging.Infof("gossip: %d seed(s) from %s, interval %ds, maxServers %d, allowPrivatePeers=%t",
		len(seeds), from, cfg.Gossip.IntervalSeconds, cfg.Gossip.MaxServers, cfg.Gossip.AllowPrivatePeers)
	return handler
}

// startGossipLoops starts the per-seed round loop and the server.met persistence timer,
// and returns a function that halts both. Touches only the handler, which carries its own
// lock, so it is safe to call after the listeners are accepting.
func startGossipLoops(
	ctx context.Context,
	cfg config.Config,
	handler *ed2k.GossipHandler,
	mainConn, gossipConn *net.UDPConn,
) func() {
	stopClient := handler.StartGossipClient(ed2k.GossipClientConfig{
		Main:       mainConn,
		Gossip:     gossipConn,
		MainPort:   cfg.UDP.Port,
		GossipPort: cfg.UDP.PortGossip,
		Interval:   time.Duration(cfg.Gossip.IntervalSeconds) * time.Second,
	})

	stopPersist := func() {}
	if cfg.Gossip.PersistOrDefault() {
		stopPersist = startServerMetPersistence(ctx, cfg.ServerMetPath(),
			time.Duration(cfg.Gossip.PersistIntervalSeconds)*time.Second, handler)
	}
	return func() {
		stopClient()
		stopPersist()
	}
}

// startServerMetPersistence writes the verified peer table on a timer, and once more on
// shutdown so a clean stop does not lose up to a full interval of learned peers.
func startServerMetPersistence(ctx context.Context, path string, every time.Duration, handler *ed2k.GossipHandler) func() {
	if every <= 0 {
		every = 225 * time.Second
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		write := func() {
			entries := handler.VerifiedEntries()
			if len(entries) == 0 {
				// Nothing verified yet. Deliberately not written: truncating a good file to
				// zero entries because this boot has not finished its first handshake would
				// throw away the mesh the file exists to preserve.
				return
			}
			if err := ed2k.WriteServerMet(path, entries); err != nil {
				logging.Warnf("gossip: cannot write %s: %v", path, err)
				return
			}
			logging.Debugf("gossip: wrote %d verified peer(s) to %s", len(entries), path)
		}
		for {
			select {
			case <-ticker.C:
				write()
			case <-ctx.Done():
				write()
				return
			case <-done:
				write()
				return
			}
		}
	}()
	// The stopper blocks until the final write has actually finished. Signalling and
	// returning would let main's remaining defers run and the process exit while
	// WriteServerMet is still writing — a small file usually wins that race, but
	// "usually" is the whole problem: the losing case silently drops a shutdown flush
	// and leaves a temp file behind. Same shape as storage.StartSnapshot's stopper.
	var once sync.Once
	return func() {
		once.Do(func() { close(done) })
		<-finished
	}
}

// advertisedUDPObfPort is the portUDPOBF value published at offset 32 of the extended
// OP_GLOBSERVSTATRES.
//
// It must be the port gossip actually sends its obfuscated frames from, because a peer
// checks our source port against this advertised value and skips us when the two disagree
// — eserver logs exactly that: "continue because portUDPobf(%d) != sin_port(%d)". That
// port is udp.portGossip, which defaults to the tcp+12 obfuscated socket for the reason
// given in config.setDefaults: eserver also derives our TCP port from the same source port
// by subtracting 12.
//
// This is one place we deliberately diverge from Lugdunum's own configuration. eserver
// advertises portUDPOBF = port+14 while sending its obfuscated frames from port+12, so its
// advertised value and its source port do not agree — a peer that enforced its own rule
// against it would skip it. We publish the port we really use instead.
//
// With gossip off the client obfuscated port is published exactly as before.
func advertisedUDPObfPort(cfg config.Config) uint16 {
	if cfg.Gossip.EnabledOrDefault() && cfg.UDP.PortGossip != 0 {
		return cfg.UDP.PortGossip
	}
	return cfg.UDP.PortObfuscated
}

// maxmindAccount converts the configured credentials, or nil when either half is
// missing. Nil means "use only an existing local database and never contact MaxMind",
// which is also what an operator gets by leaving both keys empty.
func maxmindAccount(cfg config.GeoIPConfig) *netfilter.WebServiceAccount {
	if !cfg.HasCredentials() {
		return nil
	}
	return &netfilter.WebServiceAccount{AccountID: cfg.AccountID, LicenseKey: cfg.LicenseKey}
}

// configSeedsToServers adapts config entries to the storage.Server shape
// GossipSeedsFromServers takes, so the config and server.met paths share one filter.
func configSeedsToServers(entries []config.ServerEntry) []storage.Server {
	out := make([]storage.Server, 0, len(entries))
	for _, e := range entries {
		out = append(out, storage.Server{IP: e.IP, Port: e.Port})
	}
	return out
}

// localInterfaceIPs enumerates this host's addresses, used only for gossip
// self-rejection. Failure is silent: the advertised IP is already registered, so this is
// a widening of the check rather than the check itself.
func localInterfaceIPs() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP != nil {
			out = append(out, ipnet.IP)
		}
	}
	return out
}

func startBackgroundProcess(args []string) (int, error) {
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), backgroundEnvKey+"=1")

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer devNull.Close()

	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull

	if err := cmd.Start(); err != nil {
		return 0, err
	}

	return cmd.Process.Pid, nil
}

func filterDaemonArgs(args []string) []string {
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-daemon" {
			continue
		}
		if arg == "--daemon" {
			continue
		}
		if arg == "-daemon=true" || arg == "--daemon=true" {
			continue
		}
		if arg == "-daemon=false" || arg == "--daemon=false" {
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered
}

// firstRoutableIP returns the first candidate that is a usable advertised
// address, or "" when none is. The wildcard is not routable: a client that
// receives it has been told nothing.
func firstRoutableIP(candidates ...string) string {
	for _, c := range candidates {
		if c != "" && c != "0.0.0.0" {
			return c
		}
	}
	return ""
}

// serverIdentitySeed picks what the server hash is derived from.
//
// Deriving it from cfg.Address alone meant every deployment that did not set
// `address` computed MD5("0.0.0.0" + port) — the same hash everywhere, so
// servers were not distinguishable by identity at all. The hostname is used when
// no routable IP is known: unlike a random value it is stable across restarts,
// so an unconfigured server keeps one identity instead of presenting a new one
// after every boot.
//
// Two cases it does not cover, neither worth extra machinery: two unconfigured
// servers on the same host and port would still collide (they cannot both bind
// that port anyway), and renaming the machine changes the identity once. Setting
// `address` or `dynIp` is the real fix.
func serverIdentitySeed(advertisedIP, configuredAddress string) string {
	if advertisedIP != "" {
		return advertisedIP
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		logging.Infof("server hash derived from hostname %q: no routable address configured", host)
		return host
	}
	return configuredAddress
}

// seedServers loads the configured peer servers into storage so OP_SERVERLIST can
// advertise them. This is the only caller of Engine.AddServer outside tests — the
// list was permanently empty before. Both an IPv4 and a public IPv6 address are
// accepted (the wire builder advertises the latter in the trailing v6 block); an
// entry classified as neither is skipped with a warning rather than aborting, so
// one typo cannot silence the whole list. Empty config (the default) seeds nothing.
func seedServers(store storage.Engine, entries []config.ServerEntry) {
	// The engines deduplicate on their own, so this set exists only to name the
	// offending entry: an operator who listed a peer twice should be told which one
	// was dropped rather than left to notice a count that does not match the file.
	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if _, _, fam := ed2k.ClassifyServerIP(e.IP); fam == 0 {
			logging.Warnf("skipping server list entry %q:%d: not a valid IPv4 or public IPv6", e.IP, e.Port)
			continue
		}
		server := storage.Server{IP: e.IP, Port: e.Port}
		key := storage.ServerAddrKey(server)
		if _, dup := seen[key]; dup {
			logging.Warnf("duplicate server list entry %q:%d ignored", e.IP, e.Port)
			continue
		}
		seen[key] = struct{}{}
		store.AddServer(server)
	}
	if n := store.ServersCount(); n > 0 {
		logging.Infof("advertising %d server(s) in OP_SERVERLIST", n)
	}
}

// adminDisplayHost turns a bind address into a host usable in a browseable URL.
// The wildcards (empty, 0.0.0.0, ::) are not browseable, so they map to localhost;
// an IPv6 literal is bracketed so the resulting URL is valid.
func adminDisplayHost(bindIP string) string {
	switch bindIP {
	case "", "0.0.0.0", "::", "[::]":
		return "localhost"
	}
	if ip := net.ParseIP(bindIP); ip != nil && ip.To4() == nil {
		return "[" + bindIP + "]"
	}
	return bindIP
}

// adminBindIsLoopback reports whether the dashboard bind stays on this machine.
// A non-loopback bind (a wildcard or a routable address) exposes an unauthenticated
// page off-box, which warrants a warning.
func adminBindIsLoopback(bindIP string) bool {
	if ip := net.ParseIP(bindIP); ip != nil {
		return ip.IsLoopback()
	}
	// Not an IP literal: only the empty default (resolved to 127.0.0.1 elsewhere)
	// and "localhost" are loopback; any other hostname is treated as exposed.
	return bindIP == "" || bindIP == "localhost"
}
