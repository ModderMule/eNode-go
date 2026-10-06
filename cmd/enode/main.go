package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
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
	"enode/meta"
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
	// The config exactly as the file had it, before dynIp is replaced by its resolved
	// value below: a config reload compares the file against this.
	bootFileCfg := cfg

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
	tcpCfg, udpCfg := serverListenConfigs(cfg)

	// Torrent/Usenet rows from the catalogue daemons. Built before the runtime so the
	// FlagMetaSearch bit reaches both advertised flag words; attached and started
	// below, before the listeners bind. See docs/meta-search.md.
	var metaSearcher *meta.Searcher
	if cfg.MetaSearch.AnyEnabled() {
		metaSearcher = meta.New(cfg.MetaSearch)
	}

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

	// The server-to-server search service, built before the runtime: in gossip
	// mode the UDP description reply advertises it. See docs/server-search.md.
	serverSearch, err := buildServerSearch(cfg, engine, advertisedIP)
	if err != nil {
		return fmt.Errorf("server search: %w", err)
	}

	// The client-facing Meta API, built before the runtime for the same reason:
	// OP_SERVERIDENT advertises it. Its listeners start below. It comes after the
	// server search, whose files its own search can answer with. See
	// docs/meta-api.md.
	metaAPI, err := buildMetaAPI(ctx, cfg, engine, metaSearcher, serverSearch.peerSearcher(), advertisedIP)
	if err != nil {
		return fmt.Errorf("meta api: %w", err)
	}

	serverHash := ed2k.MD5([]byte(fmt.Sprintf("%s%d", serverIdentitySeed(advertisedIP, cfg.Address), cfg.TCP.Port)))

	udpSecret, err := loadUDPSecret(cfg)
	if err != nil {
		return err
	}

	// Everything the runtime configs need beyond the config file. Computed once here and
	// reused unchanged by a config reload.
	derived := bootDerived{
		advertisedIP: advertisedIP,
		serverIPv6:   serverIPv6,
		serverHash:   serverHash,
		udpSecret:    udpSecret,
		metaSearch:   metaSearcher != nil,
		metaAPI:      metaAPI.advertisement(),
		serverSearch: serverSearch.advertisement(),
	}
	runtimeTCP, runtimeUDP := buildRuntimeConfigs(cfg, derived)
	runtime := ed2k.NewServerRuntime(runtimeTCP, runtimeUDP, engine)

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

	// The gossip peer table is attached here, before any listener binds, so no client is
	// accepted unrecorded. Its sockets and timers start further down, once the main UDP
	// socket the outbound loop sends from exists. A config reload attaches and detaches
	// the handler later, with the listeners live.
	gossipHandler := buildGossipHandler(cfg, advertisedIP, serverIPv6)
	if gossipHandler != nil {
		runtime.SetGossipHandler(gossipHandler)
	}

	// Same ordering rule as the gossip handler: the searcher is read without a lock by
	// every search, so it is attached before any listener binds.
	//
	// Other servers' files reach a search the same way, through the one searcher the
	// runtime holds, so the two are combined when both are on.
	var rowSearcher ed2k.MetaSearcher
	if metaSearcher != nil {
		rowSearcher = metaSearcher
	}
	if serverSearch != nil {
		rowSearcher = newCombinedSearcher(rowSearcher, serverSearch.searcher)
	}
	if rowSearcher != nil {
		runtime.SetMetaSearcher(rowSearcher, cfg.MetaSearch.AdvertiseToLegacyClientsOrDefault())
	}
	if metaSearcher != nil {
		warnMetaTokens(cfg.MetaSearch)
		stopMeta := metaSearcher.Start(ctx)
		defer stopMeta()
		logging.Infof("meta search enabled: networks=%v advertiseToLegacyClients=%t cache=%t",
			metaSearcher.Networks(), cfg.MetaSearch.AdvertiseToLegacyClientsOrDefault(), cfg.MetaSearch.Cache.Enabled)
	}

	// Offsets added to the counts in OP_SERVERSTATUS and OP_GLOBSERVSTATRES. Local-only
	// config; absent means the real counts are advertised.
	runtime.SetStatsBoost(statsBoostFromConfig(cfg))
	warnStatsBoost(cfg)

	startTime := time.Now()
	if metaAPI != nil {
		metaAPI.setStatus(runtime, startTime)
		stopMetaAPI, err := metaAPI.start(ctx)
		if err != nil {
			return fmt.Errorf("meta api: %w", err)
		}
		defer stopMetaAPI()
	}

	if serverSearch != nil {
		warnServerSearch(cfg)
		serverSearch.attach(runtime, accessFilter)
		stopServerSearch, err := serverSearch.start(ctx)
		if err != nil {
			return fmt.Errorf("server search: %w", err)
		}
		defer stopServerSearch()
	}

	// Local admin status dashboard. Default on and bound to loopback; a bind
	// failure is fatal because the operator asked for it. Static server facts are
	// captured once; the live counters come from a snapshot read per request.
	var adminSrv *admin.Server
	if cfg.Admin.EnabledOrDefault() {
		// Daily GitHub release check; Info() is nil-receiver safe, so a disabled
		// checker simply leaves the dashboard without an update hint.
		var updateChecker *admin.UpdateChecker
		if cfg.Admin.CheckUpdatesOrDefault() {
			updateChecker = admin.NewUpdateChecker(ed2k.ENodeVersionStr)
			defer updateChecker.Start(ctx)()
		}
		adminSrv = admin.New(
			admin.Config{BindIP: cfg.Admin.BindIP, Port: cfg.Admin.Port, Username: cfg.Admin.Username, Password: cfg.Admin.Password},
			buildAdminStatic(cfg, derived),
			func() admin.LiveStats {
				clients, files := runtime.Counts()
				// GossipStats() and accessFilter.Stats() both return zero values when the
				// subsystem is off, so neither needs a branch. Read through the runtime
				// because a config reload can replace the gossip handler.
				gossip := runtime.GossipStats()
				blockedIP, blockedGeo := accessFilter.Stats()
				metaCacheEntries, metaStats := adminMetaStats(metaSearcher)
				return admin.LiveStats{
					Clients: clients,
					Files:   files,
					LowIDs:  int(runtime.LowIDs.Count()),
					// What a client is actually sent, not Storage.ServersCount(): the latter
					// counts only configured peers and reads 0 for everything gossip learns.
					Servers:                   runtime.AdvertisedServerCount(),
					UptimeSeconds:             int64(time.Since(startTime).Seconds()),
					Time:                      time.Now().Format(time.RFC3339),
					GossipKnown:               gossip.Known,
					GossipVerified:            gossip.Verified,
					GossipParked:              gossip.Parked,
					GossipAdmitted:            gossip.Admitted,
					GossipRejectedBad:         gossip.RejectedBad,
					GossipRejectedSelf:        gossip.RejectedSelf,
					GossipRejectedClient:      gossip.RejectedPeer,
					GossipRejectedFull:        gossip.RejectedFull,
					GossipRejectedUnsolicited: gossip.RejectedUnsolicited,
					GossipRejectedPlaintext:   gossip.RejectedPlaintext,
					FilterBlockedIP:           blockedIP,
					FilterBlockedGeo:          blockedGeo,
					// Files stays the eD2K count; this is what clients are sent.
					AdvertisedFiles:  runtime.AdvertisedFiles(),
					MetaCacheEntries: metaCacheEntries,
					Meta:             metaStats,
					MetaAPI:          metaAPI.adminStats(),
					ServerSearch:     serverSearch.adminStats(),
					Update:           updateChecker.Info(),
				}
			},
		)
		if metaAPI != nil && metaAPI.accounts != nil {
			adminSrv.SetAccounts(accountAdmin{svc: metaAPI.accounts})
		}
		if err := adminSrv.Start(); err != nil {
			return fmt.Errorf("admin dashboard failed to bind %s:%d: %w", cfg.Admin.BindIP, cfg.Admin.Port, err)
		}
		defer adminSrv.Close()
		logging.Infof("admin dashboard: http://%s:%d/", adminDisplayHost(cfg.Admin.BindIP), cfg.Admin.Port)
		if !adminBindIsLoopback(cfg.Admin.BindIP) && cfg.Admin.Username == "" {
			logging.Warnf("admin dashboard bound to %s without admin.username/password: off-box clients see the status page (never accounts)", cfg.Admin.BindIP)
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
	if links := ed2kServerLinks(advertisedIP, serverIPv6, cfg.TCP.Port); len(links) > 0 {
		// The link format has no name field (srchybrid/ED2KLink.cpp rejects anything but
		// "/" after the port); clients learn the name from OP_SERVERIDENT after connecting.
		for _, link := range links {
			logging.Infof("ed2k server link (%s): %s", cfg.Name, link)
		}
	} else {
		logging.Warnf("ed2k server link: unavailable, no public address known (set address or dynIp)")
	}

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
	// buildGossipHandler above); only the sockets and timers start here, in
	// reloader.startGossipIO, which a config reload that turns gossip on runs again.
	reload := &reloader{
		ctx:       ctx,
		path:      configPath,
		bootFile:  bootFileCfg,
		boot:      cfg,
		applied:   cfg,
		derived:   derived,
		runtime:   runtime,
		engine:    engine,
		adminSrv:  adminSrv,
		udpCfg:    udpCfg,
		mainConn:  udpConn,
		obfConn:   obfUDPConn,
		gossip:    gossipHandler,
		stopLoops: func() {},
	}
	defer reload.close()
	if gossipHandler != nil {
		if err := reload.startGossipIO(cfg); err != nil {
			return err
		}
	}
	if adminSrv != nil {
		adminSrv.SetReloader(reload.Reload)
	}

	<-ctx.Done()
	logging.Infof("shutdown signal received, stopping")
	return nil
}

// buildGossipHandler creates the peer table and seeds it, or returns nil when gossip is
// disabled.
//
// Separate from startGossipLoops: at boot it is called before any listener binds, so
// every accepted client is recorded from the first connection, while the loops cannot
// start that early because phase 1 sends from the main UDP socket, which does not exist
// yet. A config reload that turns gossip on calls it with the listeners live.
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

	gossipCfg := buildGossipConfig(cfg, advertisedIP, serverIPv6)

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
	clientCfg := ed2k.GossipClientConfig{
		MainPort:   cfg.UDP.Port,
		GossipPort: cfg.UDP.PortGossip,
		Interval:   time.Duration(cfg.Gossip.IntervalSeconds) * time.Second,
	}
	// Wrapped so IPv6 frames leave from the advertised address; assigned only when
	// bound, because a nil conn stored in the interface would no longer compare nil.
	if conn := ed2k.NewUDPSourceConn(mainConn); conn != nil {
		clientCfg.Main = conn
	}
	if conn := ed2k.NewUDPSourceConn(gossipConn); conn != nil {
		clientCfg.Gossip = conn
	}
	stopClient := handler.StartGossipClient(clientCfg)

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

// firstRoutableIP returns the first candidate that is a usable advertised IPv4
// address, or "" when none is. The result fills the uint32 server-IP field of
// OP_SERVERIDENT, so only a specified IPv4 literal qualifies: the wildcard tells a
// client nothing, and an IPv6 bind such as "::" has no 32-bit form at all — it
// used to be picked here ahead of dynIp and made every OP_SERVERIDENT fail to
// build. The server's own IPv6 is advertised separately, via dynIp6.
func firstRoutableIP(candidates ...string) string {
	for _, c := range candidates {
		ip := net.ParseIP(c)
		if ip != nil && ip.To4() != nil && !ip.IsUnspecified() {
			return ip.To4().String()
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

// warnMetaTokens flags an enabled daemon on a non-loopback address with no token. The
// daemon refuses to start that way, so the likely cause is a token left out of this
// server's config — every call would then fail as unauthenticated.
func warnMetaTokens(c config.MetaSearchConfig) {
	for _, n := range []struct {
		name string
		cfg  config.MetaNetworkConfig
	}{{meta.NetworkTorrent, c.Torrent}, {meta.NetworkUsenet, c.Usenet}, {meta.NetworkKad, c.Kad}} {
		if !n.cfg.Enabled || n.cfg.Token != "" {
			continue
		}
		u, err := url.Parse(n.cfg.URL)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(u.Hostname()); u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback()) {
			continue
		}
		logging.Warnf("metaSearch.%s.url %s is not loopback but no token is set; the daemon will refuse every call",
			n.name, n.cfg.URL)
	}
}

// adminMetaStats maps the meta searcher's figures to the dashboard's own type, which
// keeps package admin free of a meta import. With meta search off it returns an empty
// list, so the page hides the section.
func adminMetaStats(s *meta.Searcher) (cacheEntries int, out []admin.MetaNetworkStats) {
	out = []admin.MetaNetworkStats{}
	if s == nil {
		return 0, out
	}
	for _, st := range s.Stats() {
		infoAt, liveOKAt := "", ""
		if !st.InfoAt.IsZero() {
			infoAt = st.InfoAt.Format(time.RFC3339)
		}
		if !st.LiveOKAt.IsZero() {
			liveOKAt = st.LiveOKAt.UTC().Format(time.RFC3339)
		}
		out = append(out, admin.MetaNetworkStats{
			Network:             st.Network,
			URL:                 st.URL,
			LiveSearch:          st.LiveSearch,
			FeedEnabled:         st.FeedEnabled,
			CountInServerStatus: st.CountInServerStatus,
			Reachable:           st.Reachable,
			LastError:           st.LastError,
			InfoAt:              infoAt,
			Down:                st.Down,
			StatsStale:          st.StatsStale,
			LiveOKAt:            liveOKAt,
			Daemon:              st.Daemon,
			Version:             st.Version,
			SearchAvailable:     st.SearchAvailable,
			Catalogued:          st.Catalogued,
			Published:           st.Published,
			Files:               st.Files,
			LastSeq:             st.LastSeq,

			NetworkUsers:             st.NetworkUsers,
			NetworkUsersExperimental: st.NetworkUsersExperimental,
			NetworkFiles:             st.NetworkFiles,

			FeedReleases:     st.FeedReleases,
			FeedRows:         st.FeedRows,
			FeedCursor:       st.FeedCursor,
			FeedCaughtUp:     st.FeedCaughtUp,
			SearchesTCP:      st.SearchesTCP,
			SearchesUDP:      st.SearchesUDP,
			RowsServed:       st.RowsServed,
			LiveCalls:        st.LiveCalls,
			LiveErrors:       st.LiveErrors,
			LiveTimeouts:     st.LiveTimeouts,
			CacheHits:        st.CacheHits,
			CacheMisses:      st.CacheMisses,
			UDPSkipped:       st.UDPSkipped,
			CatalogCalls:     st.CatalogCalls,
			CatalogErrors:    st.CatalogErrors,
			CatalogCacheHits: st.CatalogCacheHits,
			Counted:          st.Counted,
		})
	}
	return s.CacheEntries(), out
}

// ed2kServerLinks returns the ed2k://|server|...|/ links clients paste to add this
// server, in the format srchybrid/ED2KLink.cpp writes. The IPv4 link works in every
// eMule; the bracketed IPv6 link only in clients that parse it (eMuleQt ED2KLink.cpp).
// An unknown IPv4 (no routable address or dynIp) or IPv6 yields no link for it.
func ed2kServerLinks(advertisedIP string, serverIPv6 []byte, port uint16) []string {
	var links []string
	if ip := net.ParseIP(advertisedIP); ip != nil && ip.To4() != nil && !ip.IsUnspecified() {
		links = append(links, fmt.Sprintf("ed2k://|server|%s|%d|/", ip.To4(), port))
	}
	if len(serverIPv6) == net.IPv6len {
		links = append(links, fmt.Sprintf("ed2k://|server|[%s]|%d|/", net.IP(serverIPv6), port))
	}
	return links
}

// ipv6String renders a 16-byte IPv6 address, or "" when none was resolved.
func ipv6String(b []byte) string {
	if len(b) != net.IPv6len {
		return ""
	}
	return net.IP(b).String()
}

// loadUDPSecret returns the secret client UDP obfuscation keys are derived from. A
// configured udp.serverKey is honoured as before, so the keys clients already hold
// stay valid, but it is 32 bits and was shipped as the same public value everywhere.
// Without one, a 128-bit secret is generated on first start and kept in the data dir.
func loadUDPSecret(cfg config.Config) ([]byte, error) {
	if cfg.UDP.ServerKey != 0 {
		logging.Warnf("udp.serverKey is a 32-bit secret anyone can brute-force from one observed key; remove it to use a generated %s", cfg.UDPSecretPath())
		return ed2k.LegacyUDPSecret(cfg.UDP.ServerKey), nil
	}
	secret, err := ed2k.LoadOrCreateUDPSecret(cfg.UDPSecretPath())
	if err != nil {
		return nil, fmt.Errorf("udp secret: %w", err)
	}
	return secret, nil
}
