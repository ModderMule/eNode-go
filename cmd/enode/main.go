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
	"syscall"
	"time"

	"enode/admin"
	"enode/config"
	"enode/ed2k"
	"enode/logging"
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

	seedServers(engine, cfg.Servers)

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
			UDPPortObf:     cfg.UDP.PortObfuscated,
			TCPPortObf:     cfg.TCP.PortObfuscated,
			UDPServerKey:   cfg.UDP.ServerKey,
			MaxConnections: uint32(cfg.TCP.MaxConnections),
		},
		engine,
	)

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
				return admin.LiveStats{
					Clients:       clients,
					Files:         files,
					LowIDs:        int(runtime.LowIDs.Count()),
					Servers:       runtime.Storage.ServersCount(),
					UptimeSeconds: int64(time.Since(startTime).Seconds()),
					Time:          time.Now().Format(time.RFC3339),
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

	ln, err := ed2k.RunTCPServer(tcpCfg, runtime.TCPHandler(false))
	if err != nil {
		return fmt.Errorf("tcp server failed: %w", err)
	}
	defer ln.Close()
	logging.Infof("listening: tcp %s:%d", tcpCfg.Address, tcpCfg.Port)

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
		logging.Infof("listening: udp-obfuscated %s:%d", udpCryptCfg.Address, udpCryptCfg.Port)
	}

	<-ctx.Done()
	logging.Infof("shutdown signal received, stopping")
	return nil
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
	for _, e := range entries {
		if _, _, fam := ed2k.ClassifyServerIP(e.IP); fam == 0 {
			logging.Warnf("skipping server list entry %q:%d: not a valid IPv4 or public IPv6", e.IP, e.Port)
			continue
		}
		store.AddServer(storage.Server{IP: e.IP, Port: e.Port})
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
