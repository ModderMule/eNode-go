package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"enode/config"
	"enode/ed2k"
	"enode/logging"

	"gopkg.in/yaml.v3"
)

// Validation severities. An error means the server would refuse to start or would
// run with a setting that cannot work; a warning means it starts, but a key is
// ignored or the result is probably not what was meant.
const (
	severityError   = "error"
	severityWarning = "warning"
)

// validationIssue is one finding of runValidate.
type validationIssue struct {
	Severity string
	Message  string
}

// runValidate checks the config at path without binding a socket, opening the
// storage or reaching the network, prints every finding to w, and returns an error
// when at least one finding is an error. It is the -validate flag.
//
// It goes further than config.Load, which startup runs: unknown keys (a typo loads
// silently as the zero value), IP literals of the wrong family, two listeners on one
// port, and the Lugdunum port offsets eMule relies on.
func runValidate(path string, w io.Writer) error {
	issues := validateConfigFile(path)
	errors := 0
	for _, is := range issues {
		if is.Severity == severityError {
			errors++
		}
		fmt.Fprintf(w, "%-7s %s\n", is.Severity, is.Message)
	}
	if errors > 0 {
		return fmt.Errorf("%s: %d error(s), %d warning(s)", path, errors, len(issues)-errors)
	}
	fmt.Fprintf(w, "%s: ok (%d warning(s))\n", path, len(issues))
	return nil
}

// validateConfigFile returns every finding for the config at path, errors first.
func validateConfigFile(path string) []validationIssue {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []validationIssue{{severityError, err.Error()}}
	}
	var issues []validationIssue
	add := func(sev, format string, args ...any) {
		issues = append(issues, validationIssue{sev, fmt.Sprintf(format, args...)})
	}

	// Strict decode: KnownFields rejects keys the Config struct does not have.
	var strict config.Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&strict); err != nil && err != io.EOF {
		add(severityError, "yaml: %v", err)
	}

	// The defaults and checks startup applies. Nothing below can run without it.
	cfg, err := config.Load(path)
	if err != nil {
		add(severityError, "load: %v", err)
		return sortIssues(issues)
	}

	if _, err := logging.ParseLevel(cfg.LogLevel); err != nil {
		add(severityError, "logLevel %q: %v", cfg.LogLevel, err)
	}
	validateAddresses(cfg, add)
	validatePorts(cfg, add)
	validateServerList(cfg, add)
	validateMisc(cfg, add)
	return sortIssues(issues)
}

// validateAddresses checks the bind and advertised addresses of both families.
func validateAddresses(cfg config.Config, add func(string, string, ...any)) {
	ipv6On := cfg.IPv6.EnabledOrDefault()

	bind := net.ParseIP(cfg.Address)
	if cfg.Address != "" && bind == nil {
		add(severityError, "address %q is not an IP literal", cfg.Address)
	}
	// An IPv4 bind takes the listeners off IPv6, whatever the ipv6 section says.
	if ipv6On && bind != nil && bind.To4() != nil {
		add(severityWarning, "address %q is IPv4: the listeners bind IPv4 only, so IPv6 clients cannot log in although ipv6.enabled is on (leave address empty for dual-stack)", cfg.Address)
		if strings.TrimSpace(cfg.IPv6.DynIP6) != "" {
			add(severityWarning, "ipv6.dynIp6 %q is advertised to clients, but nothing listens on IPv6", cfg.IPv6.DynIP6)
		}
	}

	switch dyn := strings.TrimSpace(cfg.DynIP); {
	case dyn == "" || strings.EqualFold(dyn, "auto"):
	default:
		ip := net.ParseIP(dyn)
		switch {
		case ip == nil || ip.To4() == nil:
			add(severityError, "dynIp %q must be \"auto\", empty, or an IPv4 literal (the IPv6 goes in ipv6.dynIp6)", dyn)
		case !isPublicIP(ip):
			add(severityWarning, "dynIp %q is not a public address; remote clients cannot reach it", dyn)
		}
	}
	if firstRoutableIP(cfg.Address, cfg.DynIP) == "" && !strings.EqualFold(strings.TrimSpace(cfg.DynIP), "auto") {
		add(severityWarning, "no server IPv4 known (address and dynIp give none): clients receive serverIP=0.0.0.0")
	}

	if cfg.IPv6.Address != "" {
		// Parsed so old configs load, but no listener reads it.
		add(severityWarning, "ipv6.address %q is ignored: the listeners bind the top-level address only", cfg.IPv6.Address)
		if ip := net.ParseIP(cfg.IPv6.Address); ip == nil || ip.To4() != nil {
			add(severityError, "ipv6.address %q is not an IPv6 literal", cfg.IPv6.Address)
		}
	}
	if dyn6 := strings.TrimSpace(cfg.IPv6.DynIP6); dyn6 != "" && !strings.EqualFold(dyn6, "auto") {
		if _, ok := ed2k.ParsePublicIPv6(dyn6); !ok {
			add(severityError, "ipv6.dynIp6 %q is not a public IPv6 literal (startup would ignore it)", dyn6)
		}
	}
	if !ipv6On && strings.TrimSpace(cfg.IPv6.DynIP6) != "" {
		add(severityWarning, "ipv6.dynIp6 is set but ipv6.enabled is false, so it is not used")
	}

	if cfg.Ed3k.Enabled {
		if a := cfg.Ed3k.Advertise; a != "" {
			if ip := net.ParseIP(a); ip == nil || ip.To4() == nil {
				add(severityError, "ed3k.advertise %q is not an IPv4 literal", a)
			}
		}
		if a := cfg.Ed3k.AdvertiseIPv6; a != "" {
			if _, ok := ed2k.ParsePublicIPv6(a); !ok {
				add(severityError, "ed3k.advertiseIPv6 %q is not a public IPv6 literal", a)
			}
		}
	}
}

// validatePorts finds two enabled listeners on one port of the same transport, and
// eD2K UDP ports off Lugdunum's fixed offsets from tcp.port.
func validatePorts(cfg config.Config, add func(string, string, ...any)) {
	type listener struct {
		name, proto string
		port        int
	}
	ls := []listener{
		{"tcp.port", "tcp", int(cfg.TCP.Port)},
		{"tcp.portObfuscated", "tcp", int(cfg.TCP.PortObfuscated)},
		{"udp.port", "udp", int(cfg.UDP.Port)},
		{"udp.portObfuscated", "udp", int(cfg.UDP.PortObfuscated)},
	}
	if cfg.Gossip.EnabledOrDefault() {
		ls = append(ls, listener{"udp.portGossip", "udp", int(cfg.UDP.PortGossip)})
	}
	if cfg.NAT.Enabled {
		ls = append(ls, listener{"natTraversal.port", "udp", int(cfg.NAT.Port)})
	}
	if cfg.Admin.EnabledOrDefault() {
		ls = append(ls, listener{"admin.port", "tcp", int(cfg.Admin.Port)})
	}
	if cfg.Ed3k.Enabled {
		port := int(cfg.Ed3k.Port)
		if port == 0 {
			port = int(cfg.TCP.Port)
		}
		ls = append(ls, listener{"ed3k.port", "udp", port})
	}
	hostPorts := []struct {
		name, addr string
		on         bool
	}{
		{"metaApi.grpc.listen", cfg.MetaAPI.GRPC.Listen, cfg.MetaAPI.GRPCEnabled()},
		{"metaApi.http.listen", cfg.MetaAPI.HTTP.Listen, cfg.MetaAPI.HTTPListenerEnabled()},
		{"serverSearch.listen", cfg.ServerSearch.Listen, cfg.ServerSearch.Enabled},
	}
	for _, hp := range hostPorts {
		if !hp.on {
			continue
		}
		_, p, err := net.SplitHostPort(hp.addr)
		port, perr := strconv.Atoi(p)
		if err != nil || perr != nil {
			add(severityError, "%s %q is not host:port", hp.name, hp.addr)
			continue
		}
		ls = append(ls, listener{hp.name, "tcp", port})
	}

	seen := map[string]string{}
	for _, l := range ls {
		if l.port == 0 {
			continue
		}
		key := l.proto + "/" + strconv.Itoa(l.port)
		if other, dup := seen[key]; dup {
			add(severityError, "%s and %s both use %s port %d", other, l.name, l.proto, l.port)
			continue
		}
		seen[key] = l.name
	}

	// eMule hardwires these (srchybrid/ServerList.cpp): it pings tcp+4, sends the
	// crypt ping to tcp+12 and accepts a reply only from the port it pinged.
	tcp := int(cfg.TCP.Port)
	offsets := []struct {
		name   string
		port   int
		offset int
	}{
		{"udp.port", int(cfg.UDP.Port), 4},
		{"udp.portObfuscated", int(cfg.UDP.PortObfuscated), 12},
	}
	for _, o := range offsets {
		if o.port != tcp+o.offset {
			add(severityWarning, "%s is %d, not tcp.port+%d (%d): eMule clients expect the server there", o.name, o.port, o.offset, tcp+o.offset)
		}
	}
}

// validateServerList checks the peer servers advertised in OP_SERVERLIST.
func validateServerList(cfg config.Config, add func(string, string, ...any)) {
	seen := map[string]bool{}
	for _, e := range cfg.Servers {
		if _, _, fam := ed2k.ClassifyServerIP(e.IP); fam == 0 {
			add(severityError, "servers entry %q:%d is not an IPv4 or public IPv6 (startup skips it)", e.IP, e.Port)
			continue
		}
		if e.Port == 0 {
			add(severityError, "servers entry %q has no port", e.IP)
		}
		key := net.JoinHostPort(e.IP, strconv.Itoa(int(e.Port)))
		if seen[key] {
			add(severityWarning, "servers entry %s is listed twice", key)
		}
		seen[key] = true
	}
}

// validateMisc repeats the warnings startup logs for settings it accepts reluctantly.
func validateMisc(cfg config.Config, add func(string, string, ...any)) {
	if cfg.NAT.ServerIndependent != nil {
		add(severityWarning, "natTraversal.serverIndependent is retired and ignored")
	}
	if cfg.UDP.ServerKey != 0 {
		add(severityWarning, "udp.serverKey is a 32-bit secret anyone can brute-force; remove it to use a generated %s", cfg.UDPSecretPath())
	}
	if cfg.Admin.EnabledOrDefault() && cfg.Admin.Username == "" {
		if ip := net.ParseIP(cfg.Admin.BindIP); ip == nil || !ip.IsLoopback() {
			add(severityWarning, "admin dashboard binds %s without admin.username/password", cfg.Admin.BindIP)
		}
	}
}

func isPublicIP(ip net.IP) bool {
	return !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() && !ip.IsMulticast()
}

// sortIssues puts errors before warnings, keeping the order within each.
func sortIssues(issues []validationIssue) []validationIssue {
	sort.SliceStable(issues, func(i, j int) bool {
		return issues[i].Severity == severityError && issues[j].Severity != severityError
	})
	return issues
}
