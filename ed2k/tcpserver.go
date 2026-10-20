package ed2k

import (
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"enode/internal/handoff"
	"enode/logging"
)

type TCPServerConfig struct {
	Address        string
	Port           uint16
	MaxConnections int
	AuxiliarPort   bool
	RequireCrypt   bool
	RequestCrypt   bool
	SupportCrypt   bool
	IPInLogin      bool
	// DualStack selects the "tcp" network (accepts IPv4 and IPv6, honouring the
	// bind address) instead of the IPv4-only "tcp4", and drives the SRV_TCPFLG_IPV6
	// advertisement — a dual-stack server is exactly the one that supports IPv6.
	// False reproduces the original IPv4-only behaviour exactly.
	DualStack bool
	// NatRendezvous advertises FlagNatRendezvous (0x40000): this server offers
	// server-independent (cross-server / serverless) PR_NAT hole-punch rendezvous.
	NatRendezvous bool
	// Gate holds the accept loop while closed; nil accepts from the start. See Gate.
	Gate *Gate
}

// BuildTCPFlags builds the SRV_TCPFLG_* capability word sent in OP_IDCHANGE and
// OP_SERVERIDENT.
//
// Only bits eMule actually defines for the *server* word are emitted
// (srchybrid/Server.h): COMPRESSION 0x01, NEWTAGS 0x08, UNICODE 0x10,
// LARGEFILES 0x100, TCPOBFUSCATION 0x400, and the IPv6 extension bit 0x4000. The
// previous build packed client-side SRVCAP_* meanings (IP-in-login 0x02, aux-port
// 0x04, support-crypt 0x200, require-crypt 0x800) into this word — bits eMule
// reads as undefined and ignores. TCP obfuscation is advertised from SupportCrypt
// (the obfuscated listener actually running), not RequestCrypt, which only set
// 0x400 by coincidence and left it clear for a support-but-not-request server.
func BuildTCPFlags(cfg TCPServerConfig) uint32 {
	flags := FlagZlib + FlagNewTags + FlagUnicode + FlagLargeFiles
	if cfg.SupportCrypt {
		flags += FlagTcpObfusc
	}
	if cfg.DualStack {
		flags += FlagIPv6
	}
	if cfg.NatRendezvous {
		flags += FlagNatRendezvous
	}
	return flags
}

// RunTCPServer accepts connections until the listener is closed, enforcing
// cfg.MaxConnections.
//
// A non-positive MaxConnections means unlimited. That is deliberate rather than
// defensive: config.setDefaults leaves the field at zero when the YAML omits it,
// so treating zero as a limit would refuse every connection on a default config.
func RunTCPServer(cfg TCPServerConfig, handler func(net.Conn)) (net.Listener, error) {
	addr := net.JoinHostPort(cfg.Address, strconv.Itoa(int(cfg.Port)))
	// Through the handoff registry, so a successor process is handed this socket
	// and a process that is one gets its predecessor's back.
	ln, err := handoff.Listen(tcpNetwork(cfg.DualStack), addr)
	if err != nil {
		return nil, err
	}
	if tl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
		cfg.Gate.attach(tl.SetDeadline)
	}
	var active atomic.Int64
	go func() {
		for {
			cfg.Gate.wait()
			conn, err := ln.Accept()
			if err != nil {
				if cfg.Gate.interrupted(err) {
					continue
				}
				return
			}
			if cfg.MaxConnections > 0 && active.Add(1) > int64(cfg.MaxConnections) {
				active.Add(-1)
				logging.Warnf("tcp connection refused remote=%s: at maxConnections=%d",
					conn.RemoteAddr(), cfg.MaxConnections)
				_ = conn.Close()
				continue
			}
			go func() {
				if cfg.MaxConnections > 0 {
					defer active.Add(-1)
				}
				logging.Debugf("tcp accept remote=%s local=%s", conn.RemoteAddr(), conn.LocalAddr())
				handler(conn)
			}()
		}
	}()
	return ln, nil
}

// tcpNetwork selects the listen network. "tcp" binds dual-stack (both families,
// governed by the bind address); "tcp4" is the original IPv4-only behaviour.
func tcpNetwork(dualStack bool) string {
	if dualStack {
		return "tcp"
	}
	return "tcp4"
}
