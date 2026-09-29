package ed2k

import (
	"net"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv6"

	"enode/logging"
)

type UDPServerConfig struct {
	Address      string
	Port         uint16
	GetSources   bool
	GetFiles     bool
	SupportCrypt bool
	// DualStack selects the "udp" network (both families, honouring the bind
	// address) instead of the IPv4-only "udp4", and drives the SRV_UDPFLG_IPV6
	// advertisement. False reproduces the original behaviour exactly.
	DualStack bool
	// Workers and QueueSize bound the datagram handler pool. Zero means the
	// defaults below.
	Workers   int
	QueueSize int
}

// A datagram can cost far more to serve than to send: OP_GLOBGETSOURCES packs
// ~87 hashes into 1400 bytes and each one is a separate synchronous storage
// lookup. Unbounded goroutine-per-datagram turned that asymmetry into an
// amplifier, so the pool caps how much work is in flight at once.
const defaultUDPQueueSize = 1024

func BuildUDPFlags(cfg UDPServerConfig) uint32 {
	flags := FlagNewTags + FlagUnicode + FlagLargeFiles
	if cfg.GetSources {
		flags += FlagUdpExtSources + FlagUdpExtSrc2
	}
	if cfg.GetFiles {
		flags += FlagUdpExtFiles
	}
	if cfg.SupportCrypt {
		flags += FlagUdpObfusc + FlagTcpObfusc
	}
	if cfg.DualStack {
		flags += FlagIPv6
	}
	return flags
}

// UDPReplyConn is what a datagram handler replies through. RunUDPServer hands each
// handler a per-datagram value whose IPv6 replies leave from the address the request
// arrived on; a plain *net.UDPConn also satisfies it (tests, IPv4-only listeners).
type UDPReplyConn interface {
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	LocalAddr() net.Addr
}

type udpDatagram struct {
	data   []byte
	remote *net.UDPAddr
	// dst is the local address the datagram arrived on, when the listener captures
	// it (a wildcard dual-stack bind on a platform with IPV6_PKTINFO); nil otherwise.
	dst net.IP
}

func RunUDPServer(cfg UDPServerConfig, handler func([]byte, *net.UDPAddr, UDPReplyConn)) (*net.UDPConn, error) {
	network := udpNetwork(cfg.DualStack)
	addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(cfg.Address, strconv.Itoa(int(cfg.Port))))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		return nil, err
	}

	// A wildcard dual-stack bind on a host with several IPv6 addresses otherwise
	// replies from whichever source the kernel prefers, which need not be the address
	// the client sent to — and a client (or its stateful firewall) drops a reply from
	// an address it never contacted. Capturing the arrival address lets replies pin it.
	var oobSize int
	if cfg.DualStack && (addr.IP == nil || addr.IP.IsUnspecified()) {
		if err := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst, true); err != nil {
			logging.Debugf("udp %s: arrival-address capture unavailable, IPv6 replies use the kernel's source choice: %v", conn.LocalAddr(), err)
		} else {
			oobSize = len(ipv6.NewControlMessage(ipv6.FlagDst))
		}
	}

	workers, queueSize := udpPoolSize(cfg)
	jobs := make(chan udpDatagram, queueSize)
	var dropped atomic.Int64

	for i := 0; i < workers; i++ {
		go func() {
			for job := range jobs {
				handler(job.data, job.remote, newUDPReplyConn(conn, job.dst))
			}
		}()
	}

	go func() {
		defer close(jobs)
		buf := make([]byte, 65535)
		oob := make([]byte, oobSize)
		lastReport := time.Time{}
		for {
			n, oobn, _, remote, err := conn.ReadMsgUDP(buf, oob)
			if err != nil {
				return
			}
			var dst net.IP
			if oobn > 0 {
				var cm ipv6.ControlMessage
				if cm.Parse(oob[:oobn]) == nil {
					dst = cm.Dst
				}
			}
			// buf is reused on the next iteration, so the worker must get its own
			// copy — handing it buf[:n] would race the following read.
			data := append([]byte(nil), buf[:n]...)
			logging.Debugf("udp recv remote=%s local=%s len=%d", remote, conn.LocalAddr(), n)

			select {
			case jobs <- udpDatagram{data: data, remote: remote, dst: dst}:
			default:
				// Never block here. Blocking stalls ReadFromUDP, which turns a
				// flood into total UDP unavailability — worse than shedding load.
				total := dropped.Add(1)
				if time.Since(lastReport) >= udpDropReportEvery {
					lastReport = time.Now()
					logging.Warnf("udp queue full, dropping datagrams: total=%d queue=%d workers=%d",
						total, queueSize, workers)
				}
			}
		}
	}()
	return conn, nil
}

const udpDropReportEvery = 10 * time.Second

// WriteToUDPFrom sends b to addr from the local IPv6 src when conn is one of
// RunUDPServer's reply conns and both ends are native IPv6; otherwise it is a plain
// conn.WriteToUDP. For sends to someone other than the datagram's sender (PR_NAT
// forwarding), where the arrival address is not the right source.
func WriteToUDPFrom(conn UDPReplyConn, b []byte, addr *net.UDPAddr, src net.IP) (int, error) {
	if rc, ok := conn.(*udpReplyConn); ok {
		return rc.writeFrom(b, addr, src)
	}
	return conn.WriteToUDP(b, addr)
}

// udpPoolSize resolves the worker and queue sizes, defaulting the worker count
// from the CPU count. The work is largely storage I/O rather than CPU, so a
// small multiple of NumCPU keeps the database busy without unbounded fan-out.
func udpPoolSize(cfg UDPServerConfig) (workers, queueSize int) {
	workers = cfg.Workers
	if workers <= 0 {
		workers = runtime.NumCPU() * 4
	}
	if workers < 1 {
		workers = 1
	}
	queueSize = cfg.QueueSize
	if queueSize <= 0 {
		queueSize = defaultUDPQueueSize
	}
	return workers, queueSize
}

// udpNetwork selects the listen network. "udp" binds dual-stack; "udp4" is the
// original IPv4-only behaviour.
func udpNetwork(dualStack bool) string {
	if dualStack {
		return "udp"
	}
	return "udp4"
}

// udpReplyConn is the per-datagram UDPReplyConn: the listener plus the address the
// datagram arrived on.
type udpReplyConn struct {
	*net.UDPConn
	src net.IP
}

func newUDPReplyConn(conn *net.UDPConn, dst net.IP) *udpReplyConn {
	return &udpReplyConn{UDPConn: conn, src: nativeIPv6(dst)}
}

func (c *udpReplyConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	return c.writeFrom(b, addr, c.src)
}

// writeFrom pins the source with an IPV6_PKTINFO control message. Only between two
// native IPv6 addresses: IPv4 traffic on the dual-stack socket arrives v4-mapped, and
// Linux does not honour IPV6_PKTINFO on that path, so it keeps the kernel's choice
// exactly as before.
func (c *udpReplyConn) writeFrom(b []byte, addr *net.UDPAddr, src net.IP) (int, error) {
	src = nativeIPv6(src)
	if src == nil || addr == nil || nativeIPv6(addr.IP) == nil {
		return c.UDPConn.WriteToUDP(b, addr)
	}
	oob := (&ipv6.ControlMessage{Src: src}).Marshal()
	n, _, err := c.UDPConn.WriteMsgUDP(b, oob, addr)
	return n, err
}

// nativeIPv6 returns ip when it is a real IPv6 address (not IPv4 or v4-mapped, not
// unspecified), else nil.
func nativeIPv6(ip net.IP) net.IP {
	if ip == nil || ip.To4() != nil || ip.To16() == nil || ip.IsUnspecified() {
		return nil
	}
	return ip
}
