package ed2k

import (
	"net"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv6"

	"enode/internal/handoff"
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
	// NatCallback advertises FlagNatCallback (0x1000) in the UDP flags, as Lugdunum
	// does (its UDP word is 0x17fb).
	NatCallback bool
	// NatRendezvous and NatWake advertise FlagNatRendezvous (0x40000) and FlagNatWake
	// (0x200000) in the UDP flags too, as on the TCP word, so a client that only saw
	// the server's status reply knows it offers PR_NAT.
	NatRendezvous bool
	NatWake       bool
	// Workers and QueueSize bound the datagram handler pool. Zero means the
	// defaults below.
	Workers   int
	QueueSize int
	// Gate holds the read loop while closed; nil reads from the start. See Gate.
	Gate *Gate
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
	if cfg.NatCallback {
		flags += FlagNatCallback
	}
	if cfg.NatRendezvous {
		flags += FlagNatRendezvous
	}
	if cfg.NatWake {
		flags += FlagNatWake
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
	hostPort := net.JoinHostPort(cfg.Address, strconv.Itoa(int(cfg.Port)))
	addr, err := net.ResolveUDPAddr(network, hostPort)
	if err != nil {
		return nil, err
	}
	// Through the handoff registry, like RunTCPServer's listener.
	conn, err := handoff.ListenUDP(network, hostPort)
	if err != nil {
		return nil, err
	}
	// The read deadline only: replies are written from the worker pool, and must
	// not fail while the gate holds the reads.
	cfg.Gate.attach(conn.SetReadDeadline)

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
			cfg.Gate.wait()
			n, oobn, _, remote, err := conn.ReadMsgUDP(buf, oob)
			if err != nil {
				if cfg.Gate.interrupted(err) {
					continue
				}
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

// NewUDPSourceConn wraps a listener for sends this server initiates rather than
// replies to (the gossip loop), so their IPv6 source can be pinned the same way a
// reply's is. A nil listener yields a nil conn.
func NewUDPSourceConn(conn *net.UDPConn) UDPReplyConn {
	if conn == nil {
		return nil
	}
	return newUDPReplyConn(conn, nil)
}

// baseReplyConn strips the arrival-address pin from one of RunUDPServer's reply conns,
// for sends that answer no datagram of their own. Any other conn comes back as it is.
func baseReplyConn(conn UDPReplyConn) UDPReplyConn {
	if rc, ok := conn.(*udpReplyConn); ok {
		return newUDPReplyConn(rc.UDPConn, nil)
	}
	return conn
}

// replyConnListener is the listener behind conn, or nil when it is neither a reply conn
// nor a *net.UDPConn (test fakes).
func replyConnListener(conn UDPReplyConn) *net.UDPConn {
	switch c := conn.(type) {
	case *udpReplyConn:
		return c.UDPConn
	case *net.UDPConn:
		return c
	}
	return nil
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
