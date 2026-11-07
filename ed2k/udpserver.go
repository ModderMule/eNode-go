package ed2k

import (
	"net"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
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
	// NatWake advertises FlagNatWake (0x200000) in the UDP flags too, as on the TCP
	// word. FlagNatRendezvous (0x40000) is TCP only: PR_NAT serves logged-in clients.
	NatWake bool
	// ForeignCallback advertises FlagForeignCallback (0x100000): a client not logged
	// in here may send the foreign 0xA6 (requester ID 0).
	ForeignCallback bool
	// Workers and QueueSize bound the datagram handler pool. Zero means the
	// defaults below.
	Workers   int
	QueueSize int
	// Gate holds the read loop while closed; nil reads from the start. See Gate.
	Gate *Gate
	// SourceIPv4 is the IPv4 source for sends that answer no datagram of their own
	// (gossip, PR_NAT forwards) on a wildcard bind. Without it the kernel picks the
	// route's preferred source, which on a host with several IPv4 addresses can be
	// another server's, and peers and clients drop or misfile what arrives. Set it
	// only to an address a local interface holds; nil keeps the kernel's choice.
	// Replies always leave from the address their datagram arrived on. Linux only.
	SourceIPv4 net.IP
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
	if cfg.NatWake {
		flags += FlagNatWake
	}
	if cfg.ForeignCallback {
		flags += FlagForeignCallback
	}
	return flags
}

// UDPReplyConn is what a datagram handler replies through. RunUDPServer hands each
// handler a per-datagram value whose replies leave from the address the request
// arrived on (IPv4 on Linux only); a plain *net.UDPConn also satisfies it (tests).
type UDPReplyConn interface {
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	LocalAddr() net.Addr
}

type udpDatagram struct {
	data   []byte
	remote *net.UDPAddr
	// dst is the local address the datagram arrived on, when the listener captures
	// it (a wildcard bind on a platform with IPV6_PKTINFO or IP_PKTINFO); nil
	// otherwise. An IPv4 arrival on a dual-stack socket comes v4-mapped.
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

	// A wildcard bind on a host with several addresses otherwise replies from
	// whichever source the kernel prefers, which need not be the address the client
	// sent to — and a client (or its stateful firewall) drops a reply from an address
	// it never contacted. Capturing the arrival address lets replies pin it. On Linux
	// the IPV6_PKTINFO of a dual-stack socket reports IPv4 arrivals too, v4-mapped.
	var oobSize int
	wildcard := addr.IP == nil || addr.IP.IsUnspecified()
	switch {
	case wildcard && cfg.DualStack:
		if err := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst, true); err != nil {
			logging.Debugf("udp %s: arrival-address capture unavailable, replies use the kernel's source choice: %v", conn.LocalAddr(), err)
		} else {
			oobSize = len(ipv6.NewControlMessage(ipv6.FlagDst))
		}
	case wildcard && IPv4SourcePinning:
		if err := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst, true); err != nil {
			logging.Debugf("udp %s: arrival-address capture unavailable, replies use the kernel's source choice: %v", conn.LocalAddr(), err)
		} else {
			oobSize = len(ipv4.NewControlMessage(ipv4.FlagDst))
		}
	}
	src4 := plainIPv4(cfg.SourceIPv4)
	if !wildcard {
		// A bound socket already sends from its address; pinning another one fails.
		src4 = nil
	}

	workers, queueSize := udpPoolSize(cfg)
	jobs := make(chan udpDatagram, queueSize)
	var dropped atomic.Int64

	for i := 0; i < workers; i++ {
		go func() {
			for job := range jobs {
				handler(job.data, job.remote, newUDPReplyConn(conn, job.dst, src4))
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
				dst = arrivalAddress(oob[:oobn])
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

// IPv4SourcePinning reports whether IPv4 sends can be pinned with IP_PKTINFO. Linux
// only: elsewhere the IPv6 socket's v4-mapped path is not known to honour it, and
// macOS accepts a source it cannot send from and loses the frame (see gossipSourcePin).
const IPv4SourcePinning = runtime.GOOS == "linux"

// WriteToUDPFrom sends b to addr from the local IPv6 src when conn is one of
// RunUDPServer's reply conns and both ends are native IPv6; an IPv4 send leaves from
// the listener's SourceIPv4. Any other conn is a plain conn.WriteToUDP. For sends to
// someone other than the datagram's sender (PR_NAT forwarding), where the arrival
// address is not the right source.
func WriteToUDPFrom(conn UDPReplyConn, b []byte, addr *net.UDPAddr, src net.IP) (int, error) {
	if rc, ok := conn.(*udpReplyConn); ok {
		return rc.writeFrom(b, addr, src)
	}
	return conn.WriteToUDP(b, addr)
}

// NewUDPSourceConn wraps a listener for sends this server initiates rather than
// replies to (the gossip loop), so their source can be pinned the same way a reply's
// is: IPv6 by the caller, IPv4 to srcIPv4 (the listener's SourceIPv4; nil keeps the
// kernel's choice). A nil listener yields a nil conn.
func NewUDPSourceConn(conn *net.UDPConn, srcIPv4 net.IP) UDPReplyConn {
	if conn == nil {
		return nil
	}
	return newUDPReplyConn(conn, nil, plainIPv4(srcIPv4))
}

// baseReplyConn strips the arrival-address pin from one of RunUDPServer's reply conns,
// for sends that answer no datagram of their own. Any other conn comes back as it is.
func baseReplyConn(conn UDPReplyConn) UDPReplyConn {
	if rc, ok := conn.(*udpReplyConn); ok {
		return newUDPReplyConn(rc.UDPConn, nil, rc.src4)
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
// datagram arrived on and the listener's IPv4 source for sends that answer nothing.
type udpReplyConn struct {
	*net.UDPConn
	// src is the arrival address: native IPv6, plain IPv4, or nil.
	src net.IP
	// src4 is the listener's SourceIPv4, or nil.
	src4 net.IP
}

func newUDPReplyConn(conn *net.UDPConn, dst, src4 net.IP) *udpReplyConn {
	src := nativeIPv6(dst)
	if src == nil {
		src = plainIPv4(dst)
	}
	return &udpReplyConn{UDPConn: conn, src: src, src4: src4}
}

func (c *udpReplyConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	return c.writeFrom(b, addr, c.src)
}

// writeFrom pins the source with a PKTINFO control message. IPv6 is pinned only
// between two native IPv6 addresses. IPv4 (plain, or v4-mapped on the dual-stack
// socket) is pinned on Linux only, through IP_PKTINFO: x/net's IPV6_PKTINFO drops a
// v4-mapped source, but Linux reads the IPv4 option on an IPv6 socket's v4-mapped
// sends. An IPv4 send leaves from src when src is IPv4 (the arrival address), else
// from the listener's SourceIPv4.
func (c *udpReplyConn) writeFrom(b []byte, addr *net.UDPAddr, src net.IP) (int, error) {
	if addr != nil && addr.IP.To4() != nil {
		return c.writeFromIPv4(b, addr, src)
	}
	src = nativeIPv6(src)
	if src == nil || addr == nil || nativeIPv6(addr.IP) == nil {
		return c.UDPConn.WriteToUDP(b, addr)
	}
	oob := (&ipv6.ControlMessage{Src: src}).Marshal()
	n, _, err := c.UDPConn.WriteMsgUDP(b, oob, addr)
	return n, err
}

// writeFromIPv4 is writeFrom's IPv4 half. A pinned send the kernel refuses (the
// address left the interface: EINVAL, ENETUNREACH, ...) goes out again unpinned
// rather than not at all; a refused datagram never reached the wire, so this cannot
// send it twice.
func (c *udpReplyConn) writeFromIPv4(b []byte, addr *net.UDPAddr, src net.IP) (int, error) {
	src4 := plainIPv4(src)
	if src4 == nil {
		src4 = c.src4
	}
	if src4 == nil || !IPv4SourcePinning {
		return c.UDPConn.WriteToUDP(b, addr)
	}
	oob := (&ipv4.ControlMessage{Src: src4}).Marshal()
	n, _, err := c.UDPConn.WriteMsgUDP(b, oob, addr)
	if err != nil {
		logging.Debugf("udp %s: send from %s to %s refused, using the kernel's source choice: %v", c.UDPConn.LocalAddr(), src4, addr, err)
		return c.UDPConn.WriteToUDP(b, addr)
	}
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

// plainIPv4 returns ip as a 4-byte IPv4 address (v4-mapped included), or nil when it
// is not IPv4 or is unspecified.
func plainIPv4(ip net.IP) net.IP {
	v4 := ip.To4()
	if v4 == nil || v4.IsUnspecified() {
		return nil
	}
	return v4
}

// arrivalAddress is the local address a datagram arrived on, from its control
// messages: IPV6_PKTINFO (both families on a dual-stack socket) or IP_PKTINFO.
func arrivalAddress(oob []byte) net.IP {
	var cm6 ipv6.ControlMessage
	if cm6.Parse(oob) == nil && cm6.Dst != nil {
		return cm6.Dst
	}
	var cm4 ipv4.ControlMessage
	if cm4.Parse(oob) == nil && cm4.Dst != nil {
		return cm4.Dst
	}
	return nil
}
