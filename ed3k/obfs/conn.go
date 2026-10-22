package obfs

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"enode/ed3k/ident"
)

// Tuning values of Protocol.md §4.4 and Appendix A.
const (
	// PathLimit is the UDP payload every path carries (IPv6 minimum MTU).
	PathLimit = 1232
	// QUICMaxDatagram is the QUIC datagram size this layer leaves room for.
	QUICMaxDatagram = PathLimit - Overhead - 19 // 1200: Initials fit with pad_len ≤ 19
	// fragAttempts is how many flights of one long-header type go in fragments.
	fragAttempts = 2
	// flightGap separates two flights of one type when counting attempts. The
	// datagrams of one flight leave in one burst; a retransmission after a PTO
	// comes later than this and is a flight of its own.
	flightGap = 20 * time.Millisecond
	// stateIdle drops the per-address state of a silent address that no
	// connection holds (Validate).
	stateIdle = 2 * time.Minute
	// maxPending bounds the datagrams held back for the amplification budget.
	maxPending = 16
	// readBuf is the largest datagram read.
	readBuf = 2048
)

// Conn is a net.PacketConn that QUIC reads and writes plain QUIC datagrams
// through, while the socket carries the obfuscated form.
//
// A server Conn (NewServer) is the node that accepts: every datagram in is
// keyed with its own obf_id and dir 00, every datagram out with dir 01. An index
// node that never dials needs nothing else (Protocol.md §11). A client Conn
// (NewClient) talks to one accepting node: the peer's obf_id, dir 00 out and
// 01 in. It serves tests and tools.
type Conn struct {
	udp    *net.UDPConn
	recv   Keys
	send   Keys
	server bool // apply the anti-amplification budget to what is sent

	mu    sync.Mutex
	peers map[netip.AddrPort]*peerState
	frags *reassembler

	readBuf []byte
	closed  atomic.Bool
	stop    chan struct{}

	// Counters for the admin view.
	Dropped atomic.Uint64 // datagrams that were not ed3k under our key
	Probes  atomic.Uint64 // PROBEs received (never answered)
	Held    atomic.Uint64 // datagrams held back for the amplification budget
}

// NewServer wraps udp for the node that accepts connections. netID is nil on
// the public network.
func NewServer(udp *net.UDPConn, netID []byte, own ident.ObfID) *Conn {
	return newConn(udp, NewKeys(netID, own, DirToAcceptor), NewKeys(netID, own, DirFromAcceptor), true)
}

// NewClient wraps udp for a node that dials one peer, whose obf_id is peer.
func NewClient(udp *net.UDPConn, netID []byte, peer ident.ObfID) *Conn {
	return newConn(udp, NewKeys(netID, peer, DirFromAcceptor), NewKeys(netID, peer, DirToAcceptor), false)
}

// ReadFrom returns the next QUIC datagram. Datagrams that are not ed3k under
// this Conn's key, PROBEs and incomplete fragment sets are consumed silently.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.udp.ReadFromUDPAddrPort(c.readBuf)
		if err != nil {
			return 0, nil, err
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		d := c.readBuf[:n]
		kind, body, err := c.recv.Open(d)
		if err != nil {
			c.Dropped.Add(1)
			continue
		}
		now := time.Now()
		var out []byte
		switch kind {
		case KindProbe:
			c.Probes.Add(1)
			continue
		case KindData:
			out = body
		case KindHandshake:
			out = body
		case KindFragment:
			c.mu.Lock()
			out = c.frags.add(from, body, now)
			c.mu.Unlock()
			if out == nil {
				c.noteIn(from, n, now)
				continue
			}
			if len(out) == 0 || out[0]&0x80 == 0 {
				c.Dropped.Add(1)
				continue
			}
		}
		c.noteIn(from, n, now)
		if len(out) > len(p) {
			continue
		}
		return copy(p, out), net.UDPAddrFromAddrPort(from), nil
	}
}

// WriteTo wraps one QUIC datagram and sends it, fragmented, padded or held back
// as §4.4 says.
func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	to, ok := addrPort(addr)
	if !ok || len(p) == 0 {
		return 0, net.InvalidAddrError("obfs: not a UDP address")
	}
	now := time.Now()
	long := p[0]&0x80 != 0
	var dgrams [][]byte
	c.mu.Lock()
	ps := c.peer(to, now)
	if !long {
		pad := []byte(nil)
		if len(p) <= 256 {
			pad = randomBytes(randInt(min(64, PathLimit-Overhead-len(p)+1)))
		}
		dgrams = [][]byte{c.send.Seal(make([]byte, 0, Overhead+len(pad)+len(p)), KindData, nil, pad, p)}
	} else {
		// Attempts are counted per connection, named by the destination
		// connection ID of the long header, and are never reset (§4.4).
		fc := ps.flight(longHeaderDCID(p), now)
		typ := (p[0] >> 4) & 3
		if now.Sub(fc.last[typ]) > flightGap {
			fc.attempts[typ]++
		}
		fc.last[typ] = now
		if fc.attempts[typ] <= fragAttempts && len(p) >= 4 {
			dgrams = c.fragments(ps, p, now)
		} else {
			dgrams = [][]byte{c.whole(p, PathLimit)}
		}
	}
	// Until a connection has validated the address, everything this layer puts
	// on the wire towards it, DATA included, stays within 3 times what arrived.
	if c.server && !ps.validated() {
		if long && !ps.fits(dgrams) {
			// Shrink to the cheapest form before holding anything back.
			dgrams = [][]byte{c.whole(p, Overhead+len(p))}
		}
		if !ps.fits(dgrams) || len(ps.pending) > 0 {
			if len(ps.pending) < maxPending {
				ps.pending = append(ps.pending, dgrams...)
				c.Held.Add(uint64(len(dgrams)))
			}
			c.mu.Unlock()
			return len(p), nil
		}
		for _, d := range dgrams {
			ps.out += uint64(len(d))
		}
	}
	c.mu.Unlock()
	for _, d := range dgrams {
		if _, err := c.udp.WriteToUDPAddrPort(d, to); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Close closes the socket.
func (c *Conn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.stop)
	}
	return c.udp.Close()
}

// LocalAddr is the socket's address.
func (c *Conn) LocalAddr() net.Addr { return c.udp.LocalAddr() }

// SetDeadline forwards to the socket.
func (c *Conn) SetDeadline(t time.Time) error { return c.udp.SetDeadline(t) }

// SetReadDeadline forwards to the socket.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.udp.SetReadDeadline(t) }

// SetWriteDeadline forwards to the socket.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

// SetReadBuffer forwards to the socket.
func (c *Conn) SetReadBuffer(n int) error { return c.udp.SetReadBuffer(n) }

// SetWriteBuffer forwards to the socket.
func (c *Conn) SetWriteBuffer(n int) error { return c.udp.SetWriteBuffer(n) }

// SendProbe sends a PROBE keyed to the node whose obf_id is target (dir 00).
// An index node never sends one; it is here for tests.
func SendProbe(udp *net.UDPConn, netID []byte, target ident.ObfID, to netip.AddrPort, nonce uint64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], nonce)
	d := NewKeys(netID, target, DirToAcceptor).Seal(nil, KindProbe, nil, nil, b[:])
	_, err := udp.WriteToUDPAddrPort(d, to)
	return err
}

// Validate marks addr as validated by a QUIC connection: its handshake
// completed there, or QUIC moved the connection to it after path validation.
// Datagrams held back for the amplification budget go out. Every Validate is
// paired with a Release when the connection leaves the address.
func (c *Conn) Validate(addr net.Addr) {
	a, ok := addrPort(addr)
	if !ok {
		return
	}
	c.mu.Lock()
	ps := c.peer(a, time.Now())
	ps.refs++
	flush := ps.pending
	ps.pending = nil
	c.mu.Unlock()
	for _, d := range flush {
		c.udp.WriteToUDPAddrPort(d, a)
	}
}

// Release undoes one Validate of addr. An address that no connection holds is
// subject to the amplification budget again.
func (c *Conn) Release(addr net.Addr) {
	a, ok := addrPort(addr)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ps := c.peers[a]; ps != nil && ps.refs > 0 {
		ps.refs--
		ps.lastSeen = time.Now()
	}
}

type peerState struct {
	in, out  uint64
	refs     int // connections that validated this address
	lastSeen time.Time
	flights  map[string]*flightCount // by destination connection ID
	msgIDs   map[byte]time.Time
	pending  [][]byte
}

// flightCount counts the flights of one connection by long-header packet type.
type flightCount struct {
	attempts [4]int
	last     [4]time.Time
	seen     time.Time
}

func (ps *peerState) validated() bool { return ps.refs > 0 }

func (ps *peerState) flight(dcid string, now time.Time) *flightCount {
	fc := ps.flights[dcid]
	if fc == nil {
		fc = &flightCount{}
		ps.flights[dcid] = fc
	}
	fc.seen = now
	return fc
}

func (ps *peerState) fits(dgrams [][]byte) bool {
	n := ps.out
	for _, d := range dgrams {
		n += uint64(len(d))
	}
	return n <= 3*ps.in
}

func newConn(udp *net.UDPConn, recv, send Keys, server bool) *Conn {
	c := &Conn{
		udp:     udp,
		recv:    recv,
		send:    send,
		server:  server,
		peers:   map[netip.AddrPort]*peerState{},
		frags:   newReassembler(),
		readBuf: make([]byte, readBuf),
		stop:    make(chan struct{}),
	}
	go c.sweep()
	return c
}

// noteIn counts wire bytes from an address and sends what the budget now
// allows.
func (c *Conn) noteIn(from netip.AddrPort, n int, now time.Time) {
	c.mu.Lock()
	ps := c.peer(from, now)
	ps.in += uint64(n)
	var flush [][]byte
	for len(ps.pending) > 0 && (ps.validated() || ps.fits(ps.pending[:1])) {
		d := ps.pending[0]
		ps.pending = ps.pending[1:]
		if !ps.validated() {
			ps.out += uint64(len(d))
		}
		flush = append(flush, d)
	}
	c.mu.Unlock()
	for _, d := range flush {
		c.udp.WriteToUDPAddrPort(d, from)
	}
}

func (c *Conn) peer(a netip.AddrPort, now time.Time) *peerState {
	ps := c.peers[a]
	if ps == nil {
		ps = &peerState{msgIDs: map[byte]time.Time{}, flights: map[string]*flightCount{}}
		c.peers[a] = ps
	}
	ps.lastSeen = now
	return ps
}

// whole is one HANDSHAKE datagram with random padding that keeps it within
// limit bytes on the wire.
func (c *Conn) whole(p []byte, limit int) []byte {
	room := min(63, limit-Overhead-len(p))
	pad := []byte(nil)
	if room > 0 {
		pad = randomBytes(randInt(room + 1))
	}
	return c.send.Seal(make([]byte, 0, Overhead+len(pad)+len(p)), KindHandshake, nil, pad, p)
}

// fragments splits a long-header datagram into 2 to 4 pieces of random sizes,
// each with random padding (§4.4).
func (c *Conn) fragments(ps *peerState, p []byte, now time.Time) [][]byte {
	total := 2 + randInt(3)
	if total > len(p) {
		total = len(p)
	}
	cuts := randomCuts(len(p), total)
	id := c.msgID(ps, now)
	out := make([][]byte, 0, total)
	prev := 0
	for i, cut := range cuts {
		piece := p[prev:cut]
		prev = cut
		body := make([]byte, 0, 2+len(piece))
		body = append(body, id, byte(i<<4|total))
		body = append(body, piece...)
		pad := randomBytes(randInt(min(63, PathLimit-Overhead-len(body)) + 1))
		out = append(out, c.send.Seal(nil, KindFragment, nil, pad, body))
	}
	return out
}

// msgID draws a msg_id not used towards this address within 3 s.
func (c *Conn) msgID(ps *peerState, now time.Time) byte {
	for id, at := range ps.msgIDs {
		if now.Sub(at) > fragTimeout {
			delete(ps.msgIDs, id)
		}
	}
	for {
		id := byte(randInt(256))
		if _, used := ps.msgIDs[id]; !used || len(ps.msgIDs) >= 256 {
			ps.msgIDs[id] = now
			return id
		}
	}
}

func (c *Conn) sweep() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case now := <-t.C:
			c.mu.Lock()
			c.frags.expire(now)
			for a, ps := range c.peers {
				if ps.refs == 0 && now.Sub(ps.lastSeen) > stateIdle {
					delete(c.peers, a)
					continue
				}
				for id, fc := range ps.flights {
					if now.Sub(fc.seen) > stateIdle {
						delete(ps.flights, id)
					}
				}
			}
			c.mu.Unlock()
		}
	}
}

// longHeaderDCID is the destination connection ID of a long-header packet, ""
// when the header is too short to hold one.
func longHeaderDCID(p []byte) string {
	if len(p) < 6 {
		return ""
	}
	l := int(p[5])
	if l > 20 || len(p) < 6+l {
		return ""
	}
	return string(p[6 : 6+l])
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		ap := v.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap, err == nil
}

// randomCuts returns total-1 random cut points and n, ascending, with no empty
// piece.
func randomCuts(n, total int) []int {
	cuts := make([]int, 0, total)
	for len(cuts) < total-1 {
		c := 1 + randInt(n-1)
		dup := false
		for _, x := range cuts {
			if x == c {
				dup = true
			}
		}
		if !dup {
			cuts = append(cuts, c)
		}
	}
	for i := 1; i < len(cuts); i++ {
		for j := i; j > 0 && cuts[j] < cuts[j-1]; j-- {
			cuts[j], cuts[j-1] = cuts[j-1], cuts[j]
		}
	}
	return append(cuts, n)
}

func randomBytes(n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// randInt is a uniform int in [0, n).
func randInt(n int) int {
	if n <= 1 {
		return 0
	}
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(v.Int64())
}
