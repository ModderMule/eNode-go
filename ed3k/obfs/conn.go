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
	// flightGap separates two flights of one type when counting attempts.
	flightGap = 300 * time.Millisecond
	// stateIdle drops the per-address state of a silent address.
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
				c.noteIn(from, n, false, now)
				continue
			}
			if out[0]&0x80 == 0 {
				c.Dropped.Add(1)
				continue
			}
		}
		validated := kind == KindData || hasHandshakePacket(out)
		c.noteIn(from, n, validated, now)
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
	if p[0]&0x80 == 0 {
		pad := []byte(nil)
		if len(p) <= 256 {
			pad = randomBytes(randInt(min(64, PathLimit-Overhead-len(p)+1)))
		}
		d := c.send.Seal(make([]byte, 0, Overhead+len(pad)+len(p)), KindData, nil, pad, p)
		_, err := c.udp.WriteToUDPAddrPort(d, to)
		return len(p), err
	}
	now := time.Now()
	c.mu.Lock()
	ps := c.peer(to, now)
	typ := (p[0] >> 4) & 3
	if now.Sub(ps.lastFlight[typ]) > flightGap {
		ps.attempts[typ]++
	}
	ps.lastFlight[typ] = now
	split := ps.attempts[typ] <= fragAttempts && len(p) >= 4
	var dgrams [][]byte
	if split {
		dgrams = c.fragments(ps, p, now)
	} else {
		dgrams = [][]byte{c.whole(p, PathLimit)}
	}
	if c.server && !ps.validated {
		if !ps.fits(dgrams) {
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

type peerState struct {
	in, out    uint64
	validated  bool
	lastSeen   time.Time
	attempts   [4]int
	lastFlight [4]time.Time
	msgIDs     map[byte]time.Time
	pending    [][]byte
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

// noteIn counts wire bytes from an address, marks it validated, and sends what
// the budget now allows.
func (c *Conn) noteIn(from netip.AddrPort, n int, validated bool, now time.Time) {
	c.mu.Lock()
	ps := c.peer(from, now)
	ps.in += uint64(n)
	if validated {
		ps.validated = true
	}
	var flush [][]byte
	for len(ps.pending) > 0 && (ps.validated || ps.fits(ps.pending[:1])) {
		d := ps.pending[0]
		ps.pending = ps.pending[1:]
		if !ps.validated {
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
		ps = &peerState{msgIDs: map[byte]time.Time{}}
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
				if now.Sub(ps.lastSeen) > stateIdle {
					delete(c.peers, a)
				}
			}
			c.mu.Unlock()
		}
	}
}

// hasHandshakePacket walks the coalesced long-header packets of a datagram and
// reports whether one is a Handshake packet, which validates the sender's
// address (RFC 9000 §8.1).
func hasHandshakePacket(d []byte) bool {
	for len(d) > 0 && d[0]&0x80 != 0 {
		typ := (d[0] >> 4) & 3
		if typ == 2 {
			return true
		}
		if typ == 3 || len(d) < 6 { // Retry ends the datagram
			return false
		}
		i := 5
		for range 2 { // DCID, SCID
			if i >= len(d) {
				return false
			}
			i += 1 + int(d[i])
		}
		if typ == 0 { // Initial: token
			l, n := quicVarint(d[i:])
			if n == 0 {
				return false
			}
			i += n + int(l)
		}
		if i >= len(d) {
			return false
		}
		l, n := quicVarint(d[i:])
		if n == 0 || i+n+int(l) > len(d) {
			return false
		}
		d = d[i+n+int(l):]
	}
	return false
}

func quicVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
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
