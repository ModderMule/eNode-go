package obfs

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// pair is a server Conn and a raw UDP socket that plays its client.
type pair struct {
	srv    *Conn
	cli    *net.UDPConn
	toSrv  Keys // dir 00, as a client seals
	fromSv Keys // dir 01, as a client opens
}

func newPair(t *testing.T) *pair {
	t.Helper()
	obf := sampleObf(t)
	sudp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	cudp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &pair{srv: NewServer(sudp, nil, obf), cli: cudp,
		toSrv: NewKeys(nil, obf, DirToAcceptor), fromSv: NewKeys(nil, obf, DirFromAcceptor)}
	t.Cleanup(func() { p.srv.Close(); cudp.Close() })
	return p
}

func (p *pair) send(t *testing.T, kind byte, body []byte) {
	t.Helper()
	d := p.toSrv.Seal(nil, kind, nil, nil, body)
	if _, err := p.cli.WriteTo(d, p.srv.LocalAddr()); err != nil {
		t.Fatal(err)
	}
}

// recv reads what the server sent to the client within wait: the kind and body
// of each datagram.
func (p *pair) recv(t *testing.T, wait time.Duration) (kinds []byte, sizes []int) {
	t.Helper()
	buf := make([]byte, 2048)
	for {
		p.cli.SetReadDeadline(time.Now().Add(wait))
		n, _, err := p.cli.ReadFrom(buf)
		if err != nil {
			return kinds, sizes
		}
		kind, _, err := p.fromSv.Open(buf[:n])
		if err != nil {
			t.Fatalf("server datagram does not open: %v", err)
		}
		kinds = append(kinds, kind)
		sizes = append(sizes, n)
	}
}

func (p *pair) cliAddr() net.Addr { return p.cli.LocalAddr() }

// Bug 1: two forged FRAGMENTs with empty pieces used to reassemble into an
// empty datagram and crash ReadFrom on out[0].
func TestEmptyFragmentsDropped(t *testing.T) {
	r := newReassembler()
	from := netip.MustParseAddrPort("81.2.3.4:4662")
	a := r.add(from, []byte{0x07, 0x02}, time.Now())
	b := r.add(from, []byte{0x07, 0x12}, time.Now())
	t.Logf("pieces {07 02} + {07 12} -> %v, %v; held=%d", a, b, len(r.msgs))
	if a != nil || b != nil || len(r.msgs) != 0 {
		t.Fatal("an all-empty fragment set was not dropped")
	}

	p := newPair(t)
	p.send(t, KindFragment, []byte{0x07, 0x02})
	p.send(t, KindFragment, []byte{0x07, 0x12})
	data := []byte{0x40, 1, 2, 3, 4}
	p.send(t, KindData, data)
	p.srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := p.srv.ReadFrom(buf)
	t.Logf("after the empty set, ReadFrom -> % x, %v (dropped=%d)", buf[:n], err, p.srv.Dropped.Load())
	if err != nil || n != len(data) {
		t.Fatalf("ReadFrom: n=%d err=%v", n, err)
	}
}

// Bug 2: until a connection validated the address, DATA counts against 3 times
// what arrived like any other datagram; Validate lifts the limit and sends what
// was held, Release brings it back.
func TestAmplificationUntilValidated(t *testing.T) {
	p := newPair(t)
	p.send(t, KindData, []byte{0x40, 1, 2, 3}) // 17 bytes on the wire: 51 of budget
	buf := make([]byte, 2048)
	p.srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := p.srv.ReadFrom(buf); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 600)
	big[0] = 0x40
	if _, err := p.srv.WriteTo(big, p.cliAddr()); err != nil {
		t.Fatal(err)
	}
	kinds, _ := p.recv(t, 200*time.Millisecond)
	t.Logf("unvalidated: a 600-byte DATA after 17 bytes in -> %d datagrams out, held=%d", len(kinds), p.srv.Held.Load())
	if len(kinds) != 0 || p.srv.Held.Load() != 1 {
		t.Fatal("DATA was not held for the amplification budget")
	}

	p.srv.Validate(p.cliAddr())
	kinds, sizes := p.recv(t, 500*time.Millisecond)
	t.Logf("after Validate: %d datagrams out, sizes %v", len(kinds), sizes)
	if len(kinds) != 1 || kinds[0] != KindData {
		t.Fatal("the held datagram was not sent on Validate")
	}

	p.srv.Release(p.cliAddr())
	p.srv.WriteTo(big, p.cliAddr())
	kinds, _ = p.recv(t, 200*time.Millisecond)
	t.Logf("after Release: %d datagrams out, held=%d", len(kinds), p.srv.Held.Load())
	if len(kinds) != 0 {
		t.Fatal("budget not applied again after Release")
	}
}

// Bug 13: the first 2 flights of a type go in fragments, counted per
// connection (destination connection ID) and never reset; a retransmission
// after a PTO is a flight of its own.
func TestFragmentAttemptsPerConnection(t *testing.T) {
	p := newPair(t)
	p.srv.Validate(p.cliAddr())
	initial := func(dcid byte) []byte {
		b := make([]byte, 300)
		b[0] = 0xc0 // long header, type Initial
		b[4] = 1    // version 1
		b[5] = 8
		for i := range 8 {
			b[6+i] = dcid
		}
		return b
	}
	flight := func(dcid byte) byte {
		p.srv.WriteTo(initial(dcid), p.cliAddr())
		kinds, _ := p.recv(t, 100*time.Millisecond)
		if len(kinds) == 0 {
			t.Fatal("nothing sent")
		}
		return kinds[0]
	}
	var got []byte
	for range 4 {
		got = append(got, flight(0xaa))
		time.Sleep(2 * flightGap)
	}
	t.Logf("connection A, flights 1-4: kinds %v (2 = FRAGMENT, 1 = HANDSHAKE)", got)
	if got[0] != KindFragment || got[1] != KindFragment || got[2] != KindHandshake || got[3] != KindHandshake {
		t.Fatalf("connection A: %v", got)
	}
	b := flight(0xbb)
	t.Logf("connection B from the same address, flight 1: kind %d", b)
	if b != KindFragment {
		t.Fatal("a new connection from the same address was not split")
	}
}
