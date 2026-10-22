package ed3k

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"enode/ed3k/ed3kpb"
	"enode/ed3k/ident"
	"enode/ed3k/obfs"
	"enode/ed3k/sig"
	"enode/ed3k/token"
	"enode/ed3k/transport"
	"enode/ed3k/wire"
	quic "enode/internal/ed3k/iquic"
	"enode/storage"
)

const testNet = "enode test"

func startNode(t *testing.T) *Node {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	n, err := New(Config{Key: priv, Listen: netip.MustParseAddrPort("127.0.0.1:0"), Network: testNet,
		Agent: "eNode-go test", Store: storage.NewMemoryEngine()})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

type testClient struct {
	t    *testing.T
	priv ed25519.PrivateKey
	id   ident.NodeID
	c    *quic.Conn
	pc   *obfs.Conn
}

func dial(t *testing.T, n *Node) *testClient {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return dialWith(t, n, priv, transport.IdleIndex)
}

// dialWith connects with a given key and max_idle_timeout.
func dialWith(t *testing.T, n *Node, priv ed25519.PrivateKey, idle time.Duration) *testClient {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	pc := obfs.NewClient(udp, obfs.NetID(testNet), n.ID().Obf())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := transport.Dial(ctx, pc, n.LocalAddr(), priv, n.ID(), transport.QUICConfig(idle))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tc := &testClient{t: t, priv: priv, id: ident.NodeIDOf(priv.Public().(ed25519.PublicKey)), c: c, pc: pc}
	t.Cleanup(func() { c.CloseWithError(0, ""); pc.Close() })
	return tc
}

// exchange opens a stream, sends one frame, half-closes and reads the answer.
func (tc *testClient) exchange(typ uint64, msg proto.Message) wire.Frame {
	tc.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := tc.c.OpenStreamSync(ctx)
	if err != nil {
		tc.t.Fatal(err)
	}
	if err := wire.WriteFrame(st, typ, msg); err != nil {
		tc.t.Fatal(err)
	}
	st.Close()
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	f, err := wire.ReadFrame(wire.NewReader(st))
	if err != nil {
		tc.t.Fatalf("answer to type %d: %v", typ, err)
	}
	return f
}

func (tc *testClient) hello(nat uint32) *ed3kpb.Hello {
	f := tc.exchange(wire.TypeHello, &ed3kpb.Hello{Caps: CapED2K, Agent: "test client", Nat: nat})
	var h ed3kpb.Hello
	if f.Type != wire.TypeHello || proto.Unmarshal(f.Body, &h) != nil {
		tc.t.Fatalf("hello answer type %d", f.Type)
	}
	return &h
}

func decode[T proto.Message](t *testing.T, f wire.Frame, typ uint64, m T) T {
	t.Helper()
	if f.Type != typ {
		var e ed3kpb.Error
		proto.Unmarshal(f.Body, &e)
		t.Fatalf("answer type %d (want %d), error %v", f.Type, typ, &e)
	}
	if err := proto.Unmarshal(f.Body, m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestNodeHelloAndErrors(t *testing.T) {
	n := startNode(t)
	c := dial(t, n)
	h := c.hello(1)
	obs, _, _ := ident.DecodeEndpoint(h.Observed)
	t.Logf("node hello: caps=%#x agent=%q observed=%v nat=%d", h.Caps, h.Agent, obs, h.Nat)
	if h.Caps&CapIndex == 0 || h.Caps&CapRouter != 0 || h.Caps&CapRelay == 0 || h.Nat != 1 {
		t.Fatalf("caps %#x", h.Caps)
	}
	if obs.Port() != uint16(c.pc.LocalAddr().(*net.UDPAddr).Port) {
		t.Fatalf("observed %v", obs)
	}
	e := decode(t, c.exchange(wire.TypeHello, &ed3kpb.Hello{}), wire.TypeError, &ed3kpb.Error{})
	t.Logf("second Hello -> %v", e.Code)
	if e.Code != ed3kpb.Error_MALFORMED {
		t.Fatal("second Hello not MALFORMED")
	}
	e = decode(t, c.exchange(5, &ed3kpb.Hello{}), wire.TypeError, &ed3kpb.Error{})
	t.Logf("FileRequest -> %v", e.Code)
	if e.Code != ed3kpb.Error_UNSUPPORTED {
		t.Fatal("file transfer not UNSUPPORTED")
	}
	r := decode(t, c.exchange(wire.TypeReachTest, &ed3kpb.ReachTest{Nonce: 7}), wire.TypeReachTest, &ed3kpb.ReachTest{})
	t.Logf("ReachTest -> ok=%v", r.Ok)
	if r.Ok {
		t.Fatal("ReachTest ok")
	}
}

func TestNodeKeywordRoundTrip(t *testing.T) {
	n := startNode(t)
	pub := dial(t, n)
	pub.hello(1)
	name := "The.Big_Sleep (1946) [1080p].mkv"
	root := make([]byte, 32)
	rand.Read(root)
	target := token.KeywordTarget(0, "sleep")
	body, _ := proto.Marshal(&ed3kpb.Record{Expires: uint64(time.Now().Add(time.Hour).Unix()),
		File: &ed3kpb.FileInfo{Root: root, Size: 123, Name: name}})
	store := &ed3kpb.KadRequest{Target: target[:], Kind: ed3kpb.Kind_KEYWORD, Want: 0,
		Store: &ed3kpb.Store{Files: []*ed3kpb.Signed{sig.Sign(pub.priv, ed3kpb.Kind_KEYWORD, target[:], body)}}}
	ans := decode(t, pub.exchange(wire.TypeKadRequest, store), wire.TypeKadAnswer, &ed3kpb.KadAnswer{})
	t.Logf("store: responsible=%v results=%v", ans.Responsible, ans.Results)
	if !ans.Responsible || len(ans.Results) != 0 {
		t.Fatal("not stored")
	}
	src := &ed3kpb.KadRequest{Target: root[:16], Kind: ed3kpb.Kind_SOURCE, Store: &ed3kpb.Store{Source: &ed3kpb.Peer{}}}
	ans = decode(t, pub.exchange(wire.TypeKadRequest, src), wire.TypeKadAnswer, &ed3kpb.KadAnswer{})
	if len(ans.Results) != 0 {
		t.Fatalf("source: %v", ans.Results)
	}

	other := dial(t, n)
	other.hello(0)
	search := &ed3kpb.KadRequest{Target: target[:], Kind: ed3kpb.Kind_KEYWORD, Search: &ed3kpb.Query{All: []string{"big"}}}
	ans = decode(t, other.exchange(wire.TypeKadRequest, search), wire.TypeKadAnswer, &ed3kpb.KadAnswer{})
	t.Logf("search: files=%d keys=%d load=%d", len(ans.Files), len(ans.Keys), ans.Load)
	if len(ans.Files) != 1 || sig.CheckSigned(ans.Files[0], ed3kpb.Kind_KEYWORD, target[:], ans.Keys[0]) != nil {
		t.Fatal("keyword search")
	}
	ans = decode(t, other.exchange(wire.TypeKadRequest, &ed3kpb.KadRequest{Target: root[:16], Kind: ed3kpb.Kind_SOURCE, Search: &ed3kpb.Query{}}),
		wire.TypeKadAnswer, &ed3kpb.KadAnswer{})
	t.Logf("sources: %d", len(ans.Sources))
	if len(ans.Sources) != 1 || ident.NodeID(ans.Sources[0].Id) != pub.id {
		t.Fatal("source search")
	}
	st, _ := n.StoreStats(context.Background())
	t.Logf("store: %+v, node: %+v", st, n.Stats())
}

func TestNodeRelayPunch(t *testing.T) {
	n := startNode(t)
	leaf := dial(t, n)
	leaf.hello(2)
	r := decode(t, leaf.exchange(wire.TypeRelay, &ed3kpb.Relay{Reserve: true}), wire.TypeRelay, &ed3kpb.Relay{})
	t.Logf("reservation: ttl=%d", r.Ttl)
	if r.Ttl == 0 {
		t.Fatal("no reservation")
	}
	// The leaf answers forwarded Punches with its own endpoints.
	leafEP := ident.EncodeEndpoint(netip.MustParseAddrPort("127.0.0.1:1111"))
	got := make(chan *ed3kpb.Punch, 1)
	go func() {
		st, err := leaf.c.AcceptStream(context.Background())
		if err != nil {
			return
		}
		f, err := wire.ReadFrame(wire.NewReader(st))
		if err != nil {
			return
		}
		var p ed3kpb.Punch
		proto.Unmarshal(f.Body, &p)
		got <- &p
		wire.WriteFrame(st, wire.TypePunch, &ed3kpb.Punch{PeerId: p.PeerId, Ep4: leafEP, Nat: 2})
		st.Close()
	}()

	init := dial(t, n)
	init.hello(2)
	initEP := ident.EncodeEndpoint(netip.MustParseAddrPort("127.0.0.1:9"))
	ans := decode(t, init.exchange(wire.TypePunch, &ed3kpb.Punch{PeerId: leaf.id[:], Ep4: initEP, Nat: 2, Nonce: 42}),
		wire.TypePunch, &ed3kpb.Punch{})
	fwd := <-got
	fwdEP, _, _ := ident.DecodeEndpoint(fwd.Ep4)
	ansEP, _, _ := ident.DecodeEndpoint(ans.Ep4)
	t.Logf("forwarded to leaf: peer=%x ep4=%v nonce=%d seen=%d", fwd.PeerId, fwdEP, fwd.Nonce, fwd.Seen)
	t.Logf("answer to initiator: peer=%x ep4=%v seen=%d", ans.PeerId, ansEP, ans.Seen)
	if ident.NodeID(fwd.PeerId) != init.id || fwd.Nonce != 42 || fwd.Seen != 1 ||
		fwdEP.Port() != uint16(init.pc.LocalAddr().(*net.UDPAddr).Port) {
		t.Fatal("forwarded Punch")
	}
	if ident.NodeID(ans.PeerId) != leaf.id || ans.Seen != 1 || ansEP.Port() != uint16(leaf.pc.LocalAddr().(*net.UDPAddr).Port) {
		t.Fatal("answer to the initiator")
	}
	e := decode(t, init.exchange(wire.TypePunch, &ed3kpb.Punch{PeerId: init.id[:], Nonce: 1}), wire.TypeError, &ed3kpb.Error{})
	t.Logf("Punch for a node without a reservation -> %v", e.Code)
	if e.Code != ed3kpb.Error_NOT_FOUND {
		t.Fatal("no reservation: not NOT_FOUND")
	}
	e = decode(t, init.exchange(wire.TypePunch, &ed3kpb.Punch{PeerId: leaf.id[:], Seen: 3}), wire.TypeError, &ed3kpb.Error{})
	if e.Code != ed3kpb.Error_MALFORMED {
		t.Fatal("seen 3 not MALFORMED")
	}
	r = decode(t, leaf.exchange(wire.TypeRelay, &ed3kpb.Relay{Reserve: false}), wire.TypeRelay, &ed3kpb.Relay{})
	if r.Ttl != 0 || n.Stats().RelayLeaves != 0 {
		t.Fatal("release")
	}
}

// closeCode waits for the connection to end and returns the application close
// code the node sent, or -1.
func (tc *testClient) closeCode(wait time.Duration) int64 {
	select {
	case <-tc.c.Context().Done():
	case <-time.After(wait):
		return -1
	}
	var ae *quic.ApplicationError
	if errors.As(context.Cause(tc.c.Context()), &ae) {
		return int64(ae.ErrorCode)
	}
	return -2
}

// alive reports whether a request on a new exchange is still answered.
func (tc *testClient) alive() bool {
	select {
	case <-tc.c.Context().Done():
		return false
	default:
	}
	f := tc.exchange(wire.TypeReachTest, &ed3kpb.ReachTest{Nonce: 1})
	return f.Type == wire.TypeReachTest
}

// Bug 3: an exchange that is half-closed without a byte, or reset by the peer,
// fails alone; only a header that ends inside it closes the connection (§5.1,
// §5.2).
func TestNodeExchangeFailures(t *testing.T) {
	n := startNode(t)
	c := dial(t, n)
	c.hello(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st, _ := c.c.OpenStreamSync(ctx)
	st.Close() // FIN with zero bytes
	time.Sleep(200 * time.Millisecond)
	ok := c.alive()
	t.Logf("exchange FIN'd with zero bytes -> connection alive: %v", ok)
	if !ok {
		t.Fatal("a zero-byte exchange closed the connection")
	}

	st, _ = c.c.OpenStreamSync(ctx)
	st.Write([]byte{0x06}) // the first header byte of a KadRequest
	st.CancelWrite(0)
	time.Sleep(200 * time.Millisecond)
	ok = c.alive()
	t.Logf("exchange reset inside the header -> connection alive: %v", ok)
	if !ok {
		t.Fatal("a reset exchange closed the connection")
	}

	st, _ = c.c.OpenStreamSync(ctx)
	st.Write([]byte{0x06, 0x85}) // len varint cut off
	st.Close()
	code := c.closeCode(5 * time.Second)
	t.Logf("exchange that ends inside the header -> close code %d", code)
	if code != int64(transport.CodeProtocol) {
		t.Fatalf("close code %d, want PROTOCOL", code)
	}
}

// Bug 14: a malformed Hello is answered MALFORMED, and the connection is
// closed with PROTOCOL once that is acknowledged, not after a fixed delay.
func TestNodeMalformedHello(t *testing.T) {
	n := startNode(t)
	c := dial(t, n)
	start := time.Now()
	f := c.exchange(wire.TypeHello, &ed3kpb.Hello{Agent: string(make([]byte, 65))})
	e := decode(t, f, wire.TypeError, &ed3kpb.Error{})
	code := c.closeCode(10 * time.Second)
	t.Logf("Hello with a 65-byte agent -> %v, then close code %d after %v", e.Code, code, time.Since(start))
	if e.Code != ed3kpb.Error_MALFORMED || code != int64(transport.CodeProtocol) {
		t.Fatal("malformed Hello")
	}
}

// Bug 4: the connection that starts a ban closes the node ID's open
// connections too (§4.6).
func TestNodeBanClosesOpenConnections(t *testing.T) {
	n := startNode(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var open []*testClient
	for range DefaultBudget.NewPerNodeIDMin {
		c := dialWith(t, n, priv, transport.IdleIndex)
		c.hello(1)
		open = append(open, c)
	}
	dialWith(t, n, priv, transport.IdleIndex) // the 11th in a minute: banned
	code := open[0].closeCode(5 * time.Second)
	t.Logf("after the ban, the first open connection closed with %d; node: %+v", code, n.Stats())
	if code != int64(transport.CodeDenied) {
		t.Fatalf("open connection of a banned node ID: close code %d", code)
	}
}

// Bug 6 (and question B): a leaf with two connections shares one slot; the
// slot survives the close of one, and Punches reach the other.
func TestNodeRelaySharedSlot(t *testing.T) {
	n := startNode(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	first := dialWith(t, n, priv, transport.IdleIndex)
	first.hello(2)
	second := dialWith(t, n, priv, transport.IdleIndex)
	second.hello(2)
	for _, c := range []*testClient{first, second} {
		r := decode(t, c.exchange(wire.TypeRelay, &ed3kpb.Relay{Reserve: true}), wire.TypeRelay, &ed3kpb.Relay{})
		if r.Ttl == 0 {
			t.Fatal("no reservation")
		}
	}
	t.Logf("two connections of one leaf reserved: %d slot(s)", n.Stats().RelayLeaves)
	if n.Stats().RelayLeaves != 1 {
		t.Fatal("one leaf took two slots")
	}
	second.c.CloseWithError(0, "")
	deadline := time.Now().Add(5 * time.Second)
	for n.Stats().Connections > 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("newest connection closed: %d connection(s), %d slot(s)", n.Stats().Connections, n.Stats().RelayLeaves)
	if n.Stats().RelayLeaves != 1 {
		t.Fatal("the slot ended with one of its two connections")
	}
	go func() {
		st, err := first.c.AcceptStream(context.Background())
		if err != nil {
			return
		}
		f, err := wire.ReadFrame(wire.NewReader(st))
		if err != nil {
			return
		}
		var p ed3kpb.Punch
		proto.Unmarshal(f.Body, &p)
		wire.WriteFrame(st, wire.TypePunch, &ed3kpb.Punch{PeerId: p.PeerId, Nat: 2})
		st.Close()
	}()
	init := dial(t, n)
	init.hello(2)
	f := init.exchange(wire.TypePunch, &ed3kpb.Punch{PeerId: first.id[:], Nonce: 9})
	t.Logf("Punch to the leaf -> frame type %d", f.Type)
	if f.Type != wire.TypePunch {
		t.Fatal("Punch did not reach the remaining connection")
	}
}

// Bug 15: ttl is at most the negotiated idle timeout (§9.4).
func TestNodeRelayTTL(t *testing.T) {
	n := startNode(t)
	for _, idle := range []time.Duration{transport.IdleDefault, transport.IdleIndex} {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		c := dialWith(t, n, priv, idle)
		c.hello(2)
		r := decode(t, c.exchange(wire.TypeRelay, &ed3kpb.Relay{Reserve: true}), wire.TypeRelay, &ed3kpb.Relay{})
		t.Logf("client max_idle_timeout %v -> ttl %d", idle, r.Ttl)
		if r.Ttl != uint32(idle/time.Second) {
			t.Errorf("idle %v: ttl %d", idle, r.Ttl)
		}
	}
}
