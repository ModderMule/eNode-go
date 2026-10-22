package ed3k

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"enode/ed3k/ed3kpb"
	"enode/ed3k/ident"
	"enode/ed3k/index"
	"enode/ed3k/transport"
	"enode/ed3k/wire"
	quic "enode/internal/ed3k/iquic"
	"enode/logging"
)

// session is one accepted connection.
type session struct {
	n      *Node
	c      *quic.Conn
	id     ident.NodeID
	key    ed25519.PublicKey
	start  time.Time // the handshake completed
	connID string    // names the connection to the store for kept sources

	// addr is the client address this connection holds validated at the
	// obfuscation layer (obfs.Conn.Validate); it follows migration (§4.4).
	addrMu sync.Mutex
	addr   net.Addr
	ended  bool

	helloOnce sync.Once
	hello     chan struct{} // closed once the peer's Hello is read
	peerMu    sync.Mutex
	peer      *ed3kpb.Hello

	storedSources atomic.Bool
}

func newSession(n *Node, c *quic.Conn, id ident.NodeID, key ed25519.PublicKey) *session {
	tag := make([]byte, 6)
	rand.Read(tag)
	return &session{n: n, c: c, id: id, key: key, start: time.Now(), hello: make(chan struct{}),
		connID: n.connPrefix() + id.String() + "-" + hex.EncodeToString(tag)}
}

// remoteAddr is the client's current address. QUIC moves it when the client
// migrates (§4.1), so it is read at each use, never kept.
func (s *session) remoteAddr() netip.AddrPort {
	a := s.c.RemoteAddr()
	s.track(a)
	ap, _ := addrPort(a)
	return ap
}

// track makes a the address this connection holds validated at the
// obfuscation layer, giving the previous one back.
func (s *session) track(a net.Addr) {
	s.addrMu.Lock()
	defer s.addrMu.Unlock()
	if s.ended || a == nil || (s.addr != nil && s.addr.String() == a.String()) {
		return
	}
	s.n.pc.Validate(a)
	if s.addr != nil {
		s.n.pc.Release(s.addr)
	}
	s.addr = a
}

// untrack gives the validated address back when the connection ends.
func (s *session) untrack() {
	s.addrMu.Lock()
	defer s.addrMu.Unlock()
	if s.addr != nil {
		s.n.pc.Release(s.addr)
		s.addr = nil
	}
	s.ended = true
}

// serve accepts the peer's exchanges until the connection ends, then gives back
// its relay slot and the keeping of its sources.
func (s *session) serve() {
	ctx := s.c.Context()
	go func() {
		t := time.NewTimer(helloTimeout)
		defer t.Stop()
		select {
		case <-s.hello:
		case <-ctx.Done():
		case <-t.C:
			s.n.refused.Add(1)
			s.c.CloseWithError(transport.CodeProtocol, "no Hello")
		}
	}()
	for {
		st, err := s.c.AcceptStream(ctx)
		if err != nil {
			break
		}
		go s.exchange(st)
	}
	s.untrack()
	s.n.relay.release(s)
	if s.storedSources.Load() {
		rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := s.n.idx.Release(rctx, s.connID); err != nil {
			logging.Warnf("ed3k: releasing sources of %s: %v", s.id, err)
		}
		cancel()
	}
}

// peerHello returns the peer's Hello, or nil before it arrived.
func (s *session) peerHello() *ed3kpb.Hello {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	return s.peer
}

// exchange reads one request and answers it (§5.2).
func (s *session) exchange(st *quic.Stream) {
	defer st.Close()
	s.n.exchanges.Add(1)
	st.SetReadDeadline(time.Now().Add(requestTimeout))
	f, err := wire.ReadFrame(wire.NewReader(st))
	if err != nil {
		s.readFailed(st, err)
		return
	}
	st.SetReadDeadline(time.Time{})

	if st.StreamID() == 0 {
		s.onHello(st, f)
		return
	}
	select {
	case <-s.hello:
	case <-s.c.Context().Done():
		return
	}
	switch f.Type {
	case wire.TypeHello:
		s.answerError(st, ed3kpb.Error_MALFORMED)
	case wire.TypeError:
		// An Error is never answered.
	case wire.TypeKadRequest:
		s.onKad(st, f.Body)
	case wire.TypeRelay:
		s.onRelay(st, f.Body)
	case wire.TypePunch:
		s.onPunch(st, f.Body)
	case wire.TypeReachTest:
		s.onReachTest(st, f.Body)
	default:
		s.answerError(st, ed3kpb.Error_UNSUPPORTED)
	}
}

// onHello reads the peer's Hello on stream 0 and answers with this node's.
func (s *session) onHello(st *quic.Stream, f wire.Frame) {
	var h ed3kpb.Hello
	if f.Type != wire.TypeHello || proto.Unmarshal(f.Body, &h) != nil || len(h.Agent) > 64 || len(h.Nick) > 64 {
		s.malformedHello(st)
		return
	}
	if h.Nat > 3 {
		h.Nat = 0
	}
	s.peerMu.Lock()
	s.peer = &h
	s.peerMu.Unlock()
	if err := wire.WriteFrame(st, wire.TypeHello, s.n.helloFor(s.remoteAddr())); err != nil {
		return
	}
	s.helloOnce.Do(func() { close(s.hello) })
}

func (s *session) onKad(st *quic.Stream, body []byte) {
	var req ed3kpb.KadRequest
	if proto.Unmarshal(body, &req) != nil {
		s.answerError(st, ed3kpb.Error_MALFORMED)
		return
	}
	h := s.peerHello()
	p := index.Peer{ID: s.id, Key: s.key, Remote: s.remoteAddr(), Conn: s.connID,
		ED2K: h.GetCaps()&CapED2K != 0, Open: h.GetNat() == 1}
	ctx, cancel := context.WithTimeout(s.c.Context(), 20*time.Second)
	defer cancel()
	ans, e, err := s.n.idx.Handle(ctx, &req, p)
	if err != nil {
		logging.Warnf("ed3k: request of %s: %v", s.id, err)
		s.answerErrorRetry(st, ed3kpb.Error_BUSY, 60)
		return
	}
	if e != nil {
		wire.WriteFrame(st, wire.TypeError, e)
		return
	}
	if req.Kind == ed3kpb.Kind_SOURCE && req.Store != nil {
		s.storedSources.Store(true)
	}
	wire.WriteFrame(st, wire.TypeKadAnswer, ans)
}

// onReachTest answers as A of a ReachTest: an index node without ROUTER has no
// table to pick a prober from, so ok = false (§11).
func (s *session) onReachTest(st *quic.Stream, body []byte) {
	var r ed3kpb.ReachTest
	if proto.Unmarshal(body, &r) != nil {
		s.answerError(st, ed3kpb.Error_MALFORMED)
		return
	}
	wire.WriteFrame(st, wire.TypeReachTest, &ed3kpb.ReachTest{Ok: false})
}

func (s *session) answerError(st *quic.Stream, code ed3kpb.Error_Code) {
	wire.WriteFrame(st, wire.TypeError, &ed3kpb.Error{Code: code})
}

func (s *session) answerErrorRetry(st *quic.Stream, code ed3kpb.Error_Code, retry uint32) {
	wire.WriteFrame(st, wire.TypeError, &ed3kpb.Error{Code: code, RetryAfter: retry})
}

// readFailed handles a request that could not be read (§4.1, §5.1, §5.2).
func (s *session) readFailed(st *quic.Stream, err error) {
	var reset *quic.StreamError
	switch {
	case errors.As(err, &reset):
		// The peer reset the exchange: it failed, and nothing is answered.
		st.CancelWrite(0)
		return
	case isTimeoutErr(err):
		// Not whole within 30 s: the exchange is reset, the connection stays.
		st.CancelRead(0)
		st.CancelWrite(0)
		return
	case errors.Is(err, wire.ErrEmpty):
		// Half-closed without a byte: a failed exchange, closed quietly.
		return
	case errors.Is(err, wire.ErrHeader):
		s.c.CloseWithError(transport.CodeProtocol, "frame header")
		return
	}
	if st.StreamID() == 0 {
		// Whatever stream 0 holds that is not a Hello is a malformed one.
		s.malformedHello(st)
		return
	}
	if errors.Is(err, wire.ErrNeedDict) {
		s.answerError(st, ed3kpb.Error_UNSUPPORTED)
		return
	}
	s.answerError(st, ed3kpb.Error_MALFORMED)
}

// malformedHello answers a malformed Hello on stream 0 with Error{MALFORMED}.
// The responder answers nothing more on the connection (its Hello never
// arrives) and closes it with PROTOCOL once the Error is acknowledged, at the
// latest when the 30 s for the Hello end (§5.5).
func (s *session) malformedHello(st *quic.Stream) {
	s.answerError(st, ed3kpb.Error_MALFORMED)
	st.Close()
	go func() {
		t := time.NewTimer(time.Until(s.start.Add(helloTimeout)))
		defer t.Stop()
		select {
		case <-st.Acked():
		case <-t.C:
		case <-s.c.Context().Done():
			return
		}
		s.c.CloseWithError(transport.CodeProtocol, "malformed Hello")
	}()
}

func isTimeoutErr(err error) bool {
	var ne interface{ Timeout() bool }
	return errors.As(err, &ne) && ne.Timeout()
}
