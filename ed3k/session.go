package ed3k

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
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
	remote netip.AddrPort
	connID string // names the connection to the store for kept sources

	helloOnce sync.Once
	hello     chan struct{} // closed once the peer's Hello is read
	peerMu    sync.Mutex
	peer      *ed3kpb.Hello

	storedSources atomic.Bool
}

func newSession(n *Node, c *quic.Conn, id ident.NodeID, key ed25519.PublicKey, remote netip.AddrPort) *session {
	tag := make([]byte, 6)
	rand.Read(tag)
	return &session{n: n, c: c, id: id, key: key, remote: remote, hello: make(chan struct{}),
		connID: n.id.String()[:8] + "-" + id.String() + "-" + hex.EncodeToString(tag)}
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
	switch {
	case errors.Is(err, wire.ErrHeader):
		s.c.CloseWithError(transport.CodeProtocol, "frame header")
		return
	case errors.Is(err, wire.ErrNeedDict):
		s.answerError(st, ed3kpb.Error_UNSUPPORTED)
		return
	case errors.Is(err, wire.ErrShort):
		if isTimeout(st) {
			st.CancelRead(0)
			st.CancelWrite(0)
			return
		}
		s.answerError(st, ed3kpb.Error_MALFORMED)
		return
	case err != nil:
		s.answerError(st, ed3kpb.Error_MALFORMED)
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
		s.answerError(st, ed3kpb.Error_MALFORMED)
		// The responder answers nothing more and closes once the Error is out.
		go func() {
			time.Sleep(time.Second)
			s.c.CloseWithError(transport.CodeProtocol, "malformed Hello")
		}()
		return
	}
	if h.Nat > 3 {
		h.Nat = 0
	}
	s.peerMu.Lock()
	s.peer = &h
	s.peerMu.Unlock()
	if err := wire.WriteFrame(st, wire.TypeHello, s.n.helloFor(s.remote)); err != nil {
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
	p := index.Peer{ID: s.id, Key: s.key, Remote: s.remote, Conn: s.connID,
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

// isTimeout reports whether the stream's read deadline has passed.
func isTimeout(st *quic.Stream) bool {
	_, err := st.Read(nil)
	var ne interface{ Timeout() bool }
	return errors.As(err, &ne) && ne.Timeout()
}
