package ed3k

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"enode/ed3k/ed3kpb"
	"enode/ed3k/ident"
	"enode/ed3k/wire"
	"enode/internal/ratelimit"
)

// Relay timings and forward limits of Protocol.md §9.4 and §9.5.
const (
	punchWait          = 5 * time.Second // R waits this long for T's answer
	forwardsPerLeaf    = 30              // per minute
	forwardsPerInitHst = 3               // per minute and initiator host
	relayTTL           = 300             // seconds a slot is held without traffic: the idle timeout
	busyRetry          = 60
)

// relay holds the reservations of leaves (§9.4): one per leaf node ID, for as
// long as its connection lasts.
type relay struct {
	cfg   RelayLimits
	named bool

	mu     sync.Mutex
	leaves map[ident.NodeID]*session
	host   map[netip.Prefix]int
	site   map[netip.Prefix]int

	perLeaf *ratelimit.Limiter
	perPair *ratelimit.Limiter
}

func newRelay(cfg RelayLimits, named bool) *relay {
	return &relay{cfg: cfg, named: named, leaves: map[ident.NodeID]*session{},
		host: map[netip.Prefix]int{}, site: map[netip.Prefix]int{},
		perLeaf: ratelimit.New(forwardsPerLeaf), perPair: ratelimit.New(forwardsPerInitHst)}
}

func (r *relay) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.leaves)
}

// hasRoom decides RELAY in this node's Hello.
func (r *relay) hasRoom() bool { return r.count() < r.cfg.Leaves }

// reserve takes a slot for s; false when the relay or s's network is full.
func (r *relay) reserve(s *session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur := r.leaves[s.id]; cur == s {
		return true
	} else if cur != nil {
		r.dropLocked(cur) // the slot moves to the leaf's newer connection
	}
	host, site := ident.HostKey(s.remote.Addr(), r.named), ident.SiteKey(s.remote.Addr())
	exempt := r.named && ident.Private(s.remote.Addr())
	if len(r.leaves) >= r.cfg.Leaves || (!exempt && (r.host[host] >= r.cfg.PerHost || r.site[site] >= r.cfg.PerSite)) {
		return false
	}
	r.leaves[s.id] = s
	r.host[host]++
	r.site[site]++
	return true
}

// release gives s's slot back, if it holds one.
func (r *relay) release(s *session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.leaves[s.id] == s {
		r.dropLocked(s)
	}
}

func (r *relay) leaf(id ident.NodeID) *session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.leaves[id]
}

func (r *relay) dropLocked(s *session) {
	delete(r.leaves, s.id)
	host, site := ident.HostKey(s.remote.Addr(), r.named), ident.SiteKey(s.remote.Addr())
	if r.host[host]--; r.host[host] <= 0 {
		delete(r.host, host)
	}
	if r.site[site]--; r.site[site] <= 0 {
		delete(r.site, site)
	}
}

func (s *session) onRelay(st streamWriter, body []byte) {
	var req ed3kpb.Relay
	if proto.Unmarshal(body, &req) != nil {
		s.answerErrorW(st, ed3kpb.Error_MALFORMED, 0)
		return
	}
	if !req.Reserve {
		s.n.relay.release(s)
		wire.WriteFrame(st, wire.TypeRelay, &ed3kpb.Relay{Ttl: 0})
		return
	}
	if !s.n.relay.reserve(s) {
		s.answerErrorW(st, ed3kpb.Error_BUSY, 30*60)
		return
	}
	wire.WriteFrame(st, wire.TypeRelay, &ed3kpb.Relay{Ttl: relayTTL})
}

// onPunch forwards a Punch from an initiator I to a leaf T that holds a
// reservation here, and T's answer back (§9.5 steps 2 and 4).
func (s *session) onPunch(st streamWriter, body []byte) {
	var p ed3kpb.Punch
	if proto.Unmarshal(body, &p) != nil {
		s.answerErrorW(st, ed3kpb.Error_MALFORMED, 0)
		return
	}
	switch {
	case p.Seen > 2:
		s.answerErrorW(st, ed3kpb.Error_MALFORMED, 0)
		return
	case p.Seen != 0:
		// A forwarded Punch: this node holds no reservation at any relay.
		s.answerErrorW(st, ed3kpb.Error_DENIED, 0)
		return
	case len(p.PeerId) != 16 || !endpointLen(p.Ep4, 6) || !endpointLen(p.Ep6, 18):
		s.answerErrorW(st, ed3kpb.Error_MALFORMED, 0)
		return
	}
	t := s.n.relay.leaf(ident.NodeID(p.PeerId))
	if t == nil {
		s.answerErrorW(st, ed3kpb.Error_NOT_FOUND, 0)
		return
	}
	initHost := ident.HostKey(s.remote.Addr(), s.n.named).String()
	if !s.n.relay.perLeaf.Allow(t.id.String()) || !s.n.relay.perPair.Allow(initHost+"|"+t.id.String()) {
		s.answerErrorW(st, ed3kpb.Error_BUSY, busyRetry)
		return
	}
	s.n.punches.Add(1)
	seen := observe(s.remote, &p.Ep4, &p.Ep6)
	fwd := &ed3kpb.Punch{PeerId: s.id[:], Ep4: p.Ep4, Ep6: p.Ep6, Nat: p.Nat, Nonce: p.Nonce, Seen: seen}
	ans, eAns, err := t.ask(fwd)
	if err != nil {
		s.n.punchFailed.Add(1)
		s.answerErrorW(st, ed3kpb.Error_BUSY, busyRetry)
		return
	}
	if eAns != nil {
		wire.WriteFrame(st, wire.TypeError, eAns) // T's Error goes back unchanged
		return
	}
	seen = observe(t.remote, &ans.Ep4, &ans.Ep6)
	back := &ed3kpb.Punch{PeerId: t.id[:], Ep4: ans.Ep4, Ep6: ans.Ep6, Nat: ans.Nat, Nonce: ans.Nonce, Seen: seen}
	wire.WriteFrame(st, wire.TypePunch, back)
}

// ask sends a Punch to this leaf on a new exchange over its connection and reads
// its answer, waiting at most punchWait.
func (s *session) ask(p *ed3kpb.Punch) (*ed3kpb.Punch, *ed3kpb.Error, error) {
	ctx, cancel := context.WithTimeout(s.c.Context(), punchWait)
	defer cancel()
	st, err := s.c.OpenStreamSync(ctx)
	if err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(punchWait)
	st.SetDeadline(deadline)
	if err := wire.WriteFrame(st, wire.TypePunch, p); err != nil {
		st.CancelRead(0)
		return nil, nil, err
	}
	st.Close()
	f, err := wire.ReadFrame(wire.NewReader(st))
	if err != nil {
		st.CancelRead(0)
		return nil, nil, err
	}
	switch f.Type {
	case wire.TypeError:
		var e ed3kpb.Error
		if proto.Unmarshal(f.Body, &e) != nil {
			return nil, nil, fmt.Errorf("ed3k: malformed Error from leaf %s", s.id)
		}
		return nil, &e, nil
	case wire.TypePunch:
		var a ed3kpb.Punch
		if proto.Unmarshal(f.Body, &a) != nil || !endpointLen(a.Ep4, 6) || !endpointLen(a.Ep6, 18) {
			return nil, nil, fmt.Errorf("ed3k: malformed Punch from leaf %s", s.id)
		}
		return &a, nil, nil
	}
	return nil, nil, fmt.Errorf("ed3k: leaf %s answered type %d", s.id, f.Type)
}

// observe replaces the endpoint of the family of a connection with the address
// the relay sees, when the message holds one there, and returns the seen bit.
func observe(remote netip.AddrPort, ep4, ep6 *[]byte) uint32 {
	enc := ident.EncodeEndpoint(remote)
	if remote.Addr().Is4() {
		if len(*ep4) > 0 {
			*ep4 = enc
		}
		return 1
	}
	if len(*ep6) > 0 {
		*ep6 = enc
	}
	return 2
}

func endpointLen(b []byte, n int) bool { return len(b) == 0 || len(b) == n }

// streamWriter is the write side of an exchange.
type streamWriter interface {
	Write([]byte) (int, error)
}

func (s *session) answerErrorW(st streamWriter, code ed3kpb.Error_Code, retry uint32) {
	wire.WriteFrame(st, wire.TypeError, &ed3kpb.Error{Code: code, RetryAfter: retry})
}
