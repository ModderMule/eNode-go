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
	maxRelayTTL        = 300             // seconds a slot is held without traffic: the idle timeout
	busyRetry          = 60
)

// relay holds the reservations of leaves (§9.4): one per leaf node ID, for as
// long as a connection that made it lasts. A leaf connected over both families
// (or reconnected before its old connection timed out) shares its one slot
// across those connections: the slot ends with the last of them.
type relay struct {
	cfg   RelayLimits
	named bool

	mu     sync.Mutex
	leaves map[ident.NodeID]*reservation
	host   map[netip.Prefix]int
	site   map[netip.Prefix]int

	perLeaf *ratelimit.Limiter
	perPair *ratelimit.Limiter
}

// reservation is one leaf's slot. host and site are the groups it was counted
// in when it was made; they do not follow a migration.
type reservation struct {
	holders    []*session // oldest first
	host, site netip.Prefix
}

func newRelay(cfg RelayLimits, named bool) *relay {
	return &relay{cfg: cfg, named: named, leaves: map[ident.NodeID]*reservation{},
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

// reserve takes a slot for s at address a; false when the relay or a's network
// is full. A node ID that already holds a slot adds s to it, with no limit to
// pass, and keeps it whatever s's network: one slot per leaf node ID.
func (r *relay) reserve(s *session, a netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if res := r.leaves[s.id]; res != nil {
		res.remove(s)
		res.holders = append(res.holders, s)
		return true
	}
	host, site := ident.HostKey(a, r.named), ident.SiteKey(a)
	exempt := r.named && ident.Private(a)
	if len(r.leaves) >= r.cfg.Leaves || (!exempt && (r.host[host] >= r.cfg.PerHost || r.site[site] >= r.cfg.PerSite)) {
		return false
	}
	r.leaves[s.id] = &reservation{holders: []*session{s}, host: host, site: site}
	r.host[host]++
	r.site[site]++
	return true
}

// release takes s off its leaf's slot, if it holds it; the slot ends with its
// last holder.
func (r *relay) release(s *session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res := r.leaves[s.id]
	if res == nil || !res.remove(s) || len(res.holders) > 0 {
		return
	}
	delete(r.leaves, s.id)
	if r.host[res.host]--; r.host[res.host] <= 0 {
		delete(r.host, res.host)
	}
	if r.site[res.site]--; r.site[res.site] <= 0 {
		delete(r.site, res.site)
	}
}

// leaf returns the connections that hold id's slot, newest first.
func (r *relay) leaf(id ident.NodeID) []*session {
	r.mu.Lock()
	defer r.mu.Unlock()
	res := r.leaves[id]
	if res == nil {
		return nil
	}
	out := make([]*session, len(res.holders))
	for i, s := range res.holders {
		out[len(out)-1-i] = s
	}
	return out
}

func (res *reservation) remove(s *session) bool {
	for i, h := range res.holders {
		if h == s {
			res.holders = append(res.holders[:i], res.holders[i+1:]...)
			return true
		}
	}
	return false
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
	if !s.n.relay.reserve(s, s.remoteAddr().Addr()) {
		s.answerErrorW(st, ed3kpb.Error_BUSY, 30*60)
		return
	}
	wire.WriteFrame(st, wire.TypeRelay, &ed3kpb.Relay{Ttl: s.relayTTL()})
}

// relayTTL is the ttl of a reservation: the time the slot is kept without
// traffic, which is the connection's idle timeout, at most 300 s (§9.4).
func (s *session) relayTTL() uint32 {
	ttl := uint32(maxRelayTTL)
	if idle := s.c.ConnectionState().IdleTimeout; idle > 0 {
		ttl = min(ttl, uint32(idle/time.Second))
	}
	return ttl
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
	leafID := ident.NodeID(p.PeerId)
	holders := s.n.relay.leaf(leafID)
	if len(holders) == 0 {
		s.answerErrorW(st, ed3kpb.Error_NOT_FOUND, 0)
		return
	}
	remote := s.remoteAddr()
	initHost := ident.HostKey(remote.Addr(), s.n.named).String()
	if !s.n.relay.perLeaf.Allow(leafID.String()) || !s.n.relay.perPair.Allow(initHost+"|"+leafID.String()) {
		s.answerErrorW(st, ed3kpb.Error_BUSY, busyRetry)
		return
	}
	s.n.punches.Add(1)
	seen := observe(remote, &p.Ep4, &p.Ep6)
	fwd := &ed3kpb.Punch{PeerId: s.id[:], Ep4: p.Ep4, Ep6: p.Ep6, Nat: p.Nat, Nonce: p.Nonce, Seen: seen}
	// The newest connection of the leaf first; an older one when it fails, all
	// within the 5 s that R waits for T (§9.5).
	deadline := time.Now().Add(punchWait)
	var (
		t    *session
		ans  *ed3kpb.Punch
		eAns *ed3kpb.Error
		err  error
	)
	for _, t = range holders {
		if ans, eAns, err = t.ask(fwd, deadline); err == nil || !time.Now().Before(deadline) {
			break
		}
	}
	if err != nil {
		s.n.punchFailed.Add(1)
		s.answerErrorW(st, ed3kpb.Error_BUSY, busyRetry)
		return
	}
	if eAns != nil {
		wire.WriteFrame(st, wire.TypeError, eAns) // T's Error goes back unchanged
		return
	}
	seen = observe(t.remoteAddr(), &ans.Ep4, &ans.Ep6)
	back := &ed3kpb.Punch{PeerId: t.id[:], Ep4: ans.Ep4, Ep6: ans.Ep6, Nat: ans.Nat, Nonce: ans.Nonce, Seen: seen}
	wire.WriteFrame(st, wire.TypePunch, back)
}

// ask sends a Punch to this leaf on a new exchange over its connection and reads
// its answer, waiting until deadline at most.
func (s *session) ask(p *ed3kpb.Punch, deadline time.Time) (*ed3kpb.Punch, *ed3kpb.Error, error) {
	ctx, cancel := context.WithDeadline(s.c.Context(), deadline)
	defer cancel()
	st, err := s.c.OpenStreamSync(ctx)
	if err != nil {
		return nil, nil, err
	}
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
