// Package index answers KadRequests as an ed3k index node without ROUTER
// (Protocol.md §10.3, §10.7, §10.8, §11): it is responsible for every target,
// stores SOURCE, KEYWORD and NOTE records, and answers every other kind as a node
// that is not responsible, so clients fall back to Kad for those. It holds no
// routing table and returns no contacts.
//
// The checks that need no stored state are here: layout, the binding of a
// source record to its connection, signatures, the tokenizer, lifetimes and
// sizes. Limits that need a view of a target are the store's
// (storage.Ed3kStore), so every engine applies them alike.
package index

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"enode/ed3k/ed3kpb"
	"enode/ed3k/ident"
	"enode/ed3k/sig"
	"enode/ed3k/token"
	"enode/internal/ratelimit"
	"enode/storage"
)

// Tuning values of Protocol.md Appendix A.
const (
	MaxPerAnswer   = 100 // files, notes or sources in one answer
	MaxStoreRecs   = 256 // records in one Store; later ones are REJECTED
	MaxAlso        = 256 // targets of `also`
	MaxQueryTerms  = 64  // all and none together
	MaxRelays      = 2   // relays per family in a source record
	MaxLevel       = 15  // KEYWORD levels a storing node accepts
	SourceLifetime = 5 * time.Hour
	SignedLifetime = 24 * time.Hour // KEYWORD and NOTE
	LifetimeSlack  = time.Hour      // how far beyond the lifetime `expires` may be
	MaxNoteText    = 512
	MaxNameBytes   = 255
	// DefaultRequestsPerMinute is the request rate per (host group, kind,
	// search/store) before a store is BUSY and a search Error{BUSY}.
	DefaultRequestsPerMinute = 120
	// keepRenew is how far ahead a kept source's expiry is pushed.
	keepRenew = 2 * time.Hour
)

// Config is what an Index needs.
type Config struct {
	Store  storage.Ed3kStore
	Limits storage.Ed3kLimits
	// Named is set in a named network, where private addresses are acceptable.
	Named bool
	// RequestsPerMinute bounds requests per host group, kind and operation.
	RequestsPerMinute int
	// Reject, when set, is asked about every file name; true refuses the record
	// (content filters).
	Reject func(name string) bool
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// Peer is what the index knows of the connection a request arrived on.
type Peer struct {
	ID     ident.NodeID
	Key    ed25519.PublicKey
	Remote netip.AddrPort // the observed endpoint
	// ED2K and Open are from the peer's Hello: the ED2K capability, and nat = open.
	ED2K bool
	Open bool
	// Conn names the connection for keeping its source records (§11); empty
	// when they are not kept.
	Conn string
}

// Index is the request handler. It is safe for concurrent use.
type Index struct {
	cfg   Config
	rate  *ratelimit.Limiter
	stats counters
}

// Stats counts requests by outcome.
type Stats struct {
	Searches, Stores, Busy, Malformed int64
}

type counters struct {
	searches, stores, busy, malformed atomic.Int64
}

// New returns an Index.
func New(cfg Config) *Index {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RequestsPerMinute <= 0 {
		cfg.RequestsPerMinute = DefaultRequestsPerMinute
	}
	cfg.Limits = cfg.Limits.WithDefaults()
	return &Index{cfg: cfg, rate: ratelimit.NewWithClock(cfg.RequestsPerMinute, cfg.Now)}
}

// Stores reports whether the index stores records of kind.
func Stores(kind ed3kpb.Kind) bool {
	switch kind {
	case ed3kpb.Kind_SOURCE, ed3kpb.Kind_KEYWORD, ed3kpb.Kind_NOTE:
		return true
	}
	return false
}

// Handle answers one KadRequest. It returns either an answer or an Error to send
// instead; err is an internal failure (the store), answered Error{BUSY}.
func (x *Index) Handle(ctx context.Context, req *ed3kpb.KadRequest, p Peer) (*ed3kpb.KadAnswer, *ed3kpb.Error, error) {
	// 1. Layout.
	if e := x.layout(req); e != nil {
		return nil, e, nil
	}
	// 2. search and store.
	if req.Search == nil && req.Store == nil {
		return &ed3kpb.KadAnswer{Responsible: Stores(req.Kind)}, nil, nil
	}
	// 3. Kind and responsibility.
	if !Stores(req.Kind) || (req.Kind == ed3kpb.Kind_KEYWORD && req.Search != nil && req.Level > MaxLevel) {
		return &ed3kpb.KadAnswer{}, nil, nil
	}
	var target [16]byte
	copy(target[:], req.Target)
	op := "search"
	if req.Store != nil {
		op = "store"
	}
	allowed := x.rate.Allow(fmt.Sprintf("%s|%d|%s", ident.HostKey(p.Remote.Addr(), x.cfg.Named), req.Kind, op))
	if req.Search != nil {
		if !allowed {
			x.stats.busy.Add(1)
			return nil, &ed3kpb.Error{Code: ed3kpb.Error_BUSY, RetryAfter: 60}, nil
		}
		x.stats.searches.Add(1)
		return x.search(ctx, req, target)
	}
	if !hasRecordOf(req.Kind, req.Store) {
		x.stats.malformed.Add(1)
		return nil, &ed3kpb.Error{Code: ed3kpb.Error_MALFORMED}, nil
	}
	x.stats.stores.Add(1)
	// 4. Each record.
	return x.store(ctx, req, target, p, allowed)
}

// Stats returns the counters.
func (x *Index) Stats() Stats {
	return Stats{Searches: x.stats.searches.Load(), Stores: x.stats.stores.Load(),
		Busy: x.stats.busy.Load(), Malformed: x.stats.malformed.Load()}
}

// Keep pushes the expiry of the sources a live connection keeps (§11). The node
// calls it about once an hour per connection that stored sources.
func (x *Index) Keep(ctx context.Context, conn string) error {
	return x.cfg.Store.KeepEd3kSources(ctx, conn, x.cfg.Now().Add(keepRenew))
}

// Release ends the keeping when the connection closed.
func (x *Index) Release(ctx context.Context, conn string) error {
	return x.cfg.Store.ReleaseEd3kSources(ctx, conn)
}

// layout applies the size and layout rules of §0 and §10.3.
func (x *Index) layout(req *ed3kpb.KadRequest) *ed3kpb.Error {
	malformed := &ed3kpb.Error{Code: ed3kpb.Error_MALFORMED}
	if len(req.Target) != 16 {
		return malformed
	}
	if req.Search != nil && req.Store != nil {
		return malformed
	}
	if q := req.Search; q != nil && len(q.All)+len(q.None) > MaxQueryTerms {
		return malformed
	}
	if s := req.Store; s != nil {
		if req.Kind == ed3kpb.Kind_SOURCE && len(s.Also)%16 != 0 {
			return malformed
		}
		signedKind := req.Kind != ed3kpb.Kind_SOURCE && req.Kind != ed3kpb.Kind_LIVE &&
			req.Kind != ed3kpb.Kind_SUB && req.Kind != ed3kpb.Kind_FRIEND
		if signedKind && len(s.Signer) != 0 && len(s.Signer) != ed25519.PublicKeySize {
			return malformed
		}
	}
	return nil
}

func (x *Index) search(ctx context.Context, req *ed3kpb.KadRequest, target [16]byte) (*ed3kpb.KadAnswer, *ed3kpb.Error, error) {
	now := x.cfg.Now()
	ans := &ed3kpb.KadAnswer{Responsible: true}
	offset := int(req.Search.Offset)
	switch req.Kind {
	case ed3kpb.Kind_SOURCE:
		srcs, more, err := x.cfg.Store.SearchEd3kSources(ctx, target, offset, MaxPerAnswer, now)
		if err != nil {
			return nil, nil, err
		}
		for _, s := range srcs {
			var peer ed3kpb.Peer
			if proto.Unmarshal(s.Peer, &peer) == nil {
				ans.Sources = append(ans.Sources, &peer)
			}
		}
		ans.More = more
	case ed3kpb.Kind_KEYWORD:
		q := req.Search
		page, err := x.cfg.Store.SearchEd3kKeywords(ctx, target, storage.Ed3kQuery{
			All: q.All, None: q.None, MinSize: q.MinSize, MaxSize: q.MaxSize, MinSources: q.MinSources, Ext: q.Ext,
		}, offset, MaxPerAnswer, now)
		if err != nil {
			return nil, nil, err
		}
		keys := keyTable{}
		for _, r := range page.Records {
			if s := keys.signed(r.Signed, r.PubKey); s != nil {
				ans.Files = append(ans.Files, s)
			}
		}
		ans.Keys = keys.list
		ans.More = page.More
		ans.Load = uint32(min(100, page.Files*100/x.cfg.Limits.KeywordFiles))
		ans.Spill = page.Spill
	case ed3kpb.Kind_NOTE:
		notes, more, err := x.cfg.Store.SearchEd3kNotes(ctx, target, offset, MaxPerAnswer, now)
		if err != nil {
			return nil, nil, err
		}
		keys := keyTable{}
		for _, n := range notes {
			if s := keys.signed(n.Signed, n.PubKey); s != nil {
				ans.Notes = append(ans.Notes, s)
			}
		}
		ans.Keys = keys.list
		ans.More = more
	}
	return ans, nil, nil
}

func (x *Index) store(ctx context.Context, req *ed3kpb.KadRequest, target [16]byte, p Peer, allowed bool) (*ed3kpb.KadAnswer, *ed3kpb.Error, error) {
	now := x.cfg.Now()
	s := req.Store
	ans := &ed3kpb.KadAnswer{Responsible: true}
	var results []ed3kpb.StoreResult
	n := 0
	put := func(r ed3kpb.StoreResult) {
		n++
		if n > MaxStoreRecs {
			r = ed3kpb.StoreResult_REJECTED
		} else if !allowed {
			r = ed3kpb.StoreResult_BUSY
		}
		results = append(results, r)
	}
	reject := ed3kpb.StoreResult_REJECTED
	key := []byte(p.Key)
	viaSigner := false
	if len(s.Signer) == ed25519.PublicKeySize && req.Kind != ed3kpb.Kind_SOURCE {
		key, viaSigner = s.Signer, true
	}
	host := ident.HostKey(p.Remote.Addr(), x.cfg.Named).String()
	site := ident.SiteKey(p.Remote.Addr()).String()

	// The record fields in the order of their field numbers (§10.3).
	var sourceRec *storage.Ed3kSource
	if s.Source != nil {
		if req.Kind != ed3kpb.Kind_SOURCE {
			put(reject)
		} else if rec, ok := x.bindSource(s.Source, p, host, site, now); !ok {
			put(reject)
		} else {
			sourceRec = &rec
			put(x.storeSource(ctx, rec, target, allowed && n < MaxStoreRecs, now))
		}
	}
	for _, f := range s.Files {
		if req.Kind != ed3kpb.Kind_KEYWORD || n >= MaxStoreRecs || !allowed {
			put(reject)
			continue
		}
		put(x.storeKeyword(ctx, f, target, uint8(req.Level), key, viaSigner, host, site, now))
	}
	if s.Note != nil {
		if req.Kind != ed3kpb.Kind_NOTE || n >= MaxStoreRecs || !allowed {
			put(reject)
		} else {
			put(x.storeNote(ctx, s.Note, target, key, host, site, now))
		}
	}
	// Records of kinds this node does not store, in a request of a kind it does.
	for range otherRecords(s) {
		put(reject)
	}
	// `also`: further targets of the same source record.
	if req.Kind == ed3kpb.Kind_SOURCE {
		for i := 0; i+16 <= len(s.Also); i += 16 {
			switch {
			case i/16 >= MaxAlso || sourceRec == nil:
				results = append(results, reject)
			case !allowed:
				results = append(results, ed3kpb.StoreResult_BUSY)
			default:
				var t [16]byte
				copy(t[:], s.Also[i:i+16])
				results = append(results, x.storeSource(ctx, *sourceRec, t, true, now))
			}
		}
	}
	// A list of STOREDs is left out (absent = all stored).
	for _, r := range results {
		if r != ed3kpb.StoreResult_STORED {
			ans.Results = results
			break
		}
	}
	return ans, nil, nil
}

func (x *Index) storeSource(ctx context.Context, rec storage.Ed3kSource, target [16]byte, ok bool, now time.Time) ed3kpb.StoreResult {
	if !ok {
		return ed3kpb.StoreResult_BUSY
	}
	rec.Target = target
	res, err := x.cfg.Store.StoreEd3kSource(ctx, rec, x.cfg.Limits, now)
	if err != nil {
		return ed3kpb.StoreResult_BUSY
	}
	return ed3kpb.StoreResult(res)
}

// bindSource binds a source record to its connection (§10.3): the node ID from
// the key, the observed endpoint in the connection's family, the other family
// and the relays as claimed, all at acceptable addresses.
func (x *Index) bindSource(src *ed3kpb.Peer, p Peer, host, site string, now time.Time) (storage.Ed3kSource, bool) {
	var rec storage.Ed3kSource
	if len(src.Id) != 0 || !ident.AcceptableEndpoint(p.Remote, x.cfg.Named) {
		return rec, false
	}
	v4 := p.Remote.Addr().Is4()
	claimed := src.Ep6
	if !v4 {
		claimed = src.Ep4
	}
	if len(claimed) > 0 {
		ep, ok, err := ident.DecodeEndpoint(claimed)
		if err != nil || !ok || ep.Addr().Is4() == !v4 || !ident.AcceptableEndpoint(ep, x.cfg.Named) {
			return rec, false
		}
	}
	if !x.relaysOK(src.Relays4, 22) || !x.relaysOK(src.Relays6, 34) {
		return rec, false
	}
	observed := ident.EncodeEndpoint(p.Remote)
	out := &ed3kpb.Peer{Id: p.ID[:], Relays4: src.Relays4, Relays6: src.Relays6}
	if v4 {
		out.Ep4, out.Ep6 = observed, src.Ep6
	} else {
		out.Ep4, out.Ep6 = src.Ep4, observed
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(out)
	if err != nil {
		return rec, false
	}
	rec = storage.Ed3kSource{NodeID: p.ID, Peer: b, Host: host, Site: site, ED2K: p.ED2K,
		LifetimeEnd: now.Add(SourceLifetime), KeptBy: p.Conn}
	if v4 && p.Open {
		rec.EP4 = p.Remote
	}
	return rec, true
}

func (x *Index) relaysOK(b []byte, size int) bool {
	if len(b)%size != 0 || len(b)/size > MaxRelays {
		return false
	}
	for i := 0; i < len(b); i += size {
		ep, ok, err := ident.DecodeEndpoint(b[i+16 : i+size])
		if err != nil || !ok || !ident.AcceptableEndpoint(ep, x.cfg.Named) {
			return false
		}
	}
	return true
}

func (x *Index) storeKeyword(ctx context.Context, s *ed3kpb.Signed, target [16]byte, level uint8, key []byte,
	viaSigner bool, host, site string, now time.Time) ed3kpb.StoreResult {
	reject := ed3kpb.StoreResult_REJECTED
	rec, ok := x.parseRecord(s, SignedLifetime, now)
	if !ok || rec.File == nil || rec.Note != nil || rec.Head != nil || rec.Member != nil || rec.Sealed != nil {
		return reject
	}
	f := rec.File
	if len(f.Name) == 0 || len(f.Name) > MaxNameBytes || !utf8.ValidString(f.Name) ||
		len(f.Root) != 32 || (len(f.Ed2K) != 0 && len(f.Ed2K) != 16) {
		return reject
	}
	split := token.SplitName(f.Name)
	if !token.HasKeywordFor(split, level, target) {
		return reject
	}
	if x.cfg.Reject != nil && x.cfg.Reject(f.Name) {
		return reject
	}
	r := storage.Ed3kKeyword{Target: target, Signed: canonicalSigned(s), Words: split.Words, Ext: split.Ext,
		Size: f.Size, Sources: f.Sources, ED2K: f.Ed2K, Host: host, Site: site,
		Expires: time.Unix(int64(rec.Expires), 0), ViaSigner: viaSigner}
	copy(r.Root[:], f.Root)
	copy(r.PubKey[:], key)
	r.PublisherID = ident.NodeIDOf(key)
	verify := func() error { return sig.CheckSigned(s, ed3kpb.Kind_KEYWORD, target[:], key) }
	res, err := x.cfg.Store.StoreEd3kKeyword(ctx, r, x.cfg.Limits, now, verify)
	if err != nil {
		return ed3kpb.StoreResult_BUSY
	}
	return ed3kpb.StoreResult(res)
}

func (x *Index) storeNote(ctx context.Context, s *ed3kpb.Signed, target [16]byte, key []byte, host, site string, now time.Time) ed3kpb.StoreResult {
	reject := ed3kpb.StoreResult_REJECTED
	rec, ok := x.parseRecord(s, SignedLifetime, now)
	if !ok || rec.Note == nil || rec.File != nil || rec.Head != nil || rec.Member != nil || rec.Sealed != nil {
		return reject
	}
	if rec.Note.Rating > 5 || len(rec.Note.Text) > MaxNoteText || !utf8.ValidString(rec.Note.Text) {
		return reject
	}
	if x.cfg.Reject != nil && rec.Note.Text != "" && x.cfg.Reject(rec.Note.Text) {
		return reject
	}
	n := storage.Ed3kNote{Target: target, Signed: canonicalSigned(s), Host: host, Site: site,
		Expires: time.Unix(int64(rec.Expires), 0)}
	copy(n.PubKey[:], key)
	verify := func() error { return sig.CheckSigned(s, ed3kpb.Kind_NOTE, target[:], key) }
	res, err := x.cfg.Store.StoreEd3kNote(ctx, n, x.cfg.Limits, now, verify)
	if err != nil {
		return ed3kpb.StoreResult_BUSY
	}
	return ed3kpb.StoreResult(res)
}

// parseRecord decodes a Signed's body and checks its expiry: later than now and
// at most the lifetime plus 1 h ahead (§10.7).
func (x *Index) parseRecord(s *ed3kpb.Signed, lifetime time.Duration, now time.Time) (*ed3kpb.Record, bool) {
	var rec ed3kpb.Record
	if proto.Unmarshal(s.Body, &rec) != nil {
		return nil, false
	}
	exp := time.Unix(int64(rec.Expires), 0)
	if rec.Expires > 1<<62 || !exp.After(now) || exp.After(now.Add(lifetime+LifetimeSlack)) {
		return nil, false
	}
	if sig.CanonicalSize(s) > sig.MaxSigned {
		return nil, false
	}
	return &rec, true
}

// canonicalSigned is the Signed as it is stored and answered: key cleared, its
// unknown fields dropped, every signature kept.
func canonicalSigned(s *ed3kpb.Signed) []byte {
	c := &ed3kpb.Signed{Body: s.Body}
	for _, g := range s.Sigs {
		c.Sigs = append(c.Sigs, &ed3kpb.Signature{Alg: g.Alg, Sig: g.Sig})
	}
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	return b
}

// keyTable collects the publisher keys of an answer, each once.
type keyTable struct {
	list [][]byte
}

func (k *keyTable) signed(stored []byte, pub [32]byte) *ed3kpb.Signed {
	var s ed3kpb.Signed
	if proto.Unmarshal(stored, &s) != nil {
		return nil
	}
	idx := -1
	for i, kk := range k.list {
		if bytes.Equal(kk, pub[:]) {
			idx = i
			break
		}
	}
	if idx < 0 {
		k.list = append(k.list, append([]byte{}, pub[:]...))
		idx = len(k.list) - 1
	}
	s.Key = uint32(idx)
	return &s
}

// hasRecordOf reports whether a Store holds a record field of kind (§10.3:
// otherwise Error{MALFORMED}).
func hasRecordOf(kind ed3kpb.Kind, s *ed3kpb.Store) bool {
	switch kind {
	case ed3kpb.Kind_SOURCE:
		return s.Source != nil
	case ed3kpb.Kind_KEYWORD:
		return len(s.Files) > 0
	case ed3kpb.Kind_NOTE:
		return s.Note != nil
	}
	return false
}

// otherRecords lists the record fields of kinds this node does not store: head
// (5), members (7), sealed (9), anon (10), aliases (11).
func otherRecords(s *ed3kpb.Store) []struct{} {
	n := len(s.Members) + len(s.Aliases)
	if s.Head != nil {
		n++
	}
	if len(s.Sealed) > 0 {
		n++
	}
	if s.Anon != nil {
		n++
	}
	return make([]struct{}, n)
}
