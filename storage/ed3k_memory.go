package storage

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"
)

// memoryEd3k is the MemoryEngine's Ed3kStore. Its zero value is ready to use. It
// has its own lock: ed3k traffic must not contend with the eD2K index.
type memoryEd3k struct {
	mu        sync.Mutex
	secret    []byte
	rotatedAt time.Time

	sources  map[[16]byte]map[[16]byte]*memEd3kSource
	keywords map[[16]byte]*memEd3kKeywordTarget
	notes    map[[16]byte]map[[32]byte]*memEd3kNote

	hostTotal map[string]int
	siteTotal map[string]int
	total     int
	fullAt    map[ed3kTargetKey]time.Time
}

type ed3kTargetKey struct {
	kind   uint8
	target [16]byte
}

type memEd3kSource struct {
	Ed3kSource
	expires time.Time // when the record goes: its lifetime, or later while kept
	page    [32]byte
}

type memEd3kKeyword struct {
	Ed3kKeyword
	hash [32]byte
	page [32]byte
}

type memEd3kKeywordTarget struct {
	files     map[[32]byte][]*memEd3kKeyword // root → kept records
	keyFiles  map[[32]byte]int
	siteFiles map[string]int
}

type memEd3kNote struct {
	Ed3kNote
	hash [32]byte
	page [32]byte
}

// InitEd3k has nothing to prepare.
func (m *MemoryEngine) InitEd3k(context.Context) error { return nil }

// StoreEd3kSource stores or renews a SOURCE record.
func (m *MemoryEngine) StoreEd3kSource(_ context.Context, r Ed3kSource, lim Ed3kLimits, now time.Time) (Ed3kResult, error) {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init(now)
	lim = lim.WithDefaults()
	t := s.sources[r.Target]
	v := ed3kSourceView{Count: len(t), HostTotal: s.hostTotal[r.Host], SiteTotal: s.siteTotal[r.Site], Total: s.total}
	held := t[r.NodeID]
	if held != nil {
		v.Held = &held.Ed3kSource
	}
	for id, x := range t {
		if id == r.NodeID {
			continue
		}
		if x.Host == r.Host {
			v.HostCount++
		}
		if x.Site == r.Site {
			v.SiteCount++
		}
		if x.LifetimeEnd.Before(now) {
			v.Evictable = true
		}
	}
	d := decideSource(v, r, lim)
	if d.Full {
		s.fullAt[ed3kTargetKey{Ed3kKindSource, r.Target}] = now
	}
	if d.Result != Ed3kStored {
		return d.Result, nil
	}
	if d.Evict {
		for _, x := range t {
			if x.LifetimeEnd.Before(now) {
				s.dropSource(x)
				break
			}
		}
	}
	if held != nil {
		s.dropSource(held)
	}
	if s.sources[r.Target] == nil {
		s.sources[r.Target] = map[[16]byte]*memEd3kSource{}
	}
	x := &memEd3kSource{Ed3kSource: r, expires: r.LifetimeEnd, page: Ed3kPageKey(s.secret, r.NodeID[:])}
	x.Peer = slices.Clone(r.Peer)
	s.sources[r.Target][r.NodeID] = x
	s.count(r.Host, r.Site, 1)
	return Ed3kStored, nil
}

// StoreEd3kKeyword stores a KEYWORD record.
func (m *MemoryEngine) StoreEd3kKeyword(_ context.Context, r Ed3kKeyword, lim Ed3kLimits, now time.Time, verify func() error) (Ed3kResult, error) {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init(now)
	lim = lim.WithDefaults()
	hash := Ed3kSignedHash(r.Signed)
	t := s.keywords[r.Target]
	var held []*memEd3kKeyword
	if t != nil {
		held = t.files[r.Root]
	}
	for _, h := range held {
		if h.PubKey == r.PubKey && h.hash == hash {
			return Ed3kOlder, nil
		}
	}
	if verify != nil {
		if err := verify(); err != nil {
			return Ed3kRejected, nil
		}
	}
	v := ed3kKeywordView{HostTotal: s.hostTotal[r.Host], SiteTotal: s.siteTotal[r.Site], Total: s.total}
	if t != nil {
		v.Files = len(t.files)
		v.KeyFiles = t.keyFiles[r.PubKey]
		v.SiteFiles = t.siteFiles[r.Site]
	}
	for _, h := range held {
		v.Held = append(v.Held, ed3kHeldKeyword{PubKey: h.PubKey, Site: h.Site, Host: h.Host, StoredAt: h.StoredAt, Expires: h.Expires, SignedHash: h.hash})
	}
	d := decideKeyword(v, r, lim)
	if d.Full {
		s.fullAt[ed3kTargetKey{Ed3kKindKeyword, r.Target}] = now
	}
	if d.Result != Ed3kStored {
		return d.Result, nil
	}
	if t == nil {
		t = &memEd3kKeywordTarget{files: map[[32]byte][]*memEd3kKeyword{}, keyFiles: map[[32]byte]int{}, siteFiles: map[string]int{}}
		s.keywords[r.Target] = t
	}
	before := siteSet(t.files[r.Root])
	if d.Replace != nil {
		recs := t.files[r.Root]
		for i, h := range recs {
			if h.PubKey == *d.Replace {
				t.files[r.Root] = append(recs[:i:i], recs[i+1:]...)
				t.keyFiles[h.PubKey]--
				s.count(h.Host, h.Site, -1)
				break
			}
		}
	}
	r.StoredAt = now
	x := &memEd3kKeyword{Ed3kKeyword: r, hash: hash, page: Ed3kPageKey(s.secret, r.Root[:], r.PubKey[:])}
	x.Signed = slices.Clone(r.Signed)
	t.files[r.Root] = append(t.files[r.Root], x)
	t.keyFiles[r.PubKey]++
	s.count(r.Host, r.Site, 1)
	t.adjustSites(before, siteSet(t.files[r.Root]))
	return Ed3kStored, nil
}

// StoreEd3kNote stores a NOTE record.
func (m *MemoryEngine) StoreEd3kNote(_ context.Context, r Ed3kNote, lim Ed3kLimits, now time.Time, verify func() error) (Ed3kResult, error) {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init(now)
	lim = lim.WithDefaults()
	hash := Ed3kSignedHash(r.Signed)
	t := s.notes[r.Target]
	held := t[r.PubKey]
	if held != nil && held.hash == hash {
		return Ed3kOlder, nil
	}
	if verify != nil {
		if err := verify(); err != nil {
			return Ed3kRejected, nil
		}
	}
	v := ed3kNoteView{Count: len(t), HostTotal: s.hostTotal[r.Host], SiteTotal: s.siteTotal[r.Site], Total: s.total}
	if held != nil {
		v.Held = &held.Ed3kNote
	}
	for k, x := range t {
		if k == r.PubKey {
			continue
		}
		if x.Host == r.Host {
			v.HostCount++
		}
		if x.Site == r.Site {
			v.SiteCount++
		}
	}
	d := decideNote(v, r, lim)
	if d.Full {
		s.fullAt[ed3kTargetKey{Ed3kKindNote, r.Target}] = now
	}
	if d.Result != Ed3kStored {
		return d.Result, nil
	}
	if held != nil {
		delete(t, r.PubKey)
		s.count(held.Host, held.Site, -1)
	}
	if s.notes[r.Target] == nil {
		s.notes[r.Target] = map[[32]byte]*memEd3kNote{}
	}
	x := &memEd3kNote{Ed3kNote: r, hash: hash, page: Ed3kPageKey(s.secret, r.PubKey[:])}
	x.Signed = slices.Clone(r.Signed)
	s.notes[r.Target][r.PubKey] = x
	s.count(r.Host, r.Site, 1)
	return Ed3kStored, nil
}

// SearchEd3kSources pages the live sources of a target.
func (m *MemoryEngine) SearchEd3kSources(_ context.Context, target [16]byte, offset, limit int, now time.Time) ([]Ed3kSource, bool, error) {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init(now)
	var all []*memEd3kSource
	for _, x := range s.sources[target] {
		if x.expires.After(now) {
			all = append(all, x)
		}
	}
	slices.SortFunc(all, func(a, b *memEd3kSource) int { return bytes.Compare(a.page[:], b.page[:]) })
	page, more := pageOf(all, offset, limit)
	out := make([]Ed3kSource, len(page))
	for i, x := range page {
		out[i] = x.Ed3kSource
	}
	return out, more, nil
}

// SearchEd3kKeywords pages the records of a keyword target matching q.
func (m *MemoryEngine) SearchEd3kKeywords(_ context.Context, target [16]byte, q Ed3kQuery, offset, limit int, now time.Time) (Ed3kKeywordPage, error) {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init(now)
	var p Ed3kKeywordPage
	t := s.keywords[target]
	if at, ok := s.fullAt[ed3kTargetKey{Ed3kKindKeyword, target}]; ok && now.Sub(at) < ed3kFullMemory(Ed3kKindKeyword) {
		p.Spill = true
	}
	if t == nil {
		return p, nil
	}
	p.Files = len(t.files)
	var all []*memEd3kKeyword
	for _, recs := range t.files {
		for _, x := range recs {
			if x.Expires.After(now) && ed3kMatches(&x.Ed3kKeyword, q) {
				all = append(all, x)
			}
		}
	}
	slices.SortFunc(all, func(a, b *memEd3kKeyword) int { return bytes.Compare(a.page[:], b.page[:]) })
	page, more := pageOf(all, offset, limit)
	p.More = more
	for _, x := range page {
		p.Records = append(p.Records, x.Ed3kKeyword)
	}
	return p, nil
}

// SearchEd3kNotes pages the notes of a file target.
func (m *MemoryEngine) SearchEd3kNotes(_ context.Context, target [16]byte, offset, limit int, now time.Time) ([]Ed3kNote, bool, error) {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init(now)
	var all []*memEd3kNote
	for _, x := range s.notes[target] {
		if x.Expires.After(now) {
			all = append(all, x)
		}
	}
	slices.SortFunc(all, func(a, b *memEd3kNote) int { return bytes.Compare(a.page[:], b.page[:]) })
	page, more := pageOf(all, offset, limit)
	out := make([]Ed3kNote, len(page))
	for i, x := range page {
		out[i] = x.Ed3kNote
	}
	return out, more, nil
}

// KeepEd3kSources extends the records kept by a live connection.
func (m *MemoryEngine) KeepEd3kSources(_ context.Context, keptBy string, until time.Time) error {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.sources {
		for _, x := range t {
			if x.KeptBy == keptBy && until.After(x.expires) {
				x.expires = until
			}
		}
	}
	return nil
}

// ReleaseEd3kSources ends the keeping of a closed connection.
func (m *MemoryEngine) ReleaseEd3kSources(_ context.Context, keptBy string) error {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.sources {
		for _, x := range t {
			if x.KeptBy == keptBy {
				x.KeptBy = ""
				x.expires = x.LifetimeEnd
			}
		}
	}
	return nil
}

// ExpireEd3k deletes what has expired and rotates the paging secret.
func (m *MemoryEngine) ExpireEd3k(_ context.Context, now time.Time) (int, error) {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init(now)
	n := 0
	for _, t := range s.sources {
		for _, x := range t {
			if !x.expires.After(now) {
				s.dropSource(x)
				n++
			}
		}
	}
	for target, t := range s.keywords {
		for root, recs := range t.files {
			before := siteSet(recs)
			kept := recs[:0]
			for _, x := range recs {
				if x.Expires.After(now) {
					kept = append(kept, x)
					continue
				}
				t.keyFiles[x.PubKey]--
				s.count(x.Host, x.Site, -1)
				n++
			}
			if len(kept) == 0 {
				delete(t.files, root)
			} else {
				t.files[root] = kept
			}
			t.adjustSites(before, siteSet(kept))
		}
		if len(t.files) == 0 {
			delete(s.keywords, target)
		}
	}
	for target, t := range s.notes {
		for k, x := range t {
			if !x.Expires.After(now) {
				delete(t, k)
				s.count(x.Host, x.Site, -1)
				n++
			}
		}
		if len(t) == 0 {
			delete(s.notes, target)
		}
	}
	for k, at := range s.fullAt {
		if now.Sub(at) >= ed3kFullMemory(k.kind) {
			delete(s.fullAt, k)
		}
	}
	if now.Sub(s.rotatedAt) >= Ed3kSecretPeriod {
		s.rotate(now)
	}
	return n, nil
}

// Ed3kBridge returns live sources of the ed2k hash whose publisher also signed a
// KEYWORD record giving that hash for the file.
func (m *MemoryEngine) Ed3kBridge(_ context.Context, ed2k [16]byte, limit int, now time.Time) ([]Ed3kBridgeSource, error) {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Ed3kBridgeSource
	seen := map[[16]byte]bool{}
	for _, t := range s.keywords {
		for root, recs := range t.files {
			for _, x := range recs {
				if len(out) >= limit {
					return out, nil
				}
				if !bytes.Equal(x.ED2K, ed2k[:]) || !x.Expires.After(now) || seen[x.PublisherID] {
					continue
				}
				var target [16]byte
				copy(target[:], root[:16])
				src := s.sources[target][x.PublisherID]
				if src == nil || !src.ED2K || !src.EP4.IsValid() || !src.expires.After(now) {
					continue
				}
				seen[x.PublisherID] = true
				out = append(out, Ed3kBridgeSource{NodeID: src.NodeID, EP4: src.EP4})
			}
		}
	}
	return out, nil
}

// Ed3kStats counts the records.
func (m *MemoryEngine) Ed3kStats(_ context.Context, now time.Time) (Ed3kStats, error) {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	var st Ed3kStats
	for _, t := range s.sources {
		for _, x := range t {
			st.Sources++
			if x.KeptBy != "" && x.LifetimeEnd.Before(now) {
				st.Kept++
			}
		}
	}
	for _, t := range s.keywords {
		for _, recs := range t.files {
			st.Keywords += len(recs)
		}
	}
	for _, t := range s.notes {
		st.Notes += len(t)
	}
	return st, nil
}

func (s *memoryEd3k) init(now time.Time) {
	if s.sources != nil {
		return
	}
	s.sources = map[[16]byte]map[[16]byte]*memEd3kSource{}
	s.keywords = map[[16]byte]*memEd3kKeywordTarget{}
	s.notes = map[[16]byte]map[[32]byte]*memEd3kNote{}
	s.hostTotal = map[string]int{}
	s.siteTotal = map[string]int{}
	s.fullAt = map[ed3kTargetKey]time.Time{}
	s.rotate(now)
}

// rotate replaces the paging secret and recomputes every page key.
func (s *memoryEd3k) rotate(now time.Time) {
	s.secret = ed3kNewSecret()
	s.rotatedAt = now
	for _, t := range s.sources {
		for _, x := range t {
			x.page = Ed3kPageKey(s.secret, x.NodeID[:])
		}
	}
	for _, t := range s.keywords {
		for _, recs := range t.files {
			for _, x := range recs {
				x.page = Ed3kPageKey(s.secret, x.Root[:], x.PubKey[:])
			}
		}
	}
	for _, t := range s.notes {
		for _, x := range t {
			x.page = Ed3kPageKey(s.secret, x.PubKey[:])
		}
	}
}

func (s *memoryEd3k) count(host, site string, d int) {
	s.hostTotal[host] += d
	if s.hostTotal[host] <= 0 {
		delete(s.hostTotal, host)
	}
	s.siteTotal[site] += d
	if s.siteTotal[site] <= 0 {
		delete(s.siteTotal, site)
	}
	s.total += d
}

func (s *memoryEd3k) dropSource(x *memEd3kSource) {
	t := s.sources[x.Target]
	if t[x.NodeID] != x {
		return
	}
	delete(t, x.NodeID)
	if len(t) == 0 {
		delete(s.sources, x.Target)
	}
	s.count(x.Host, x.Site, -1)
}

// adjustSites keeps siteFiles: a file counts for a site while a kept record of
// it has that site.
func (t *memEd3kKeywordTarget) adjustSites(before, after map[string]bool) {
	for site := range before {
		if !after[site] {
			if t.siteFiles[site]--; t.siteFiles[site] <= 0 {
				delete(t.siteFiles, site)
			}
		}
	}
	for site := range after {
		if !before[site] {
			t.siteFiles[site]++
		}
	}
	for k, n := range t.keyFiles {
		if n <= 0 {
			delete(t.keyFiles, k)
		}
	}
}

func siteSet(recs []*memEd3kKeyword) map[string]bool {
	m := make(map[string]bool, len(recs))
	for _, x := range recs {
		m[x.Site] = true
	}
	return m
}

func pageOf[T any](all []T, offset, limit int) ([]T, bool) {
	if offset >= len(all) {
		return nil, false
	}
	end := offset + limit
	if end >= len(all) {
		return all[offset:], false
	}
	return all[offset:end], true
}

func (m *MemoryEngine) ed3kPageSecret(_ context.Context, now time.Time) ([]byte, error) {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init(now)
	return slices.Clone(s.secret), nil
}

func (m *MemoryEngine) ed3kFileKeywords(_ context.Context, target [16]byte, root [32]byte) ([]Ed3kKeyword, error) {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Ed3kKeyword
	if t := s.keywords[target]; t != nil {
		for _, x := range t.files[root] {
			out = append(out, x.Ed3kKeyword)
		}
	}
	return out, nil
}

func (m *MemoryEngine) ed3kEachKeyword(ctx context.Context, now time.Time, fn func(Ed3kKeyword) error) error {
	s := &m.ed3k
	s.mu.Lock()
	var all []Ed3kKeyword
	for _, t := range s.keywords {
		for _, recs := range t.files {
			for _, x := range recs {
				if x.Expires.After(now) {
					all = append(all, x.Ed3kKeyword)
				}
			}
		}
	}
	s.mu.Unlock()
	for _, r := range all {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

func (m *MemoryEngine) ed3kKeywordTarget(_ context.Context, target [16]byte, now time.Time) (int, bool, error) {
	s := &m.ed3k
	s.mu.Lock()
	defer s.mu.Unlock()
	files := 0
	if t := s.keywords[target]; t != nil {
		files = len(t.files)
	}
	at, ok := s.fullAt[ed3kTargetKey{Ed3kKindKeyword, target}]
	return files, ok && now.Sub(at) < ed3kFullMemory(Ed3kKindKeyword), nil
}
