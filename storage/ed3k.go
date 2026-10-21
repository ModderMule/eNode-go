package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/netip"
	"time"

	"lukechampine.com/blake3"

	"enode/ed3k/ident"
)

// The ed3k index store: the records an ed3k index node holds (Protocol.md §10.3,
// §10.7, §10.8, §11, extensions/ip-diversity.md §2.4). It lives beside the eD2K
// tables behind its own interface, Ed3kStore, like the account store, and every
// engine implements it: memory, mysql and mongodb; a Manticore engine mirrors
// keyword records for term search.
//
// The store owns the limits that need a consistent view of a target (places,
// counts per host, site and key, FULL), the paging secret and the paging order.
// Checks that need no stored state — parsing, signatures, the tokenizer, the
// lifetime — belong to the caller (package ed3k/index). The rules are written
// once, as the decide* functions below over a snapshot of the target; each
// engine loads that snapshot under a lock of the target and applies the result.

// Ed3kResult is the outcome of one stored record; the values are those of
// StoreResult in the ed3k proto.
type Ed3kResult uint8

const (
	Ed3kStored   Ed3kResult = 0
	Ed3kFull     Ed3kResult = 1
	Ed3kBusy     Ed3kResult = 2
	Ed3kRejected Ed3kResult = 3
	Ed3kOlder    Ed3kResult = 5
)

// String names the result for logs.
func (r Ed3kResult) String() string {
	switch r {
	case Ed3kStored:
		return "STORED"
	case Ed3kFull:
		return "FULL"
	case Ed3kBusy:
		return "BUSY"
	case Ed3kRejected:
		return "REJECTED"
	case Ed3kOlder:
		return "OLDER"
	}
	return "UNKNOWN"
}

// Ed3k record kinds as stored (the Kind values of the proto).
const (
	Ed3kKindSource  uint8 = 1
	Ed3kKindKeyword uint8 = 2
	Ed3kKindNote    uint8 = 3
)

// Ed3kLimits are the bounds a store applies. Zero values take the defaults of
// DefaultEd3kLimits.
type Ed3kLimits struct {
	SourcesPerTarget int // §10.8: 10,000, then FULL
	SourcesPerHost   int // ip-diversity §2.4: 8 per file
	SourcesPerSite   int // 32 per file
	KeywordFiles     int // §10.8 level size: 100,000 files per keyword target
	KeywordPlaces    int // 3 records per file
	KeywordPerKey    int // 1,000 files of one publisher key per target
	KeywordPerSite   int // 2,000 files of one publisher site per target
	NotesPerTarget   int // 64, then FULL
	NotesPerHost     int // 4
	NotesPerSite     int // 8
	// RecordsPerHost and RecordsPerSite bound what one publisher host or site
	// holds over all targets and kinds (§11 MUST); beyond them REJECTED.
	RecordsPerHost int
	RecordsPerSite int
	// MaxRecords bounds the whole store; beyond it BUSY.
	MaxRecords int
}

// DefaultEd3kLimits are the initial values of the spec plus node-wide bounds
// sized for a large index node.
var DefaultEd3kLimits = Ed3kLimits{
	SourcesPerTarget: 10000, SourcesPerHost: 8, SourcesPerSite: 32,
	KeywordFiles: 100000, KeywordPlaces: 3, KeywordPerKey: 1000, KeywordPerSite: 2000,
	NotesPerTarget: 64, NotesPerHost: 4, NotesPerSite: 8,
	RecordsPerHost: 50000, RecordsPerSite: 200000, MaxRecords: 50_000_000,
}

// WithDefaults fills the zero fields.
func (l Ed3kLimits) WithDefaults() Ed3kLimits {
	d := DefaultEd3kLimits
	set := func(v *int, def int) {
		if *v <= 0 {
			*v = def
		}
	}
	set(&l.SourcesPerTarget, d.SourcesPerTarget)
	set(&l.SourcesPerHost, d.SourcesPerHost)
	set(&l.SourcesPerSite, d.SourcesPerSite)
	set(&l.KeywordFiles, d.KeywordFiles)
	set(&l.KeywordPlaces, d.KeywordPlaces)
	set(&l.KeywordPerKey, d.KeywordPerKey)
	set(&l.KeywordPerSite, d.KeywordPerSite)
	set(&l.NotesPerTarget, d.NotesPerTarget)
	set(&l.NotesPerHost, d.NotesPerHost)
	set(&l.NotesPerSite, d.NotesPerSite)
	set(&l.RecordsPerHost, d.RecordsPerHost)
	set(&l.RecordsPerSite, d.RecordsPerSite)
	set(&l.MaxRecords, d.MaxRecords)
	return l
}

// Ed3kSource is a SOURCE record: bound to the publishing connection, unsigned.
type Ed3kSource struct {
	Target [16]byte
	NodeID [16]byte
	// Peer is the serialised Peer as it is answered: id set, the endpoint of the
	// connection's family replaced by the observed one.
	Peer []byte
	// Host and Site are the ip-diversity groups of the publishing address.
	Host, Site string
	// EP4 is the observed IPv4 endpoint when the connection is IPv4 and direct;
	// the eD2K bridge lists only such sources.
	EP4 netip.AddrPort
	// ED2K is set when the publisher's Hello has the ED2K capability.
	ED2K bool
	// LifetimeEnd is when the record's lifetime (5 h) ends.
	LifetimeEnd time.Time
	// KeptBy names the connection that keeps the record beyond its lifetime
	// (§11); empty when the record is not kept.
	KeptBy string
}

// Ed3kKeyword is a KEYWORD record: a signed file entry under one keyword.
type Ed3kKeyword struct {
	Target      [16]byte
	Root        [32]byte
	PubKey      [32]byte
	PublisherID [16]byte // H("ed3k v1 node id", PubKey)[0..16)
	// Signed is the serialised Signed (key field cleared), returned as stored.
	Signed []byte
	// Words are the normalised words of the name (§10.1) for Query.all/none.
	Words   []string
	Ext     string
	Size    uint64
	Sources uint32
	ED2K    []byte // 16-byte MD4 hash from FileInfo.ed2k, or nil
	Host    string
	Site    string
	Expires time.Time
	// ViaSigner is set when the Store carried signer (§10.8 rule on signer).
	ViaSigner bool
	// StoredAt is when this node last stored the record; set by the store.
	StoredAt time.Time
}

// Ed3kNote is a NOTE record: one signed note per publisher and file target.
type Ed3kNote struct {
	Target  [16]byte
	PubKey  [32]byte
	Signed  []byte
	Host    string
	Site    string
	Expires time.Time
}

// Ed3kQuery is the part of a KEYWORD Query a store evaluates (§10.3).
type Ed3kQuery struct {
	All        []string
	None       []string
	MinSize    uint64
	MaxSize    uint64 // 0 = no limit
	MinSources uint32
	Ext        string
}

// Ed3kKeywordPage is one page of a keyword search.
type Ed3kKeywordPage struct {
	Records []Ed3kKeyword
	More    bool
	// Files is how many files the target holds, for KadAnswer.load.
	Files int
	// Spill is set when the target answered FULL within the last 24 h.
	Spill bool
}

// Ed3kBridgeSource is an ed3k node listed as an eD2K source (ed2k-tags.md §6).
type Ed3kBridgeSource struct {
	NodeID [16]byte
	EP4    netip.AddrPort
}

// Ed3kStats counts what a store holds.
type Ed3kStats struct {
	Sources, Keywords, Notes int
	Kept                     int // sources kept beyond their lifetime
}

// Ed3kStore is the persistence of an ed3k index node. now is passed in so that
// tests control the clock.
type Ed3kStore interface {
	// InitEd3k creates the tables, collections or indexes; only called when ed3k
	// is enabled.
	InitEd3k(ctx context.Context) error
	// StoreEd3kSource stores or renews a SOURCE record.
	StoreEd3kSource(ctx context.Context, r Ed3kSource, lim Ed3kLimits, now time.Time) (Ed3kResult, error)
	// StoreEd3kKeyword stores a KEYWORD record. verify is called only when the
	// record is not byte for byte the one held (§11 Load); its error makes the
	// record REJECTED.
	StoreEd3kKeyword(ctx context.Context, r Ed3kKeyword, lim Ed3kLimits, now time.Time, verify func() error) (Ed3kResult, error)
	// StoreEd3kNote stores a NOTE record, with verify as above.
	StoreEd3kNote(ctx context.Context, r Ed3kNote, lim Ed3kLimits, now time.Time, verify func() error) (Ed3kResult, error)
	// SearchEd3kSources pages the live sources of a target.
	SearchEd3kSources(ctx context.Context, target [16]byte, offset, limit int, now time.Time) ([]Ed3kSource, bool, error)
	// SearchEd3kKeywords pages the records of a keyword target matching q.
	SearchEd3kKeywords(ctx context.Context, target [16]byte, q Ed3kQuery, offset, limit int, now time.Time) (Ed3kKeywordPage, error)
	// SearchEd3kNotes pages the notes of a file target.
	SearchEd3kNotes(ctx context.Context, target [16]byte, offset, limit int, now time.Time) ([]Ed3kNote, bool, error)
	// KeepEd3kSources extends the records kept by a live connection.
	KeepEd3kSources(ctx context.Context, keptBy string, until time.Time) error
	// ReleaseEd3kSources ends the keeping of a closed connection: its records
	// go at the end of their lifetime.
	ReleaseEd3kSources(ctx context.Context, keptBy string) error
	// ExpireEd3k deletes what has expired, and rotates the paging secret every
	// 24 h.
	ExpireEd3k(ctx context.Context, now time.Time) (int, error)
	// Ed3kBridge returns sources of the ed2k hash for the eD2K bridge.
	Ed3kBridge(ctx context.Context, ed2k [16]byte, limit int, now time.Time) ([]Ed3kBridgeSource, error)
	// Ed3kStats counts the records.
	Ed3kStats(ctx context.Context, now time.Time) (Ed3kStats, error)
}

// Every engine is an Ed3kStore.
var (
	_ Ed3kStore = (*MemoryEngine)(nil)
	_ Ed3kStore = (*MySQLEngine)(nil)
	_ Ed3kStore = (*MongoDBEngine)(nil)
)

// Ed3kSecretPeriod is how often the paging secret is replaced (§10.3).
const Ed3kSecretPeriod = 24 * time.Hour

// Ed3kPageKey is the paging order of §10.3: H("ed3k v1 page", secret ‖ parts).
func Ed3kPageKey(secret []byte, parts ...[]byte) [32]byte {
	var out [32]byte
	in := append([]byte{}, secret...)
	for _, p := range parts {
		in = append(in, p...)
	}
	copy(out[:], ident.H("ed3k v1 page", 32, in))
	return out
}

// Ed3kSignedHash identifies a Signed byte for byte (the OLDER shortcut).
func Ed3kSignedHash(signed []byte) [32]byte { return blake3.Sum256(signed) }

// ed3kHeldKeyword is a kept record of one file under a keyword target.
type ed3kHeldKeyword struct {
	PubKey     [32]byte
	Site       string
	Host       string
	StoredAt   time.Time
	Expires    time.Time
	SignedHash [32]byte
}

// ed3kKeywordView is what decideKeyword needs of a target.
type ed3kKeywordView struct {
	Held      []ed3kHeldKeyword // records of this file
	Files     int               // files the target holds
	KeyFiles  int               // files of the publisher key
	SiteFiles int               // files the record's site holds a place of
	HostTotal int               // records of the host, all targets and kinds
	SiteTotal int               // records of the site, all targets and kinds
	Total     int               // records in the store
}

// ed3kKeywordDecision is what an engine applies.
type ed3kKeywordDecision struct {
	Result  Ed3kResult
	Replace *[32]byte // publisher key of the held record that gives its place
	Insert  bool
	Full    bool // remember FULL for spill
}

// decideKeyword applies §10.7 (newer) and §10.8 (places, limits) to a valid
// record. The OLDER shortcut and the signature check come before it.
func decideKeyword(v ed3kKeywordView, r Ed3kKeyword, lim Ed3kLimits) ed3kKeywordDecision {
	var own *ed3kHeldKeyword
	siteHeld := -1 // the least fresh held record of the record's site
	for i := range v.Held {
		h := &v.Held[i]
		if h.PubKey == r.PubKey {
			own = h
		}
		if h.Site == r.Site && (siteHeld < 0 || lessFresh(*h, v.Held[siteHeld])) {
			siteHeld = i
		}
	}
	siteHasFile := siteHeld >= 0
	reject := ed3kKeywordDecision{Result: Ed3kRejected}

	if own != nil {
		if !r.Expires.After(own.Expires) {
			return ed3kKeywordDecision{Result: Ed3kOlder}
		}
		// Rule 1: the publisher's own place, whatever site it comes from.
		if own.Site != r.Site && !siteHasFile && v.SiteFiles >= lim.KeywordPerSite {
			return reject
		}
		if own.Host != r.Host && v.HostTotal >= lim.RecordsPerHost {
			return reject
		}
		k := own.PubKey
		return ed3kKeywordDecision{Result: Ed3kStored, Replace: &k}
	}
	if v.Total >= lim.MaxRecords {
		return ed3kKeywordDecision{Result: Ed3kBusy}
	}
	// Address and key limits come first (ip-diversity §2.4).
	if v.HostTotal >= lim.RecordsPerHost || v.SiteTotal >= lim.RecordsPerSite {
		return reject
	}
	if v.KeyFiles >= lim.KeywordPerKey {
		return reject
	}
	if len(v.Held) == 0 {
		if v.SiteFiles >= lim.KeywordPerSite {
			return reject
		}
		if v.Files >= lim.KeywordFiles {
			return ed3kKeywordDecision{Result: Ed3kFull, Full: true}
		}
		return ed3kKeywordDecision{Result: Ed3kStored, Insert: true}
	}
	if siteHasFile {
		// Rule 2: the place of that site's least fresh record.
		k := v.Held[siteHeld].PubKey
		return ed3kKeywordDecision{Result: Ed3kStored, Replace: &k}
	}
	// Rule 3: another site.
	if v.SiteFiles >= lim.KeywordPerSite {
		return reject
	}
	if len(v.Held) < lim.KeywordPlaces {
		return ed3kKeywordDecision{Result: Ed3kStored, Insert: true}
	}
	if r.ViaSigner {
		return reject
	}
	least := 0
	for i := range v.Held {
		if lessFresh(v.Held[i], v.Held[least]) {
			least = i
		}
	}
	k := v.Held[least].PubKey
	return ed3kKeywordDecision{Result: Ed3kStored, Replace: &k}
}

// lessFresh orders kept records: stored longest ago first, and of two stored in
// the same second the one with the lower publisher key.
func lessFresh(a, b ed3kHeldKeyword) bool {
	as, bs := a.StoredAt.Unix(), b.StoredAt.Unix()
	if as != bs {
		return as < bs
	}
	return bytes.Compare(a.PubKey[:], b.PubKey[:]) < 0
}

// ed3kSourceView is what decideSource needs of a target.
type ed3kSourceView struct {
	Held      *Ed3kSource // the node's own record, if any
	Count     int         // records under the target
	HostCount int         // records of the host under the target, the node's own excluded
	SiteCount int         // the same for the site
	HostTotal int
	SiteTotal int
	Total     int
	Evictable bool // a kept record past its lifetime that can give its place
}

type ed3kSourceDecision struct {
	Result Ed3kResult
	Evict  bool // drop one kept record past its lifetime first
	Full   bool
}

// decideSource applies §10.8 and ip-diversity §2.4 to a SOURCE record.
func decideSource(v ed3kSourceView, r Ed3kSource, lim Ed3kLimits) ed3kSourceDecision {
	reject := ed3kSourceDecision{Result: Ed3kRejected}
	if v.Held != nil {
		if v.Held.Host != r.Host && (v.HostCount >= lim.SourcesPerHost || v.HostTotal >= lim.RecordsPerHost) {
			return reject
		}
		if v.Held.Site != r.Site && (v.SiteCount >= lim.SourcesPerSite || v.SiteTotal >= lim.RecordsPerSite) {
			return reject
		}
		return ed3kSourceDecision{Result: Ed3kStored}
	}
	if v.Total >= lim.MaxRecords {
		return ed3kSourceDecision{Result: Ed3kBusy}
	}
	if v.HostTotal >= lim.RecordsPerHost || v.SiteTotal >= lim.RecordsPerSite ||
		v.HostCount >= lim.SourcesPerHost || v.SiteCount >= lim.SourcesPerSite {
		return reject
	}
	if v.Count >= lim.SourcesPerTarget {
		if v.Evictable {
			return ed3kSourceDecision{Result: Ed3kStored, Evict: true}
		}
		return ed3kSourceDecision{Result: Ed3kFull, Full: true}
	}
	return ed3kSourceDecision{Result: Ed3kStored}
}

// ed3kNoteView is what decideNote needs of a target.
type ed3kNoteView struct {
	Held      *Ed3kNote
	HeldHash  [32]byte
	Count     int
	HostCount int // notes of the host under the target, the publisher's own excluded
	SiteCount int
	HostTotal int
	SiteTotal int
	Total     int
}

type ed3kNoteDecision struct {
	Result Ed3kResult
	Full   bool
}

// decideNote applies §10.7 and §10.8 to a valid NOTE record.
func decideNote(v ed3kNoteView, r Ed3kNote, lim Ed3kLimits) ed3kNoteDecision {
	reject := ed3kNoteDecision{Result: Ed3kRejected}
	if v.Held != nil {
		if !r.Expires.After(v.Held.Expires) {
			return ed3kNoteDecision{Result: Ed3kOlder}
		}
		if v.Held.Host != r.Host && (v.HostCount >= lim.NotesPerHost || v.HostTotal >= lim.RecordsPerHost) {
			return reject
		}
		if v.Held.Site != r.Site && (v.SiteCount >= lim.NotesPerSite || v.SiteTotal >= lim.RecordsPerSite) {
			return reject
		}
		return ed3kNoteDecision{Result: Ed3kStored}
	}
	if v.Total >= lim.MaxRecords {
		return ed3kNoteDecision{Result: Ed3kBusy}
	}
	if v.HostTotal >= lim.RecordsPerHost || v.SiteTotal >= lim.RecordsPerSite ||
		v.HostCount >= lim.NotesPerHost || v.SiteCount >= lim.NotesPerSite {
		return reject
	}
	if v.Count >= lim.NotesPerTarget {
		return ed3kNoteDecision{Result: Ed3kFull, Full: true}
	}
	return ed3kNoteDecision{Result: Ed3kStored}
}

// ed3kMatches evaluates a Query against a keyword record (§10.3): every word of
// all is a word of the name, no word of none is, size, sources and extension.
func ed3kMatches(r *Ed3kKeyword, q Ed3kQuery) bool {
	if r.Size < q.MinSize || (q.MaxSize != 0 && r.Size > q.MaxSize) || r.Sources < q.MinSources {
		return false
	}
	if q.Ext != "" && r.Ext != q.Ext {
		return false
	}
	has := func(w string) bool {
		for _, x := range r.Words {
			if x == w {
				return true
			}
		}
		return false
	}
	for _, w := range q.All {
		if !has(w) {
			return false
		}
	}
	for _, w := range q.None {
		if has(w) {
			return false
		}
	}
	return true
}

// ed3kNewSecret draws a paging secret.
func ed3kNewSecret() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails: crypto/rand crashes the program instead
	return b
}

// ed3kFullMemory is how long a target that answered FULL sets spill: the
// lifetime of the kind (24 h for KEYWORD and NOTE, 5 h for SOURCE).
func ed3kFullMemory(kind uint8) time.Duration {
	if kind == Ed3kKindSource {
		return 5 * time.Hour
	}
	return 24 * time.Hour
}

// ed3kMirrorSource is what the Manticore mirror reads from the database engine it
// wraps: the paging secret, the kept records of one file, every live record, and
// a target's file count and spill.
type ed3kMirrorSource interface {
	ed3kPageSecret(ctx context.Context, now time.Time) ([]byte, error)
	ed3kFileKeywords(ctx context.Context, target [16]byte, root [32]byte) ([]Ed3kKeyword, error)
	ed3kEachKeyword(ctx context.Context, now time.Time, fn func(Ed3kKeyword) error) error
	ed3kKeywordTarget(ctx context.Context, target [16]byte, now time.Time) (int, bool, error)
}

var (
	_ ed3kMirrorSource = (*MemoryEngine)(nil)
	_ ed3kMirrorSource = (*MySQLEngine)(nil)
	_ ed3kMirrorSource = (*MongoDBEngine)(nil)
)

var _ Ed3kStore = (*ManticoreEngine)(nil)
