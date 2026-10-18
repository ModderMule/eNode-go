package metaapi

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"enode/logging"

	"connectrpc.com/connect/v2"
	"github.com/ModderMule/enodemeta"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/metahash"
	"github.com/ModderMule/enodemeta/weblinks"
	"golang.org/x/sync/singleflight"
)

// Network names, as the meta package spells them.
const (
	networkTorrent = "torrent"
	networkUsenet  = "usenet"
	networkWeb     = "web"
	// networkKad has no metafiles: its rows are eD2K files. It is a network of
	// MetaApi.Search only.
	networkKad = "kad"
	// networkServers has no daemon and no metafiles: it is the eD2K files this
	// server's users share and those of the servers it exchanges searches with
	// (serverlink.NetworkServers). It too is a network of MetaApi.Search only.
	networkServers = "servers"
)

// MetaFileSource fetches metafiles from the catalogue daemons. *meta.Searcher is one.
type MetaFileSource interface {
	FetchMetaFile(ctx context.Context, network, catalogID string) (*metav1.MetaFile, error)
	Networks() []string
}

// CatalogHolder is a MetaFileSource that knows which network's feed holds a
// catalog_id. *meta.Searcher is one. A kind two networks serve — a torrent
// found by torrent-crawler, or on a web page by web-crawler (ingest contract,
// amendment 27) — is fetched from the holder first.
type CatalogHolder interface {
	HoldingNetwork(catalogID string) string
}

// FetchError is a metafile fetch failure with its MsgCode and status.
type FetchError struct {
	Code    connect.Code
	MsgCode string
	cause   error
}

func (e *FetchError) Error() string {
	if e.cause != nil {
		return e.MsgCode + ": " + e.cause.Error()
	}
	return e.MsgCode
}

func (e *FetchError) Unwrap() error { return e.cause }

// MsgCodes of metafile fetches. Each must exist in every locales/*.json file.
const (
	CodeNotFound       = "metafile.not_found"
	CodeVerifyFailed   = "metafile.verify_failed"
	CodeUnavailable    = "metafile.upstream_unavailable"
	CodeInvalidRequest = "metafile.invalid_request"
	CodeTooLarge       = "metafile.too_large"
	CodeMagnetOnly     = "metafile.magnet_only"
)

// Fetcher serves metafiles: from its cache, or from the owning daemon, checked
// against the meta hash before anything is cached or returned.
type Fetcher struct {
	source   MetaFileSource
	timeout  time.Duration
	maxBytes int
	cache    *byteCache
	negTTL   time.Duration
	flight   singleflight.Group
	now      func() time.Time

	negMu sync.Mutex
	neg   map[string]negEntry

	stats FetchStats
}

// FetchStats are the fetcher's counters, for the dashboard.
type FetchStats struct {
	Served        atomic.Int64
	CacheHits     atomic.Int64
	NotFound      atomic.Int64
	VerifyFailed  atomic.Int64
	UpstreamError atomic.Int64
}

type negEntry struct {
	err     *FetchError
	expires time.Time
}

// NewFetcher returns a fetcher over source.
func NewFetcher(source MetaFileSource, timeout time.Duration, maxBytes int, cacheBytes int64, ttl, negTTL time.Duration) *Fetcher {
	return &Fetcher{
		source:   source,
		timeout:  timeout,
		maxBytes: maxBytes,
		cache:    newByteCache(cacheBytes, ttl),
		negTTL:   negTTL,
		now:      time.Now,
		neg:      map[string]negEntry{},
	}
}

// Stats returns the counters.
func (f *Fetcher) Stats() *FetchStats { return &f.stats }

// CacheBytes is how many bytes the cache holds.
func (f *Fetcher) CacheBytes() int64 { return f.cache.size() }

// Kinds are the MetaKinds whose metafiles can be served, by enabled network.
func (f *Fetcher) Kinds() []metav1.MetaKind {
	var out []metav1.MetaKind
	if f.source == nil {
		return out
	}
	for _, n := range f.source.Networks() {
		switch n {
		case networkTorrent:
			out = append(out, metav1.MetaKind_META_KIND_BT_V1, metav1.MetaKind_META_KIND_BT_V2)
		case networkUsenet:
			out = append(out, metav1.MetaKind_META_KIND_NZB)
		case networkWeb:
			// A web daemon serves the torrents and link containers its pages offer
			// too (amendment 27).
			out = append(out, metav1.MetaKind_META_KIND_WEB, metav1.MetaKind_META_KIND_BT_V1,
				metav1.MetaKind_META_KIND_BT_V2, metav1.MetaKind_META_KIND_CONTAINER)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Get returns the metafile behind a row.
func (f *Fetcher) Get(ctx context.Context, rawHash []byte, catalogID string) (*metav1.MetaFile, error) {
	hash, err := metahash.FromBytes(rawHash)
	if err != nil {
		return nil, &FetchError{Code: connect.CodeInvalidArgument, MsgCode: CodeInvalidRequest, cause: err}
	}
	parsed, err := metahash.Parse(hash[:])
	if err != nil {
		return nil, &FetchError{Code: connect.CodeInvalidArgument, MsgCode: CodeInvalidRequest, cause: err}
	}
	if catalogID == "" || len(catalogID) > 256 {
		return nil, &FetchError{Code: connect.CodeInvalidArgument, MsgCode: CodeInvalidRequest, cause: errors.New("catalog_id missing or too long")}
	}
	if f.source == nil {
		// Meta search is off, so no daemon owns any row.
		return nil, &FetchError{Code: connect.CodeNotFound, MsgCode: CodeNotFound, cause: errors.New("meta search is disabled")}
	}
	if len(networksFor(parsed.Kind)) == 0 {
		return nil, &FetchError{Code: connect.CodeInvalidArgument, MsgCode: CodeInvalidRequest, cause: fmt.Errorf("kind %s", parsed.Kind)}
	}
	networks := f.networks(parsed.Kind, catalogID)
	if len(networks) == 0 {
		return nil, &FetchError{Code: connect.CodeNotFound, MsgCode: CodeNotFound, cause: fmt.Errorf("no network serving %s is enabled", parsed.Kind)}
	}
	// The cache is keyed by hash alone: an entry was verified against the hash, so
	// it is the right file whatever catalog_id the caller echoed.
	if mf, ok := f.cache.get(string(hash[:]), f.now()); ok {
		f.stats.CacheHits.Add(1)
		f.stats.Served.Add(1)
		return mf, nil
	}
	flightKey := string(hash[:]) + "\x00" + catalogID
	if e := f.negative(flightKey); e != nil {
		return nil, e
	}
	ch := f.flight.DoChan(flightKey, func() (any, error) {
		// Detached from the first caller's ctx: a caller giving up must not fail the
		// fetch for the others waiting on it. The timeout bounds it instead.
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), f.timeout)
		defer cancel()
		return f.fetchFrom(fctx, hash, parsed.Kind, networks, catalogID)
	})
	select {
	case <-ctx.Done():
		return nil, connect.NewError(connect.CodeCanceled, "canceled")
	case res := <-ch:
		if res.Err != nil {
			var fe *FetchError
			if errors.As(res.Err, &fe) {
				return nil, fe
			}
			return nil, res.Err
		}
		f.stats.Served.Add(1)
		return res.Val.(*metav1.MetaFile), nil
	}
}

// ContentType is the default media type of a metafile kind.
func ContentType(kind metav1.MetaKind) string {
	switch kind {
	case metav1.MetaKind_META_KIND_NZB:
		return "application/x-nzb"
	case metav1.MetaKind_META_KIND_WEB:
		return weblinks.ContentType
	case metav1.MetaKind_META_KIND_CONTAINER:
		// The daemon names the format; without that the bytes are opaque.
		return "application/octet-stream"
	default:
		return "application/x-bittorrent"
	}
}

// networks are the enabled networks that may serve a kind's metafile for
// catalogID, the one whose feed holds it first.
func (f *Fetcher) networks(kind metahash.Kind, catalogID string) []string {
	enabled := f.source.Networks()

	var out []string
	if holder, ok := f.source.(CatalogHolder); ok {
		if n := holder.HoldingNetwork(catalogID); n != "" && slices.Contains(networksFor(kind), n) && slices.Contains(enabled, n) {
			out = append(out, n)
		}
	}
	for _, n := range networksFor(kind) {
		if slices.Contains(enabled, n) && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// fetchFrom asks each network in turn, moving on while one answers that it does
// not have the release. Any other answer is the answer.
func (f *Fetcher) fetchFrom(ctx context.Context, hash metahash.Hash, kind metahash.Kind, networks []string, catalogID string) (*metav1.MetaFile, error) {
	var err error
	for i, network := range networks {
		var mf *metav1.MetaFile
		mf, err = f.fetch(ctx, hash, kind, network, catalogID, i == len(networks)-1)
		var fe *FetchError
		if err == nil || !errors.As(err, &fe) || fe.Code != connect.CodeNotFound {
			return mf, err
		}
	}
	return nil, err
}

// fetch asks one network. last says no other network is left to ask, so a "not
// found" is the answer and is remembered.
func (f *Fetcher) fetch(ctx context.Context, hash metahash.Hash, kind metahash.Kind, network, catalogID string, last bool) (*metav1.MetaFile, error) {
	mf, err := f.source.FetchMetaFile(ctx, network, catalogID)
	if err != nil {
		fe := classify(err)
		switch fe.Code {
		case connect.CodeNotFound:
			if !last {
				return nil, fe
			}
			f.stats.NotFound.Add(1)
			f.remember(string(hash[:])+"\x00"+catalogID, fe)
		case connect.CodeFailedPrecondition:
			f.stats.NotFound.Add(1)
			f.remember(string(hash[:])+"\x00"+catalogID, fe)
		default:
			f.stats.UpstreamError.Add(1)
			logging.Warnf("meta api: fetch %s %s from %s: %v", hash, catalogID, network, err)
		}
		return nil, fe
	}
	if len(mf.GetContent()) > f.maxBytes {
		return nil, &FetchError{Code: connect.CodeResourceExhausted, MsgCode: CodeTooLarge,
			cause: fmt.Errorf("%d bytes over the %d limit", len(mf.GetContent()), f.maxBytes)}
	}
	if err := enodemeta.VerifyMetaFile(hash, mf.GetContent()); err != nil {
		f.stats.VerifyFailed.Add(1)
		logging.Warnf("meta api: %s catalog_id %s from %s does not verify: %v", hash, catalogID, network, err)
		fe := &FetchError{Code: connect.CodeDataLoss, MsgCode: CodeVerifyFailed, cause: err}
		f.remember(string(hash[:])+"\x00"+catalogID, fe)
		return nil, fe
	}
	out := &metav1.MetaFile{Kind: metav1.MetaKind(kind), Content: mf.GetContent(), ContentType: mf.GetContentType()}
	if out.ContentType == "" {
		out.ContentType = ContentType(out.Kind)
	}
	f.cache.put(string(hash[:]), out, f.now())
	return out, nil
}

func (f *Fetcher) negative(key string) *FetchError {
	f.negMu.Lock()
	defer f.negMu.Unlock()
	e, ok := f.neg[key]
	if !ok {
		return nil
	}
	if f.now().After(e.expires) {
		delete(f.neg, key)
		return nil
	}
	return e.err
}

func (f *Fetcher) remember(key string, e *FetchError) {
	f.negMu.Lock()
	defer f.negMu.Unlock()
	now := f.now()
	if len(f.neg) > 50000 {
		for k, v := range f.neg {
			if now.After(v.expires) {
				delete(f.neg, k)
			}
		}
	}
	f.neg[key] = negEntry{err: e, expires: now.Add(f.negTTL)}
}

// classify maps a daemon error onto what the client is told.
func classify(err error) *FetchError {
	if errors.Is(err, context.DeadlineExceeded) {
		return &FetchError{Code: connect.CodeUnavailable, MsgCode: CodeUnavailable, cause: err}
	}
	switch connect.CodeOf(err) {
	case connect.CodeNotFound, connect.CodeInvalidArgument:
		// invalid_argument: the id is not one of that daemon's kinds — from the
		// client's side the release simply is not there.
		return &FetchError{Code: connect.CodeNotFound, MsgCode: CodeNotFound, cause: err}
	case connect.CodeFailedPrecondition:
		// The server sends no identity, so the daemon's other failed_precondition
		// (identity mismatch) cannot happen: this is a magnet-only release, which has
		// no metafile. The client uses the row's magnet instead.
		return &FetchError{Code: connect.CodeFailedPrecondition, MsgCode: CodeMagnetOnly, cause: err}
	case connect.CodeDataLoss:
		return &FetchError{Code: connect.CodeDataLoss, MsgCode: CodeVerifyFailed, cause: err}
	default:
		return &FetchError{Code: connect.CodeUnavailable, MsgCode: CodeUnavailable, cause: err}
	}
}

// networksFor are the networks that may serve a kind's metafiles, in the order
// they are asked when no feed says which holds the release: a torrent is
// torrent-crawler's first, and web-crawler's when a page offered it; a link
// container only a web page offers.
func networksFor(kind metahash.Kind) []string {
	switch kind {
	case metahash.KindBTV1, metahash.KindBTV2:
		return []string{networkTorrent, networkWeb}
	case metahash.KindNZB:
		return []string{networkUsenet}
	case metahash.KindWeb, metahash.KindContainer:
		return []string{networkWeb}
	default:
		return nil
	}
}

// byteCache is an LRU bounded by the total size of its metafiles, with a TTL.
type byteCache struct {
	maxBytes int64
	ttl      time.Duration

	mu    sync.Mutex
	bytes int64
	order *list.List // front = most recent; values are *cacheItem
	items map[string]*list.Element
}

type cacheItem struct {
	key     string
	mf      *metav1.MetaFile
	expires time.Time
}

func newByteCache(maxBytes int64, ttl time.Duration) *byteCache {
	return &byteCache{maxBytes: maxBytes, ttl: ttl, order: list.New(), items: map[string]*list.Element{}}
}

func (c *byteCache) get(key string, now time.Time) (*metav1.MetaFile, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	it := el.Value.(*cacheItem)
	if now.After(it.expires) {
		c.remove(el)
		return nil, false
	}
	c.order.MoveToFront(el)
	return it.mf, true
}

func (c *byteCache) put(key string, mf *metav1.MetaFile, now time.Time) {
	size := int64(len(mf.GetContent()))
	if size > c.maxBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.remove(el)
	}
	c.items[key] = c.order.PushFront(&cacheItem{key: key, mf: mf, expires: now.Add(c.ttl)})
	c.bytes += size
	for c.bytes > c.maxBytes {
		c.remove(c.order.Back())
	}
}

func (c *byteCache) size() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytes
}

// remove drops one element. Callers hold mu.
func (c *byteCache) remove(el *list.Element) {
	it := el.Value.(*cacheItem)
	c.order.Remove(el)
	delete(c.items, it.key)
	c.bytes -= int64(len(it.mf.GetContent()))
}
