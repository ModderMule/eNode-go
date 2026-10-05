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
	"golang.org/x/sync/singleflight"
)

// Network names, as the meta package spells them.
const (
	networkTorrent = "torrent"
	networkUsenet  = "usenet"
	// networkKad has no metafiles: its rows are eD2K files. It is a network of
	// MetaApi.Search only.
	networkKad = "kad"
)

// MetaFileSource fetches metafiles from the catalogue daemons. *meta.Searcher is one.
type MetaFileSource interface {
	FetchMetaFile(ctx context.Context, network, catalogID string) (*metav1.MetaFile, error)
	Networks() []string
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
		}
	}
	return out
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
	network := networkFor(parsed.Kind)
	if f.source == nil {
		// Meta search is off, so no daemon owns any row.
		return nil, &FetchError{Code: connect.CodeNotFound, MsgCode: CodeNotFound, cause: errors.New("meta search is disabled")}
	}
	if network == "" {
		return nil, &FetchError{Code: connect.CodeInvalidArgument, MsgCode: CodeInvalidRequest, cause: fmt.Errorf("kind %s", parsed.Kind)}
	}
	if !slices.Contains(f.source.Networks(), network) {
		return nil, &FetchError{Code: connect.CodeNotFound, MsgCode: CodeNotFound, cause: fmt.Errorf("%s search is not enabled", network)}
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
		return f.fetch(fctx, hash, parsed.Kind, network, catalogID)
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
	if kind == metav1.MetaKind_META_KIND_NZB {
		return "application/x-nzb"
	}
	return "application/x-bittorrent"
}

func (f *Fetcher) fetch(ctx context.Context, hash metahash.Hash, kind metahash.Kind, network, catalogID string) (*metav1.MetaFile, error) {
	mf, err := f.source.FetchMetaFile(ctx, network, catalogID)
	if err != nil {
		fe := classify(err)
		switch fe.Code {
		case connect.CodeNotFound:
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

func networkFor(kind metahash.Kind) string {
	switch kind {
	case metahash.KindBTV1, metahash.KindBTV2:
		return networkTorrent
	case metahash.KindNZB:
		return networkUsenet
	default:
		return ""
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
