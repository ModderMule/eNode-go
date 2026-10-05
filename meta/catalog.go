package meta

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"enode/logging"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"google.golang.org/protobuf/proto"
)

// ChunkSize is how many releases one catalogue chunk covers: chunk k holds the
// daemon's releases at offsets [k*ChunkSize, (k+1)*ChunkSize). It matches the
// daemons' own per-call cap, so a chunk is usually one call.
const ChunkSize = 100

// maxChunkCalls bounds the calls one chunk may take when a daemon caps its pages
// below ChunkSize.
const maxChunkCalls = 10

// Errors of SearchCatalog.
var (
	// ErrNetworkDown: the network's daemon is paused after an error that will not
	// change on the next call (see downBackoff).
	ErrNetworkDown = errors.New("meta: network paused after an error")
	// ErrCatalogOff: EnableCatalog was not called.
	ErrCatalogOff = errors.New("meta: catalogue search is not enabled")
)

// Release is one catalogue release: its rows in daemon order, all sharing a
// catalog_id. A multi-file release has a whole-set row and one row per file.
type Release []*metav1.MetaEntry

// Chunk is one cached slice of a network's answer to a search.
type Chunk struct {
	Releases []Release
	// Total is what the daemon reported for the whole search; 0 = not counted.
	Total uint64
	// TotalExact reports that Total counts every match rather than bounding it.
	TotalExact bool
	// More reports that the daemon has releases past this chunk.
	More bool
}

// CatalogConfig configures MetaApi.Search's access to the daemons.
type CatalogConfig struct {
	// Timeout bounds the daemon calls of one chunk.
	Timeout    time.Duration
	MaxEntries int
	TTL        time.Duration
}

// EnableCatalog turns on SearchCatalog, with a chunk cache of its own: MetaApi paging
// must not evict the entries eD2K searches rely on, and the eD2K cache keeps lossy
// storage.File rows keyed without most of SearchRequest's filters.
func (s *Searcher) EnableCatalog(cfg CatalogConfig) {
	s.catalog = NewValueCache[Chunk](cfg.MaxEntries, cfg.TTL, nil)
	s.catalogTimeout = cfg.Timeout
}

// CatalogNetworks lists the networks SearchCatalog can query: enabled, with live
// search on. A network with live search off is one whose operator chose not to
// forward keywords to its daemon. A native network (Kad) is one of them: its rows
// are eD2K files, served with the file's own hash where the others carry a minted
// one.
func (s *Searcher) CatalogNetworks() []string {
	var out []string
	for _, src := range s.sources {
		if src.live {
			out = append(out, src.network)
		}
	}
	return out
}

// CatalogCacheEntries is how many chunks the catalogue cache holds.
func (s *Searcher) CatalogCacheEntries() int {
	if s.catalog == nil {
		return 0
	}
	return s.catalog.Len()
}

// SearchCatalog returns chunk k of network's answer to req, from the cache or the
// daemon. req's limit, offset and network are ignored; everything else is forwarded.
// Rows that fail validation are dropped, so a chunk can hold fewer than ChunkSize
// releases while More is still true.
func (s *Searcher) SearchCatalog(ctx context.Context, network string, req *metav1.SearchRequest, k int) (Chunk, error) {
	if s.catalog == nil {
		return Chunk{}, ErrCatalogOff
	}
	var src *source
	for _, candidate := range s.sources {
		if candidate.network == network && candidate.live {
			src = candidate
		}
	}
	if src == nil {
		return Chunk{}, ErrNetworkDisabled
	}
	if src.isDown() {
		return Chunk{}, ErrNetworkDown
	}
	base := normalizeRequest(req)
	key := network + "\x00" + requestKey(base) + "\x00" + strconv.Itoa(k)

	loaded := false
	chunk, err := s.catalog.Get(ctx, key, func() (Chunk, error) {
		loaded = true
		cctx, cancel := context.WithTimeout(ctx, s.catalogTimeout)
		defer cancel()
		return src.loadChunk(cctx, base, k)
	})
	switch {
	case loaded && err != nil:
		src.counters.catalogErrors.Add(1)
		src.noteError(err)
	case !loaded && err == nil:
		src.counters.catalogCacheHits.Add(1)
	}
	return chunk, err
}

// loadChunk asks the daemon for chunk k, following its next_offset when it caps a
// page below ChunkSize.
func (src *source) loadChunk(ctx context.Context, base *metav1.SearchRequest, k int) (Chunk, error) {
	start := uint32(k * ChunkSize)
	end := start + ChunkSize
	var (
		out     Chunk
		entries []*metav1.MetaEntry
	)
	for offset, calls := start, 0; offset < end && calls < maxChunkCalls; calls++ {
		req := proto.Clone(base).(*metav1.SearchRequest)
		req.Offset, req.Limit = offset, end-offset
		src.counters.catalogCalls.Add(1)
		resp, err := src.client.Search(ctx, req)
		if err != nil {
			return Chunk{}, err
		}
		src.noteLiveOK()
		if calls == 0 {
			out.Total, out.TotalExact = resp.GetTotal(), resp.GetTotalExact()
		}
		entries = append(entries, resp.GetEntries()...)
		next := resp.GetNextOffset()
		out.More = next != 0
		if next == 0 || next <= offset || next >= end {
			break
		}
		offset = next
	}

	byID := map[string]int{}
	for _, pb := range entries {
		entry, err := MintEntry(pb)
		if err != nil {
			logging.Debugf("meta catalogue %s: dropped row %q: %v", src.network, pb.GetCatalogId(), err)
			continue
		}
		if i, ok := byID[entry.GetCatalogId()]; ok {
			out.Releases[i] = append(out.Releases[i], entry)
			continue
		}
		byID[entry.GetCatalogId()] = len(out.Releases)
		out.Releases = append(out.Releases, Release{entry})
	}
	return out, nil
}

// normalizeRequest is req as forwarded: no paging or network, and keywords, excludes,
// kinds, categories, groups and the sort in a canonical order and case, so equal
// searches share cache entries.
func normalizeRequest(req *metav1.SearchRequest) *metav1.SearchRequest {
	out := proto.Clone(req).(*metav1.SearchRequest)
	out.Limit, out.Offset, out.Network = 0, 0, metav1.MetaNetwork_META_NETWORK_UNSPECIFIED
	out.Query = strings.Join(sortedLower(strings.Fields(out.GetQuery())), " ")
	out.Exclude = sortedLower(out.GetExclude())
	out.Type = strings.ToLower(out.GetType())
	kinds := slices.Clone(out.GetKinds())
	slices.Sort(kinds)
	out.Kinds = slices.Compact(kinds)
	categories := slices.Clone(out.GetCategories())
	slices.Sort(categories)
	out.Categories = slices.Compact(categories)
	// Newsgroup names are lower case on the wire and in every daemon's catalogue.
	out.Groups = slices.Compact(sortedLower(out.GetGroups()))
	// Relevance is the default order, and a ranked order has no direction.
	if rankedSort(out.GetSort()) {
		out.Sort, out.SortAscending = metav1.SearchSort_SEARCH_SORT_UNSPECIFIED, false
	}
	return out
}

// rankedSort reports whether sort is a relevance order, which is best-first only
// and cannot be compared across daemons.
func rankedSort(sort metav1.SearchSort) bool {
	switch sort {
	case metav1.SearchSort_SEARCH_SORT_UNSPECIFIED, metav1.SearchSort_SEARCH_SORT_RELEVANCE, metav1.SearchSort_SEARCH_SORT_BEST:
		return true
	default:
		return false
	}
}

func requestKey(req *metav1.SearchRequest) string {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(req)
	if err != nil {
		// A SearchRequest always marshals; fall back to its text form regardless.
		return req.String()
	}
	return string(b)
}
