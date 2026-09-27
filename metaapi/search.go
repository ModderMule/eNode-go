package metaapi

import (
	"context"
	"slices"
	"strings"
	"sync"

	"enode/internal/ratelimit"
	"enode/meta"

	"connectrpc.com/connect/v2"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"google.golang.org/protobuf/proto"
)

// MsgCodes of MetaApi.Search. Each must exist in every locales/*.json file.
const (
	CodeSearchQueryRequired = "search.query_required"
	CodeSearchQueryTooLong  = "search.query_too_long"
	CodeSearchUnavailable   = "search.unavailable"
	CodeSearchDisabled      = "search.disabled"
)

// Search request bounds.
const (
	defaultSearchLimit = 50
	maxQueryBytes      = 256
)

// CatalogSource answers MetaApi.Search from the catalogue daemons. *meta.Searcher is
// one.
type CatalogSource interface {
	SearchCatalog(ctx context.Context, network string, req *metav1.SearchRequest, chunk int) (meta.Chunk, error)
	CatalogNetworks() []string
}

// SearchConfig turns MetaApi.Search on.
type SearchConfig struct {
	Catalog CatalogSource
	// RequireAccount asks for an active account; it only applies with accounts on.
	RequireAccount bool
	// MaxLimit caps releases per page; Window is the deepest release reachable.
	MaxLimit            int
	Window              int
	PerIPPerMinute      int
	PerAccountPerMinute int
}

// catalogSearch is the Service's search half.
type catalogSearch struct {
	cfg    SearchConfig
	limits limits
}

// limits are one call type's rate limiters.
type limits struct {
	ip      *ratelimit.Limiter
	account *ratelimit.Limiter
}

// networkKinds are the MetaKinds each network's rows carry.
var networkKinds = map[string][]metav1.MetaKind{
	networkTorrent: {metav1.MetaKind_META_KIND_BT_V1, metav1.MetaKind_META_KIND_BT_V2},
	networkUsenet:  {metav1.MetaKind_META_KIND_NZB},
}

// Search pages through the torrent and Usenet catalogues. See the contract's
// MetaApi.Search for the paging rules.
func (s *Service) Search(ctx context.Context, req *metav1.SearchRequest) (*metav1.SearchResponse, error) {
	if s.search == nil {
		return nil, s.toConnectError(&FetchError{Code: connect.CodeUnimplemented, MsgCode: CodeSearchDisabled})
	}
	auth, ip := callAuth(ctx, s.trustForwardedFor)
	required := s.accounts != nil && s.search.cfg.RequireAccount
	if _, err := s.authorize(ctx, auth, ip, s.search.limits, required); err != nil {
		return nil, err
	}
	s.stats.Searches.Add(1)
	resp, err := s.search.run(ctx, req)
	if err != nil {
		return nil, s.toConnectError(err)
	}
	return resp, nil
}

// SearchNetworks lists the networks Search can query, in the MetaNetwork spelling.
func (s *Service) SearchNetworks() []metav1.MetaNetwork {
	if s.search == nil {
		return nil
	}
	var out []metav1.MetaNetwork
	for _, n := range s.search.cfg.Catalog.CatalogNetworks() {
		switch n {
		case networkTorrent:
			out = append(out, metav1.MetaNetwork_META_NETWORK_TORRENT)
		case networkUsenet:
			out = append(out, metav1.MetaNetwork_META_NETWORK_USENET)
		}
	}
	return out
}

func (c *catalogSearch) run(ctx context.Context, req *metav1.SearchRequest) (*metav1.SearchResponse, error) {
	if len(req.GetQuery()) > maxQueryBytes {
		return nil, &FetchError{Code: connect.CodeInvalidArgument, MsgCode: CodeSearchQueryTooLong}
	}
	if len(strings.Fields(req.GetQuery())) == 0 {
		return nil, &FetchError{Code: connect.CodeInvalidArgument, MsgCode: CodeSearchQueryRequired}
	}
	limit := int(req.GetLimit())
	if limit == 0 {
		limit = defaultSearchLimit
	}
	limit = min(limit, c.cfg.MaxLimit)
	offset := int(req.GetOffset())
	if offset >= c.cfg.Window {
		return &metav1.SearchResponse{}, nil
	}
	limit = min(limit, c.cfg.Window-offset)

	streams := c.streams(ctx, req, offset+limit)
	if len(streams) == 0 {
		return &metav1.SearchResponse{}, nil
	}
	page, more := mergePage(streams, offset, limit)

	failed := 0
	for _, st := range streams {
		if st.err != nil {
			failed++
		}
	}
	if failed == len(streams) && len(page) == 0 {
		return nil, &FetchError{Code: connect.CodeUnavailable, MsgCode: CodeSearchUnavailable, cause: streams[0].err}
	}

	resp := &metav1.SearchResponse{Window: uint32(c.cfg.Window)}
	resp.Total, resp.TotalExact = total(streams)
	for _, release := range page {
		resp.Entries = append(resp.Entries, release...)
	}
	if next := offset + len(page); more && next < c.cfg.Window {
		resp.NextOffset = uint32(next)
	}
	return resp, nil
}

// streams returns one release stream per network the request selects, with the
// request's kinds narrowed to that network's. The chunks a page of want releases
// needs are fetched concurrently across streams, so a page over two networks waits
// for the slower daemon, not for both in turn.
func (c *catalogSearch) streams(ctx context.Context, req *metav1.SearchRequest, want int) []*releaseStream {
	var out []*releaseStream
	for _, network := range c.cfg.Catalog.CatalogNetworks() {
		if !networkSelected(req.GetNetwork(), network) {
			continue
		}
		kinds := networkKinds[network]
		if len(req.GetKinds()) > 0 {
			kinds = slices.DeleteFunc(slices.Clone(kinds), func(k metav1.MetaKind) bool {
				return !slices.Contains(req.GetKinds(), k)
			})
			if len(kinds) == 0 {
				continue
			}
		}
		nreq := proto.Clone(req).(*metav1.SearchRequest)
		if len(req.GetKinds()) > 0 {
			nreq.Kinds = kinds
		}
		out = append(out, &releaseStream{
			maxChunks: c.cfg.Window/meta.ChunkSize + 1,
			load: func(k int) (meta.Chunk, error) {
				return c.cfg.Catalog.SearchCatalog(ctx, network, nreq, k)
			},
		})
	}
	// Prefetch what an even split of the first want releases needs from each stream.
	var wg sync.WaitGroup
	for _, st := range out {
		wg.Add(1)
		go func(st *releaseStream) {
			defer wg.Done()
			st.at(want / len(out))
		}(st)
	}
	wg.Wait()
	return out
}

// releaseStream is one network's releases for one search, read chunk by chunk as
// the merge asks for them.
type releaseStream struct {
	load      func(k int) (meta.Chunk, error)
	maxChunks int
	chunks    []meta.Chunk
	done      bool
	err       error
}

// at returns the stream's i-th release, loading chunks until it is reached or the
// stream ends. A failed load ends the stream and keeps the error.
func (st *releaseStream) at(i int) (meta.Release, bool) {
	for {
		n := 0
		for _, ch := range st.chunks {
			if i < n+len(ch.Releases) {
				return ch.Releases[i-n], true
			}
			n += len(ch.Releases)
		}
		if st.done {
			return nil, false
		}
		if len(st.chunks) >= st.maxChunks || (len(st.chunks) > 0 && !st.chunks[len(st.chunks)-1].More) {
			st.done = true
			return nil, false
		}
		ch, err := st.load(len(st.chunks))
		if err != nil {
			st.err, st.done = err, true
			return nil, false
		}
		st.chunks = append(st.chunks, ch)
	}
}

// mergePage alternates the streams' releases, one from each in turn, and returns
// the releases at [offset, offset+limit) and whether any stream has more past them.
// A stream that runs out drops out of the rotation.
func mergePage(streams []*releaseStream, offset, limit int) (page []meta.Release, more bool) {
	want := offset + limit
	next := make([]int, len(streams))
	var merged []meta.Release
	for len(merged) < want {
		progressed := false
		for i, st := range streams {
			if len(merged) == want {
				break
			}
			if release, ok := st.at(next[i]); ok {
				merged = append(merged, release)
				next[i]++
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	for i, st := range streams {
		if _, ok := st.at(next[i]); ok {
			more = true
			break
		}
	}
	if offset < len(merged) {
		page = merged[offset:]
	}
	return page, more
}

// total adds the daemons' counts, or reports 0 ("not counted") when any stream
// failed or returned releases without a count. The sum is exact only when every
// daemon's count was: one lower bound makes the whole sum one, and a network
// whose first chunk was never loaded was not counted at all.
func total(streams []*releaseStream) (sum uint64, exact bool) {
	exact = true
	for _, st := range streams {
		if st.err != nil {
			return 0, false
		}
		if len(st.chunks) == 0 {
			exact = false
			continue
		}
		first := st.chunks[0]
		if first.Total == 0 && len(first.Releases) > 0 {
			return 0, false
		}
		sum += first.Total
		exact = exact && first.TotalExact
	}
	return sum, exact
}

func networkSelected(want metav1.MetaNetwork, network string) bool {
	switch want {
	case metav1.MetaNetwork_META_NETWORK_UNSPECIFIED:
		return true
	case metav1.MetaNetwork_META_NETWORK_TORRENT:
		return network == networkTorrent
	case metav1.MetaNetwork_META_NETWORK_USENET:
		return network == networkUsenet
	default:
		return false
	}
}
