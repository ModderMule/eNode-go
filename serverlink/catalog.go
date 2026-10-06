package serverlink

import (
	"context"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"time"

	"enode/logging"
	"enode/meta"
	"enode/storage"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/model"
	"github.com/ModderMule/enodemeta/pbconv"
	"github.com/ModderMule/enodemeta/tags"
)

// NetworkServers is the name of the catalogue network this package answers for
// MetaApi.Search: META_NETWORK_SERVERS, the eD2K files servers know.
const NetworkServers = "servers"

// maxCatalogCalls bounds the calls one search makes to one peer when the peer
// caps its pages below the window.
const maxCatalogCalls = 10

// OwnFiles searches the files this server's own users share. A storage.Engine
// is one.
type OwnFiles interface {
	FindBySearch(*storage.SearchExpr) []storage.File
}

// CatalogConfig configures the answers to MetaApi.Search.
type CatalogConfig struct {
	// Own is the server's file index. Nil leaves its files out.
	Own OwnFiles
	// Window is the most files one search answers.
	Window int
	// Timeout bounds one peer's answer.
	Timeout time.Duration
	// MaxEntries and TTL size the cache of answers; an entry is one search's
	// whole list.
	MaxEntries int
	TTL        time.Duration
}

// catalog is the searcher's MetaApi.Search half.
type catalog struct {
	cfg   CatalogConfig
	cache *meta.Cache[catalogAnswer]
}

// catalogAnswer is one search's whole answer, in the order it is paged in.
type catalogAnswer struct {
	releases []meta.Release
	// exact is false when a peer could not be asked or the list was cut.
	exact bool
}

// EnableCatalog turns on SearchCatalog. Call it before Start.
func (s *Searcher) EnableCatalog(cfg CatalogConfig) {
	if cfg.Window <= 0 {
		cfg.Window = storage.MaxSearchResults
	}
	s.catalog = &catalog{
		cfg:   cfg,
		cache: meta.NewValueCache[catalogAnswer](cfg.MaxEntries, cfg.TTL, nil),
	}
}

// CatalogEnabled reports whether EnableCatalog was called. Nil-receiver safe.
func (s *Searcher) CatalogEnabled() bool {
	return s != nil && s.catalog != nil
}

// SearchCatalog returns chunk k of the answer to req: the files this server's
// users share and the files of the other servers, each once and the server's
// own first among equals. req's limit, offset and network are ignored.
//
// The whole answer is computed once and cached, so paging it asks no peer again
// and a page is the same on every call while the cache holds it. Entries are
// eD2K files shaped like a Kad row. None names a client: they are built from a
// file's description and its two counts.
func (s *Searcher) SearchCatalog(ctx context.Context, req *metav1.SearchRequest, k int) (meta.Chunk, error) {
	if s.catalog == nil {
		return meta.Chunk{}, meta.ErrCatalogOff
	}
	answer, err := s.catalog.cache.Get(ctx, meta.CatalogKey(req), func() (catalogAnswer, error) {
		return s.catalogAnswer(ctx, req), nil
	})
	if err != nil {
		return meta.Chunk{}, err
	}
	start := min(k*meta.ChunkSize, len(answer.releases))
	end := min(start+meta.ChunkSize, len(answer.releases))
	return meta.Chunk{
		Releases:   answer.releases[start:end],
		Total:      uint64(len(answer.releases)),
		TotalExact: answer.exact,
		More:       end < len(answer.releases),
	}, nil
}

// -- internals ---------------------------------------------------------------

// catalogAnswer computes one search's list.
func (s *Searcher) catalogAnswer(ctx context.Context, req *metav1.SearchRequest) catalogAnswer {
	c := s.catalog.cfg
	q := model.ServerSearchQuery{
		Query:   req.GetQuery(),
		Exclude: req.GetExclude(),
		Type:    req.GetType(),
		MinSize: req.GetMinSize(),
		MaxSize: req.GetMaxSize(),
	}
	// The source filter is applied by hand: another server's count is capped
	// here, and the search tree would compare the cap.
	expr, ok := searchExpr(q)
	if !ok {
		return catalogAnswer{exact: true}
	}
	minSources := req.GetMinSeeders()
	exact := true

	merged := newMerge()
	if c.Own != nil {
		own := shared(slices.Clone(c.Own.FindBySearch(expr)))
		merged.add(slices.DeleteFunc(own, func(f storage.File) bool { return f.Sources < minSources }))
	}
	ownCount := len(merged.files)

	// Other servers' files go into a merge of their own, so that their counts
	// meet each other but never the server's own row.
	others := newMerge()
	if s.mirror != nil {
		others.add(s.mirror.Search(expr, c.Window))
	}
	if s.cfg.Live {
		type result struct {
			rows []storage.File
			ok   bool
		}
		var asked []chan result
		for _, p := range s.peerList() {
			if p.mirrored.Load() {
				continue
			}
			if p.isDown() {
				exact = false
				continue
			}
			ch := make(chan result, 1)
			asked = append(asked, ch)
			go func(p *peer) {
				rows, err := s.catalogLive(ctx, p, q, minSources, expr)
				ch <- result{rows, err == nil}
			}(p)
		}
		for _, ch := range asked {
			r := <-ch
			others.add(r.rows)
			exact = exact && r.ok
		}
	}
	peerMin := min(minSources, tags.MaxSources)
	for _, f := range others.files {
		if f.Sources < peerMin {
			continue
		}
		key := mergeKey{size: f.Size}
		copy(key.hash[:], f.Hash)
		if _, mine := merged.index[key]; mine {
			continue
		}
		merged.files = append(merged.files, f)
	}

	files := sortCatalog(merged.files, req)
	if len(files) > c.Window {
		files, exact = files[:c.Window], false
	}
	out := catalogAnswer{exact: exact, releases: make([]meta.Release, 0, len(files))}
	for _, f := range files {
		entry, err := catalogEntry(f)
		if err != nil {
			logging.Debugf("server search catalogue: dropped %x: %v", f.Hash, err)
			continue
		}
		out.releases = append(out.releases, meta.Release{entry})
	}
	logging.Debugf("server search catalogue: %q own=%d others=%d answered=%d", q.Query, ownCount, len(others.files), len(out.releases))
	return out
}

// catalogLive asks one peer for up to the window, following its paging.
func (s *Searcher) catalogLive(ctx context.Context, p *peer, q model.ServerSearchQuery, minSources uint32, expr *storage.SearchExpr) ([]storage.File, error) {
	c := s.catalog.cfg
	callCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	var out []storage.File
	offset := uint32(0)
	for calls := 0; calls < maxCatalogCalls && len(out) < c.Window; calls++ {
		p.liveCalls.Add(1)
		res, err := p.client.SearchFiles(callCtx, &metav1.ServerSearchRequest{
			Query:      strings.Join(storage.SearchTerms(q.Query), " "),
			Exclude:    q.Exclude,
			Type:       q.Type,
			MinSize:    q.MinSize,
			MaxSize:    q.MaxSize,
			MinSources: minSources,
			Limit:      uint32(c.Window - len(out)),
			Offset:     offset,
		})
		if err != nil {
			p.noteError(err, "search")
			return out, err
		}
		for _, f := range fromPeer(pbconv.ServerFilesFromProto(res.GetFiles())) {
			if storage.MatchSearchExpr(expr, f) {
				out = append(out, f)
			}
		}
		next := res.GetNextOffset()
		if next == 0 || next <= offset {
			break
		}
		offset = next
	}
	p.rows.Add(int64(len(out)))
	return out, nil
}

// sortCatalog orders an answer: by size when the request sorts by size, and
// otherwise by sources, most first. A server knows no age and scores no
// relevance, so every other sort is that order too. Ties fall back to the hash,
// which makes the order the same every time it is computed.
func sortCatalog(files []storage.File, req *metav1.SearchRequest) []storage.File {
	files = sortFiles(files)
	if req.GetSort() == metav1.SearchSort_SEARCH_SORT_SIZE {
		ascending := req.GetSortAscending()
		slices.SortStableFunc(files, func(a, b storage.File) int {
			switch {
			case a.Size == b.Size:
				return 0
			case (a.Size < b.Size) == ascending:
				return -1
			}
			return 1
		})
	}
	return files
}

// catalogEntry is a file as MetaApi.Search answers it: an eD2K entry with the
// fields a Kad row carries. It is the only place a file becomes an entry, and a
// storage.File's source address is not among what it reads.
func catalogEntry(f storage.File) (*metav1.MetaEntry, error) {
	return meta.MintEntry(&metav1.MetaEntry{
		Kind:      metav1.MetaKind_META_KIND_ED2K,
		Identity:  slices.Clone(f.Hash),
		CatalogId: "ed2k:" + strings.ToUpper(hex.EncodeToString(f.Hash)) + ":" + strconv.FormatUint(f.Size, 10),
		Name:      f.Name,
		Size:      f.Size,
		Type:      f.Type,
		Seeders:   f.Completed,
		Peers:     f.Sources,
		FileCount: 1,
	})
}
