// Package serverlink is the server-to-server search service: it answers other
// eD2K servers' searches and catalogue walks over this server's own files, and
// asks theirs. The contract is enodemeta's docs/server-search-contract.md; this
// side of it is docs/server-search.md.
//
// One rule shapes the package: a client is never identified to another server.
// Everything that leaves goes through toServerFile, which has no source to copy.
package serverlink

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"enode/internal/ratelimit"
	"enode/logging"
	"enode/meta"
	"enode/storage"

	"connectrpc.com/connect/v2"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/model"
	"github.com/ModderMule/enodemeta/pbconv"
)

// maxQueryBytes bounds a search query, as the Meta API does.
const maxQueryBytes = 256

// Catalog is the part of the storage engine the service reads: this server's
// own files, as its connected clients offer them.
type Catalog interface {
	FilesCount() int
	FindBySearch(*storage.SearchExpr) []storage.File
	BrowseFiles(cursor []byte, limit int) (files []storage.File, next []byte, err error)
}

// ServiceConfig is what the service serves and to whom.
type ServiceConfig struct {
	// Name is the server's display name, or a function for one that can change.
	Name func() string
	// Search and Browse say which calls answer.
	Search bool
	Browse bool
	// MaxSearchLimit and MaxBrowseLimit cap the files in one answer.
	MaxSearchLimit int
	MaxBrowseLimit int
	// BrowseMinInterval is the pause asked of a caller between two browse calls.
	BrowseMinInterval time.Duration
	// CacheEntries and CacheTTL size the cache that keeps a search's pages stable.
	CacheEntries int
	CacheTTL     time.Duration
	// PerIPPerMinute and PerPeerPerMinute cap calls; 0 disables a limit.
	PerIPPerMinute   int
	PerPeerPerMinute int
	// TrustForwardedFor takes the caller's address from X-Forwarded-For.
	TrustForwardedFor bool
	// Tokens are the configured peers' tokens. A caller presenting one is that peer.
	Tokens []string
	// Verified reports whether an address belongs to a server the gossip peer
	// table has verified. Nil admits nobody without a token.
	Verified func(net.IP) bool
	// Blocked reports whether the access filter refuses an address. May be nil.
	Blocked func(net.IP) bool
}

// Service implements metav1connect.ServerSearchHandler.
type Service struct {
	cfg     ServiceConfig
	catalog Catalog
	// epoch is drawn at start: a page token of another run of the server must not
	// be continued from, whatever the engine would make of its cursor.
	epoch uint64

	cache     *meta.Cache[[]storage.File]
	ipLimit   *ratelimit.Limiter
	peerLimit *ratelimit.Limiter
	stats     ServiceStats
}

// NewService returns the service over catalog.
func NewService(cfg ServiceConfig, catalog Catalog) *Service {
	var seed [8]byte
	_, _ = rand.Read(seed[:])
	return &Service{
		cfg:       cfg,
		catalog:   catalog,
		epoch:     binary.BigEndian.Uint64(seed[:]) | 1,
		cache:     meta.NewValueCache[[]storage.File](cfg.CacheEntries, cfg.CacheTTL, nil),
		ipLimit:   ratelimit.New(cfg.PerIPPerMinute),
		peerLimit: ratelimit.New(cfg.PerPeerPerMinute),
	}
}

// Stats returns the service's counters.
func (s *Service) Stats() *ServiceStats { return &s.stats }

// GetServerInfo describes the server to another one.
func (s *Service) GetServerInfo(ctx context.Context, _ *metav1.GetServerInfoRequest) (*metav1.ServerInfo, error) {
	if _, err := s.admit(ctx); err != nil {
		return nil, err
	}
	s.stats.InfoCalls.Add(1)
	info := model.ServerInfo{
		ContractVersion:          model.ServerContractVersion,
		Files:                    uint64(max(s.catalog.FilesCount(), 0)),
		SearchAvailable:          s.cfg.Search,
		BrowseAvailable:          s.cfg.Browse,
		MaxSearchLimit:           uint32(s.cfg.MaxSearchLimit),
		MaxBrowseLimit:           uint32(s.cfg.MaxBrowseLimit),
		BrowseMinIntervalSeconds: uint32(s.cfg.BrowseMinInterval / time.Second),
		CatalogEpoch:             s.epoch,
	}
	if s.cfg.Name != nil {
		info.Name = s.cfg.Name()
	}
	return pbconv.ServerInfoToProto(info), nil
}

// SearchFiles answers a keyword search, paged by offset over a cached result.
func (s *Service) SearchFiles(ctx context.Context, req *metav1.ServerSearchRequest) (*metav1.ServerSearchResponse, error) {
	if _, err := s.admit(ctx); err != nil {
		return nil, err
	}
	if !s.cfg.Search {
		return nil, connectError(connect.CodeUnimplemented, CodeSearchDisabled)
	}
	q := pbconv.ServerSearchQueryFromProto(req)
	if len(q.Query) > maxQueryBytes {
		return nil, connectError(connect.CodeInvalidArgument, CodeSearchQueryTooLong)
	}
	expr, ok := searchExpr(q)
	if !ok {
		return nil, connectError(connect.CodeInvalidArgument, CodeSearchQueryRequired)
	}
	s.stats.Searches.Add(1)

	files, err := s.cache.Get(ctx, searchKey(q), func() ([]storage.File, error) {
		return sortFiles(shared(s.catalog.FindBySearch(expr))), nil
	})
	if err != nil {
		return nil, connectError(connect.CodeUnavailable, CodeUnavailable)
	}

	limit := clampLimit(q.Limit, s.cfg.MaxSearchLimit)
	res := model.ServerSearchResult{Total: uint64(len(files))}
	if int(q.Offset) < len(files) {
		end := min(int(q.Offset)+limit, len(files))
		res.Files = toServerFiles(files[q.Offset:end])
		if end < len(files) {
			res.NextOffset = uint32(end)
		}
	}
	s.stats.FilesServed.Add(int64(len(res.Files)))
	return pbconv.ServerSearchResultToProto(res), nil
}

// BrowseFiles returns one page of a walk of the whole catalogue.
func (s *Service) BrowseFiles(ctx context.Context, req *metav1.BrowseFilesRequest) (*metav1.BrowseFilesResponse, error) {
	if _, err := s.admit(ctx); err != nil {
		return nil, err
	}
	if !s.cfg.Browse {
		return nil, connectError(connect.CodeUnimplemented, CodeBrowseDisabled)
	}
	q := pbconv.BrowseQueryFromProto(req)
	page := model.BrowsePage{CatalogEpoch: s.epoch, Total: uint64(max(s.catalog.FilesCount(), 0))}

	var cursor []byte
	if len(q.PageToken) != 0 {
		// A token is the epoch it was issued in, then the engine's cursor. One
		// too short to hold an epoch was never issued here.
		if len(q.PageToken) <= 8 {
			return nil, connectError(connect.CodeInvalidArgument, CodeCursorInvalid)
		}
		if binary.BigEndian.Uint64(q.PageToken) != s.epoch {
			return s.reset(page), nil
		}
		cursor = q.PageToken[8:]
	}

	files, next, err := s.catalog.BrowseFiles(cursor, clampLimit(q.Limit, s.cfg.MaxBrowseLimit))
	switch {
	case errors.Is(err, storage.ErrBrowseCursor):
		return s.reset(page), nil
	case err != nil:
		logging.Errorf("server search: browse failed: %v", err)
		return nil, connectError(connect.CodeUnavailable, CodeUnavailable)
	}
	s.stats.Browses.Add(1)
	page.Files = toServerFiles(files)
	if next != nil {
		page.NextPageToken = append(binary.BigEndian.AppendUint64(make([]byte, 0, 8+len(next)), s.epoch), next...)
	}
	s.stats.FilesServed.Add(int64(len(page.Files)))
	return pbconv.BrowsePageToProto(page), nil
}

// -- internals ---------------------------------------------------------------

// reset answers a token that can no longer be continued from.
func (s *Service) reset(page model.BrowsePage) *metav1.BrowseFilesResponse {
	s.stats.Resets.Add(1)
	page.Reset = true
	return pbconv.BrowsePageToProto(page)
}

// toServerFile is the one place a stored file becomes what another server sees.
// It copies the fields that describe the file and has none to copy that would
// say who shares it: storage.File's SourceID and SourcePort stay behind.
func toServerFile(f storage.File) model.ServerFile {
	return model.ServerFile{
		Hash:            f.Hash,
		Size:            f.Size,
		Name:            f.Name,
		Type:            f.Type,
		Sources:         f.Sources,
		CompleteSources: f.Completed,
		Title:           f.Title,
		Artist:          f.Artist,
		Album:           f.Album,
		RuntimeSeconds:  f.Runtime,
		Bitrate:         f.Bitrate,
		Codec:           f.Codec,
	}
}

func toServerFiles(files []storage.File) []model.ServerFile {
	out := make([]model.ServerFile, 0, len(files))
	for _, f := range files {
		out = append(out, toServerFile(f))
	}
	return out
}

// shared keeps the files a connected client offers now. An engine may still
// hold a file whose last source has gone, and the catalogue is not that.
func shared(files []storage.File) []storage.File {
	return slices.DeleteFunc(files, func(f storage.File) bool {
		return f.Sources == 0 || f.Meta != nil
	})
}

// sortFiles orders a search result the same way every time it is computed, so a
// page asked for again after the cache dropped it starts where it did before.
func sortFiles(files []storage.File) []storage.File {
	slices.SortFunc(files, func(a, b storage.File) int {
		if a.Sources != b.Sources {
			if a.Sources > b.Sources {
				return -1
			}
			return 1
		}
		if c := bytes.Compare(a.Hash, b.Hash); c != 0 {
			return c
		}
		switch {
		case a.Size < b.Size:
			return -1
		case a.Size > b.Size:
			return 1
		}
		return 0
	})
	return files
}

// searchExpr turns a query into the tree the engines search. ok is false when
// the query holds no keyword.
func searchExpr(q model.ServerSearchQuery) (*storage.SearchExpr, bool) {
	if len(storage.SearchTerms(q.Query)) == 0 {
		return nil, false
	}
	expr := &storage.SearchExpr{Kind: storage.SearchText, Text: q.Query}
	and := func(leaf *storage.SearchExpr) {
		expr = &storage.SearchExpr{Kind: storage.SearchAnd, Left: expr, Right: leaf}
	}
	if q.Type != "" {
		and(&storage.SearchExpr{Kind: storage.SearchString, TagType: storage.SearchFileTypeTag, ValueString: q.Type})
	}
	if q.MinSize > 0 {
		and(numericLeaf(storage.SearchTagSize, storage.SearchOpGreaterEqual, q.MinSize))
	}
	if q.MaxSize > 0 {
		and(numericLeaf(storage.SearchTagSize, storage.SearchOpLessEqual, q.MaxSize))
	}
	if q.MinSources > 0 {
		and(numericLeaf(storage.SearchTagSources, storage.SearchOpGreaterEqual, uint64(q.MinSources)))
	}
	for _, word := range q.Exclude {
		if len(storage.SearchTerms(word)) == 0 {
			continue
		}
		expr = &storage.SearchExpr{
			Kind:  storage.SearchAndNot,
			Left:  expr,
			Right: &storage.SearchExpr{Kind: storage.SearchText, Text: word},
		}
	}
	return expr, true
}

// numericLeaf builds a numeric constraint in the wire form the engines decode
// with storage.NumericConstraint: operator, a one-byte tag name, the tag id.
func numericLeaf(tag, op uint8, value uint64) *storage.SearchExpr {
	return &storage.SearchExpr{
		Kind:      storage.SearchUInt64,
		TagType:   uint32(op) | 1<<8 | uint32(tag)<<24,
		ValueUint: value,
	}
}

// searchKey is the cache key of a query: everything but the page asked for.
func searchKey(q model.ServerSearchQuery) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(strings.Join(strings.Fields(q.Query), " ")))
	for _, word := range q.Exclude {
		b.WriteString("\x00-")
		b.WriteString(strings.ToLower(word))
	}
	b.WriteString("\x00t" + q.Type)
	b.WriteString("\x00" + strconv.FormatUint(q.MinSize, 10))
	b.WriteString("\x00" + strconv.FormatUint(q.MaxSize, 10))
	b.WriteString("\x00" + strconv.FormatUint(uint64(q.MinSources), 10))
	return b.String()
}

// clampLimit applies the server's cap to a caller's limit; 0 asks for the cap.
func clampLimit(limit uint32, most int) int {
	if limit == 0 || int(limit) > most {
		return most
	}
	return int(limit)
}
