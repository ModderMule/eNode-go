package ed2k

import (
	"context"

	"enode/storage"
)

// MetaSearcher supplies torrent and Usenet rows for a search (package meta). It is an
// interface so this package takes no dependency on the catalogue daemons' transport,
// and so tests can stand in a fixed answer.
//
// Search must return within its own deadline and must not fail: a slow or missing
// daemon yields fewer rows, never an error, because the eD2K answer is sent either way.
type MetaSearcher interface {
	Search(ctx context.Context, expr *storage.SearchExpr, udp bool) []storage.File
}

// SetMetaSearcher attaches the meta searcher. advertiseToLegacy sends its rows to
// every client; when false only a client that asked for them receives them — the
// SrvCapMetaSearch login bit on TCP, the SrvCapUDPMetaSearch flag of
// OP_GLOBSEARCHREQ3 on UDP.
//
// Like SetGossipHandler it must be called before the listeners bind: the field is
// read without a lock by every search. nil leaves searches exactly as they were.
func (s *ServerRuntime) SetMetaSearcher(m MetaSearcher, advertiseToLegacy bool) {
	s.meta = m
	s.metaAdvertiseLegacy = advertiseToLegacy
}

// metaSearchFor reports whether a requester gets meta rows. capable is whether it
// announced it can act on them.
func (s *ServerRuntime) metaSearchFor(capable bool) bool {
	return s.meta != nil && (s.metaAdvertiseLegacy || capable)
}

// startMetaSearch begins the meta half of a search alongside the storage query, so
// the two run concurrently and the reply waits for the slower of them, not their
// sum. It returns nil when this requester gets no meta rows.
func (s *ServerRuntime) startMetaSearch(expr *storage.SearchExpr, capable, udp bool) <-chan []storage.File {
	if !s.metaSearchFor(capable) {
		return nil
	}
	ch := make(chan []storage.File, 1)
	go func() {
		ch <- s.meta.Search(context.Background(), expr, udp)
	}()
	return ch
}

// mergeMetaResults appends the meta rows to the eD2K results. eD2K files come first
// — they are what a stock client can download — and the total stays within
// storage.MaxSearchResults, the ceiling paging and every engine already assume. A
// meta row whose hash an eD2K row already has is dropped; the OP_OFFERFILES guard
// makes that impossible for a pseudo-hash, so this only defends the page invariant.
func mergeMetaResults(files []storage.File, metaCh <-chan []storage.File) []storage.File {
	if metaCh == nil {
		return files
	}
	meta := <-metaCh
	if len(meta) == 0 {
		return files
	}
	seen := make(map[string]struct{}, len(files))
	for _, f := range files {
		seen[string(f.Hash)] = struct{}{}
	}
	for _, m := range meta {
		if len(files) >= storage.MaxSearchResults {
			break
		}
		if _, dup := seen[string(m.Hash)]; dup {
			continue
		}
		seen[string(m.Hash)] = struct{}{}
		files = append(files, m)
	}
	return files
}

// udpSearchFlags returns the CT_SERVER_UDPSEARCH_FLAGS value from an OP_GLOBSEARCHREQ3
// tag block. The tag's id, 0x0e, is decoded under TagSearchTree's name.
func udpSearchFlags(tags []NamedTag) uint32 {
	for _, t := range tags {
		if t.Name != tagName(TagSearchTree) {
			continue
		}
		if v, ok := t.Value.(uint64); ok {
			return uint32(v)
		}
		return 0
	}
	return 0
}
