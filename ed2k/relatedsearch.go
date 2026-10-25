package ed2k

import (
	"enode/storage"
)

// Lugdunum's related search: for `related::HASH[::HASH…]` the server returns the
// files that the users sharing HASH also share, most common first (do_related_search
// in eserver 17.15). It is a TCP search only, advertised by FlagRelatedSearch; the
// UDP global search does not answer it, as Lugdunum does not.

const (
	// defaultRelatedMinClients is how many online users must share the searched
	// files before a related search answers. Lugdunum's author gives 5.
	defaultRelatedMinClients = 5
	// relatedMaxClients bounds the users of the seed files a related search walks,
	// as Lugdunum bounds its own walk. The value is ours: their bound is not
	// documented.
	relatedMaxClients = 500
)

// relatedSearch answers a search whose tree holds a related leaf on its AND path.
// Leaves AND-ed with it, such as a size or type filter, narrow the answer.
func (s *ServerRuntime) relatedSearch(expr *storage.SearchExpr, seeds []storage.FileKey) []storage.File {
	cfg := s.tcp()
	if !cfg.RelatedSearch {
		return nil
	}
	minClients := cfg.RelatedMinClients
	if minClients <= 0 {
		minClients = defaultRelatedMinClients
	}
	files := s.Storage.RelatedFiles(seeds, minClients, relatedMaxClients)
	kept := files[:0]
	for _, f := range files {
		if storage.MatchRelatedFilter(expr, f) {
			kept = append(kept, f)
		}
	}
	return s.withholdFiles(kept)
}

// isRelatedSearch reports whether expr is a related search.
func isRelatedSearch(expr *storage.SearchExpr) bool {
	_, ok := storage.FindRelated(expr)
	return ok
}
