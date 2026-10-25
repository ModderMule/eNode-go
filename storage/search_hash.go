package storage

import (
	"encoding/hex"
	"strings"
)

// FileKey names one file: its hash and size. Size 0 means any size.
type FileKey struct {
	Hash []byte
	Size uint64
}

// MaxRelatedSeeds is how many files one related search may name, as in Lugdunum
// 17.15's Is_related_search.
const MaxRelatedSeeds = 32

// hashTermPrefixes are the forms Lugdunum 17.15 reads a file hash from
// (Is_ed2k_search). Each gives the hash only; the size-carrying forms are parsed
// by ParseHashTerm itself.
var hashTermPrefixes = []string{
	"magnet:?xt=urn:ed2khash:",
	"magnet:?xt=urn:ed2k:",
	"magnet:?xt=ed2k:",
}

// ParseHashTerm reads a search term that asks for one file by its hash. It
// accepts the forms Lugdunum 17.15 accepts (Is_ed2k_search):
//
//	ed2k::HASH                         hash only (what eMule sends for a pasted link)
//	ed2k:SIZE:HASH                     hash and size
//	ed2k://|file|NAME|SIZE|HASH|…      hash and size
//	<a href= ed2k://|file|NAME|SIZE|HASH|…
//	magnet:?xt=ed2k:HASH, magnet:?xt=urn:ed2k:HASH, magnet:?xt=urn:ed2khash:HASH
//
// HASH is 32 hex digits; whatever follows it is ignored, and a size of 0 means any
// size. A term in none of these forms, or with a bad hash, is not a hash term and
// stays an ordinary keyword. Web front ends query servers this way, for example
// ed2k.shortypower.org (ed2k-stats), which lists each server's answer for a hash.
func ParseHashTerm(text string) (hash []byte, size uint64, ok bool) {
	t := strings.TrimSpace(text)
	lower := strings.ToLower(t)
	switch {
	case strings.HasPrefix(lower, "<a href= ed2k://|file|"):
		return parseLinkTail(t[len("<a href= ed2k://|file|"):])
	case strings.HasPrefix(lower, "ed2k://|file|"):
		return parseLinkTail(t[len("ed2k://|file|"):])
	case strings.HasPrefix(lower, "ed2k:"):
		rest := t[len("ed2k:"):]
		size, n := leadingDigits(rest)
		if n >= len(rest) || rest[n] != ':' {
			return nil, 0, false
		}
		hash, ok := hexHash(rest[n+1:])
		return hash, size, ok
	}
	for _, p := range hashTermPrefixes {
		if strings.HasPrefix(lower, p) {
			hash, ok := hexHash(t[len(p):])
			return hash, 0, ok
		}
	}
	return nil, 0, false
}

// ParseRelatedTerm reads a related search, "files that the users sharing these
// also share": the prefix `related:` followed by up to MaxRelatedSeeds entries
// `[SIZE]:HASH`, separated by `:`. eMule sends `related::H1::H2`
// (srchybrid/SearchResultsWnd.cpp:1666-1688) and eMuleQt the same
// (src/gui/panels/SearchPanel.cpp:204). As in Lugdunum 17.15 (Is_related_search),
// reading stops at the first malformed entry; a term with no entry at all is not a
// related search.
func ParseRelatedTerm(text string) ([]FileKey, bool) {
	t := strings.TrimSpace(text)
	if len(t) < len("related:") || !strings.EqualFold(t[:len("related:")], "related:") {
		return nil, false
	}
	rest := t[len("related:"):]
	var seeds []FileKey
	for len(seeds) < MaxRelatedSeeds {
		size, n := leadingDigits(rest)
		if n >= len(rest) || rest[n] != ':' {
			break
		}
		hash, ok := hexHash(rest[n+1:])
		if !ok {
			break
		}
		seeds = append(seeds, FileKey{Hash: hash, Size: size})
		rest = rest[n+1+2*hashLen:]
		if rest == "" || rest[0] != ':' {
			break
		}
		rest = rest[1:]
	}
	return seeds, len(seeds) > 0
}

// FindRelated returns the seeds of the related leaf on the AND path from the root
// of expr, which is the only place Lugdunum acts on one. A related leaf under OR or
// NOT is pruned like an unsupported tag.
func FindRelated(expr *SearchExpr) ([]FileKey, bool) {
	if expr == nil {
		return nil, false
	}
	switch expr.Kind {
	case SearchRelated:
		return expr.Related, len(expr.Related) > 0
	case SearchAnd:
		if seeds, ok := FindRelated(expr.Left); ok {
			return seeds, true
		}
		return FindRelated(expr.Right)
	}
	return nil, false
}

// MatchRelatedFilter reports whether file passes the constraints AND-ed with a
// related leaf. The related leaf itself prunes, so a tree that is only the leaf
// constrains nothing and every related file passes.
func MatchRelatedFilter(expr *SearchExpr, file File) bool {
	matches, prune := (*searchMatcher)(nil).matchNode(expr, file, strings.ToLower(file.Name))
	return prune || matches
}

// searchPrunes reports whether the whole tree constrains nothing, so it matches no
// file. Pruning is decided by the shape of the tree alone, so any file will do.
func searchPrunes(expr *SearchExpr) bool {
	_, prune := (*searchMatcher)(nil).matchNode(expr, File{}, "")
	return prune
}

// matchHashLeaf is the per-file test of a SearchHash leaf.
func matchHashLeaf(expr *SearchExpr, file File) bool {
	if string(file.Hash) != expr.ValueString {
		return false
	}
	return expr.ValueUint == 0 || file.Size == expr.ValueUint
}

// parseLinkTail reads `NAME|SIZE|HASH` of an ed2k file link. Like Lugdunum, text
// between the size digits and the next `|` is skipped.
func parseLinkTail(s string) ([]byte, uint64, bool) {
	i := strings.IndexByte(s, '|')
	if i < 0 {
		return nil, 0, false
	}
	s = s[i+1:]
	size, n := leadingDigits(s)
	j := strings.IndexByte(s[n:], '|')
	if j < 0 {
		return nil, 0, false
	}
	hash, ok := hexHash(s[n+j+1:])
	return hash, size, ok
}

// leadingDigits parses the decimal digits s starts with, returning their value and
// how many there were. An overflowing value saturates; no real file is that large.
func leadingDigits(s string) (uint64, int) {
	var v uint64
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		d := uint64(s[n] - '0')
		if v > (^uint64(0)-d)/10 {
			v = ^uint64(0)
		} else {
			v = v*10 + d
		}
		n++
	}
	return v, n
}

// hexHash decodes the 32 hex digits s starts with.
func hexHash(s string) ([]byte, bool) {
	if len(s) < 2*hashLen {
		return nil, false
	}
	b, err := hex.DecodeString(s[:2*hashLen])
	if err != nil {
		return nil, false
	}
	return b, true
}
