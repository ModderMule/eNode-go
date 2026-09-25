package meta

import (
	"sort"
	"strconv"
	"strings"

	"enode/storage"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
)

// Query is what an eD2K search tree forwards to a daemon's Search: the keywords every
// result must contain, plus the constraints the MetaIngest request can express.
//
// The request is deliberately narrower than the tree. A daemon's Search takes "all of
// these keywords", so an OR branch cannot be forwarded and is dropped, which widens
// the query rather than narrowing it. Every row that comes back is then run through
// storage.MatchSearchExpr against the full tree, so the answer a client sees is exact
// even where the request was not.
type Query struct {
	Terms    []string
	Exclude  []string
	FileType string
	MinSize  uint64
	MaxSize  uint64
}

// BuildQuery extracts the forwardable part of a search tree. It reports false when
// no positive keyword survives: a daemon's Search needs one, and asking without one
// would fetch its best-ranked releases for a query that named nothing.
func BuildQuery(expr *storage.SearchExpr) (Query, bool) {
	var q Query
	q.walk(expr)
	q.Terms = dedupeFold(q.Terms)
	q.Exclude = dedupeFold(q.Exclude)
	return q, len(q.Terms) > 0
}

// Request renders the query as a MetaIngest SearchRequest asking for up to limit
// releases.
func (q Query) Request(limit int) *metav1.SearchRequest {
	return &metav1.SearchRequest{
		Query:   strings.Join(q.Terms, " "),
		Exclude: q.Exclude,
		MinSize: q.MinSize,
		MaxSize: q.MaxSize,
		Type:    q.FileType,
		Limit:   uint32(limit),
	}
}

// Key identifies the query for the result cache: two searches with the same key send
// the same request. Terms are compared case-insensitively and in any order, which is
// how a daemon's full-text match treats them.
func (q Query) Key() string {
	terms := sortedLower(q.Terms)
	exclude := sortedLower(q.Exclude)
	var b strings.Builder
	b.WriteString(strings.Join(terms, "\x1f"))
	b.WriteByte(0)
	b.WriteString(strings.Join(exclude, "\x1f"))
	b.WriteByte(0)
	b.WriteString(strings.ToLower(q.FileType))
	b.WriteByte(0)
	b.WriteString(strconv.FormatUint(q.MinSize, 10))
	b.WriteByte(0)
	b.WriteString(strconv.FormatUint(q.MaxSize, 10))
	return b.String()
}

// walk collects the constraints on the path of AND nodes from the root. A constraint
// under an OR is not required of every result, so it is not forwarded.
func (q *Query) walk(expr *storage.SearchExpr) {
	if expr == nil {
		return
	}
	switch expr.Kind {
	case storage.SearchText:
		q.Terms = append(q.Terms, storage.SearchTerms(expr.Text)...)
	case storage.SearchString:
		switch expr.TagType {
		case storage.SearchTermTag:
			q.Terms = append(q.Terms, storage.SearchTerms(expr.ValueString)...)
		case storage.SearchFileTypeTag:
			q.FileType = expr.ValueString
		}
	case storage.SearchUInt32, storage.SearchUInt64:
		switch expr.TagType {
		case storage.SearchSizeGtTag:
			// eD2K sends "greater than"; the daemon's min_size is inclusive.
			if min := expr.ValueUint + 1; min > q.MinSize {
				q.MinSize = min
			}
		case storage.SearchSizeLtTag:
			if expr.ValueUint > 0 {
				if max := expr.ValueUint - 1; q.MaxSize == 0 || max < q.MaxSize {
					q.MaxSize = max
				}
			}
		}
	case storage.SearchAnd:
		q.walk(expr.Left)
		q.walk(expr.Right)
	case storage.SearchAndNot:
		q.walk(expr.Left)
		if terms, ok := excludeTerms(expr.Right); ok {
			q.Exclude = append(q.Exclude, terms...)
		}
	}
}

// excludeTerms returns the words whose presence alone must drop a result. That holds
// for a single-word leaf and for an OR of them — NOT (a OR b) drops anything with a
// or b. It does not hold for NOT (a AND b) or a multi-word leaf, which only drop a
// result containing every word; forwarding those words one by one would discard rows
// the client asked for, so they are left to the post-filter.
func excludeTerms(expr *storage.SearchExpr) ([]string, bool) {
	if expr == nil {
		return nil, false
	}
	switch expr.Kind {
	case storage.SearchText:
		return singleTerm(expr.Text)
	case storage.SearchString:
		if expr.TagType == storage.SearchTermTag {
			return singleTerm(expr.ValueString)
		}
	case storage.SearchOr:
		left, okLeft := excludeTerms(expr.Left)
		right, okRight := excludeTerms(expr.Right)
		if okLeft && okRight {
			return append(left, right...), true
		}
	}
	return nil, false
}

func singleTerm(text string) ([]string, bool) {
	terms := storage.SearchTerms(text)
	if len(terms) != 1 {
		return nil, false
	}
	return terms, true
}

func dedupeFold(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		k := strings.ToLower(s)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}
	return out
}

func sortedLower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	sort.Strings(out)
	return out
}
