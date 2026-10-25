package storage

import (
	"math"
	"strings"
	"unicode"
)

// manticoreMinInfix is the min_infix_len the default table options set: the
// shortest run a `*run*` wildcard expands. A shorter run matched as a wildcard
// finds nothing at all, so it is looked up as a whole keyword instead.
const manticoreMinInfix = 2

// manticoreQuery is a search tree rendered for Manticore. A tree turns into three
// parts because Manticore evaluates them in three different places:
//
//	match  — the MATCH() expression over the text fields (name, title, artist, album)
//	filter — the WHERE expression over the per-source attributes, with its args
//	agg    — the constraints on a file's source counters, which only exist once the
//	         sources are grouped per file
type manticoreQuery struct {
	match  string
	filter string
	args   []any
	agg    *aggNode
}

// manticoreOutcome says what a tree became.
type manticoreOutcome int

const (
	// manticoreRun: the query is complete and can be run.
	manticoreRun manticoreOutcome = iota
	// manticoreEmpty: the tree constrains nothing or nothing can satisfy it. The
	// SQL engines return no rows for either, and so does this.
	manticoreEmpty
	// manticoreUnsupported: Manticore cannot express the tree — a keyword OR-ed
	// with an attribute, a negated keyword with no keyword to subtract it from, a
	// term with no letter or digit in it. The caller runs it on the database.
	manticoreUnsupported
)

// aggNode is a constraint over a file's grouped counters, as a tree because a
// client can combine them freely. A single leaf is pushed into HAVING; anything
// larger is checked in Go on the grouped rows (Manticore's HAVING takes exactly
// one condition).
type aggNode struct {
	kind  SearchKind // SearchAnd, SearchOr, SearchAndNot, or SearchUInt64 for a leaf
	tag   uint8      // SearchTagSources or SearchTagComplete
	op    uint8
	value uint64
	left  *aggNode
	right *aggNode
}

// buildManticoreQuery renders a search tree for Manticore.
func buildManticoreQuery(expr *SearchExpr) (manticoreQuery, manticoreOutcome) {
	node := manticoreNode(expr)
	switch {
	case node.unsupported:
		return manticoreQuery{}, manticoreUnsupported
	case node.prune, node.contradiction:
		return manticoreQuery{}, manticoreEmpty
	}
	return manticoreQuery{match: node.match, filter: node.filter, args: node.args, agg: node.agg}, manticoreRun
}

// having is the single HAVING condition the agg tree can be pushed down as, or ""
// when it has to be checked in Go.
func (q manticoreQuery) having() (string, []any) {
	if q.agg == nil || q.agg.kind != SearchUInt64 {
		return "", nil
	}
	return aggColumn(q.agg.tag) + " " + sqlOperators[q.agg.op] + " ?", []any{clampInt64(q.agg.value)}
}

// matches evaluates the agg tree against one grouped row.
func (a *aggNode) matches(sources, completed uint64) bool {
	if a == nil {
		return true
	}
	switch a.kind {
	case SearchAnd:
		return a.left.matches(sources, completed) && a.right.matches(sources, completed)
	case SearchOr:
		return a.left.matches(sources, completed) || a.right.matches(sources, completed)
	case SearchAndNot:
		return a.left.matches(sources, completed) && !a.right.matches(sources, completed)
	default:
		have := sources
		if a.tag == SearchTagComplete {
			have = completed
		}
		return CompareSearchValue(a.op, have, a.value)
	}
}

// mNode is one subtree on its way to a manticoreQuery. prune and contradiction
// mean exactly what they mean for whereNode, and are combined by the same rules,
// so every engine prunes the same tree the same way.
type mNode struct {
	prune         bool
	contradiction bool
	unsupported   bool

	match  string
	filter string
	args   []any
	agg    *aggNode
}

var (
	mPruned        = mNode{prune: true}
	mContradiction = mNode{contradiction: true}
	mUnsupported   = mNode{unsupported: true}
)

func manticoreNode(expr *SearchExpr) mNode {
	if expr == nil {
		return mPruned
	}
	switch expr.Kind {
	case SearchText:
		return manticoreTextLeaf("name", expr.Text)
	case SearchString:
		if expr.TagType == searchTypeText {
			return manticoreTextLeaf("name", expr.ValueString)
		}
		switch expr.TagType {
		case searchTypeFileType:
			return mNode{filter: "type = ?", args: []any{NormalizeSearchFileType(expr.ValueString)}}
		case searchTypeExt:
			return mNode{filter: "ext = ?", args: []any{expr.ValueString}}
		case searchTypeCodec:
			return mNode{filter: "codec = ?", args: []any{expr.ValueString}}
		}
		if field, ok := mediaStringField(expr.TagType); ok {
			// An empty value is LIKE '%%' on the database, which every row meets: a
			// constraint no MATCH can state.
			if strings.TrimSpace(expr.ValueString) == "" {
				return mUnsupported
			}
			return manticoreTextLeaf(field, expr.ValueString)
		}
		return mPruned
	case SearchUInt32, SearchUInt64:
		tag, op, ok := NumericConstraint(expr)
		if !ok {
			return mPruned
		}
		switch tag {
		case SearchTagSources, SearchTagComplete:
			return mNode{agg: &aggNode{kind: SearchUInt64, tag: tag, op: op, value: expr.ValueUint}}
		}
		attr, ok := manticoreNumericAttr(tag)
		if !ok {
			return mPruned
		}
		return mNode{filter: attr + " " + sqlOperators[op] + " ?", args: []any{clampInt64(expr.ValueUint)}}
	case SearchHash:
		// A point lookup the database's hash index answers directly.
		return mUnsupported
	case SearchAnd, SearchOr, SearchAndNot:
		return combineManticoreNodes(expr.Kind, manticoreNode(expr.Left), manticoreNode(expr.Right))
	default:
		return mPruned
	}
}

// combineManticoreNodes follows combineWhereNodes step for step on prune and
// contradiction, then joins what is left part by part.
func combineManticoreNodes(kind SearchKind, left, right mNode) mNode {
	if kind == SearchAndNot {
		if right.prune || right.contradiction {
			return left
		}
		if left.prune {
			return mPruned
		}
		if left.contradiction {
			return mContradiction
		}
		if left.unsupported || right.unsupported {
			return mUnsupported
		}
		return andNotManticoreNodes(left, right)
	}

	if left.prune {
		return right
	}
	if right.prune {
		return left
	}

	if kind == SearchOr {
		if left.contradiction {
			return right
		}
		if right.contradiction {
			return left
		}
		if left.unsupported || right.unsupported {
			return mUnsupported
		}
		return orManticoreNodes(left, right)
	}

	if left.contradiction || right.contradiction {
		return mContradiction
	}
	if left.unsupported || right.unsupported {
		return mUnsupported
	}
	return andManticoreNodes(left, right)
}

// andManticoreNodes joins each part on its own: MATCH terms side by side, WHERE
// expressions with AND, counter constraints into an AND node.
func andManticoreNodes(left, right mNode) mNode {
	return mNode{
		match:  joinParts(left.match, right.match, " "),
		filter: joinParts(left.filter, right.filter, " AND "),
		args:   append(append([]any(nil), left.args...), right.args...),
		agg:    joinAgg(SearchAnd, left.agg, right.agg),
	}
}

// orManticoreNodes joins two nodes of one kind. A keyword OR-ed with an attribute
// is the one thing Manticore cannot run: MATCH and WHERE are both conjuncts of
// the statement, never alternatives.
func orManticoreNodes(left, right mNode) mNode {
	lk, rk := left.kinds(), right.kinds()
	if lk != rk || bitsSet(lk) != 1 {
		return mUnsupported
	}
	switch lk {
	case partMatch:
		// Each side in its own brackets: in Manticore's syntax OR binds tighter
		// than the implicit AND, so `a b | c` would mean a AND (b OR c).
		return mNode{match: "((" + left.match + ") | (" + right.match + "))"}
	case partFilter:
		return mNode{
			filter: "(" + left.filter + " OR " + right.filter + ")",
			args:   append(append([]any(nil), left.args...), right.args...),
		}
	default:
		return mNode{agg: joinAgg(SearchOr, left.agg, right.agg)}
	}
}

// andNotManticoreNodes subtracts a node of one kind. A keyword can only be
// subtracted from a MATCH that has a keyword of its own: Manticore refuses a
// query that is nothing but a negation.
func andNotManticoreNodes(left, right mNode) mNode {
	switch right.kinds() {
	case partMatch:
		if left.match == "" {
			return mUnsupported
		}
		out := left
		out.match = left.match + " -(" + right.match + ")"
		return out
	case partFilter:
		out := left
		out.filter = joinParts(left.filter, "NOT ("+right.filter+")", " AND ")
		out.args = append(append([]any(nil), left.args...), right.args...)
		return out
	case partAgg:
		out := left
		base := left.agg
		if base == nil {
			// Nothing to subtract from, so "not right" on its own.
			base = aggTrue
		}
		out.agg = &aggNode{kind: SearchAndNot, left: base, right: right.agg}
		return out
	default:
		return mUnsupported
	}
}

// aggTrue is the left side of a negation that stands alone: sources >= 0, which
// every file meets.
var aggTrue = &aggNode{kind: SearchUInt64, tag: SearchTagSources, op: SearchOpGreaterEqual}

// manticoreTextLeaf renders a keyword leaf as a MATCH group limited to one field.
//
// The words are split into runs exactly as the other engines split them
// (termRuns), and each run becomes:
//
//	*run*  — a substring of a word, the memory engine's semantics, through the
//	         min_infix_len index
//	run    — a whole word, for a run shorter than min_infix_len, which a wildcard
//	         would not find at all
//	"run"  — a phrase, for a run in a script without spaces (CJK, Thai): the
//	         ngram tokenizer indexes every character on its own, so the phrase
//	         is the characters in order
//
// A run holds only letters and digits (alnumRuns), so it can carry none of the
// characters Manticore's query syntax reserves. A term with no run at all — pure
// punctuation — is matched literally by the other engines and cannot be here.
func manticoreTextLeaf(field, text string) mNode {
	terms := splitTerms(text)
	if len(terms) == 0 {
		return mContradiction
	}
	var parts []string
	for _, term := range terms {
		runs := alnumRuns(term)
		if len(runs) == 0 {
			return mUnsupported
		}
		for _, run := range runs {
			parts = append(parts, manticoreRunTerms(strings.ToLower(run))...)
		}
	}
	return mNode{match: "(@" + field + " " + strings.Join(parts, " ") + ")"}
}

// manticoreRunTerms splits a run where it changes between a spaced and an
// unspaced script, since the tokenizer splits it there too.
func manticoreRunTerms(run string) []string {
	var out []string
	var b strings.Builder
	cont := false
	flush := func() {
		if b.Len() == 0 {
			return
		}
		seg := b.String()
		b.Reset()
		switch {
		case cont:
			out = append(out, `"`+seg+`"`)
		case len([]rune(seg)) < manticoreMinInfix:
			out = append(out, seg)
		default:
			out = append(out, "*"+seg+"*")
		}
	}
	for _, r := range run {
		c := isContinuousScript(r)
		if c != cont {
			flush()
			cont = c
		}
		b.WriteRune(r)
	}
	flush()
	return out
}

// isContinuousScript reports whether r belongs to a script written without
// spaces, the set Manticore's ngram_chars='cont' covers.
func isContinuousScript(r rune) bool {
	return unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul,
		unicode.Thai, unicode.Lao, unicode.Khmer, unicode.Myanmar, unicode.Tibetan)
}

// manticoreNumericAttr is the attribute a numeric leaf constrains. Sources and
// completed are not attributes but grouped counters, handled by the caller.
func manticoreNumericAttr(tag uint8) (string, bool) {
	switch tag {
	case SearchTagSize:
		return "size", true
	case SearchTagBitrate:
		return "bitrate", true
	case SearchTagLength:
		return "length", true
	}
	return "", false
}

// aggColumn is the select alias a counter constraint is checked against.
func aggColumn(tag uint8) string {
	if tag == SearchTagComplete {
		return "completed"
	}
	return "sources"
}

// clampInt64 keeps a client's value inside Manticore's signed bigint: a size
// above it compares as nothing at all otherwise.
func clampInt64(v uint64) uint64 {
	return min(v, math.MaxInt64)
}

// partKinds is which parts a node carries.
type partKinds uint8

const (
	partMatch partKinds = 1 << iota
	partFilter
	partAgg
)

func (n mNode) kinds() partKinds {
	var k partKinds
	if n.match != "" {
		k |= partMatch
	}
	if n.filter != "" {
		k |= partFilter
	}
	if n.agg != nil {
		k |= partAgg
	}
	return k
}

func bitsSet(k partKinds) int {
	n := 0
	for ; k != 0; k &= k - 1 {
		n++
	}
	return n
}

func joinParts(left, right, sep string) string {
	switch {
	case left == "":
		return right
	case right == "":
		return left
	case sep == " AND ":
		return "(" + left + sep + right + ")"
	}
	return left + sep + right
}

func joinAgg(kind SearchKind, left, right *aggNode) *aggNode {
	switch {
	case left == nil:
		return right
	case right == nil:
		return left
	}
	return &aggNode{kind: kind, left: left, right: right}
}
