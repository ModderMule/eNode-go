package storage

import (
	"path/filepath"
	"strings"
	"unicode"
)

type SearchKind int

const (
	SearchText SearchKind = iota
	SearchAnd
	SearchOr
	SearchAndNot
	SearchString
	SearchUInt32
	SearchUInt64
)

type SearchExpr struct {
	Kind        SearchKind
	Text        string
	TagType     uint32
	ValueString string
	ValueUint   uint64
	Left        *SearchExpr
	Right       *SearchExpr
}

const (
	searchTypeText     uint32 = 0x0000ff
	searchTypeAnd      uint32 = 0x000000
	searchTypeOr       uint32 = 0x000001
	searchTypeAndNot   uint32 = 0x000002
	searchTypeFileType uint32 = 0x030001
	searchTypeExt      uint32 = 0x040001
	searchTypeArtist   uint32 = 0xd00001
	searchTypeAlbum    uint32 = 0xd10001
	searchTypeTitle    uint32 = 0xd20001
	searchTypeCodec    uint32 = 0xd50001
	searchTypeSizeGt   uint32 = 0x02000101
	searchTypeSizeLt   uint32 = 0x02000102
	searchTypeSources  uint32 = 0x15000101
	searchTypeBitrate  uint32 = 0xd4000101
	searchTypeDuration uint32 = 0xd3000101
	searchTypeComplete uint32 = 0x30000101
)

// Comparison operators of a numeric search leaf (srchybrid/Opcodes.h:482-487). eMule
// sends every filter it offers in the search window as GreaterEqual or LessEqual
// (srchybrid/SearchResultsWnd.cpp:1035-1053); Greater and Less are the older dserver
// forms, still sent by other clients.
const (
	SearchOpEqual        uint8 = 0
	SearchOpGreater      uint8 = 1
	SearchOpLess         uint8 = 2
	SearchOpGreaterEqual uint8 = 3
	SearchOpLessEqual    uint8 = 4
	SearchOpNotEqual     uint8 = 5
)

// Tag ids a numeric leaf can constrain (srchybrid/Opcodes.h). Any other id, such as
// FT_FILERATING, has no stored column and prunes.
const (
	SearchTagSize     uint8 = 0x02
	SearchTagSources  uint8 = 0x15
	SearchTagComplete uint8 = 0x30
	SearchTagLength   uint8 = 0xd3
	SearchTagBitrate  uint8 = 0xd4
)

// SearchTermTag, SearchFileTypeTag, SearchExtTag, SearchSizeGtTag and SearchSizeLtTag
// are the tag types a caller outside this package needs to read a parsed tree: a
// SearchString leaf with SearchTermTag is a keyword, the others are constraints. A
// numeric leaf is better read through NumericConstraint, which covers every operator.
const (
	SearchTermTag     = searchTypeText
	SearchFileTypeTag = searchTypeFileType
	SearchExtTag      = searchTypeExt
	SearchSizeGtTag   = searchTypeSizeGt
	SearchSizeLtTag   = searchTypeSizeLt
)

// SearchTerms splits a keyword leaf into the terms the engines match one by one.
func SearchTerms(text string) []string {
	return splitTerms(text)
}

// NumericConstraint decodes a numeric leaf. Its TagType is the four bytes that follow
// the value on the wire — operator(1), tag-name length(2, always 1), tag id(1) — read
// as one little-endian uint32 (srchybrid/SearchResultsWnd.cpp:902-919). ok is false for
// a non-numeric leaf, a multi-byte tag name, or an operator outside 0-5.
func NumericConstraint(expr *SearchExpr) (tag, op uint8, ok bool) {
	if expr == nil || (expr.Kind != SearchUInt32 && expr.Kind != SearchUInt64) {
		return 0, 0, false
	}
	if (expr.TagType>>8)&0xffff != 1 {
		return 0, 0, false
	}
	op = uint8(expr.TagType)
	if op > SearchOpNotEqual {
		return 0, 0, false
	}
	return uint8(expr.TagType >> 24), op, true
}

// whereNode is a partially built WHERE clause. Three states matter and must not
// be conflated:
//
//	prune       — the node expresses no constraint (an unsupported tag). It is
//	              dropped and its siblings survive.
//	contradiction — a real constraint that nothing can satisfy (an all-whitespace
//	              text term). It propagates through AND, not through OR.
//	constraint  — ordinary SQL.
//
// Collapsing the first two into "" is what made a single unsupported tag
// discard the entire query, so callers got zero rows for a search that should
// have matched.
type whereNode struct {
	sql   string
	args  []any
	prune bool
}

func (n whereNode) contradiction() bool { return !n.prune && n.sql == "" }

var (
	prunedNode        = whereNode{prune: true}
	contradictionNode = whereNode{}
)

// BuildSearchWhere renders a search expression to a MySQL/MariaDB WHERE clause.
// dialect selects the full-text strategy for name terms (DialectMariaDB or
// DialectMySQL); see ftLeaf. An empty dialect is treated as DialectMariaDB.
func BuildSearchWhere(expr *SearchExpr, dialect string) (string, []any) {
	node := buildSearchNode(expr, dialect)
	// A tree that is entirely unsupported carries no constraint at all. Return
	// the empty clause so engines keep their existing "no results" guard rather
	// than running an unfiltered scan.
	if node.prune {
		return "", nil
	}
	return node.sql, node.args
}

func buildSearchWhere(expr *SearchExpr, dialect string) (string, []any) {
	return BuildSearchWhere(expr, dialect)
}

func buildSearchNode(expr *SearchExpr, dialect string) whereNode {
	if expr == nil {
		return prunedNode
	}
	switch expr.Kind {
	case SearchText:
		terms := splitTerms(expr.Text)
		if len(terms) == 0 {
			// An all-whitespace term is a real constraint that nothing meets —
			// distinct from an unsupported tag, and it must not be dropped.
			return contradictionNode
		}
		return ftLeaf(terms, dialect)
	case SearchString:
		if expr.TagType == searchTypeText {
			return buildSearchNode(&SearchExpr{Kind: SearchText, Text: expr.ValueString}, dialect)
		}
		switch expr.TagType {
		case searchTypeFileType:
			return whereNode{sql: "(s.type = ?)", args: []any{NormalizeSearchFileType(expr.ValueString)}}
		case searchTypeExt:
			return whereNode{sql: "(s.ext = ?)", args: []any{expr.ValueString}}
		case searchTypeCodec:
			return whereNode{sql: "(s.codec = ?)", args: []any{expr.ValueString}}
		default:
			if col, ok := mediaStringField(expr.TagType); ok {
				return whereNode{sql: "(s." + col + " LIKE ?)", args: []any{"%" + escapeLike(expr.ValueString) + "%"}}
			}
			return prunedNode
		}
	case SearchUInt32, SearchUInt64:
		tag, op, ok := NumericConstraint(expr)
		if !ok {
			return prunedNode
		}
		col, ok := sqlNumericColumn(tag)
		if !ok {
			return prunedNode
		}
		return whereNode{sql: "(" + col + " " + sqlOperators[op] + " ?)", args: []any{expr.ValueUint}}
	case SearchAnd, SearchOr, SearchAndNot:
		return combineWhereNodes(expr.Kind, buildSearchNode(expr.Left, dialect), buildSearchNode(expr.Right, dialect))
	default:
		return prunedNode
	}
}

func MatchSearchExpr(expr *SearchExpr, file File) bool {
	if expr == nil {
		return false
	}
	// The name is lowercased once per file rather than once per text leaf: matching
	// costs leaves x files, and the per-leaf copy dominated it.
	matches, prune := matchSearchExpr(expr, file, strings.ToLower(file.Name))
	// A query made entirely of unsupported tags constrains nothing, so it
	// matches nothing — the same answer the SQL engines give for that tree.
	if prune {
		return false
	}
	return matches
}

// CompareSearchValue applies a numeric leaf's operator: have <op> want. op must be one
// NumericConstraint accepted.
func CompareSearchValue(op uint8, have, want uint64) bool {
	switch op {
	case SearchOpEqual:
		return have == want
	case SearchOpGreater:
		return have > want
	case SearchOpLess:
		return have < want
	case SearchOpGreaterEqual:
		return have >= want
	case SearchOpLessEqual:
		return have <= want
	default:
		return have != want
	}
}

// matchSearchExpr evaluates an expression against one file, returning whether
// it matched and whether the node should be pruned (carried no constraint).
// lowerName is file.Name lowercased, computed once by MatchSearchExpr.
//
// It mirrors buildSearchNode's rules exactly. Before this existed the memory
// engine returned plain false for an unsupported leaf, so `supported OR
// unsupported` matched here but returned nothing from MySQL and MongoDB — the
// three engines gave different answers for identical input.
func matchSearchExpr(expr *SearchExpr, file File, lowerName string) (matches, prune bool) {
	if expr == nil {
		return false, true
	}
	switch expr.Kind {
	case SearchText:
		terms := splitTerms(expr.Text)
		if len(terms) == 0 {
			return false, false
		}
		for _, t := range terms {
			for _, run := range termRuns(strings.ToLower(t)) {
				if !strings.Contains(lowerName, run) {
					return false, false
				}
			}
		}
		return true, false
	case SearchString:
		if expr.TagType == searchTypeText {
			return matchSearchExpr(&SearchExpr{Kind: SearchText, Text: expr.ValueString}, file, lowerName)
		}
		switch expr.TagType {
		case searchTypeFileType:
			// Both sides: meta results keep the daemon's own Arc/Iso types.
			return strings.EqualFold(NormalizeSearchFileType(file.Type), NormalizeSearchFileType(expr.ValueString)), false
		case searchTypeExt:
			return strings.EqualFold(fileExt(file.Name), expr.ValueString), false
		case searchTypeCodec:
			return strings.EqualFold(file.Codec, expr.ValueString), false
		case searchTypeArtist:
			return containsFold(file.Artist, expr.ValueString), false
		case searchTypeAlbum:
			return containsFold(file.Album, expr.ValueString), false
		case searchTypeTitle:
			return containsFold(file.Title, expr.ValueString), false
		default:
			return false, true
		}
	case SearchUInt32, SearchUInt64:
		tag, op, ok := NumericConstraint(expr)
		if !ok {
			return false, true
		}
		var have uint64
		switch tag {
		case SearchTagSize:
			have = file.Size
		case SearchTagSources:
			have = uint64(file.Sources)
		case SearchTagComplete:
			have = uint64(file.Completed)
		case SearchTagBitrate:
			have = uint64(file.Bitrate)
		case SearchTagLength:
			have = uint64(file.Runtime)
		default:
			return false, true
		}
		return CompareSearchValue(op, have, expr.ValueUint), false
	case SearchAnd, SearchOr, SearchAndNot:
		leftMatch, leftPrune := matchSearchExpr(expr.Left, file, lowerName)
		rightMatch, rightPrune := matchSearchExpr(expr.Right, file, lowerName)

		if expr.Kind == SearchAndNot {
			if rightPrune {
				return leftMatch, leftPrune
			}
			if leftPrune {
				return false, true
			}
			return leftMatch && !rightMatch, false
		}
		if leftPrune {
			return rightMatch, rightPrune
		}
		if rightPrune {
			return leftMatch, false
		}
		if expr.Kind == SearchOr {
			return leftMatch || rightMatch, false
		}
		return leftMatch && rightMatch, false
	default:
		return false, true
	}
}

// combineWhereNodes joins two operands, dropping any that carry no constraint.
//
// Substituting a truth value for a pruned operand would be wrong: neutral-true
// under AND NOT turns `A AND NOT <unsupported>` into `A AND NOT TRUE`, which is
// empty. Removing the node from the tree is a different operation, and it is
// the one that preserves the user's intent.
func combineWhereNodes(kind SearchKind, left, right whereNode) whereNode {
	if kind == SearchAndNot {
		// Nothing meaningful to negate: keep the positive side as-is. That covers
		// both an unsupported right operand and NOT(matches-nothing), which is
		// unconstrained rather than universally true.
		if right.prune || right.contradiction() {
			return left
		}
		// Dropping the left operand would leave a bare NOT, which matches very
		// nearly the whole table — far wider than anything the client asked for.
		if left.prune {
			return prunedNode
		}
		if left.contradiction() {
			return contradictionNode
		}
		return joinWhereNodes(left, right, " AND NOT ")
	}

	if left.prune {
		return right
	}
	if right.prune {
		return left
	}

	if kind == SearchOr {
		// A contradiction is absorbed by the other branch rather than poisoning
		// it — this is where the memory engine and the SQL engines used to
		// disagree on identical input.
		if left.contradiction() {
			return right
		}
		if right.contradiction() {
			return left
		}
		return joinWhereNodes(left, right, " OR ")
	}

	if left.contradiction() || right.contradiction() {
		return contradictionNode
	}
	return joinWhereNodes(left, right, " AND ")
}

func joinWhereNodes(left, right whereNode, op string) whereNode {
	args := make([]any, 0, len(left.args)+len(right.args))
	args = append(args, left.args...)
	args = append(args, right.args...)
	return whereNode{sql: "(" + left.sql + op + right.sql + ")", args: args}
}

func splitTerms(text string) []string {
	return strings.Fields(strings.TrimSpace(text))
}

// escapeLike backslash-escapes the LIKE metacharacters % and _ (and the escape
// character itself) so a search term matches them literally — the way the memory
// engine (strings.Contains) and MongoDB (regexp.QuoteMeta) already do. Without
// this the three engines disagree: `50%` is a wildcard on MySQL but a literal
// elsewhere, the same class of cross-engine divergence as M9/C3.
//
// No explicit `ESCAPE` clause is emitted. LIKE's default escape character is the
// backslash regardless of sql_mode (NO_BACKSLASH_ESCAPES governs string- and
// identifier-literal parsing, not the LIKE operator, and these terms arrive as
// bound parameters, not literals). An explicit `ESCAPE '\\'` would be
// self-defeating — that clause is itself a string literal that NO_BACKSLASH_ESCAPES
// turns into two backslashes, which is not a single escape character.
func escapeLike(term string) string {
	return likeEscaper.Replace(term)
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func fileExt(name string) string {
	ext := filepath.Ext(name)
	if ext == "" {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(ext, "."))
}

// ftLeaf builds the WHERE fragment for a group of AND-ed name terms, using the
// full-text index as the access path instead of a leading-wildcard LIKE scan.
//
// Every term's indexable alphanumeric runs go into a single boolean-mode MATCH:
//
//	DialectMariaDB — `+run*` prefix operators: word-prefix matching, the only
//	                 strategy MariaDB can index.
//	DialectMySQL   — `+"run"` phrase operators over the ngram index: substring
//	                 candidates, then a residual `s.name LIKE '%run%'` per run
//	                 pins the exact substring (the MATCH is a superset).
//
// A term is matched run by run, never literally: `spider-man` must find
// `Spider.Man.avi`, as it does on the memory engine (termRuns). A run shorter than
// the server's minimum token size (e.g. the `x` of `x-men`) contributes
// `s.name LIKE '%run%'` instead of being dropped, which used to widen `x-men` to
// any name with `men` in it. A term with no run at all (punctuation only) keeps a
// literal LIKE. Because the MATCH is the index access path, a residual/short-run
// LIKE rides an indexed query; the only leading-`%` scan left is a leaf whose
// every run is sub-token-size, which is rare and unavoidable.
func ftLeaf(terms []string, dialect string) whereNode {
	minTok := ftMinTokenSize(dialect)

	var phrases []string // boolean-mode operators, joined into one MATCH probe
	parts := make([]string, 0, len(terms)+1)
	args := make([]any, 0, len(terms)+1)

	for _, t := range terms {
		for _, run := range alnumRuns(t) {
			if len([]rune(run)) < minTok {
				continue
			}
			phrases = append(phrases, ftPhrase(run, dialect))
		}
	}
	if len(phrases) > 0 {
		parts = append(parts, "MATCH(s.name) AGAINST (? IN BOOLEAN MODE)")
		args = append(args, strings.Join(phrases, " "))
	}

	for _, t := range terms {
		// The ngram MATCH only narrows to a superset, so every mysql run also
		// gets an exact-substring LIKE. A mariadb run is fully expressed by its
		// `+run*` prefix; only a run too short to index needs the LIKE fallback
		// (and that fallback is the sole sanctioned leading-`%`).
		for _, run := range termRuns(t) {
			if dialect == DialectMySQL || len([]rune(run)) < minTok {
				parts = append(parts, "s.name LIKE ?")
				args = append(args, "%"+escapeLike(run)+"%")
			}
		}
	}

	return whereNode{sql: "(" + strings.Join(parts, " AND ") + ")", args: args}
}

// ftMinTokenSize is the shortest term the full-text index can tokenize, which
// bounds when MATCH can stand in for a LIKE scan. It must track the server
// setting: ngram_token_size (default 2) for the mysql/ngram index, and
// innodb_ft_min_token_size (default 3) for the mariadb/word index.
func ftMinTokenSize(dialect string) int {
	if dialect == DialectMySQL {
		return 2
	}
	return 3
}

// ftPhrase renders one alphanumeric run as a required boolean-mode operator. The
// run holds only letters/digits (alnumRuns strips everything else), so it can
// carry no boolean operator or quote that would corrupt the AGAINST expression.
func ftPhrase(run, dialect string) string {
	if dialect == DialectMySQL {
		// A quoted phrase forces the bigrams to be adjacent, i.e. a contiguous
		// substring, rather than merely co-occurring.
		return `+"` + run + `"`
	}
	return "+" + run + "*"
}

// alnumRuns splits a term into maximal runs of Unicode letters/digits, the
// delimiters being exactly the characters a full-text tokenizer also drops.
// Splitting at least as aggressively as the tokenizer keeps the MATCH a superset
// of the term, so the residual LIKE never has to recover a false negative.
func alnumRuns(s string) []string {
	var runs []string
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			continue
		}
		if b.Len() > 0 {
			runs = append(runs, b.String())
			b.Reset()
		}
	}
	if b.Len() > 0 {
		runs = append(runs, b.String())
	}
	return runs
}

// termRuns is what a query word has to match: each of its alphanumeric runs, so
// separators inside the word (`spider-man`, `ac/dc`, `o'brien`) match any
// separator in the name, as they do on the full-text path. eMule's keyword lexer
// keeps such a word whole. A word with no run at all is matched literally.
func termRuns(term string) []string {
	if runs := alnumRuns(term); len(runs) > 0 {
		return runs
	}
	return []string{term}
}

// sqlOperators maps a numeric leaf's operator to SQL, indexed by SearchOp*.
var sqlOperators = [...]string{"=", ">", "<", ">=", "<=", "<>"}

// sqlNumericColumn is the column a numeric leaf's tag constrains. The counters live on
// files (f), the media properties on the offering source (s).
func sqlNumericColumn(tag uint8) (string, bool) {
	switch tag {
	case SearchTagSize:
		return "f.size", true
	case SearchTagSources:
		return "f.sources", true
	case SearchTagComplete:
		return "f.completed", true
	case SearchTagBitrate:
		return "s.bitrate", true
	case SearchTagLength:
		return "s.length", true
	}
	return "", false
}

// mediaStringField names the stored field an artist/album/title leaf matches: the
// same name in all three engines (a sources column, a source document field).
func mediaStringField(tagType uint32) (string, bool) {
	switch tagType {
	case searchTypeArtist:
		return "artist", true
	case searchTypeAlbum:
		return "album", true
	case searchTypeTitle:
		return "title", true
	}
	return "", false
}

// containsFold reports whether needle occurs in s, ignoring case. An artist, album or
// title constraint is a substring match — a user types part of a name, not all of it.
func containsFold(s, needle string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(needle))
}
