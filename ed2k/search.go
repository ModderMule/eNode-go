package ed2k

import (
	"fmt"

	"enode/storage"
)

// MaxSearchExprDepth bounds how deeply a boolean search expression may nest.
// Each 0x00 token costs 2 bytes and recurses twice, so without a limit a peer
// can drive the parser past Go's 1 GB stack ceiling — which is a runtime throw,
// not a panic, so no recover() could contain it.
//
// 24 matches eMule, which uses the same value when *building* an expression:
// srchybrid/kademlia/net/KademliaUDPListener.cpp:889 and
// src/core/kademlia/KadUDPListener.cpp:525. The C++ comment notes the parse
// limit has to match the generation limit, so a lower value here would reject
// queries real clients legitimately emit.
const MaxSearchExprDepth = 24

// MaxSearchExprLeaves bounds how many leaves (keywords and constraints) one search
// expression may carry. The depth limit alone still admits a balanced tree of
// thousands of leaves in one 64 KB datagram, and matching costs leaves x files — one
// such UDP search held the storage lock for seconds.
//
// eMule and eMuleQt fold a plain AND chain of keywords into a single leaf
// (srchybrid/SearchResultsWnd.cpp:783, src/core/search/SearchExprParser.cpp:894) and
// add at most 13 filter constraints, so a real tree stays near 15 leaves. 64 leaves
// headroom for hand-written OR/NOT queries.
const MaxSearchExprLeaves = 64

// ErrSearchTooManyLeaves is returned when an expression exceeds MaxSearchExprLeaves.
var ErrSearchTooManyLeaves = fmt.Errorf("search expression has more than %d leaves", MaxSearchExprLeaves)

func ParseSearchExpr(b *Buffer) (*storage.SearchExpr, error) {
	if b == nil {
		return nil, fmt.Errorf("search buffer is nil")
	}
	leaves := 0
	return parseSearchExpr(b, 0, &leaves)
}

func parseSearchExpr(b *Buffer, depth int, leaves *int) (*storage.SearchExpr, error) {
	if depth >= MaxSearchExprDepth {
		return nil, fmt.Errorf("search expression nested deeper than %d levels", MaxSearchExprDepth)
	}
	token, err := b.GetUInt8()
	if err != nil {
		return nil, err
	}
	// Counted before the leaf is read, so an oversized tree is refused as soon as it
	// crosses the limit rather than after the whole buffer has been parsed.
	if token != 0x00 {
		*leaves++
		if *leaves > MaxSearchExprLeaves {
			return nil, ErrSearchTooManyLeaves
		}
	}

	switch token {
	case 0x01:
		s, err := b.GetString()
		if err != nil {
			return nil, err
		}
		return &storage.SearchExpr{Kind: storage.SearchText, Text: s}, nil
	case TypeString:
		s, err := b.GetString()
		if err != nil {
			return nil, err
		}
		nameLen, code, err := readSearchTagName(b)
		if err != nil {
			return nil, err
		}
		// [len lo][len hi][code] read as a little-endian value, e.g. 0x00030001 for
		// FT_FILETYPE; any other name length leaves an unknown type that is pruned.
		typ := uint32(nameLen) | uint32(code)<<16
		return &storage.SearchExpr{Kind: storage.SearchString, TagType: typ, ValueString: s}, nil
	case TypeUint32:
		v, err := b.GetUInt32LE()
		if err != nil {
			return nil, err
		}
		typ, err := readSearchNumericType(b)
		if err != nil {
			return nil, err
		}
		return &storage.SearchExpr{Kind: storage.SearchUInt32, TagType: typ, ValueUint: uint64(v)}, nil
	case 0x08:
		lo, err := b.GetUInt32LE()
		if err != nil {
			return nil, err
		}
		hi, err := b.GetUInt32LE()
		if err != nil {
			return nil, err
		}
		typ, err := readSearchNumericType(b)
		if err != nil {
			return nil, err
		}
		val := uint64(lo) + uint64(hi)<<32
		return &storage.SearchExpr{Kind: storage.SearchUInt64, TagType: typ, ValueUint: val}, nil
	case 0x00:
		op, err := b.GetUInt8()
		if err != nil {
			return nil, err
		}
		// Only the boolean token recurses, so incrementing here counts nesting
		// levels rather than nodes — matching how eMule seeds and advances
		// iLevel in CreateSearchExpressionTree.
		left, err := parseSearchExpr(b, depth+1, leaves)
		if err != nil {
			return nil, err
		}
		right, err := parseSearchExpr(b, depth+1, leaves)
		if err != nil {
			return nil, err
		}
		kind := storage.SearchAnd
		switch op {
		case 0x01:
			kind = storage.SearchOr
		case 0x02:
			kind = storage.SearchAndNot
		}
		return &storage.SearchExpr{Kind: kind, Left: left, Right: right}, nil
	default:
		return nil, fmt.Errorf("unknown search token 0x%x", token)
	}
}

// readSearchTagName reads a leaf's tag name: a uint16 length, then the name. eMule
// names its tags by a one-byte id, but CSearchExprTarget can also write a string
// name (SearchResultsWnd.cpp WriteMetaDataSearchParam). Reading a fixed three bytes
// misframed every leaf after such a name; it is consumed whole now, and code is set
// only for the one-byte form.
func readSearchTagName(b *Buffer) (nameLen uint16, code uint8, err error) {
	nameLen, err = b.GetUInt16LE()
	if err != nil {
		return 0, 0, err
	}
	if b.Remaining() < int(nameLen) {
		return 0, 0, ErrOutOfBounds
	}
	name := b.Get(int(nameLen))
	if nameLen == 1 {
		code = name[0]
	}
	return nameLen, code, nil
}

// readSearchNumericType reads a numeric leaf's operator and tag name into the
// TagType storage decodes: op | nameLen<<8 | code<<24, the wire bytes read as one
// little-endian uint32 when the name is a one-byte id. Any other name length
// yields a type NumericConstraint rejects, so the leaf is pruned.
func readSearchNumericType(b *Buffer) (uint32, error) {
	op, err := b.GetUInt8()
	if err != nil {
		return 0, err
	}
	nameLen, code, err := readSearchTagName(b)
	if err != nil {
		return 0, err
	}
	return uint32(op) | uint32(nameLen)<<8 | uint32(code)<<24, nil
}
