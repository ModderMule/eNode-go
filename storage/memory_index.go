package storage

import (
	"slices"
	"sort"
	"strings"
	"unicode"
)

// nameIndex is the memory engine's inverted index over file names. It narrows a
// search to candidate file ids; it never decides a match. FindBySearch re-checks
// every candidate with MatchSearchExpr, so the index only has to return a superset
// of the files that match, and search answers stay exactly what the full scan gave.
//
// Matching is by case-insensitive substring (matchSearchExpr), which a plain word
// index cannot answer: "bin" must still find "cabinet". So names are split into
// words — maximal runs of letters and digits of the lowercased name, the same
// alnumRuns a query term is split with — and a query run is looked up as a
// substring of the vocabulary, through a trigram index over the words. A query run
// holds only letters and digits, so wherever it occurs in a lowercased name it lies
// inside one word; the words containing it therefore cover every file it can match.
//
// Everything is guarded by MemoryEngine.mu: writes under the write lock, lookups
// under the read lock.
type nameIndex struct {
	vocab map[string]uint32
	// words[wid] is the word, sharing its bytes with the vocab key.
	words []string
	// post[wid] is the sorted list of file ids whose name has the word.
	post [][]uint32
	// tails holds out-of-order ids of a long posting list (see add), kept sorted and
	// merged into post once full, so an insert never shifts a list of millions.
	tails map[uint32][]uint32
	// grams maps a byte trigram of a word to the ascending ids of the words that
	// contain it. Word ids are never freed, so the lists only ever grow at the end.
	grams map[uint32][]uint32
	// entries counts posting entries, live the words of the names files hold now.
	// The difference is what renames left behind: stale entries the re-check filters
	// out and a rebuild drops.
	entries, live int
}

const (
	// postingInlineMax is the longest posting list that takes an out-of-order id by
	// direct sorted insert; a longer one queues it in its tail.
	postingInlineMax = 1024
	// postingTailMax is how many ids a tail holds before it is merged.
	postingTailMax = 256
	// candidateFloor is the smallest posting total ever treated as too wide to
	// collect; wider leaves fall back to the scan, which stops at the result cap.
	candidateFloor = 65536
)

// fileSlab holds the memory engine's file records by id, in fixed-size chunks. A
// single []File would copy every record, pointers and all, each time it doubled —
// most of the publish time at a few million files, and a second copy of the whole
// table at the peak.
type fileSlab struct {
	chunks [][]File
	n      int
}

// slabChunkBits sizes a chunk: 4096 records, under a megabyte.
const slabChunkBits = 12

func (s *fileSlab) at(id uint32) *File {
	return &s.chunks[id>>slabChunkBits][id&(1<<slabChunkBits-1)]
}

// push stores f under the next id and returns it.
func (s *fileSlab) push(f File) uint32 {
	id := uint32(s.n)
	if int(id>>slabChunkBits) == len(s.chunks) {
		s.chunks = append(s.chunks, make([]File, 1<<slabChunkBits))
	}
	*s.at(id) = f
	s.n++
	return id
}

// len is how many ids have been handed out, live or not.
func (s *fileSlab) len() int { return s.n }

func newNameIndex() nameIndex {
	return nameIndex{
		vocab: map[string]uint32{},
		tails: map[uint32][]uint32{},
		grams: map[uint32][]uint32{},
	}
}

// indexName adds file id under every word of name it is not listed under yet.
func (x *nameIndex) indexName(id uint32, name string) {
	words := nameWords(name)
	x.live += len(words)
	for _, w := range words {
		wid := x.wordID(w)
		if x.add(wid, id) {
			x.entries++
		}
	}
}

// renameFile moves file id from oldName to name. Words both names share are left
// alone; new ones are added. The id stays listed under words only oldName had:
// removing it from a long list costs a shift of the list, and the re-check drops the
// false candidate. A rebuild reclaims those entries once they add up.
func (x *nameIndex) renameFile(id uint32, oldName, name string) {
	if oldName == name {
		return
	}
	x.live -= len(nameWords(oldName))
	x.indexName(id, name)
}

// removeFile accounts for a file going away; purge drops its entries later.
func (x *nameIndex) removeFile(name string) {
	x.live -= len(nameWords(name))
}

// purge removes every id dead reports from all posting lists, so the ids can be
// reused without inheriting another file's words.
func (x *nameIndex) purge(dead func(uint32) bool) {
	for wid, ids := range x.post {
		kept := ids[:0]
		for _, id := range ids {
			if !dead(id) {
				kept = append(kept, id)
			}
		}
		x.entries -= len(ids) - len(kept)
		x.post[wid] = shrink(kept)
	}
	for wid, tail := range x.tails {
		kept := tail[:0]
		for _, id := range tail {
			if !dead(id) {
				kept = append(kept, id)
			}
		}
		x.entries -= len(tail) - len(kept)
		if len(kept) == 0 {
			delete(x.tails, wid)
			continue
		}
		x.tails[wid] = kept
	}
}

// needsRebuild reports whether renames have left so many stale entries that
// rebuilding from the live names is worth it.
func (x *nameIndex) needsRebuild() bool {
	stale := x.entries - x.live
	return stale > 1024 && stale > x.entries/4
}

// candidates returns the ids expr can match, ascending and without duplicates, or
// all=true when the index cannot narrow it and the caller must scan. limit is the
// widest posting total collected before a leaf is given up as all.
func (x *nameIndex) candidates(expr *SearchExpr, limit int) (ids []uint32, all bool) {
	if expr == nil {
		return nil, true
	}
	switch expr.Kind {
	case SearchText:
		return x.textCandidates(expr.Text, limit)
	case SearchString:
		if expr.TagType == searchTypeText {
			return x.textCandidates(expr.ValueString, limit)
		}
		return nil, true
	case SearchAnd:
		l, lAll := x.candidates(expr.Left, limit)
		if !lAll && len(l) == 0 {
			return nil, false
		}
		r, rAll := x.candidates(expr.Right, limit)
		switch {
		case lAll:
			return r, rAll
		case rAll:
			return l, false
		}
		return intersectSorted(l, r), false
	case SearchOr:
		l, lAll := x.candidates(expr.Left, limit)
		if lAll {
			return nil, true
		}
		r, rAll := x.candidates(expr.Right, limit)
		if rAll {
			return nil, true
		}
		return unionSorted(l, r), false
	case SearchAndNot:
		// The right side only takes files away; the left bounds the result.
		return x.candidates(expr.Left, limit)
	default:
		// Numeric, type, extension and media leaves are not indexed; pruned and
		// unknown nodes constrain nothing. The re-check applies them.
		return nil, true
	}
}

// textCandidates is a text leaf: every term must occur, so the term sets intersect.
func (x *nameIndex) textCandidates(text string, limit int) ([]uint32, bool) {
	terms := splitTerms(text)
	if len(terms) == 0 {
		// matchSearchExpr answers false for an all-whitespace leaf.
		return nil, false
	}
	type runSet struct {
		wids []uint32
		size int
	}
	var sets []runSet
	for _, t := range terms {
		for _, run := range alnumRuns(strings.ToLower(t)) {
			if len(run) < 3 {
				// Too short for a trigram. Leaving it out keeps the set a superset.
				continue
			}
			wids := x.wordsContaining(run)
			size := 0
			for _, wid := range wids {
				size += x.postingLen(wid)
			}
			if size == 0 {
				return nil, false
			}
			sets = append(sets, runSet{wids, size})
		}
	}
	if len(sets) == 0 {
		return nil, true
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].size < sets[j].size })
	if sets[0].size > limit {
		return nil, true
	}
	out := x.collect(sets[0].wids)
	for _, s := range sets[1:] {
		// A much wider set barely narrows the result; the re-check covers it.
		if len(out) == 0 || s.size > 16*len(out) {
			break
		}
		out = intersectSorted(out, x.collect(s.wids))
	}
	return out, false
}

// wordsContaining returns the ids of the words run occurs in. run is at least three
// bytes long.
func (x *nameIndex) wordsContaining(run string) []uint32 {
	var lists [][]uint32
	for i := 0; i+3 <= len(run); i++ {
		l := x.grams[trigram(run[i:])]
		if len(l) == 0 {
			return nil
		}
		lists = append(lists, l)
	}
	sort.Slice(lists, func(i, j int) bool { return len(lists[i]) < len(lists[j]) })
	cand := lists[0]
	for _, l := range lists[1:] {
		if len(cand) == 0 {
			return nil
		}
		cand = intersectSorted(cand, l)
	}
	out := make([]uint32, 0, len(cand))
	for _, wid := range cand {
		if strings.Contains(x.words[wid], run) {
			out = append(out, wid)
		}
	}
	return out
}

// wordID returns w's id, adding it to the vocabulary and the trigram lists if new.
func (x *nameIndex) wordID(w string) uint32 {
	if wid, ok := x.vocab[w]; ok {
		return wid
	}
	w = strings.Clone(w)
	wid := uint32(len(x.words))
	x.vocab[w] = wid
	x.words = append(x.words, w)
	x.post = append(x.post, nil)
	for i := 0; i+3 <= len(w); i++ {
		g := trigram(w[i:])
		l := x.grams[g]
		if n := len(l); n > 0 && l[n-1] == wid {
			continue // a trigram repeated within the word
		}
		x.grams[g] = append(l, wid)
	}
	return wid
}

// add lists file id under word wid, returning false if it already was. Ids of new
// files only grow, so the common case is an append; a reused id or a renamed file's
// new word goes in by sorted insert, or through the tail on a long list.
func (x *nameIndex) add(wid, id uint32) bool {
	// ids and its tail are each sorted and never share an id.
	ids, tail := x.post[wid], x.tails[wid]
	tpos, inTail := slices.BinarySearch(tail, id)
	if inTail {
		return false
	}
	if n := len(ids); n == 0 || ids[n-1] < id {
		x.post[wid] = append(ids, id)
		return true
	}
	pos, found := slices.BinarySearch(ids, id)
	if found {
		return false
	}
	if len(ids) <= postingInlineMax && len(tail) == 0 {
		x.post[wid] = slices.Insert(ids, pos, id)
		return true
	}
	tail = slices.Insert(tail, tpos, id)
	if len(tail) < postingTailMax {
		x.tails[wid] = tail
		return true
	}
	x.post[wid] = unionSorted(ids, tail)
	delete(x.tails, wid)
	return true
}

func (x *nameIndex) postingLen(wid uint32) int {
	return len(x.post[wid]) + len(x.tails[wid])
}

// collect unions the posting lists (and tails) of wids into one sorted set. A single
// list is returned as is, so the result must not be modified.
func (x *nameIndex) collect(wids []uint32) []uint32 {
	if len(wids) == 1 && len(x.tails[wids[0]]) == 0 {
		return x.post[wids[0]]
	}
	var out []uint32
	for _, wid := range wids {
		out = append(out, x.post[wid]...)
		out = append(out, x.tails[wid]...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// nameWords splits a name into the distinct words the index lists it under: the
// runs alnumRuns finds, taken as substrings of the lowercased name instead of built
// rune by rune, since this runs for every name published.
func nameWords(name string) []string {
	lower := strings.ToLower(name)
	words := make([]string, 0, 8)
	start := -1
	for i, r := range lower {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			words = append(words, lower[start:i])
			start = -1
		}
	}
	if start >= 0 {
		words = append(words, lower[start:])
	}
	slices.Sort(words)
	return slices.Compact(words)
}

func trigram(s string) uint32 {
	return uint32(s[0])<<16 | uint32(s[1])<<8 | uint32(s[2])
}

// shrink releases a list's spare capacity once a purge has emptied a good part of it.
func shrink(ids []uint32) []uint32 {
	if len(ids) == 0 {
		return nil
	}
	if cap(ids) > 64 && len(ids) < cap(ids)/2 {
		return slices.Clone(ids)
	}
	return ids
}

// intersectSorted returns the ids in both ascending lists. It gallops through the
// longer list when the two differ a lot in length.
func intersectSorted(a, b []uint32) []uint32 {
	if len(a) > len(b) {
		a, b = b, a
	}
	out := make([]uint32, 0, len(a))
	if len(a)*32 < len(b) {
		for _, v := range a {
			pos, found := slices.BinarySearch(b, v)
			if found {
				out = append(out, v)
			}
			b = b[pos:]
		}
		return out
	}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] < b[j]:
			i++
		case a[i] > b[j]:
			j++
		default:
			out = append(out, a[i])
			i++
			j++
		}
	}
	return out
}

// unionSorted merges two ascending lists without duplicates.
func unionSorted(a, b []uint32) []uint32 {
	out := make([]uint32, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] < b[j]:
			out = append(out, a[i])
			i++
		case a[i] > b[j]:
			out = append(out, b[j])
			j++
		default:
			out = append(out, a[i])
			i++
			j++
		}
	}
	out = append(out, a[i:]...)
	return append(out, b[j:]...)
}
