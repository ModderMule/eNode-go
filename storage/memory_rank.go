package storage

import (
	"encoding/binary"
	"hash/fnv"
	"slices"
)

// searchRanker collects the answer to one memory-engine search. Up to
// MaxSearchResults matches it only appends. Past that it keeps the best
// MaxSearchResults seen, and stops the search after searchRankScan matches.
//
// Best is most sources. Most files have exactly one, so the tie-break orders the
// bulk of a wide answer, and it must not be the file id: ids follow publication
// order, which would hand the answer back to whoever published first. The tie is
// broken on a hash of the query and the file instead, so the same query gives the
// same answer every time and different queries favour different files.
type searchRanker struct {
	expr *SearchExpr
	out  []File
	// ids[i] is the record id of out[i], kept until the answer overflows and the
	// heap takes over.
	ids []uint32
	// heap is a min-heap over the kept files, the worst on top, built on overflow.
	heap    []rankEntry
	seed    uint64
	matches int
	// arena is where the kept files' hashes are copied to; see own.
	arena []byte
}

// rankEntry is one kept file's rank and where it sits in searchRanker.out.
type rankEntry struct {
	sources uint32
	id      uint32
	tie     uint64
	idx     int
}

// add takes one match and reports whether the search should go on.
func (r *searchRanker) add(id uint32, f File) bool {
	r.matches++
	if len(r.out) < MaxSearchResults {
		f.Hash = r.own(f.Hash)
		r.out = append(r.out, f)
		r.ids = append(r.ids, id)
		return true
	}
	if r.heap == nil {
		r.seed = searchSeed(r.expr)
		r.heap = make([]rankEntry, len(r.out))
		for i, kept := range r.out {
			r.heap[i] = rankEntry{sources: kept.Sources, id: r.ids[i], tie: rankTie(r.seed, kept), idx: i}
		}
		r.ids = nil
		for i := len(r.heap)/2 - 1; i >= 0; i-- {
			r.siftDown(i)
		}
	}
	if e := (rankEntry{sources: f.Sources, id: id, tie: rankTie(r.seed, f), idx: r.heap[0].idx}); r.heap[0].below(e) {
		f.Hash = r.own(f.Hash)
		r.out[e.idx] = f
		r.heap[0] = e
		r.siftDown(0)
	}
	return r.matches < searchRankScan
}

// result is the answer: in the order the matches came when all of them fit, best
// first when they were ranked.
func (r *searchRanker) result() []File {
	if r.heap == nil {
		return r.out
	}
	slices.SortFunc(r.heap, func(a, b rankEntry) int {
		switch {
		case b.below(a):
			return -1
		case a.below(b):
			return 1
		}
		return 0
	})
	out := make([]File, len(r.heap))
	for i, e := range r.heap {
		out[i] = r.out[e.idx]
	}
	return out
}

// own copies a hash out of the engine's record, which a match arrives pointing
// into. The copies of one search share a few blocks instead of each being its own
// allocation.
func (r *searchRanker) own(hash []byte) []byte {
	if len(r.arena) < len(hash) {
		r.arena = make([]byte, 64*hashLen)
	}
	out := r.arena[:len(hash):len(hash)]
	r.arena = r.arena[len(hash):]
	copy(out, hash)
	return out
}

func (r *searchRanker) siftDown(i int) {
	h := r.heap
	for {
		least := i
		for _, child := range [2]int{2*i + 1, 2*i + 2} {
			if child < len(h) && h[child].below(h[least]) {
				least = child
			}
		}
		if least == i {
			return
		}
		h[i], h[least] = h[least], h[i]
		i = least
	}
}

// below reports whether a ranks under b. The id only makes the order total: two
// files share a tie when 64 bits collide.
func (a rankEntry) below(b rankEntry) bool {
	if a.sources != b.sources {
		return a.sources < b.sources
	}
	if a.tie != b.tie {
		return a.tie < b.tie
	}
	return a.id > b.id
}

// rankTie is the tie-break of file f under a query's seed.
func rankTie(seed uint64, f File) uint64 {
	var h [8]byte
	copy(h[:], f.Hash)
	z := seed ^ binary.LittleEndian.Uint64(h[:]) ^ f.Size*0x9e3779b97f4a7c15
	// splitmix64's finalizer.
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// searchSeed hashes a query, so that the same query breaks ties the same way.
func searchSeed(expr *SearchExpr) uint64 {
	h := fnv.New64a()
	var walk func(e *SearchExpr)
	walk = func(e *SearchExpr) {
		if e == nil {
			_, _ = h.Write([]byte{0})
			return
		}
		var num [13]byte
		num[0] = byte(e.Kind) + 1
		binary.LittleEndian.PutUint32(num[1:], e.TagType)
		binary.LittleEndian.PutUint64(num[5:], e.ValueUint)
		_, _ = h.Write(num[:])
		_, _ = h.Write([]byte(e.Text))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(e.ValueString))
		_, _ = h.Write([]byte{0})
		walk(e.Left)
		walk(e.Right)
	}
	walk(expr)
	return h.Sum64()
}
