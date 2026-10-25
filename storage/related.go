package storage

import (
	"bytes"
	"slices"
)

// Related search, after Lugdunum 17.15's do_related_search (related.c): the files
// that the users sharing the seed files also share, most common first. Every engine
// answers it the same way:
//
//   - the users are the online clients that share a seed, at most maxClients of
//     them;
//   - fewer than minClients such users and nothing is returned, so the share list of
//     one or two users is never shown on its own;
//   - a file's weight is how many of those users share it, and the seeds themselves
//     (any size) are left out;
//   - the answer is the files with an online source, by weight, then by sources,
//     at most MaxSearchResults of them.

// relatedFile is one candidate of a related search with its weight.
type relatedFile struct {
	file    File
	clients int
}

// RelatedFiles answers a related search on the memory engine; see the comment at
// the top of this file.
func (m *MemoryEngine) RelatedFiles(seeds []FileKey, minClients, maxClients int) []File {
	if len(seeds) == 0 {
		return nil
	}
	maxClients = max(maxClients, minClients, 1)
	m.mu.RLock()
	defer m.mu.RUnlock()

	seedHashes := make(map[[hashLen]byte]struct{}, len(seeds))
	var users []uint64
	seen := map[uint64]struct{}{}
	for _, seed := range seeds {
		key := hashArray(seed.Hash)
		seedHashes[key] = struct{}{}
		head, ok := m.files[key]
		if !ok {
			continue
		}
		// The memory engine drops a session's sources when it goes, so every
		// source here is online.
		m.eachSourceLocked(head, func(s *memSource) {
			if len(users) >= maxClients || (seed.Size != 0 && s.size != seed.Size) {
				return
			}
			if _, dup := seen[s.peer.storeID]; dup {
				return
			}
			seen[s.peer.storeID] = struct{}{}
			users = append(users, s.peer.storeID)
		})
	}
	if len(users) < minClients {
		return nil
	}

	weights := map[uint32]int{}
	for _, storeID := range users {
		c := m.clients[storeID]
		if c == nil {
			continue
		}
		for _, head := range c.offered {
			rec := m.recs.at(head)
			if rec.flags&recLive == 0 {
				continue
			}
			if _, isSeed := seedHashes[rec.hash]; isSeed {
				continue
			}
			if rec.next == 0 {
				weights[head]++
				continue
			}
			// The hash is held at several sizes: the client's own source says which.
			m.eachSourceLocked(head, func(s *memSource) {
				if s.peer != c.peer {
					return
				}
				if id, ok := m.findLocked(rec.hash, s.size); ok {
					weights[id]++
				}
			})
		}
	}
	out := make([]relatedFile, 0, len(weights))
	for id, n := range weights {
		if f := m.fileLocked(id, true); f.Sources > 0 {
			out = append(out, relatedFile{file: f, clients: n})
		}
	}
	return rankRelated(out)
}

// rankRelated orders related candidates by weight, then sources, then hash and size
// so the answer does not depend on map order, and keeps MaxSearchResults of them.
func rankRelated(c []relatedFile) []File {
	slices.SortFunc(c, func(a, b relatedFile) int {
		if a.clients != b.clients {
			return b.clients - a.clients
		}
		if a.file.Sources != b.file.Sources {
			if a.file.Sources > b.file.Sources {
				return -1
			}
			return 1
		}
		if d := bytes.Compare(a.file.Hash, b.file.Hash); d != 0 {
			return d
		}
		switch {
		case a.file.Size < b.file.Size:
			return -1
		case a.file.Size > b.file.Size:
			return 1
		}
		return 0
	})
	c = c[:min(len(c), MaxSearchResults)]
	files := make([]File, len(c))
	for i := range c {
		files[i] = c[i].file
	}
	return files
}
