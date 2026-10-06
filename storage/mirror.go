package storage

import "sync"

// Mirror is a searchable in-memory copy of files that other servers reported:
// what a walk of their catalogues returned. It is kept apart from every Engine
// on purpose. A mirrored file has no client and no source here, and it must
// never be served on to a third server or counted as this server's own.
//
// A file is held once however many origins report it, with a reference per
// origin. A reference carries the walk that last saw the file, which is how a
// file leaves: after a walk of an origin completes, Sweep drops that origin's
// references the walk did not renew.
//
// It reuses the memory engine's name index, so a keyword search costs what it
// costs there.
type Mirror struct {
	mu       sync.RWMutex
	maxFiles int

	files map[string]uint32
	recs  fileSlab
	refs  [][]mirrorRef
	names nameIndex
	free  []uint32
	count int
}

// mirrorRef is one origin's claim on a file.
type mirrorRef struct {
	origin    uint32
	walk      uint32
	sources   uint32
	completed uint32
}

// NewMirror returns a mirror that holds at most maxFiles files.
func NewMirror(maxFiles int) *Mirror {
	return &Mirror{maxFiles: maxFiles, files: map[string]uint32{}, names: newNameIndex()}
}

// Put records that origin reported files during walk. It returns how many were
// taken: a file the mirror has no room for is left out, though one it already
// holds is always updated.
//
// Only what describes a file is kept. Whatever the caller left in SourceID,
// SourcePort or Meta is dropped.
func (m *Mirror) Put(origin, walk uint32, files []File) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	taken := 0
	for _, f := range files {
		if len(f.Hash) != hashLen || f.Name == "" {
			continue
		}
		f.SourceID, f.SourcePort, f.Meta = 0, 0, nil
		ref := mirrorRef{origin: origin, walk: walk, sources: f.Sources, completed: f.Completed}
		key := fileMapKey(f.Hash, f.Size)
		id, ok := m.files[key]
		if !ok {
			if m.count >= m.maxFiles {
				continue
			}
			id = m.allocLocked()
			m.files[key] = id
			m.count++
			f.Hash = append([]byte(nil), f.Hash...)
			*m.recs.at(id) = f
			m.names.indexName(id, f.Name)
			m.refs[id] = append(m.refs[id][:0], ref)
			taken++
			continue
		}
		m.setRefLocked(id, ref)
		rec := m.recs.at(id)
		if rec.Name != f.Name {
			m.names.renameFile(id, rec.Name, f.Name)
		}
		hash := rec.Hash
		*rec = f
		rec.Hash = hash
		m.countLocked(id)
		taken++
	}
	return taken
}

// Sweep ends a completed walk of origin: every file origin referenced that the
// walk did not see loses that reference, and a file left without any is removed.
// It returns how many files were removed.
func (m *Mirror) Sweep(origin, walk uint32) int {
	return m.dropRefs(func(r mirrorRef) bool { return r.origin == origin && r.walk != walk })
}

// Drop removes everything origin reported, and returns how many files went.
func (m *Mirror) Drop(origin uint32) int {
	return m.dropRefs(func(r mirrorRef) bool { return r.origin == origin })
}

// Search returns up to limit files that match expr. The counts of a file several
// origins report are the largest any of them gave: nothing says their users
// differ, so they are not added up.
func (m *Mirror) Search(expr *SearchExpr, limit int) []File {
	if expr == nil || limit <= 0 {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []File
	match := func(id uint32) bool {
		f := *m.recs.at(id)
		if f.Hash != nil && MatchSearchExpr(expr, f) {
			out = append(out, f)
		}
		return len(out) >= limit
	}
	ids, all := m.names.candidates(expr, max(candidateFloor, m.count/8))
	if all {
		for id := range m.recs.len() {
			if match(uint32(id)) {
				break
			}
		}
		return out
	}
	for _, id := range ids {
		if match(id) {
			break
		}
	}
	return out
}

// Len is how many files the mirror holds.
func (m *Mirror) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.count
}

// OriginFiles is how many files origin currently has a reference to.
func (m *Mirror) OriginFiles(origin uint32) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for id := range m.recs.len() {
		for _, r := range m.refs[id] {
			if r.origin == origin {
				n++
				break
			}
		}
	}
	return n
}

// allocLocked returns a free record id.
func (m *Mirror) allocLocked() uint32 {
	if n := len(m.free); n > 0 {
		id := m.free[n-1]
		m.free = m.free[:n-1]
		return id
	}
	m.refs = append(m.refs, nil)
	return m.recs.push(File{})
}

// setRefLocked renews origin's reference to file id, or adds it.
func (m *Mirror) setRefLocked(id uint32, ref mirrorRef) {
	for i, r := range m.refs[id] {
		if r.origin == ref.origin {
			m.refs[id][i] = ref
			return
		}
	}
	m.refs[id] = append(m.refs[id], ref)
}

// countLocked sets file id's counts to the largest its references give.
func (m *Mirror) countLocked(id uint32) {
	rec := m.recs.at(id)
	rec.Sources, rec.Completed = 0, 0
	for _, r := range m.refs[id] {
		rec.Sources = max(rec.Sources, r.sources)
		rec.Completed = max(rec.Completed, r.completed)
	}
}

// dropRefs removes the references gone reports, and the files left without one.
func (m *Mirror) dropRefs(gone func(mirrorRef) bool) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	var dead []uint32
	for i := range m.recs.len() {
		id := uint32(i)
		rec := m.recs.at(id)
		if rec.Hash == nil {
			continue
		}
		kept := m.refs[id][:0]
		for _, r := range m.refs[id] {
			if !gone(r) {
				kept = append(kept, r)
			}
		}
		if len(kept) == len(m.refs[id]) {
			continue
		}
		m.refs[id] = kept
		if len(kept) > 0 {
			m.countLocked(id)
			continue
		}
		delete(m.files, fileMapKey(rec.Hash, rec.Size))
		m.names.removeFile(rec.Name)
		*rec = File{}
		m.refs[id] = nil
		m.count--
		dead = append(dead, id)
	}
	if len(dead) == 0 {
		return 0
	}
	// The ids are purged from the index before they are reused, so a new file
	// does not inherit the words of the one that held its id.
	deadSet := make(map[uint32]struct{}, len(dead))
	for _, id := range dead {
		deadSet[id] = struct{}{}
	}
	m.names.purge(func(id uint32) bool {
		_, ok := deadSet[id]
		return ok
	})
	m.free = append(m.free, dead...)
	if m.names.needsRebuild() {
		m.reindexLocked()
	}
	return len(dead)
}

// reindexLocked rebuilds the name index from the names the files hold now, which
// drops the entries renames left behind.
func (m *Mirror) reindexLocked() {
	m.names = newNameIndex()
	for i := range m.recs.len() {
		if f := m.recs.at(uint32(i)); f.Hash != nil {
			m.names.indexName(uint32(i), f.Name)
		}
	}
}
