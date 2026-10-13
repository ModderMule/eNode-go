package storage

import "sync"

// hashGate lets one Connect or Disconnect of a user hash run at a time.
//
// The DB engines keep one client row per user hash across sessions, and a source
// belongs to that row. A Disconnect is several statements — for a large share,
// many — and a new session of the same user that connected and offered in the
// middle of them would have its fresh sources marked offline by the statements
// still to come. The server serialises a re-login against the session it replaces,
// but not against a session that is already on its way out; this does.
//
// The memory engine needs none of it: every Connect there gets a StoreID of its own.
type hashGate struct {
	mu   sync.Mutex
	held map[string]*gateEntry
}

// gateEntry is the lock of one hash, kept while anyone holds or waits for it.
type gateEntry struct {
	mu   sync.Mutex
	refs int
}

// lock waits for the gate of hash and returns what releases it. A caller without a
// hash is not serialised.
func (g *hashGate) lock(hash []byte) (unlock func()) {
	if len(hash) == 0 {
		return func() {}
	}
	key := string(hash)
	g.mu.Lock()
	if g.held == nil {
		g.held = map[string]*gateEntry{}
	}
	entry := g.held[key]
	if entry == nil {
		entry = &gateEntry{}
		g.held[key] = entry
	}
	entry.refs++
	g.mu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		g.mu.Lock()
		if entry.refs--; entry.refs == 0 {
			delete(g.held, key)
		}
		g.mu.Unlock()
	}
}
