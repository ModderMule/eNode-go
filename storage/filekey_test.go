package storage

import (
	"testing"
	"time"
)

// The memory engine used to key a file on its hash alone, so a second offer of the same
// hash at a different size overwrote the first record outright — Size included — and
// GetSources then rejected every lookup for the real size. Files are keyed on
// (hash, size) now, matching UNIQUE(hash,size) on MySQL and the {hash,size} index on
// MongoDB. See fileMapKey.

// twoSizeEngine seeds one hash at two sizes from two different clients and returns the
// engine plus the two client records.
func twoSizeEngine(t *testing.T) (*MemoryEngine, []byte, ClientInfo, ClientInfo) {
	t.Helper()
	m := NewMemoryEngine()
	if err := m.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	hash := []byte("0123456789abcdef")
	honest := ClientInfo{ID: 1, Port: 4662, Hash: []byte("aaaaaaaaaaaaaaaa")}
	liar := ClientInfo{ID: 2, Port: 4663, Hash: []byte("bbbbbbbbbbbbbbbb")}
	for _, c := range []ClientInfo{honest, liar} {
		if _, err := m.Connect(c); err != nil {
			t.Fatalf("connect %d: %v", c.ID, err)
		}
	}
	t.Logf("input:  hash=%x offered as (size=100 name=real.mkv) by id=%d, then (size=200 name=fake.mkv) by id=%d",
		hash, honest.ID, liar.ID)
	m.AddFile(File{Hash: hash, Name: "real.mkv", Size: 100, Type: "Video"}, honest)
	m.AddFile(File{Hash: hash, Name: "fake.mkv", Size: 200, Type: "Video"}, liar)
	return m, hash, honest, liar
}

func TestMemoryKeepsBothSizesOfOneHash(t *testing.T) {
	m, _, _, _ := twoSizeEngine(t)

	found := m.FindByNameContains("")
	names := map[string]uint64{}
	for _, f := range found {
		names[f.Name] = f.Size
	}
	t.Logf("output: FilesCount=%d search hits=%d records=%v", m.FilesCount(), len(found), names)

	if m.FilesCount() != 2 {
		t.Fatalf("both sizes must be indexed: FilesCount=%d, want 2", m.FilesCount())
	}
	if len(found) != 2 {
		t.Fatalf("search must return one hit per (hash, size), got %d want 2", len(found))
	}
	// The whole point: the first record is untouched, not rewritten by the second.
	if got, ok := names["real.mkv"]; !ok || got != 100 {
		t.Fatalf("the first offer's record was rewritten: real.mkv size=%d present=%v, want 100", got, ok)
	}
	if got, ok := names["fake.mkv"]; !ok || got != 200 {
		t.Fatalf("the second offer is missing: fake.mkv size=%d present=%v, want 200", got, ok)
	}
}

func TestMemorySizeMismatchNoLongerBlackholesSources(t *testing.T) {
	m, hash, _, _ := twoSizeEngine(t)

	atReal := m.GetSources(hash, 100)
	atFake := m.GetSources(hash, 200)
	t.Logf("output: GetSources(hash,100)=%d GetSources(hash,200)=%d", len(atReal), len(atFake))

	// Before the key change this was nil: the second offer had rewritten Size to 200
	// and GetSources bailed on the mismatch, permanently.
	if len(atReal) == 0 {
		t.Fatalf("the real size must still resolve sources, got %d", len(atReal))
	}
	if len(atFake) == 0 {
		t.Fatalf("the second size must resolve sources of its own, got %d", len(atFake))
	}
}

// TestMemorySourcesAreSharedAcrossSizesOfOneHash pins an accepted divergence so it reads
// as a decision rather than an accident.
//
// Sources stay keyed on the hash alone, because the legacy UDP OP_GLOBGETSOURCES (0x9a)
// carries bare hashes with no size and has to stay an O(1) lookup. So when one hash
// carries two sizes, GetSources returns the union where MySQL and MongoDB — whose source
// rows hang off the (hash,size) file row — return only the matching size's. Harmless: a
// client cannot be stopped from offering a file it does not have at any size, so the
// size bucket buys no protection here. What it did buy, record corruption, is fixed.
func TestMemorySourcesAreSharedAcrossSizesOfOneHash(t *testing.T) {
	m, hash, honest, liar := twoSizeEngine(t)

	got := m.GetSources(hash, 100)
	ids := []uint32{}
	for _, s := range got {
		ids = append(ids, s.ID)
	}
	t.Logf("output: GetSources(hash,100) ids=%v (the DB engines would return only id=%d)", ids, honest.ID)

	if len(got) != 2 {
		t.Fatalf("the memory engine shares one source list per hash: got %d sources, want 2 (ids %d and %d)",
			len(got), honest.ID, liar.ID)
	}
}

func TestMemoryGetSourcesRejectsAnUnknownSize(t *testing.T) {
	m, hash, _, _ := twoSizeEngine(t)

	got := m.GetSources(hash, 999)
	t.Logf("output: GetSources(hash,999)=%d", len(got))

	if len(got) != 0 {
		t.Fatalf("a size nobody offered must resolve nothing, got %d sources", len(got))
	}
}

func TestMemoryCleanupRemovesEverySizeOfAHash(t *testing.T) {
	m, hash, honest, liar := twoSizeEngine(t)
	m.Disconnect(honest)
	m.Disconnect(liar)

	res, err := m.CleanupStale(time.Hour, CleanupOptions{KeepZeroSourceFiles: false})
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	t.Logf("input:  both offerers disconnected, KeepZeroSourceFiles=false")
	t.Logf("output: cleanup removed files=%d, FilesCount=%d, GetSourcesByHash=%d",
		res.Files, m.FilesCount(), len(m.GetSourcesByHash(hash)))

	// Both records share one source bucket, so emptying it must reap both — the delete
	// of the bucket on the first record's iteration must not leave the second orphaned.
	if m.FilesCount() != 0 {
		t.Fatalf("every size of an unsourced hash must be reaped, FilesCount=%d want 0", m.FilesCount())
	}
	if res.Files != 2 {
		t.Fatalf("cleanup should report both records removed, got %d want 2", res.Files)
	}
}
