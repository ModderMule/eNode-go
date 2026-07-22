package main

import (
	"os"
	"path/filepath"
	"testing"

	"enode/ed2k"
	"enode/storage"
	"enode/tests"
)

// TestSeedDebugFixturesFromTempFile seeds a memory engine from a small hand-written
// fixtures file and verifies that both wire-facing paths are populated: the files
// become searchable (search results) and each peer becomes a source for the file it
// offers (the source list). A peer with a malformed hash is skipped, not fatal.
func TestSeedDebugFixturesFromTempFile(t *testing.T) {
	const fixture = `
peers:
  - ipv4: "203.0.113.7"
    port: 4662
    userHash: "0123456789abcdef0123456789abcdef"
    files:
      - hash: "fedcba9876543210fedcba9876543210"
        name: "Debian-13.iso"
        size: 4700000000
        type: "Pro"
        completed: true
  - ipv4: "198.51.100.42"
    port: 5000
    userHash: "aaaabbbbccccddddeeeeffff00001111"
    files:
      # Same file as peer 1 -> two sources.
      - hash: "fedcba9876543210fedcba9876543210"
        name: "Debian-13.iso"
        size: 4700000000
  - ipv4: ""
    id: 123456
    lowID: true
    port: 4662
    userHash: "99998888777766665555444433332211"
    files:
      - hash: "22223333444455556666777788889999"
        name: "Sintel.mkv"
        size: 1129240576
  # Malformed: odd-length hash -> whole peer skipped, others unaffected.
  - ipv4: "192.0.2.9"
    port: 4662
    userHash: "zzzz"
    files:
      - hash: "deadbeef"
        name: "bad.bin"
        size: 1
`
	dir := t.TempDir()
	path := filepath.Join(dir, "fixtures.yaml")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write temp fixture: %v", err)
	}
	t.Logf("input fixture:\n%s", fixture)

	engine := storage.NewMemoryEngine()
	if err := seedDebugFixtures(engine, path); err != nil {
		t.Fatalf("seedDebugFixtures: %v", err)
	}

	// 3 valid peers seeded (the malformed one skipped).
	if got := engine.ClientsCount(); got != 3 {
		t.Fatalf("ClientsCount = %d, want 3 (one malformed peer skipped)", got)
	}
	// 2 distinct file hashes offered.
	if got := engine.FilesCount(); got != 2 {
		t.Fatalf("FilesCount = %d, want 2", got)
	}
	t.Logf("output: clients=%d files=%d", engine.ClientsCount(), engine.FilesCount())

	// The shared file has two sources; their IDs are the two HighID peers' IPs.
	debianHash := mustHash(t, "fedcba9876543210fedcba9876543210")
	sources := engine.GetSources(debianHash, 4700000000)
	t.Logf("sources for Debian-13.iso: %+v", sources)
	if len(sources) != 2 {
		t.Fatalf("GetSources returned %d sources, want 2", len(sources))
	}
	wantID1 := mustID(t, "203.0.113.7")
	wantID2 := mustID(t, "198.51.100.42")
	gotIDs := map[uint32]bool{sources[0].ID: true, sources[1].ID: true}
	if !gotIDs[wantID1] || !gotIDs[wantID2] {
		t.Fatalf("source IDs = %v, want {%d, %d}", gotIDs, wantID1, wantID2)
	}

	// The file is discoverable by name (search-result path).
	if hits := engine.FindByNameContains("Debian"); len(hits) != 1 {
		t.Fatalf("FindByNameContains(Debian) = %d hits, want 1", len(hits))
	}

	// Wrong size must not match: GetSources keys on (hash, size).
	if s := engine.GetSources(debianHash, 999); len(s) != 0 {
		t.Fatalf("GetSources with wrong size returned %d, want 0", len(s))
	}
}

// TestSeedDebugFixturesRealFile seeds from the checked-in fixtures file the shipped
// local config points at, guarding it against drift (a schema/field rename that
// silently stops loading).
func TestSeedDebugFixturesRealFile(t *testing.T) {
	path := tests.FixRelativeTestingPath(filepath.Join("tests", "data", "debug_fixtures.yaml"))
	engine := storage.NewMemoryEngine()
	if err := seedDebugFixtures(engine, path); err != nil {
		t.Fatalf("seedDebugFixtures(%s): %v", path, err)
	}
	t.Logf("real fixtures %q: clients=%d files=%d", path, engine.ClientsCount(), engine.FilesCount())
	if engine.ClientsCount() == 0 || engine.FilesCount() == 0 {
		t.Fatalf("real fixtures seeded nothing: clients=%d files=%d", engine.ClientsCount(), engine.FilesCount())
	}
}

// TestSeedDebugFixturesMissingFile confirms a missing file is a hard error (the
// operator explicitly enabled seeding), while startup logs it non-fatally.
func TestSeedDebugFixturesMissingFile(t *testing.T) {
	engine := storage.NewMemoryEngine()
	err := seedDebugFixtures(engine, filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	t.Logf("missing-file error: %v", err)
	if err == nil {
		t.Fatal("want error for missing fixtures file, got nil")
	}
}

func mustHash(t *testing.T, s string) []byte {
	t.Helper()
	h, err := decodeHash(s)
	if err != nil {
		t.Fatalf("decodeHash(%q): %v", s, err)
	}
	return h
}

func mustID(t *testing.T, ipv4 string) uint32 {
	t.Helper()
	id, err := ed2k.IPv4ToInt32LE(ipv4)
	if err != nil {
		t.Fatalf("IPv4ToInt32LE(%q): %v", ipv4, err)
	}
	return id
}
