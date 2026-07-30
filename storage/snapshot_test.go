package storage

import (
	"bytes"
	"encoding/gob"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// seedSnapshotEngine fills an engine with n files, each offered by its own client,
// so a round-trip has clients, files and sources to carry.
func seedSnapshotEngine(t *testing.T, n int) *MemoryEngine {
	t.Helper()
	engine := NewMemoryEngine()
	for i := range n {
		hash := make([]byte, 16)
		hash[0] = byte(i)
		hash[1] = byte(i >> 8)
		userHash := make([]byte, 16)
		userHash[0] = 0xAA
		userHash[1] = byte(i)

		info := ClientInfo{
			ID:           uint32(0x01020300 + i),
			IPv4:         uint32(0x0A000000 + i),
			Port:         uint16(4662 + i),
			Hash:         userHash,
			CryptOptions: 0x01,
		}
		if _, err := engine.Connect(info); err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
		engine.AddFile(File{
			Hash:      hash,
			Name:      "Great.Release.S01E01.1080p.WEB-DL.x264-GROUP.mkv",
			Size:      uint64(700_000_000 + i),
			Type:      "Video",
			Sources:   1,
			Completed: 1,
			Bitrate:   4500,
			Codec:     "h264",
		}, info)
	}
	return engine
}

// TestSnapshotRoundTrip is the core case: an index written and read back must come
// out identical, in both the plain and the compressed form.
func TestSnapshotRoundTrip(t *testing.T) {
	for _, compress := range []bool{false, true} {
		name := "plain"
		if compress {
			name = "gzip"
		}
		t.Run(name, func(t *testing.T) {
			const files = 25
			src := seedSnapshotEngine(t, files)
			path := filepath.Join(t.TempDir(), "storage.gob")

			written, err := src.WriteSnapshot(path, compress)
			if err != nil {
				t.Fatalf("write: %v", err)
			}
			t.Logf("input:  %d files, %d clients, compress=%t",
				src.FilesCount(), src.ClientsCount(), compress)
			t.Logf("output: wrote files=%d sources=%d clients=%d bytes=%d took=%s",
				written.Files, written.Sources, written.Clients, written.Bytes, written.Took)

			if written.Files != files || written.Sources != files || written.Clients != files {
				t.Fatalf("wrote files=%d sources=%d clients=%d, want %d of each",
					written.Files, written.Sources, written.Clients, files)
			}

			dst := NewMemoryEngine()
			read, err := dst.LoadSnapshot(path)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			t.Logf("output: loaded files=%d (sources=%d clients=%d present in the file) took=%s",
				read.Files, read.Sources, read.Clients, read.Took)

			if read.Files != files {
				t.Fatalf("loaded %d files, want %d", read.Files, files)
			}
			if dst.FilesCount() != files {
				t.Fatalf("engine holds %d files, want %d", dst.FilesCount(), files)
			}

			// Field-by-field on one entry, so a silently dropped column fails here.
			hash := make([]byte, 16)
			want, ok := src.files[hashKey(hash)]
			if !ok {
				t.Fatal("fixture file missing from the source engine")
			}
			got, ok := dst.files[hashKey(hash)]
			if !ok {
				t.Fatal("file absent after load")
			}
			t.Logf("output: restored %+v", got)
			if !bytes.Equal(got.Hash, want.Hash) || got.Name != want.Name || got.Size != want.Size ||
				got.Type != want.Type || got.Sources != want.Sources || got.Completed != want.Completed ||
				got.Bitrate != want.Bitrate || got.Codec != want.Codec {
				t.Fatalf("restored file differs:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

// TestSnapshotLoadMatchesDatabaseRestart is the parity contract. After a mysql or
// mongodb server restarts, Init has set every client and source offline, so files
// are still searchable but no source list resolves and no client counts as online.
// A restored memory engine must look the same.
func TestSnapshotLoadMatchesDatabaseRestart(t *testing.T) {
	const files = 5
	src := seedSnapshotEngine(t, files)
	path := filepath.Join(t.TempDir(), "storage.gob")
	if _, err := src.WriteSnapshot(path, false); err != nil {
		t.Fatalf("write: %v", err)
	}

	dst := NewMemoryEngine()
	stats, err := dst.LoadSnapshot(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	hash := make([]byte, 16)
	sources := dst.GetSourcesByHash(hash)
	found := dst.FindByNameContains("Great.Release")
	restored := dst.files[hashKey(hash)]

	t.Logf("input:  a snapshot with %d files, %d sources, %d clients",
		stats.Files, stats.Sources, stats.Clients)
	t.Logf("output: FilesCount=%d ClientsCount=%d GetSourcesByHash=%d search hits=%d File.Sources=%d",
		dst.FilesCount(), dst.ClientsCount(), len(sources), len(found), restored.Sources)

	if dst.FilesCount() != files {
		t.Fatalf("files must survive the restart: got %d, want %d", dst.FilesCount(), files)
	}
	if len(found) != files {
		t.Fatalf("files must stay searchable: got %d hits, want %d", len(found), files)
	}
	if dst.ClientsCount() != 0 {
		t.Fatalf("no client may be online after a restart, got %d", dst.ClientsCount())
	}
	if len(sources) != 0 {
		t.Fatalf("no source may resolve until a client re-offers, got %d", len(sources))
	}
	// files.sources is a COUNT(*) over all rows in SQL and is not recomputed at
	// startup, so a stale count here is parity, not a bug. CleanupStale fixes it.
	if restored.Sources != 1 {
		t.Fatalf("File.Sources must survive as written, got %d want 1", restored.Sources)
	}
}

// TestSnapshotNextClientIDSurvives guards against reissuing a StoreID that a
// restored record already claims, the memory-engine stand-in for AUTO_INCREMENT.
func TestSnapshotNextClientIDSurvives(t *testing.T) {
	src := seedSnapshotEngine(t, 7)
	path := filepath.Join(t.TempDir(), "storage.gob")
	if _, err := src.WriteSnapshot(path, false); err != nil {
		t.Fatalf("write: %v", err)
	}

	dst := NewMemoryEngine()
	if _, err := dst.LoadSnapshot(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	storeID, err := dst.Connect(ClientInfo{ID: 999, Hash: bytes.Repeat([]byte{0x5A}, 16)})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Logf("input:  snapshot written after 7 connects (nextClientID=%d)", src.nextClientID)
	t.Logf("output: first StoreID issued after the load = %d", storeID)
	if storeID <= 7 {
		t.Fatalf("StoreID %d collides with a restored record; want > 7", storeID)
	}
}

// TestSnapshotMissingFileIsNotAnError: no snapshot yet is the normal first-boot
// state, and must not stop the server from starting. Mirrors ReadServerMet.
func TestSnapshotMissingFileIsNotAnError(t *testing.T) {
	engine := NewMemoryEngine()
	path := filepath.Join(t.TempDir(), "absent.gob")
	stats, err := engine.LoadSnapshot(path)
	t.Logf("input:  %s (does not exist)", path)
	t.Logf("output: stats=%+v err=%v", stats, err)
	if err != nil {
		t.Fatalf("a missing snapshot must not be an error, got %v", err)
	}
	if stats.Files != 0 {
		t.Fatalf("want no files, got %d", stats.Files)
	}
}

// TestSnapshotRejectsForeignFile covers pointing the config at the wrong path. The
// magic is checked before anything is decoded so the message names the real problem.
func TestSnapshotRejectsForeignFile(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
	}{
		{name: "not a snapshot", content: []byte("this is not a gob stream at all")},
		{name: "empty file", content: []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "storage.gob")
			if err := os.WriteFile(path, tc.content, 0o644); err != nil {
				t.Fatal(err)
			}
			engine := NewMemoryEngine()
			_, err := engine.LoadSnapshot(path)
			t.Logf("input:  %d byte(s) %q", len(tc.content), tc.content)
			t.Logf("output: err=%v", err)
			if err == nil {
				t.Fatal("want an error for a file that is not a snapshot")
			}
		})
	}
}

// TestSnapshotRejectsWrongMagic exercises the magic check itself: a well-formed
// gob stream of the right shape but from some other producer. Without the check
// this would decode happily and install whatever it contained.
func TestSnapshotRejectsWrongMagic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.gob")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	header := SnapshotHeader{Magic: "some-other-tool", Version: snapshotVersion, WrittenAt: time.Now()}
	if err := gob.NewEncoder(f).Encode(header); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	engine := NewMemoryEngine()
	_, err = engine.LoadSnapshot(path)
	t.Logf("input:  a valid gob stream with magic %q", header.Magic)
	t.Logf("output: err=%v", err)
	if err == nil {
		t.Fatal("want an error for a foreign file with a valid gob header")
	}
}

// TestSnapshotRejectsUnknownVersion: a future format must be refused rather than
// half-understood, because whatever is decoded would then be served to clients.
func TestSnapshotRejectsUnknownVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.gob")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	header := SnapshotHeader{
		Magic:     snapshotMagic,
		Version:   snapshotVersion + 1,
		WrittenAt: time.Now(),
		Engine:    "memory",
	}
	if err := gob.NewEncoder(f).Encode(header); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	engine := NewMemoryEngine()
	_, err = engine.LoadSnapshot(path)
	t.Logf("input:  header version=%d (this build reads %d)", header.Version, snapshotVersion)
	t.Logf("output: err=%v", err)
	if err == nil {
		t.Fatal("want an error for an unknown snapshot version")
	}
}

// TestSnapshotEmptyEngineKeepsExistingFile: a server that has just started holds no
// files, and its first scheduled write must not truncate the snapshot it was about
// to be restored from. Same guard the server.met writer has.
func TestSnapshotEmptyEngineKeepsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.gob")
	seeded := seedSnapshotEngine(t, 4)
	if _, err := seeded.WriteSnapshot(path, false); err != nil {
		t.Fatalf("write: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	empty := NewMemoryEngine()
	stats, err := empty.WriteSnapshot(path, false)
	if err != nil {
		t.Fatalf("write from an empty engine must not fail: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input:  an empty engine writing over a %d byte snapshot", len(before))
	t.Logf("output: stats=%+v, file is now %d bytes", stats, len(after))
	if !bytes.Equal(before, after) {
		t.Fatal("an empty engine overwrote a good snapshot")
	}
}

// TestSnapshotWriteIsAtomic: the write goes to a temp file and is renamed, so a
// crash cannot leave a truncated index behind. Nothing may be left in the directory
// but the snapshot itself.
func TestSnapshotWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "storage.gob")
	engine := seedSnapshotEngine(t, 3)
	if _, err := engine.WriteSnapshot(path, false); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	t.Logf("input:  one snapshot written to %s", dir)
	t.Logf("output: directory contains %v", names)
	if len(entries) != 1 || entries[0].Name() != "storage.gob" {
		t.Fatalf("want only storage.gob, got %v", names)
	}
}

// TestSnapshotCreatesDirectory: data/ does not exist on a fresh install, and the
// first write must create it rather than fail.
func TestSnapshotCreatesDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "nested", "storage.gob")
	engine := seedSnapshotEngine(t, 2)
	stats, err := engine.WriteSnapshot(path, false)
	t.Logf("input:  %s (parent directories absent)", path)
	t.Logf("output: stats=%+v err=%v", stats, err)
	if err != nil {
		t.Fatalf("want the directory created, got %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("snapshot not written: %v", err)
	}
}

// TestSnapshotRejectsEmptyPath keeps a misconfiguration from writing to the working
// directory.
func TestSnapshotRejectsEmptyPath(t *testing.T) {
	engine := seedSnapshotEngine(t, 1)
	_, writeErr := engine.WriteSnapshot("", false)
	_, loadErr := engine.LoadSnapshot("")
	t.Logf("output: write err=%v, load err=%v", writeErr, loadErr)
	if writeErr == nil || loadErr == nil {
		t.Fatal("an empty path must be rejected by both directions")
	}
}

// TestSnapshotTolersatesUnknownSourceGroup: the chunked write can capture a source
// group whose file was deleted mid-write. The loader must skip it, not fail — that
// tolerance is what makes the short lock holds safe.
func TestSnapshotToleratesUnknownSourceGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.gob")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	enc := gob.NewEncoder(f)
	if err := enc.Encode(SnapshotHeader{
		Magic: snapshotMagic, Version: snapshotVersion, WrittenAt: time.Now(), Engine: "memory", Files: 1,
	}); err != nil {
		t.Fatal(err)
	}
	knownHash := bytes.Repeat([]byte{0x11}, 16)
	orphanHash := bytes.Repeat([]byte{0x99}, 16)
	if err := enc.Encode(SnapshotBatch{
		Files: []File{{Hash: knownHash, Name: "kept.mkv", Size: 1}},
		Sources: []SnapshotSources{
			{FileHash: orphanHash, Sources: []Source{{ID: 7, Port: 4662}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	engine := NewMemoryEngine()
	stats, err := engine.LoadSnapshot(path)
	t.Logf("input:  1 file plus a source group for a file that is not in the snapshot")
	t.Logf("output: stats=%+v err=%v filesCount=%d", stats, err, engine.FilesCount())
	if err != nil {
		t.Fatalf("an orphaned source group must be skipped, not fatal: %v", err)
	}
	if engine.FilesCount() != 1 {
		t.Fatalf("want the one real file kept, got %d", engine.FilesCount())
	}
}

// TestStartSnapshotWritesOnStop covers the shutdown path: the stopper must flush,
// or everything since the last tick is lost on a clean restart. The interval here
// is long enough that only the stop path can produce the file.
func TestStartSnapshotWritesOnStop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.gob")
	engine := seedSnapshotEngine(t, 3)

	stop := StartSnapshot(engine, path, time.Hour, false)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("nothing should have been written before the first tick")
	}
	stop()
	stop() // the stopper is registered with defer alongside others; must not panic

	// Deliberately not polled: the stopper waits for the encode, so the file has to
	// be there the instant it returns. Anything weaker would pass against a stopper
	// that only signals the goroutine, which is exactly the bug this guards.
	_, err := os.Stat(path)
	t.Logf("input:  StartSnapshot with a 1h interval, stopped immediately")
	t.Logf("output: snapshot present the moment stop() returned=%t", err == nil)
	if err != nil {
		t.Fatalf("the stop path must write a final snapshot before returning: %v", err)
	}

	dst := NewMemoryEngine()
	stats, loadErr := dst.LoadSnapshot(path)
	if loadErr != nil {
		t.Fatalf("load: %v", loadErr)
	}
	t.Logf("output: reloaded %d file(s)", stats.Files)
	if stats.Files != 3 {
		t.Fatalf("want 3 files in the shutdown snapshot, got %d", stats.Files)
	}
}

// TestStartSnapshotSkipsNonSnapshotEngine: enabling the key while running mysql or
// mongodb is a no-op, not an error — those engines already persist.
func TestStartSnapshotSkipsNonSnapshotEngine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.gob")
	stop := StartSnapshot(&MySQLEngine{}, path, time.Millisecond, false)
	stop()
	_, err := os.Stat(path)
	t.Logf("input:  StartSnapshot on the mysql engine")
	t.Logf("output: snapshot written=%t", err == nil)
	if err == nil {
		t.Fatal("no snapshot may be written for an engine that persists natively")
	}
}
