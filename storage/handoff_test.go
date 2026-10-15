package storage

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func handoffHash(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }

// The memory engine's whole live state crosses a handover: files, sources in their
// offer order, clients with their StoreIDs and offered lists, and the StoreID
// counter — so the successor answers exactly as the predecessor did.
func TestMemoryEngineHandoffRoundTrip(t *testing.T) {
	src := NewMemoryEngine()
	alice := ClientInfo{Hash: handoffHash(0xa1), ID: 0x0100007f, IPv4: 0x0100007f, Port: 4662, CryptOptions: 0x03,
		IPv6: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, IPv6Reachable: true}
	bob := ClientInfo{Hash: handoffHash(0xb0), ID: 1234, LowID: true, Port: 4672}
	var err error
	if alice.StoreID, err = src.Connect(alice); err != nil {
		t.Fatal(err)
	}
	if bob.StoreID, err = src.Connect(bob); err != nil {
		t.Fatal(err)
	}
	shared := handoffHash(0x51)
	src.AddFiles([]File{
		{Hash: shared, Name: "shared movie.avi", Size: 700 << 20, Type: "Video", Completed: 1},
		{Hash: handoffHash(0x52), Name: "alice only.mp3", Size: 4 << 20, Type: "Audio", Artist: "someone", Bitrate: 320},
	}, alice)
	src.AddFiles([]File{
		// The same hash at a second size is a second file. Its sources are the hash's,
		// so bob's offer of it takes over his source of the first size.
		{Hash: shared, Name: "shared movie.avi", Size: 700 << 20, Type: "Video"},
		{Hash: shared, Name: "shared movie (other size).avi", Size: 701 << 20, Type: "Video"},
	}, bob)
	// A file with no source left must survive too: it is still searchable.
	carol := ClientInfo{Hash: handoffHash(0xc0), ID: 99, LowID: true, Port: 1}
	if carol.StoreID, err = src.Connect(carol); err != nil {
		t.Fatal(err)
	}
	src.AddFile(File{Hash: handoffHash(0x53), Name: "orphan.txt", Size: 10, Type: "Doc"}, carol)
	src.Disconnect(carol)

	var buf bytes.Buffer
	if err := src.ExportHandoff(&buf); err != nil {
		t.Fatal(err)
	}
	dst := NewMemoryEngine()
	if err := dst.ImportHandoff(&buf); err != nil {
		t.Fatal(err)
	}

	sourceIDs := func(e *MemoryEngine, size uint64) []uint32 {
		sources := e.GetSourcesByHash(shared)
		if size != 0 {
			sources = e.GetSources(shared, size)
		}
		var out []uint32
		for _, s := range sources {
			out = append(out, s.ID)
		}
		return out
	}
	t.Logf("input: 2 clients, 4 files, 1 orphan; output: files %d→%d clients %d→%d sources(700M) %v→%v sources(any) %d→%d",
		src.FilesCount(), dst.FilesCount(), src.ClientsCount(), dst.ClientsCount(),
		sourceIDs(src, 700<<20), sourceIDs(dst, 700<<20),
		len(src.GetSourcesByHash(shared)), len(dst.GetSourcesByHash(shared)))

	if dst.FilesCount() != src.FilesCount() || dst.ClientsCount() != 2 {
		t.Fatalf("files %d clients %d, want %d and 2", dst.FilesCount(), dst.ClientsCount(), src.FilesCount())
	}
	for _, size := range []uint64{0, 700 << 20, 701 << 20} {
		if got, want := sourceIDs(dst, size), sourceIDs(src, size); !slices.Equal(got, want) {
			t.Fatalf("size %d: sources %v, want %v in the same order", size, got, want)
		}
	}
	if got := sourceIDs(dst, 0); len(got) != 2 {
		t.Fatalf("sources of the hash %v, want alice and bob", got)
	}
	for _, info := range []ClientInfo{alice, bob} {
		if !dst.IsConnected(ClientInfo{Hash: info.Hash}) {
			t.Fatalf("client %x not connected after import", info.Hash)
		}
		if got, want := dst.OfferedCount(info), src.OfferedCount(info); got != want {
			t.Fatalf("client %x offered %d, want %d", info.Hash, got, want)
		}
	}
	srcSources, dstSources := src.GetSourcesByHash(shared), dst.GetSourcesByHash(shared)
	for i := range srcSources {
		a, b := srcSources[i], dstSources[i]
		if a.Port != b.Port || a.CryptOptions != b.CryptOptions || !bytes.Equal(a.UserHash, b.UserHash) ||
			!bytes.Equal(a.IPv6, b.IPv6) || a.IPv6Reachable != b.IPv6Reachable {
			t.Fatalf("source %d = %+v, want %+v", i, b, a)
		}
	}
	files := dst.FindByNameContains("alice only")
	if len(files) != 1 || files[0].Artist != "someone" || files[0].Bitrate != 320 || files[0].Sources != 1 {
		t.Fatalf("media file after import: %+v", files)
	}
	if len(dst.FindByNameContains("orphan")) != 1 {
		t.Fatal("a file without sources was lost")
	}
	// Complete sources are counted from the flags, so they must have crossed too.
	if f := dst.FindByNameContains("shared movie.avi"); len(f) != 1 || f[0].Completed != 1 {
		t.Fatalf("complete count after import: %+v", f)
	}

	// A disconnect in the successor removes exactly that client's sources, which
	// needs its offered list to have been rebuilt.
	dst.Disconnect(alice)
	if got := sourceIDs(dst, 0); len(got) != 1 || got[0] != bob.ID {
		t.Fatalf("after alice leaves: sources %v, want bob only", got)
	}
	if len(dst.GetSources(handoffHash(0x52), 4<<20)) != 0 {
		t.Fatal("alice's own file kept its source after she left")
	}
	// A new session never reuses a StoreID a handed-over one holds.
	id, _ := dst.Connect(ClientInfo{Hash: handoffHash(0xd0)})
	if id <= carol.StoreID {
		t.Fatalf("new StoreID %d reuses one issued before the handover (max %d)", id, carol.StoreID)
	}
}

// A successor configured with another engine refuses the stream rather than
// decoding it into something else.
func TestHandoffRefusesAnotherEngine(t *testing.T) {
	mysql, err := NewMySQLEngine(MySQLConfig{Host: "h", Port: 1, User: "u", Database: "d"})
	if err != nil {
		t.Fatal(err)
	}
	mysql.offered = map[uint64]int{7: 3}
	var buf bytes.Buffer
	if err := ExportHandoff(mysql, &buf); err != nil {
		t.Fatal(err)
	}
	err = ImportHandoff(NewMemoryEngine(), &buf)
	t.Logf("input: mysql handoff into the memory engine; output: %v", err)
	if err == nil {
		t.Fatal("the memory engine accepted a mysql handoff")
	}
}

// The database engines keep their rows in the database; what crosses is the
// per-session offered count the soft limit is held against.
func TestDatabaseEnginesHandOffOfferedCounts(t *testing.T) {
	mysqlSrc, _ := NewMySQLEngine(MySQLConfig{Host: "h", Port: 1, User: "u", Database: "d"})
	mysqlSrc.offered = map[uint64]int{7: 3, 9: 120}
	mysqlDst, _ := NewMySQLEngine(MySQLConfig{Host: "h", Port: 1, User: "u", Database: "d"})
	var buf bytes.Buffer
	if err := ExportHandoff(mysqlSrc, &buf); err != nil {
		t.Fatal(err)
	}
	if err := ImportHandoff(mysqlDst, &buf); err != nil {
		t.Fatal(err)
	}
	t.Logf("mysql: input %v output %v", mysqlSrc.offered, mysqlDst.offered)
	if mysqlDst.offered[7] != 3 || mysqlDst.offered[9] != 120 {
		t.Fatalf("mysql offered counts %v", mysqlDst.offered)
	}

	mongoSrc, _ := NewMongoDBEngine(MongoConfig{URI: "mongodb://h", Database: "d"})
	mongoSrc.offered = map[string]int{string(handoffHash(1)): 5}
	mongoDst, _ := NewMongoDBEngine(MongoConfig{URI: "mongodb://h", Database: "d"})
	buf.Reset()
	if err := ExportHandoff(mongoSrc, &buf); err != nil {
		t.Fatal(err)
	}
	if err := ImportHandoff(mongoDst, &buf); err != nil {
		t.Fatal(err)
	}
	t.Logf("mongodb: output %d entries", len(mongoDst.offered))
	if mongoDst.offered[string(handoffHash(1))] != 5 {
		t.Fatalf("mongodb offered counts %v", mongoDst.offered)
	}

	// Manticore keeps nothing per session and passes the wrapped engine's through.
	wrapped := &ManticoreEngine{Engine: mysqlSrc}
	buf.Reset()
	if err := ExportHandoff(wrapped, &buf); err != nil {
		t.Fatal(err)
	}
	into := &ManticoreEngine{Engine: mysqlDst}
	mysqlDst.offered = nil
	if err := ImportHandoff(into, &buf); err != nil {
		t.Fatal(err)
	}
	if mysqlDst.offered[9] != 120 {
		t.Fatalf("manticore did not pass the handoff through: %v", mysqlDst.offered)
	}
}

// KeepOnline reaches both database engine configs.
func TestKeepOnlineReachesDatabaseEngines(t *testing.T) {
	engine, err := NewEngine(Config{Engine: "mysql", KeepOnline: true,
		MySQL: MySQLConfig{Host: "h", Port: 1, User: "u", Database: "d"}})
	if err != nil {
		t.Fatal(err)
	}
	mongo, err := NewEngine(Config{Engine: "mongodb", KeepOnline: true,
		MongoDB: MongoConfig{URI: "mongodb://h", Database: "d"}})
	if err != nil {
		t.Fatal(err)
	}
	gotMySQL, gotMongo := engine.(*MySQLEngine).cfg.KeepOnline, mongo.(*MongoDBEngine).cfg.KeepOnline
	t.Logf("output: mysql KeepOnline=%t mongodb KeepOnline=%t", gotMySQL, gotMongo)
	if !gotMySQL || !gotMongo {
		t.Fatal("KeepOnline was not passed on")
	}
}

// handoff.memory "file": the index goes through a file and the predecessor lets go
// of it before the successor reads it, so the two never hold it at once. The
// successor ends up with exactly what a stream would have given it.
func TestMemoryEngineHandoffThroughFile(t *testing.T) {
	src := NewMemoryEngine()
	alice := ClientInfo{Hash: handoffHash(0xa1), ID: 0x0100007f, IPv4: 0x0100007f, Port: 4662}
	var err error
	if alice.StoreID, err = src.Connect(alice); err != nil {
		t.Fatal(err)
	}
	src.AddFiles([]File{
		{Hash: handoffHash(0x51), Name: "first.avi", Size: 700 << 20, Type: "Video"},
		{Hash: handoffHash(0x52), Name: "second.mp3", Size: 4 << 20, Type: "Audio"},
	}, alice)
	var direct bytes.Buffer
	if err := src.ExportHandoff(&direct); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "data", "storage.gob.handoff")
	var stream bytes.Buffer
	ok, err := ExportHandoffFile(src, &stream, path)
	if !ok || err != nil {
		t.Fatalf("ExportHandoffFile = %t, %v", ok, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("handoff file: %v", err)
	}
	t.Logf("input: 2 files, 1 client; output: file %d bytes, stream %d bytes, predecessor left with %d files %d clients",
		info.Size(), stream.Len(), src.FilesCount(), src.ClientsCount())
	if src.FilesCount() != 0 || src.ClientsCount() != 0 || len(src.GetSourcesByHash(handoffHash(0x51))) != 0 {
		t.Fatal("the predecessor still holds the index after writing it out")
	}
	if stream.Len() >= int(info.Size()) {
		t.Fatalf("the stream (%d bytes) carries the index instead of naming the file (%d bytes)", stream.Len(), info.Size())
	}

	dst, want := NewMemoryEngine(), NewMemoryEngine()
	if err := dst.ImportHandoff(&stream); err != nil {
		t.Fatal(err)
	}
	if err := want.ImportHandoff(&direct); err != nil {
		t.Fatal(err)
	}
	for _, h := range []byte{0x51, 0x52} {
		got, exp := dst.GetSourcesByHash(handoffHash(h)), want.GetSourcesByHash(handoffHash(h))
		if len(got) != 1 || len(exp) != 1 || got[0].ID != exp[0].ID || got[0].Port != exp[0].Port {
			t.Fatalf("hash %x: sources %+v, want %+v", h, got, exp)
		}
	}
	if dst.FilesCount() != 2 || !dst.IsConnected(ClientInfo{Hash: alice.Hash}) || dst.OfferedCount(alice) != 2 {
		t.Fatalf("successor: files %d connected %t offered %d", dst.FilesCount(), dst.IsConnected(ClientInfo{Hash: alice.Hash}), dst.OfferedCount(alice))
	}
	// The predecessor removes the file once the handover is committed; until then
	// it is what an abort reads back.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the import removed the file the predecessor may still need: %v", err)
	}
	// A new session never reuses a StoreID issued before the handover.
	if id, _ := dst.Connect(ClientInfo{Hash: handoffHash(0xd0)}); id <= alice.StoreID {
		t.Fatalf("new StoreID %d reuses %d", id, alice.StoreID)
	}
}

// A handover through a file that does not happen gives the predecessor its index
// back, and the file is removed.
func TestMemoryEngineHandoffFileRestore(t *testing.T) {
	m := NewMemoryEngine()
	bob := ClientInfo{Hash: handoffHash(0xb0), ID: 1234, LowID: true, Port: 4672}
	var err error
	if bob.StoreID, err = m.Connect(bob); err != nil {
		t.Fatal(err)
	}
	m.AddFile(File{Hash: handoffHash(0x61), Name: "kept.iso", Size: 1 << 30, Type: "Iso"}, bob)
	path := filepath.Join(t.TempDir(), "storage.gob.handoff")
	if err := m.ExportHandoffFile(io.Discard, path); err != nil {
		t.Fatal(err)
	}
	if err := m.RestoreHandoffFile(path); err != nil {
		t.Fatal(err)
	}
	sources := m.GetSourcesByHash(handoffHash(0x61))
	t.Logf("output after restore: files %d clients %d sources %d", m.FilesCount(), m.ClientsCount(), len(sources))
	if m.FilesCount() != 1 || m.ClientsCount() != 1 || len(sources) != 1 || sources[0].ID != 1234 {
		t.Fatalf("index not restored: files %d clients %d sources %+v", m.FilesCount(), m.ClientsCount(), sources)
	}
	// Bob's disconnect still removes his source: his offered list was rebuilt.
	m.Disconnect(bob)
	if len(m.GetSourcesByHash(handoffHash(0x61))) != 0 {
		t.Fatal("source kept after its client left")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("handoff file left behind: %v", err)
	}
}

// A file whose writing fails leaves the engine as it was.
func TestMemoryEngineHandoffFileErrorKeepsIndex(t *testing.T) {
	m := NewMemoryEngine()
	m.AddFile(File{Hash: handoffHash(0x71), Name: "x", Size: 1, Type: "Doc"}, ClientInfo{Hash: handoffHash(1), ID: 5})
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	err := m.ExportHandoffFile(io.Discard, filepath.Join(blocker, "under-a-file", "storage.gob.handoff"))
	t.Logf("input: a path under a regular file; output: %v, files %d", err, m.FilesCount())
	if err == nil || m.FilesCount() != 1 {
		t.Fatalf("err %v, files %d; want an error and the index kept", err, m.FilesCount())
	}
}

// While the index is out in the handoff file, a periodic snapshot finds nothing
// and must not replace the good snapshot on disk with an empty one.
func TestSnapshotKeepsFileWhileIndexIsHandedOff(t *testing.T) {
	m := NewMemoryEngine()
	m.AddFile(File{Hash: handoffHash(0x81), Name: "snap.avi", Size: 9, Type: "Video"}, ClientInfo{Hash: handoffHash(2), ID: 6})
	dir := t.TempDir()
	snap := filepath.Join(dir, "storage.gob")
	if _, err := m.WriteSnapshot(snap, false); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(snap)
	if err := m.ExportHandoffFile(io.Discard, snap+".handoff"); err != nil {
		t.Fatal(err)
	}
	stats, err := m.WriteSnapshot(snap, false)
	after, _ := os.ReadFile(snap)
	t.Logf("snapshot while handed off: %+v, %v; file %d → %d bytes", stats, err, len(before), len(after))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("the snapshot was replaced while the index was handed off")
	}
}
