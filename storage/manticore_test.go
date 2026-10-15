package storage

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// newTestManticore wraps a memory engine; nothing connects to Manticore, which is
// all these tests need.
func newTestManticore(t *testing.T, cfg ManticoreConfig) *ManticoreEngine {
	t.Helper()
	m, err := NewManticoreEngine(NewMemoryEngine(), cfg)
	if err != nil {
		t.Fatalf("NewManticoreEngine: %v", err)
	}
	t.Cleanup(func() { _ = m.db.Close() })
	return m
}

func TestManticoreDSN(t *testing.T) {
	for _, in := range []string{"tcp(127.0.0.1:9306)/", "user:pw@tcp(host:9306)/enode?timeout=5s"} {
		got, err := manticoreDSN(in)
		t.Logf("input: %q, output: %q err=%v", in, got, err)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got, "interpolateParams=true") || strings.Contains(got, "/enode") {
			t.Fatalf("dsn %q must interpolate and name no database", got)
		}
	}
	if _, err := manticoreDSN("::not a dsn"); err == nil {
		t.Fatal("an invalid dsn was accepted")
	}
}

// TestManticoreKeys pins the document identity: one per (file, client), one group
// per file, always a positive non-zero bigint.
func TestManticoreKeys(t *testing.T) {
	file := File{Hash: fileHash(1), Size: 700, Name: "a.avi"}
	a := sourceDoc(IndexedSource{File: file, ClientHash: userHash(1)})
	b := sourceDoc(IndexedSource{File: file, ClientHash: userHash(2)})
	other := sourceDoc(IndexedSource{File: File{Hash: fileHash(1), Size: 701}, ClientHash: userHash(1)})
	t.Logf("output: a=%d/%d b=%d/%d other=%d/%d", a.id, a.fileKey, b.id, b.fileKey, other.id, other.fileKey)
	if a.id == b.id || a.fileKey != b.fileKey {
		t.Fatal("two clients of one file must share the file key and nothing else")
	}
	if other.fileKey == a.fileKey {
		t.Fatal("a second size of a hash is a different file")
	}
	if again := sourceDoc(IndexedSource{File: file, ClientHash: userHash(1)}); again.id != a.id {
		t.Fatal("a re-offer must rewrite the same document")
	}
	for _, key := range []uint64{a.id, a.fileKey, a.clientKey, manticoreKey()} {
		if key == 0 || key > 1<<63-1 {
			t.Fatalf("key %d is not a positive bigint", key)
		}
	}
}

// TestOfferDocs checks an offer is indexed as the database engines store it.
func TestOfferDocs(t *testing.T) {
	info := ClientInfo{ID: 1234, Port: 4662, Hash: userHash(3)}
	files := []File{
		{Hash: fileHash(1), Size: 10, Name: "Clip.AVI", Type: "EmuleCollection", Completed: 1},
		{Hash: fileHash(2), Size: 20, Name: "first.mp3"},
		{Hash: fileHash(2), Size: 20, Name: "second.mp3"},
	}
	now := time.Unix(1700000000, 0)
	docs := offerDocs(files, info, now)
	for _, d := range docs {
		t.Logf("output: %+v", d)
	}
	if len(docs) != 2 {
		t.Fatalf("got %d documents, want 2: a duplicate in one offer is one source", len(docs))
	}
	clip := docs[0]
	if clip.typ != "Video" || clip.ext != "avi" || !clip.complete || !clip.online || clip.timeOffer != now.Unix() ||
		clip.srcID != 1234 || clip.srcPort != 4662 {
		t.Fatalf("clip document %+v", clip)
	}
	if docs[1].name != "second.mp3" {
		t.Fatalf("the later duplicate must win, got %q", docs[1].name)
	}
}

// TestManticoreSearchesDatabaseUntilReady: an index that is still being filled
// would answer with nothing, so the database answers.
func TestManticoreSearchesDatabaseUntilReady(t *testing.T) {
	m := newTestManticore(t, ManticoreConfig{Enabled: true})
	info := ClientInfo{ID: 1, Port: 4662, Hash: userHash(1)}
	info.StoreID, _ = m.Engine.Connect(info)
	m.Engine.AddFile(File{Hash: fileHash(1), Size: 1, Name: "needle.avi"}, info)
	got := m.FindBySearch(textLeaf("needle"))
	t.Logf("input: needle, output: %d result(s)", len(got))
	if len(got) != 1 {
		t.Fatalf("got %d results from the database, want 1", len(got))
	}
}

// TestManticoreQueueFullMarksDirty: an offer never waits on the index. What does
// not fit the queue is dropped and left to the reconcile pass.
func TestManticoreQueueFullMarksDirty(t *testing.T) {
	m := newTestManticore(t, ManticoreConfig{Enabled: true, QueueSize: 1})
	info := ClientInfo{ID: 1, Port: 4662, Hash: userHash(1)}
	files := []File{{Hash: fileHash(1), Size: 1, Name: "a.avi"}, {Hash: fileHash(2), Size: 2, Name: "b.avi"}}
	m.enqueue(manticoreOp{docs: offerDocs(files[:1], info, time.Now())})
	if m.dirty.Load() {
		t.Fatal("the first op fits the queue")
	}
	m.enqueue(manticoreOp{docs: offerDocs(files, info, time.Now())})
	t.Logf("output: dropped=%d dirty=%v", m.dropped.Load(), m.dirty.Load())
	if !m.dirty.Load() || m.dropped.Load() != 2 {
		t.Fatalf("dropped=%d dirty=%v, want 2 and true", m.dropped.Load(), m.dirty.Load())
	}
}

// TestManticoreWritesNothingBeforeSetup: a write before the table is checked is
// dropped and repaired by the pass that follows setup.
func TestManticoreWritesNothingBeforeSetup(t *testing.T) {
	m := newTestManticore(t, ManticoreConfig{Enabled: true})
	m.write(offerDocs([]File{{Hash: fileHash(1), Size: 1, Name: "a.avi"}}, ClientInfo{Hash: userHash(1)}, time.Now()))
	t.Logf("output: dropped=%d dirty=%v", m.dropped.Load(), m.dirty.Load())
	if !m.dirty.Load() || m.dropped.Load() != 1 {
		t.Fatal("a write before setup must be dropped and mark the index dirty")
	}
}

func TestUnwrapEngine(t *testing.T) {
	m := newTestManticore(t, ManticoreConfig{Enabled: true})
	if _, ok := UnwrapEngine(m).(*MemoryEngine); !ok {
		t.Fatal("UnwrapEngine did not reach the database engine")
	}
	inner := NewMemoryEngine()
	if UnwrapEngine(inner) != Engine(inner) {
		t.Fatal("an unwrapped engine must come back as it is")
	}
}

func TestNewEngineWrapsOnlyDatabaseEngines(t *testing.T) {
	mem, err := NewEngine(Config{Engine: "memory", Manticore: ManticoreConfig{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mem.(*MemoryEngine); !ok {
		t.Fatalf("memory engine was wrapped: %T", mem)
	}
	db, err := NewEngine(Config{Engine: "mysql", MySQL: MySQLConfig{Host: "h", Port: 1, User: "u", Database: "d"},
		Manticore: ManticoreConfig{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: memory=%T mysql=%T", mem, db)
	if _, ok := db.(*ManticoreEngine); !ok {
		t.Fatalf("mysql engine with manticore enabled is %T", db)
	}
	plain, _ := NewEngine(Config{Engine: "mysql", MySQL: MySQLConfig{Host: "h", Port: 1, User: "u", Database: "d"}})
	if _, ok := plain.(*MySQLEngine); !ok {
		t.Fatalf("manticore off must leave the engine as it is, got %T", plain)
	}
}

// TestManticoreStatusBeforeSetup: an index that never connected reports itself
// down, without asking Manticore for a count, and keeps the DSN off the page.
func TestManticoreStatusBeforeSetup(t *testing.T) {
	dsn := "enode:secret@tcp(127.0.0.1:1)/"
	m := newTestManticore(t, ManticoreConfig{Enabled: true, DSN: dsn})
	m.setError(fmt.Errorf("connecting to %s: invalid connection", dsn))
	m.lost(3, fmt.Errorf("writing 3 source(s): broken pipe"))
	st := m.Status()
	t.Logf("output: %+v", st)
	if st.Up || st.Ready || st.Filling || st.Documents != -1 || st.Dropped != 3 || !st.Dirty {
		t.Fatalf("status %+v", st)
	}
	m.setError(fmt.Errorf("connecting to %s: invalid connection", dsn))
	st = m.Status()
	t.Logf("output: last error %q at %s", st.LastError, st.LastErrorAt)
	if strings.Contains(st.LastError, "secret") || !strings.Contains(st.LastError, "invalid connection") || st.LastErrorAt.IsZero() {
		t.Fatalf("last error %q", st.LastError)
	}
	m.setError(nil)
	if st = m.Status(); st.LastError != "" || !st.LastErrorAt.IsZero() {
		t.Fatalf("a cleared error is still reported: %q", st.LastError)
	}
}
