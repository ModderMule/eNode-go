package storage

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// runOfferedContract checks what every engine owes the soft file limit and a large
// sharer's disconnect: OfferedCount is the distinct files a session sources now,
// HasOffered tells a re-offer from a new file, and a disconnect of more files than
// one chunk leaves no source behind.
func runOfferedContract(t *testing.T, engine Engine) {
	t.Helper()
	connect := func(who byte) ClientInfo {
		info := ClientInfo{
			ID: 0x0a000000 + uint32(who), IPv4: 0x0100000a + uint32(who), Port: 4662,
			Hash: []byte(fmt.Sprintf("offered-user-%03d", who)),
		}
		id, err := engine.Connect(info)
		if err != nil {
			t.Fatalf("connect %c: %v", who, err)
		}
		info.StoreID = id
		return info
	}
	a, b := connect('a'), connect('b')
	// More than offerBatchSize, so a DB engine counts across two of its chunks.
	const share = offerBatchSize + 200
	files := sharerFiles('a', 0, share, "offered")
	own := sharerFiles('b', 0, 10, "theirs")
	unknown := File{Hash: sharerHash('z', 1), Size: 1}

	check := func(step string, wantA, wantB int) {
		t.Helper()
		gotA, gotB := engine.OfferedCount(a), engine.OfferedCount(b)
		t.Logf("input: %s output: OfferedCount a=%d b=%d", step, gotA, gotB)
		if gotA != wantA || gotB != wantB {
			t.Fatalf("%s: OfferedCount a=%d b=%d, want %d and %d", step, gotA, gotB, wantA, wantB)
		}
	}
	has := func(step string, info ClientInfo, ask []File, want string) {
		t.Helper()
		got := engine.HasOffered(info, ask)
		t.Logf("input: %s output: HasOffered=%v", step, got)
		if fmt.Sprint(got) != want {
			t.Fatalf("%s: HasOffered=%v, want %s", step, got, want)
		}
	}

	check("two sessions, nothing offered", 0, 0)
	engine.AddFiles(files, a)
	check(fmt.Sprintf("a offers %d files", share), share, 0)
	engine.AddFiles(files, a)
	check("a re-offers all of them", share, 0)
	partial := append([]File(nil), files[:100]...)
	for i := range partial {
		partial[i].Completed = 0
	}
	engine.AddFiles(partial, a)
	check("a re-offers 100 of them as incomplete", share, 0)
	engine.AddFiles(files[:50], b)
	engine.AddFiles(own, b)
	check("b offers 50 of a's files and 10 of its own", share, 60)
	ask := []File{files[0], own[0], files[share-1], unknown}
	has("a: its first file, a file of b, its last file, an unknown file", a, ask, "[true false true false]")
	has("b: the same four", b, ask, "[true true false false]")

	engine.Disconnect(a)
	check("a disconnects", 0, 60)
	has("a after its disconnect", a, ask, "[false false false false]")
	if n := len(engine.GetSources(files[share-1].Hash, files[share-1].Size)); n != 0 {
		t.Fatalf("a file only a had still has %d source(s)", n)
	}
	if n := len(engine.GetSources(files[0].Hash, files[0].Size)); n != 1 {
		t.Fatalf("a file b also has shows %d source(s), want 1", n)
	}

	// A new session of the same user starts from nothing, whatever the engine kept
	// of the old one.
	a = connect('a')
	check("a connects again", 0, 60)
	engine.AddFiles(files[100:105], a)
	check("a offers 5 of its old files", 5, 60)
	has("a: one of the 5, one of the old ones it has not offered again", a, []File{files[100], files[200]}, "[true false]")

	// A share of several disconnect chunks.
	const large = 2*disconnectChunk + 300
	big := sharerFiles('c', 0, large, "bulky")
	for start := 0; start < large; start += 200 {
		engine.AddFiles(big[start:min(start+200, large)], a)
	}
	check(fmt.Sprintf("a offers %d more files, 200 a packet", large), 5+large, 60)
	before := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: "c002299"})
	// The user is back while the old session is still being released. Its new
	// session and what it offers must come through whole: nothing the release still
	// has to do may touch them.
	old, released := a, make(chan struct{})
	go func() {
		defer close(released)
		engine.Disconnect(old)
	}()
	for deadline := time.Now().Add(30 * time.Second); engine.IsConnected(old); {
		if time.Now().After(deadline) {
			t.Fatal("the session is still connected 30 s into its disconnect")
		}
		runtime.Gosched()
	}
	a = connect('a')
	engine.AddFiles(files[300:305], a)
	<-released
	left := 0
	for _, f := range big {
		left += len(engine.GetSources(f.Hash, f.Size))
	}
	after := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: "c002299"})
	check("a disconnects, and reconnects and offers 5 files while that runs", 5, 60)
	for _, f := range files[300:305] {
		if n := len(engine.GetSources(f.Hash, f.Size)); n != 1 {
			t.Fatalf("a file of the new session has %d source(s), want 1: the old session's release reached it", n)
		}
	}
	if !engine.IsConnected(a) {
		t.Fatal("the new session is not connected once the old one is released")
	}
	t.Logf("output: sources left on a's %d files=%d; result source of its last file before=%v after=%v",
		large, left, resultSources(before), resultSources(after))
	if left != 0 {
		t.Fatalf("%d source(s) of the departed session remain", left)
	}
	if len(before) != 1 || before[0].SourceID != a.ID {
		t.Fatalf("setup: the last file should name a as its source: %v", resultSources(before))
	}
	for _, f := range after {
		if f.SourceID != 0 || f.SourcePort != 0 {
			t.Fatalf("a search result still names the departed session: %#x:%d", f.SourceID, f.SourcePort)
		}
	}
	if n := len(engine.GetSources(own[0].Hash, own[0].Size)); n != 1 {
		t.Fatalf("b's own file has %d source(s) after a left, want 1", n)
	}
}

func resultSources(files []File) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = fmt.Sprintf("%#x:%d", f.SourceID, f.SourcePort)
	}
	return out
}

// The gate lets one holder per hash in, and different hashes do not wait for each
// other.
func TestHashGateSerialisesOneHash(t *testing.T) {
	var gate hashGate
	var inside, most, total atomic.Int64
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hash := []byte{byte(i % 2)}
			unlock := gate.lock(hash)
			if i%2 == 0 {
				n := inside.Add(1)
				for {
					seen := most.Load()
					if n <= seen || most.CompareAndSwap(seen, n) {
						break
					}
				}
				runtime.Gosched()
				inside.Add(-1)
			}
			total.Add(1)
			unlock()
		}()
	}
	wg.Wait()
	other := gate.lock([]byte{9})
	done := make(chan struct{})
	go func() {
		gate.lock([]byte{8})()
		gate.lock(nil)()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a second hash, or no hash, waited for the first")
	}
	other()
	t.Logf("input: 64 goroutines over two hashes, then two hashes held at once output: ran=%d most inside one hash=%d entries left=%d",
		total.Load(), most.Load(), len(gate.held))
	if total.Load() != 64 || most.Load() != 1 {
		t.Fatalf("ran=%d, most inside one hash at a time=%d, want 64 and 1", total.Load(), most.Load())
	}
	if len(gate.held) != 0 {
		t.Fatalf("%d entries left in the gate after everyone released", len(gate.held))
	}
}

func TestMemoryOfferedContract(t *testing.T) {
	runOfferedContract(t, NewMemoryEngine())
}

func TestMySQLOfferedContract(t *testing.T) {
	requireIntegration(t)
	engine, _ := startMySQL(t, "enode_offered")
	runOfferedContract(t, engine)
}

func TestMongoOfferedContract(t *testing.T) {
	requireIntegration(t)
	runOfferedContract(t, startMongoEngine(t, "enode_offered"))
}
