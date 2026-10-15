package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

// startManticore runs a Manticore container and returns its DSN once it answers.
func startManticore(t *testing.T) string {
	t.Helper()
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("docker not available: %v", err)
	}
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "manticoresearch/manticore",
		Tag:        "latest",
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("start manticore container: %v", err)
	}
	t.Cleanup(func() { _ = pool.Purge(resource) })
	dsn := fmt.Sprintf("tcp(localhost:%s)/", resource.GetPort("9306/tcp"))
	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error {
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			return err
		}
		defer db.Close()
		return db.Ping()
	}); err != nil {
		t.Fatalf("manticore not ready: %v", err)
	}
	return dsn
}

// wrapManticore puts Manticore in front of inner and initialises both.
func wrapManticore(t *testing.T, inner Engine, dsn string) *ManticoreEngine {
	t.Helper()
	m, err := NewManticoreEngine(inner, ManticoreConfig{Enabled: true, DSN: dsn, FallbackToEngine: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// countDocs is the number of documents in the engine's table.
func countDocs(t *testing.T, m *ManticoreEngine) int {
	t.Helper()
	var n int
	if err := m.db.QueryRow("SELECT COUNT(*) FROM " + m.cfg.Table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestManticoreMatchesMemoryEngine runs random search trees against Manticore and
// against the memory engine holding the same files, and requires the same files
// back wherever the two promise the same semantics: substring matching of runs
// of two or more characters. One-letter runs (a whole word on Manticore) and
// case folding outside ASCII (each tokenizer folds its own way) are skipped.
func TestManticoreMatchesMemoryEngine(t *testing.T) {
	requireIntegration(t)
	dsn := startManticore(t)
	db, _ := startMySQL(t, "enode")
	inner, err := NewMySQLEngine(db.cfg)
	if err != nil {
		t.Fatal(err)
	}
	m := wrapManticore(t, inner, dsn)
	waitFor(t, "the startup pass", m.ready.Load)
	ref := NewMemoryEngine()

	rng := rand.New(rand.NewPCG(5, 6))
	const users, files = 8, 400
	clients := make([]ClientInfo, users)
	refClients := make([]ClientInfo, users)
	for u := range clients {
		ci := ClientInfo{ID: uint32(1000 + u), Port: 4662, Hash: userHash(u)}
		refClients[u] = ci
		ci.StoreID, _ = m.Connect(ci)
		refClients[u].StoreID, _ = ref.Connect(refClients[u])
		clients[u] = ci
	}
	for i := range files {
		file := File{Hash: fileHash(i), Size: uint64(1000 + i), Name: randomName(rng), Completed: uint32(rng.IntN(2))}
		u := rng.IntN(users)
		m.AddFiles([]File{file}, clients[u])
		ref.AddFile(file, refClients[u])
	}
	waitFor(t, "the offers to reach the index", func() bool { return countDocs(t, m) == files })

	compared, skipped := 0, 0
	for range 3000 {
		expr := randomExpr(rng, 3)
		if !manticoreComparable(expr) || SearchNeedsScan(expr, manticoreMinInfix) {
			skipped++
			continue
		}
		if _, outcome := buildManticoreQuery(expr); outcome == manticoreUnsupported {
			skipped++
			continue
		}
		got := fileHashes(m.FindBySearch(expr))
		want := fileHashes(ref.FindBySearch(expr))
		if !slices.Equal(got, want) {
			q, _ := buildManticoreQuery(expr)
			t.Fatalf("%s: manticore %d file(s), memory %d\nmatch=%q filter=%q args=%v\nonly manticore: %v\nonly memory: %v",
				indexExprString(expr), len(got), len(want), q.match, q.filter, q.args,
				difference(got, want), difference(want, got))
		}
		compared++
	}
	t.Logf("output: %d trees agreed, %d skipped", compared, skipped)
	if compared < 500 {
		t.Fatalf("only %d trees compared", compared)
	}
}

// TestManticoreLifecycleMySQL follows sources through offer, disconnect, cleanup
// and reconcile, and checks a startup pass fills an empty table.
func TestManticoreLifecycleMySQL(t *testing.T) {
	requireIntegration(t)
	dsn := startManticore(t)
	db, _ := startMySQL(t, "enode")
	testManticoreLifecycle(t, db, func() Engine {
		inner, err := NewMySQLEngine(db.cfg)
		if err != nil {
			t.Fatal(err)
		}
		return inner
	}, dsn)
}

// TestManticoreLifecycleMongo is the same on the mongodb engine, whose
// BrowseSources and disconnect differ.
func TestManticoreLifecycleMongo(t *testing.T) {
	requireIntegration(t)
	dsn := startManticore(t)
	db := startMongoEngine(t, "enode")
	testManticoreLifecycle(t, db, func() Engine {
		inner, err := NewMongoDBEngine(db.cfg)
		if err != nil {
			t.Fatal(err)
		}
		return inner
	}, dsn)
}

// TestManticoreRejectsDrift: a table made with other options is refused at Init
// and recreated with Recreate.
func TestManticoreRejectsDrift(t *testing.T) {
	requireIntegration(t)
	dsn := startManticore(t)
	m, err := NewManticoreEngine(NewMemoryEngine(), ManticoreConfig{Enabled: true, DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer m.db.Close()
	if _, err := m.db.Exec(manticoreCreateStatement(m.cfg.Table, "min_infix_len='3'")); err != nil {
		t.Fatal(err)
	}
	err = m.setup(t.Context())
	t.Logf("output: setup on a drifted table: %v", err)
	if !errors.Is(err, ErrManticoreSchemaDrift) {
		t.Fatalf("got %v, want ErrManticoreSchemaDrift", err)
	}
	m.cfg.Recreate = true
	if err := m.setup(t.Context()); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	m.cfg.Recreate = false
	if err := m.setup(t.Context()); err != nil {
		t.Fatalf("the recreated table is still refused: %v", err)
	}
	var tables int
	rows, err := m.db.Query("SHOW TABLES")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		tables++
	}
	rows.Close()
	if tables != 2 {
		t.Fatalf("%d tables, want the index and its state table: a probe table was left behind", tables)
	}
}

// TestManticoreReadyNeedsFinishedPass: a table holding documents is not searched
// until a pass has finished on it, so a restart halfway through the first fill
// does not answer searches from a partial index. The record survives a restart
// and goes with -reindex-manticore.
func TestManticoreReadyNeedsFinishedPass(t *testing.T) {
	requireIntegration(t)
	dsn := startManticore(t)
	m, err := NewManticoreEngine(NewMemoryEngine(), ManticoreConfig{Enabled: true, DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer m.db.Close()
	setup := func(step string) {
		t.Helper()
		if err := m.setup(t.Context()); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		t.Logf("output: %s: ready=%v pass=%d last finished=%+v", step, m.ready.Load(), m.pass.Load(), m.Status().LastPass)
	}

	setup("empty table")
	if m.ready.Load() {
		t.Fatal("an empty table is ready")
	}
	doc := sourceDoc(IndexedSource{File: File{Hash: fileHash(1), Size: 1, Name: "partial.avi"},
		ClientHash: userHash(1), TimeOffer: time.Unix(1000, 0)})
	if err := m.replace([]manticoreDoc{doc}, 1); err != nil {
		t.Fatal(err)
	}
	setup("documents, no finished pass")
	if m.ready.Load() || m.pass.Load() != 1 {
		t.Fatal("a table no pass has finished on is ready")
	}
	finished := ManticorePass{Number: 1, Written: 1, Took: 1500 * time.Millisecond, Finished: time.Unix(2000, 0)}
	if err := m.storeFinishedPass(finished); err != nil {
		t.Fatal(err)
	}
	setup("finished pass recorded")
	if !m.ready.Load() || m.Status().LastPass != finished {
		t.Fatalf("got ready=%v last pass %+v, want ready and %+v", m.ready.Load(), m.Status().LastPass, finished)
	}
	m.cfg.Recreate = true
	setup("recreated")
	if m.ready.Load() || m.Status().LastPass.Number != 0 {
		t.Fatal("the recreated table kept the record of a pass")
	}
}

func testManticoreLifecycle(t *testing.T, db Engine, fresh func() Engine, dsn string) {
	t.Helper()
	alice := ClientInfo{ID: 0x0a000001, IPv4: 0x0a000001, Port: 4662, Hash: userHash(1)}
	bob := ClientInfo{ID: 0x0a000002, IPv4: 0x0a000002, Port: 4672, Hash: userHash(2)}
	early := File{Hash: fileHash(100), Size: 100, Name: "Early.Bird.Spécial 東京.avi", Completed: 1}

	// Offered before Manticore is in front: the startup pass must find it.
	alice.StoreID, _ = db.Connect(alice)
	db.AddFiles([]File{early}, alice)

	m := wrapManticore(t, fresh(), dsn)
	waitFor(t, "the startup pass", m.ready.Load)
	got := m.FindBySearch(textLeaf("early bird"))
	t.Logf("output: after startup pass %+v", got)
	if len(got) != 1 || got[0].SourceID != 0 {
		t.Fatalf("startup pass: %+v, want the file, offline (Init resets every source)", got)
	}
	if got := m.FindBySearch(textLeaf("東京")); len(got) != 1 {
		t.Fatalf("CJK search found %d file(s)", len(got))
	}
	if got := m.FindBySearch(textLeaf("spéc")); len(got) != 1 {
		t.Fatalf("accented search found %d file(s)", len(got))
	}

	shared := File{Hash: fileHash(1), Size: 700, Name: "Spider-Man (2002) it's.avi", Completed: 1}
	alice.StoreID, _ = m.Connect(alice)
	bob.StoreID, _ = m.Connect(bob)
	m.AddFiles([]File{shared}, alice)
	m.AddFiles([]File{{Hash: shared.Hash, Size: shared.Size, Name: "spider man.avi"}}, bob)
	search := &SearchExpr{Kind: SearchAnd, Left: textLeaf("spider-man"),
		Right: numericLeaf(SearchTagSources, SearchOpGreaterEqual, 2)}
	waitFor(t, "both sources", func() bool { return len(m.FindBySearch(search)) == 1 })
	got = m.FindBySearch(search)
	t.Logf("output: two sources %+v", got)
	// Either client may stand for the file: both offered within the same second,
	// which is time_offer's resolution.
	if got[0].Sources != 2 || got[0].Completed != 1 || got[0].Size != 700 ||
		(got[0].SourceID != alice.ID && got[0].SourceID != bob.ID) {
		t.Fatalf("got %+v, want 2 sources, 1 complete, an online client as the source", got[0])
	}
	if got := m.FindBySearch(textLeaf("it's")); len(got) != 1 {
		t.Fatalf("a quote in the query found %d file(s)", len(got))
	}

	m.Disconnect(bob)
	waitFor(t, "bob offline", func() bool {
		r := m.FindBySearch(search)
		return len(r) == 1 && r[0].SourceID == alice.ID
	})
	m.Disconnect(alice)
	waitFor(t, "every source offline", func() bool {
		r := m.FindBySearch(search)
		return len(r) == 1 && r[0].SourceID == 0 && r[0].Sources == 2
	})

	// An orphan the database never had goes on the next pass.
	orphan := sourceDoc(IndexedSource{File: File{Hash: fileHash(999), Size: 1, Name: "orphan.avi"},
		ClientHash: userHash(9), TimeOffer: time.Unix(1000, 0)})
	if err := m.replace([]manticoreDoc{orphan}, 0); err != nil {
		t.Fatal(err)
	}
	if len(m.FindBySearch(textLeaf("orphan"))) != 1 {
		t.Fatal("the orphan was not written")
	}
	m.reconcile()
	if got := m.FindBySearch(textLeaf("orphan")); len(got) != 0 {
		t.Fatalf("reconcile left the orphan: %+v", got)
	}
	if len(m.FindBySearch(search)) != 1 {
		t.Fatal("reconcile removed a source the database has")
	}

	// Stale offline sources go with the database's sweep.
	time.Sleep(2100 * time.Millisecond)
	if _, err := m.CleanupStale(time.Second, CleanupOptions{KeepZeroSourceFiles: true}); err != nil {
		t.Fatal(err)
	}
	if got := m.FindBySearch(search); len(got) != 0 {
		t.Fatalf("cleanup left %+v", got)
	}
	t.Logf("output: docs left after cleanup: %d", countDocs(t, m))
}

// manticoreComparable reports whether every keyword run in expr is one both
// engines match the same way: two or more characters, folded alike.
func manticoreComparable(expr *SearchExpr) bool {
	if expr == nil {
		return true
	}
	text := ""
	switch {
	case expr.Kind == SearchText:
		text = expr.Text
	case expr.Kind == SearchString && expr.TagType == searchTypeText:
		text = expr.ValueString
	}
	for _, term := range splitTerms(text) {
		for _, run := range alnumRuns(term) {
			if len([]rune(run)) < manticoreMinInfix && !strings.ContainsFunc(run, isContinuousScript) {
				return false
			}
			for _, r := range run {
				if r > unicode.MaxASCII && !isContinuousScript(r) {
					return false
				}
			}
		}
	}
	return manticoreComparable(expr.Left) && manticoreComparable(expr.Right)
}

func fileHashes(files []File) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = fmt.Sprintf("%x/%d", f.Hash, f.Size)
	}
	slices.Sort(out)
	return out
}

func difference(a, b []string) []string {
	var out []string
	for _, s := range a {
		if !slices.Contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}
