package storage

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	mrand "math/rand/v2"
	"testing"
	"time"

	"enode/tests"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

// The Ed3kStore conformance suite (ed3k_test.go) on the database engines.
// Run with ENODE_INTEGRATION=1 and Docker.

func TestMySQLEd3kStore(t *testing.T) {
	requireIntegration(t)
	engine, _ := startMySQL(t, "enode")
	testEd3kStore(t, engine)
}

// TestMariaDBEd3kStore covers the default dialect: the ed3k DDL and queries must
// not use anything MySQL-only.
func TestMariaDBEd3kStore(t *testing.T) {
	requireIntegration(t)
	testEd3kStore(t, startMariaDB(t, "enode"))
}

func TestMongoEd3kStore(t *testing.T) {
	requireIntegration(t)
	testEd3kStore(t, startMongoEngine(t, "enode_ed3k"))
}

// startMariaDB brings up mariadb:11 and returns an initialized engine.
func startMariaDB(t *testing.T, database string) *MySQLEngine {
	t.Helper()
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("docker not available: %v", err)
	}
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mariadb",
		Tag:        "11",
		Env:        []string{"MARIADB_ROOT_PASSWORD=root", "MARIADB_DATABASE=" + database},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("start mariadb container: %v", err)
	}
	t.Cleanup(func() { _ = pool.Purge(resource) })
	port := resource.GetPort("3306/tcp")
	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error {
		db, err := sql.Open("mysql", fmt.Sprintf("root:root@tcp(localhost:%s)/%s", port, database))
		if err != nil {
			return err
		}
		defer db.Close()
		return db.Ping()
	}); err != nil {
		t.Fatalf("mariadb not ready: %v", err)
	}
	engine, err := NewMySQLEngine(MySQLConfig{
		Host: "localhost", Port: mustAtoi(port), User: "root", Pass: "root", Database: database,
		MaxOpenConns: 8, MaxIdleConns: 2, Dialect: DialectMariaDB,
		SchemaFile: tests.FixRelativeTestingPath("misc/enode.sql"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

// TestManticoreEd3kStore runs the suite through the Manticore mirror, then checks
// that word searches ran on Manticore and answer exactly as the database does.
func TestManticoreEd3kStore(t *testing.T) {
	requireIntegration(t)
	dsn := startManticore(t)
	inner := NewMemoryEngine()
	m := wrapManticore(t, inner, dsn)
	testEd3kStore(t, m)
	waitFor(t, "the ed3k mirror", m.Ed3kMirrorReady)
	t.Logf("mirror ready=%v, searches answered by Manticore=%d", m.Ed3kMirrorReady(), m.Ed3kMirrorMatched())
	if m.Ed3kMirrorMatched() == 0 {
		t.Fatal("no keyword search ran on Manticore")
	}

	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	target := rnd16()
	vocab := []string{"big", "sleep", "noir", "1946", "mkv", "ça", "été", "東京", "物語", "x2"}
	r := mrand.New(mrand.NewPCG(1, 2))
	for i := range 60 {
		k := testKeyword(target, rnd32(), rnd32(), fmt.Sprintf("m-site-%d", i), now.Add(time.Hour))
		k.Words = nil
		for _, w := range vocab {
			if r.IntN(3) == 0 {
				k.Words = append(k.Words, w)
			}
		}
		k.Size = uint64(r.IntN(1000))
		k.Ext = []string{"mkv", "avi"}[r.IntN(2)]
		if res, err := m.StoreEd3kKeyword(ctx, k, Ed3kLimits{}, now, nil); res != Ed3kStored || err != nil {
			t.Fatalf("store %d: %v %v", i, res, err)
		}
	}
	before := m.Ed3kMirrorMatched()
	for i := range 40 {
		q := Ed3kQuery{All: []string{vocab[r.IntN(len(vocab))]}}
		if r.IntN(2) == 0 {
			q.None = []string{vocab[r.IntN(len(vocab))]}
		}
		if r.IntN(3) == 0 {
			q.Ext = "avi"
		}
		if r.IntN(3) == 0 {
			q.MinSize, q.MaxSize = 100, 700
		}
		for off := 0; off < 30; off += 7 {
			got, err := m.SearchEd3kKeywords(ctx, target, q, off, 7, now)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := inner.SearchEd3kKeywords(ctx, target, q, off, 7, now)
			if !sameKeywordPages(got, want) {
				t.Fatalf("query %d %+v offset %d: manticore %d (more=%v) vs database %d (more=%v)",
					i, q, off, len(got.Records), got.More, len(want.Records), want.More)
			}
		}
	}
	t.Logf("40 random queries × 5 pages agree; %d answered by Manticore", m.Ed3kMirrorMatched()-before)
}

func sameKeywordPages(a, b Ed3kKeywordPage) bool {
	if len(a.Records) != len(b.Records) || a.More != b.More || a.Files != b.Files {
		return false
	}
	for i := range a.Records {
		if a.Records[i].PubKey != b.Records[i].PubKey || !bytes.Equal(a.Records[i].Signed, b.Records[i].Signed) {
			return false
		}
	}
	return true
}
