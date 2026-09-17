package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// startMongoEngine brings up mongo:7 and returns an initialized engine.
func startMongoEngine(t *testing.T, database string) *MongoDBEngine {
	t.Helper()

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("docker not available: %v", err)
	}
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mongo",
		Tag:        "7",
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("start mongo container: %v", err)
	}
	t.Cleanup(func() { _ = pool.Purge(resource) })

	uri := fmt.Sprintf("mongodb://localhost:%s", resource.GetPort("27017/tcp"))
	engine, err := NewMongoDBEngine(MongoConfig{
		URI: uri, Database: database, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error { return engine.Init() }); err != nil {
		t.Fatalf("mongo not ready: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

// The whole point of the sweep, on the engine where rows genuinely accumulate:
// an offline client older than the TTL goes, a live one stays regardless of age,
// and files.sources is recomputed rather than left overstating reality.
func TestMySQLCleanupStale(t *testing.T) {
	requireIntegration(t)
	engine, db := startMySQL(t, "enode")

	fileHash := []byte("fedcba9876543210")

	// Three clients offering one file; two will be aged out.
	var clients []ClientInfo
	for i := 0; i < 3; i++ {
		c := ClientInfo{
			ID:   uint32(500 + i),
			IPv4: 0x0100007f,
			Port: uint16(4662 + i),
			Hash: []byte{byte('a' + i), '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'},
		}
		storeID, err := engine.Connect(c)
		if err != nil {
			t.Fatal(err)
		}
		c.StoreID = storeID
		engine.AddFile(File{Hash: fileHash, Size: 1024, Name: "movie.avi", Type: "Video"}, c)
		clients = append(clients, c)
	}

	// Two go offline and are backdated well past the TTL. The third stays online
	// and is backdated too — it must survive anyway.
	engine.Disconnect(clients[0])
	engine.Disconnect(clients[1])
	for _, c := range clients {
		if _, err := db.Exec(`UPDATE clients SET time_login = NOW() - INTERVAL 48 HOUR WHERE id = ?`, c.StoreID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE sources SET time_offer = NOW() - INTERVAL 48 HOUR WHERE id_client = ?`, c.StoreID); err != nil {
			t.Fatal(err)
		}
	}

	var before int
	if err := db.QueryRow(`SELECT sources FROM files WHERE hash = ?`, fileHash).Scan(&before); err != nil {
		t.Fatal(err)
	}
	t.Logf("input: 3 sources, 2 offline and 48h old, 1 online and 48h old; files.sources=%d", before)

	result, err := engine.CleanupStale(24*time.Hour, CleanupOptions{KeepZeroSourceFiles: true})
	if err != nil {
		t.Fatal(err)
	}

	var remainingClients, remainingSources, filesSources, fileRows int
	_ = db.QueryRow(`SELECT COUNT(*) FROM clients`).Scan(&remainingClients)
	_ = db.QueryRow(`SELECT COUNT(*) FROM sources`).Scan(&remainingSources)
	_ = db.QueryRow(`SELECT COUNT(*) FROM files WHERE hash = ?`, fileHash).Scan(&fileRows)
	if err := db.QueryRow(`SELECT sources FROM files WHERE hash = ?`, fileHash).Scan(&filesSources); err != nil {
		t.Fatal(err)
	}
	t.Logf("output: removed clients=%d sources=%d; remaining clients=%d sources=%d files.sources=%d",
		result.Clients, result.Sources, remainingClients, remainingSources, filesSources)

	if result.Clients != 2 {
		t.Fatalf("removed %d clients, want 2", result.Clients)
	}
	if remainingClients != 1 {
		t.Fatalf("%d clients remain, want 1 — an online row was deleted", remainingClients)
	}
	// The FK cascade should have taken the two offline clients' sources with them.
	if remainingSources != 1 {
		t.Fatalf("%d source rows remain, want 1", remainingSources)
	}
	// This is the assertion that catches a sweep which deletes without recounting.
	if filesSources != remainingSources {
		t.Fatalf("files.sources=%d but %d source rows remain — the counter drifted",
			filesSources, remainingSources)
	}
	if fileRows != 1 {
		t.Fatalf("the file row was deleted despite keepZeroSourceFiles")
	}
}

// The composite indexes must exist and be *applicable* to the two predicates
// that matter. Deliberately not asserting that the optimizer picks them: on a
// small table a full scan is genuinely cheaper and MySQL will rightly choose
// one, so pinning the chosen plan would make this a flaky test of the optimizer
// rather than a test of the schema.
func TestMySQLCleanupIndexesExistAndApply(t *testing.T) {
	requireIntegration(t)
	engine, db := startMySQL(t, "enode")

	// A mix of online and offline rows, so the predicates are selective enough
	// for the optimizer to list the index in possible_keys.
	for i := 0; i < 40; i++ {
		c := ClientInfo{
			ID:   uint32(700 + i),
			IPv4: 0x0100007f,
			Port: uint16(4662 + i),
			Hash: []byte{byte('a' + i%26), byte('0' + i/26), '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'},
		}
		storeID, err := engine.Connect(c)
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			c.StoreID = storeID
			engine.Disconnect(c)
		}
	}

	for _, tc := range []struct {
		table string
		index string
	}{
		{"clients", "online_time_login"},
		{"sources", "online_time_offer"},
	} {
		var count int
		err := db.QueryRow(
			`SELECT COUNT(*) FROM information_schema.statistics
			 WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`,
			tc.table, tc.index).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("output: index %s.%s columns indexed=%d", tc.table, tc.index, count)
		if count != 2 {
			t.Fatalf("index %s on %s has %d columns, want the 2-column composite",
				tc.index, tc.table, count)
		}
	}

	// And the optimizer must consider it for both shapes. possible_keys being
	// empty would mean the index cannot serve the predicate at all, which is a
	// schema bug rather than a costing decision.
	for _, query := range []string{
		`SELECT COUNT(*) FROM clients WHERE online = 1`,
		`SELECT id FROM clients WHERE online = 0 AND time_login < NOW() - INTERVAL 24 HOUR`,
	} {
		possible := explainPossibleKeys(t, db, query)
		t.Logf("output: %q -> possible_keys=%q", query, possible)
		if !strings.Contains(possible, "online_time_login") {
			t.Fatalf("online_time_login is not applicable to %q (possible_keys=%q)", query, possible)
		}
	}
}

// explainPossibleKeys returns the possible_keys column of the first EXPLAIN row,
// treating a SQL NULL as the empty string rather than the literal "<nil>".
func explainPossibleKeys(t *testing.T, db *sql.DB, query string) string {
	t.Helper()
	rows, err := db.Query("EXPLAIN " + query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		values := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for i, col := range cols {
			if col == "possible_keys" {
				return values[i].String
			}
		}
	}
	return ""
}

// Same contract on MongoDB, which has no foreign keys — the sweep has to remove
// a departed client's source documents itself.
func TestMongoCleanupStale(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_cleanup_test")

	fileHash := []byte("fedcba9876543210")
	var clients []ClientInfo
	for i := 0; i < 3; i++ {
		c := ClientInfo{
			ID:   uint32(600 + i),
			IPv4: 0x0100007f,
			Port: uint16(4662 + i),
			Hash: []byte{byte('a' + i), '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'},
		}
		storeID, err := engine.Connect(c)
		if err != nil {
			t.Fatal(err)
		}
		c.StoreID = storeID
		engine.AddFile(File{Hash: fileHash, Size: 1024, Name: "movie.avi", Type: "Video"}, c)
		clients = append(clients, c)
	}

	engine.Disconnect(clients[0])
	engine.Disconnect(clients[1])

	// Backdate everything so age is not what distinguishes them — only `online`.
	old := time.Now().Add(-48 * time.Hour)
	ctx, cancel := contextWithTimeout(engine)
	defer cancel()
	if _, err := engine.db.Collection("clients").UpdateMany(ctx, bsonAll(), bsonSetTime("time_login", old)); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.db.Collection("sources").UpdateMany(ctx, bsonAll(), bsonSetTime("time_offer", old)); err != nil {
		t.Fatal(err)
	}

	t.Logf("input: 3 sources, 2 offline, all backdated 48h")

	result, err := engine.CleanupStale(24*time.Hour, CleanupOptions{KeepZeroSourceFiles: true})
	if err != nil {
		t.Fatal(err)
	}

	remainingClients, _ := engine.db.Collection("clients").CountDocuments(ctx, bsonAll())
	remainingSources, _ := engine.db.Collection("sources").CountDocuments(ctx, bsonAll())
	files := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: "movie"})

	// Read the counter from the files collection, which is where it lives.
	// FindBySearch cannot be used for this: its pipeline runs over the sources
	// collection and decodes `sources` from the source document, which has no
	// such field, so it reports 0 unless the query happened to need the file
	// $lookup. (That is a separate divergence from MySQL, noted in the audit —
	// not something this sweep introduced or fixes.)
	var fileDoc struct {
		Sources uint32 `bson:"sources"`
	}
	if err := engine.db.Collection("files").FindOne(ctx, bson.M{"hash": fileHash}).Decode(&fileDoc); err != nil {
		t.Fatalf("read files counter: %v", err)
	}

	t.Logf("output: removed clients=%d sources=%d; remaining clients=%d sources=%d files.sources=%d",
		result.Clients, result.Sources, remainingClients, remainingSources, fileDoc.Sources)

	if result.Clients != 2 {
		t.Fatalf("removed %d clients, want 2", result.Clients)
	}
	if remainingClients != 1 {
		t.Fatalf("%d clients remain, want 1", remainingClients)
	}
	if remainingSources != 1 {
		t.Fatalf("%d source documents remain, want 1 — a departed client's sources were left behind", remainingSources)
	}
	if len(files) != 1 {
		t.Fatalf("search returned %d files, want 1", len(files))
	}
	// The assertion that catches a sweep which deletes without recounting.
	if int64(fileDoc.Sources) != remainingSources {
		t.Fatalf("files.sources=%d but %d source documents remain — the counter drifted",
			fileDoc.Sources, remainingSources)
	}
}

// Small helpers so the Mongo test can reach the driver without importing bson
// into every call site.
func contextWithTimeout(engine *MongoDBEngine) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), engine.cfg.Timeout)
}

func bsonAll() bson.M { return bson.M{} }

func bsonSetTime(field string, value time.Time) bson.M {
	return bson.M{"$set": bson.M{field: value}}
}

// cleanupBatchFixture offers n files from a client that then goes stale and from one
// that stays online, in that order, so every file loses exactly one source to the
// sweep and its stamped source address belongs to the survivor.
func cleanupBatchFixture(t *testing.T, engine Engine, n int) (stale, live ClientInfo, files []File) {
	t.Helper()
	stale = ClientInfo{ID: 801, IPv4: 0x0100007f, Port: 4662, Hash: []byte("ssssssssssssssss")}
	live = ClientInfo{ID: 802, IPv4: 0x0200007f, Port: 4663, Hash: []byte("llllllllllllllll")}
	for _, c := range []*ClientInfo{&stale, &live} {
		id, err := engine.Connect(*c)
		if err != nil {
			t.Fatal(err)
		}
		c.StoreID = id
	}
	for i := 0; i < n; i++ {
		hash := []byte(fmt.Sprintf("batchfile%07d", i))
		files = append(files, File{Hash: hash, Size: uint64(1000 + i), Name: fmt.Sprintf("batch %d.avi", i)})
	}
	engine.AddFiles(files, stale)
	engine.AddFiles(files, live)
	engine.Disconnect(stale)
	return stale, live, files
}

// The recount now runs one statement per batch instead of one per file. BatchSize 2
// over 5 affected files puts a boundary inside the set and a short final batch at the
// end, which is where an off-by-one would leave a file uncounted.
func TestMySQLCleanupRecountsAcrossBatches(t *testing.T) {
	requireIntegration(t)
	engine, db := startMySQL(t, "enode")

	stale, live, files := cleanupBatchFixture(t, engine, 5)
	if _, err := db.Exec(`UPDATE clients SET time_login = NOW() - INTERVAL 48 HOUR WHERE id = ?`, stale.StoreID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE sources SET time_offer = NOW() - INTERVAL 48 HOUR WHERE id_client = ?`, stale.StoreID); err != nil {
		t.Fatal(err)
	}
	t.Logf("input: %d files with 2 sources each, one source stale; BatchSize=2", len(files))

	result, err := engine.CleanupStale(24*time.Hour, CleanupOptions{KeepZeroSourceFiles: true, BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: removed clients=%d sources=%d", result.Clients, result.Sources)

	for _, f := range files {
		var sources int
		var sourceID uint32
		var sourcePort uint16
		if err := db.QueryRow(`SELECT sources, source_id, source_port FROM files WHERE hash = ? AND size = ?`,
			f.Hash, f.Size).Scan(&sources, &sourceID, &sourcePort); err != nil {
			t.Fatal(err)
		}
		t.Logf("output: %s sources=%d source=%d:%d", f.Hash, sources, sourceID, sourcePort)
		if sources != 1 {
			t.Errorf("%s: files.sources=%d, want 1 — not recounted", f.Hash, sources)
		}
		if sourceID != live.ID || sourcePort != live.Port {
			t.Errorf("%s: source=%d:%d, want %d:%d — the sweep must not touch the source address",
				f.Hash, sourceID, sourcePort, live.ID, live.Port)
		}
	}
}

// The MongoDB twin of TestMySQLCleanupRecountsAcrossBatches.
func TestMongoCleanupRecountsAcrossBatches(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_cleanup_batches")

	stale, live, files := cleanupBatchFixture(t, engine, 5)
	backdateMongoClient(t, engine, stale, time.Now().Add(-48*time.Hour))
	t.Logf("input: %d files with 2 sources each, one source stale; BatchSize=2", len(files))

	result, err := engine.CleanupStale(24*time.Hour, CleanupOptions{KeepZeroSourceFiles: true, BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: removed clients=%d sources=%d", result.Clients, result.Sources)
	assertMongoCountersAfterSweep(t, engine, files, live)
}

// The sweep used to run under one Timeout for all of its operations, so its real
// limit was total round-trips × RTT. Here the Timeout is far longer than any single
// operation takes but far shorter than the whole sweep, which is exactly the shape a
// remote database gives a busy server's hourly sweep: it must now complete.
func TestMongoCleanupSurvivesCumulativeDeadline(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_cleanup_deadline")

	const affectedFiles = 400
	stale, live, files := cleanupBatchFixture(t, engine, affectedFiles)
	backdateMongoClient(t, engine, stale, time.Now().Add(-48*time.Hour))

	engine.cfg.Timeout = 150 * time.Millisecond
	t.Logf("input: %d affected files, BatchSize=1 (2 round-trips each), Timeout=%s per operation",
		affectedFiles, engine.cfg.Timeout)

	start := time.Now()
	result, err := engine.CleanupStale(24*time.Hour, CleanupOptions{KeepZeroSourceFiles: true, BatchSize: 1})
	elapsed := time.Since(start)
	t.Logf("output: err=%v removed clients=%d sources=%d elapsed=%s", err, result.Clients, result.Sources, elapsed)
	if err != nil {
		t.Fatalf("sweep failed: %v", err)
	}

	engine.cfg.Timeout = 10 * time.Second
	assertMongoCountersAfterSweep(t, engine, files, live)

	if elapsed <= 150*time.Millisecond {
		t.Skipf("sweep took %s, inside one Timeout, so this run cannot tell a per-operation deadline from a cumulative one", elapsed)
	}
}

// Init runs ensureIndexes on every start; it must write each index once. The upgrade
// case is the one that matters most: a database built by the old inline calls carries
// driver-generated names, and the explicit names have to match them exactly, or every
// existing index would be "missing" and re-created under a conflicting name.
func TestMongoEnsureIndexesCreatesOnce(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_indexes_init")
	ctx, cancel := contextWithTimeout(engine)
	defer cancel()

	t.Run("fresh database", func(t *testing.T) {
		engine.db = engine.client.Database("enode_indexes_fresh")
		first, err := engine.ensureIndexes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		second, err := engine.ensureIndexes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("input: empty database, ensureIndexes twice")
		t.Logf("output: first=%d %q", len(first), first)
		t.Logf("output: second=%q", second)
		if len(first) != len(mongoIndexes) {
			t.Fatalf("first run created %d indexes, want %d", len(first), len(mongoIndexes))
		}
		if len(second) != 0 {
			t.Fatalf("second run created %q, want nothing", second)
		}

		if err := engine.db.Collection("sources").Indexes().DropOne(ctx, "client_hash_1"); err != nil {
			t.Fatal(err)
		}
		third, err := engine.ensureIndexes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("input: dropped sources.client_hash_1")
		t.Logf("output: third=%q", third)
		if strings.Join(third, ",") != "sources.client_hash_1" {
			t.Fatalf("after the drop created %q, want exactly sources.client_hash_1", third)
		}
	})

	t.Run("database from before explicit names", func(t *testing.T) {
		engine.db = engine.client.Database("enode_indexes_legacy")
		// The index set of commit 8d0bde6: without the two indexes added since, and
		// with file_hash_1_file_size_1, which the source lookup index replaced.
		var legacy []mongoIndex
		for _, idx := range mongoIndexes {
			switch idx.name {
			case "client_hash_1", "file_hash_1_file_size_1_online_1_time_offer_-1":
				continue
			}
			legacy = append(legacy, idx)
		}
		legacy = append(legacy, mongoIndex{collection: "sources", name: "file_hash_1_file_size_1",
			keys: bson.D{{Key: "file_hash", Value: 1}, {Key: "file_size", Value: 1}}})
		for _, idx := range legacy {
			model := mongo.IndexModel{Keys: idx.keys}
			if idx.unique {
				model.Options = options.Index().SetUnique(true)
			}
			if _, err := engine.db.Collection(idx.collection).Indexes().CreateOne(ctx, model); err != nil {
				t.Fatalf("legacy %s.%s: %v", idx.collection, idx.name, err)
			}
		}
		created, err := engine.ensureIndexes(ctx)
		t.Logf("input: %d indexes created the old way, with driver-generated names", len(legacy))
		t.Logf("output: created=%q err=%v", created, err)
		if err != nil {
			t.Fatal(err)
		}
		want := "sources.file_hash_1_file_size_1_online_1_time_offer_-1,sources.client_hash_1"
		if strings.Join(created, ",") != want {
			t.Fatalf("created %q, want only the two new indexes %s — an explicit name differs from the generated one", created, want)
		}
	})
}

// Disconnect and the sweep select sources by client hash. Before client_hash_1 no
// index led with that field, so each was a collection scan.
func TestMongoClientHashIndexUsed(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_client_hash_index")
	ctx, cancel := contextWithTimeout(engine)
	defer cancel()

	h := []byte("hhhhhhhhhhhhhhhh")
	cases := []struct {
		label  string
		filter bson.M
	}{
		{"Disconnect: client_hash equality", bson.M{"client_hash": h}},
		{"sweep delete: client_hash $in", bson.M{"client_hash": bson.M{"$in": []any{h, []byte("iiiiiiiiiiiiiiii")}}}},
		{"affectedFileKeys: $or of stale sources and client_hash $in", bson.M{"$or": []bson.M{
			{"online": false, "time_offer": bson.M{"$lt": time.Now()}},
			{"client_hash": bson.M{"$in": []any{h}}},
		}}},
	}
	for _, tc := range cases {
		var plan struct {
			QueryPlanner struct {
				WinningPlan bson.Raw `bson:"winningPlan"`
			} `bson:"queryPlanner"`
		}
		err := engine.db.RunCommand(ctx, bson.D{
			{Key: "explain", Value: bson.D{{Key: "find", Value: "sources"}, {Key: "filter", Value: tc.filter}}},
			{Key: "verbosity", Value: "queryPlanner"},
		}).Decode(&plan)
		if err != nil {
			t.Fatalf("%s: explain: %v", tc.label, err)
		}
		winning := plan.QueryPlanner.WinningPlan.String()
		t.Logf("input: %s", tc.label)
		t.Logf("output: winningPlan=%s", winning)
		if strings.Contains(winning, "COLLSCAN") {
			t.Errorf("%s: collection scan", tc.label)
		}
		if !strings.Contains(winning, `"client_hash_1"`) {
			t.Errorf("%s: plan does not use client_hash_1", tc.label)
		}
	}
}

// GetSources on a popular file must read MaxWireSources index keys, not every source
// of the file: the plan has to use the source lookup index and must not sort in
// memory.
func TestMongoSourceLookupUsesIndex(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_source_lookup_index")
	ctx, cancel := contextWithTimeout(engine)
	defer cancel()

	const sources = 1000
	fileHash := []byte("popularpopularpo")
	now := time.Now()
	docs := make([]any, sources)
	clients := make([]any, sources)
	for i := range docs {
		clientHash := []byte(fmt.Sprintf("lookupclient%04d", i))
		docs[i] = bson.M{"file_hash": fileHash, "file_size": int64(4096), "client_hash": clientHash,
			"name": "popular.avi", "online": true, "time_offer": now.Add(-time.Duration(i) * time.Second)}
		clients[i] = bson.M{"hash": clientHash, "id_ed2k": int64(1000 + i), "port": int64(4662), "online": true}
	}
	if _, err := engine.db.Collection("sources").InsertMany(ctx, docs); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.db.Collection("clients").InsertMany(ctx, clients); err != nil {
		t.Fatal(err)
	}

	var explain bson.Raw
	err := engine.db.RunCommand(ctx, bson.D{
		{Key: "explain", Value: bson.D{
			{Key: "aggregate", Value: "sources"},
			{Key: "pipeline", Value: sourceLookupPipeline(bson.M{"file_hash": fileHash, "file_size": int64(4096), "online": true})},
			{Key: "cursor", Value: bson.D{}},
		}},
		{Key: "verbosity", Value: "executionStats"},
	}).Decode(&explain)
	if err != nil {
		t.Fatal(err)
	}
	// Explain nests the query layer under the first stage's $cursor, or at the top
	// when the whole pipeline ran in the slot-based engine.
	cursor := explain
	if c, err := explain.LookupErr("stages", "0", "$cursor"); err == nil {
		cursor = c.Document()
	}
	winning, err := cursor.LookupErr("queryPlanner", "winningPlan")
	if err != nil {
		t.Fatalf("no winning plan in %s", explain)
	}
	plan := winning.String()
	keys, err := cursor.LookupErr("executionStats", "totalKeysExamined")
	if err != nil {
		t.Fatalf("no executionStats in %s", explain)
	}
	docsExamined, _ := cursor.LookupErr("executionStats", "totalDocsExamined")
	t.Logf("input: %d online sources of one file, the GetSources pipeline", sources)
	t.Logf("output: totalKeysExamined=%s totalDocsExamined=%s", keys, docsExamined)
	t.Logf("output: winningPlan=%s", plan)
	if !strings.Contains(plan, `"file_hash_1_file_size_1_online_1_time_offer_-1"`) {
		t.Errorf("winning plan does not use file_hash_1_file_size_1_online_1_time_offer_-1")
	}
	if strings.Contains(plan, `"SORT"`) {
		t.Errorf("winning plan sorts in memory instead of reading the index in order")
	}
	if n := keys.AsInt64(); n > MaxWireSources {
		t.Errorf("examined %d index keys, want at most %d", n, MaxWireSources)
	}
	if got := len(engine.GetSources(fileHash, 4096)); got != MaxWireSources {
		t.Errorf("GetSources returned %d sources, want %d", got, MaxWireSources)
	}
}

// A sweep splits its stale client hashes into chunks of the batch size; every chunk
// must still lose its clients and sources, and every affected file its count.
func TestMongoCleanupChunksStaleClients(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_cleanup_chunks")

	const staleClients = 7
	live := ClientInfo{ID: 850, IPv4: 0x0100007f, Port: 4662, Hash: []byte("livelivelivelive")}
	if _, err := engine.Connect(live); err != nil {
		t.Fatal(err)
	}
	var files []File
	for i := 0; i < staleClients; i++ {
		c := ClientInfo{ID: uint32(860 + i), IPv4: 0x0200007f, Port: 4662, Hash: []byte(fmt.Sprintf("chunkstaleclie%02d", i))}
		if _, err := engine.Connect(c); err != nil {
			t.Fatal(err)
		}
		f := File{Hash: []byte(fmt.Sprintf("chunkfile%07d", i)), Size: uint64(700 + i), Name: fmt.Sprintf("chunk %d.avi", i)}
		files = append(files, f)
		engine.AddFiles([]File{f}, c)
		engine.AddFiles([]File{f}, live)
		engine.Disconnect(c)
		backdateMongoClient(t, engine, c, time.Now().Add(-48*time.Hour))
	}

	result, err := engine.CleanupStale(24*time.Hour, CleanupOptions{BatchSize: 2, KeepZeroSourceFiles: true})
	t.Logf("input: %d stale clients, one file each also offered by a live client, BatchSize=2", staleClients)
	t.Logf("output: result=%+v err=%v", result, err)
	if err != nil {
		t.Fatal(err)
	}
	if result.Clients != staleClients || result.Sources != staleClients {
		t.Fatalf("removed %d clients and %d sources, want %d of each", result.Clients, result.Sources, staleClients)
	}
	assertMongoCountersAfterSweep(t, engine, files, live)
}

// The sweep deletes a file left without sources only when no offer has stamped it
// since the cutoff. A file an offer is writing also has sources = 0 for a moment —
// between its files upsert and its counter refresh — and deleting it then cascaded
// away (MySQL) or orphaned (MongoDB) the source the offer had just stored. Found by
// tests/dblatency's load test; here the in-flight offer is the fresh time_offer.
func TestMySQLCleanupKeepsZeroSourceFileBeingOffered(t *testing.T) {
	requireIntegration(t)
	engine, db := startMySQL(t, "enode_zero_source_offer")
	gone, old, fresh := zeroSourceFixture(t, engine)
	for _, q := range []struct {
		query string
		arg   any
	}{
		{`UPDATE clients SET time_login = NOW() - INTERVAL 48 HOUR WHERE id = ?`, gone.StoreID},
		{`UPDATE sources SET time_offer = NOW() - INTERVAL 48 HOUR WHERE id_client = ?`, gone.StoreID},
		{`UPDATE files SET time_offer = NOW() - INTERVAL 48 HOUR WHERE hash = ?`, old.Hash},
	} {
		if _, err := db.Exec(q.query, q.arg); err != nil {
			t.Fatal(err)
		}
	}

	result, err := engine.CleanupStale(24*time.Hour, CleanupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	remaining := func(f File) int {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM files WHERE hash = ? AND sources = 0`, f.Hash).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	assertZeroSourceSweep(t, result, remaining(old), remaining(fresh))
}

// The MongoDB twin of TestMySQLCleanupKeepsZeroSourceFileBeingOffered.
func TestMongoCleanupKeepsZeroSourceFileBeingOffered(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_zero_source_offer")
	gone, old, fresh := zeroSourceFixture(t, engine)
	backdateMongoClient(t, engine, gone, time.Now().Add(-48*time.Hour))
	ctx, cancel := contextWithTimeout(engine)
	defer cancel()
	if _, err := engine.db.Collection("files").UpdateOne(ctx, bson.M{"hash": old.Hash},
		bsonSetTime("time_offer", time.Now().Add(-48*time.Hour))); err != nil {
		t.Fatal(err)
	}

	result, err := engine.CleanupStale(24*time.Hour, CleanupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	remaining := func(f File) int {
		n, err := engine.db.Collection("files").CountDocuments(ctx, bson.M{"hash": f.Hash, "sources": 0})
		if err != nil {
			t.Fatal(err)
		}
		return int(n)
	}
	assertZeroSourceSweep(t, result, remaining(old), remaining(fresh))
}

// zeroSourceFixture has one client offer two files and log off. The caller ages the
// client and its sources past the sweep's cutoff, and the old file with them.
func zeroSourceFixture(t *testing.T, engine Engine) (gone ClientInfo, old, fresh File) {
	t.Helper()
	gone = ClientInfo{ID: 811, IPv4: 0x0100007f, Port: 4662, Hash: []byte("gggggggggggggggg")}
	id, err := engine.Connect(gone)
	if err != nil {
		t.Fatal(err)
	}
	gone.StoreID = id
	old = File{Hash: []byte("oldoldoldoldoldo"), Size: 111, Name: "old.avi"}
	fresh = File{Hash: []byte("freshfreshfreshf"), Size: 222, Name: "fresh.avi"}
	engine.AddFiles([]File{old, fresh}, gone)
	engine.Disconnect(gone)
	return gone, old, fresh
}

func assertZeroSourceSweep(t *testing.T, result CleanupResult, old, fresh int) {
	t.Helper()
	t.Logf("input: both files lose their only source; old.avi last offered 48h ago, fresh.avi just now")
	t.Logf("output: result=%+v; zero-source rows left: old.avi=%d fresh.avi=%d", result, old, fresh)
	if result.Files != 1 || old != 0 {
		t.Errorf("deleted %d files and old.avi remains %d times, want old.avi deleted", result.Files, old)
	}
	if fresh != 1 {
		t.Errorf("fresh.avi remains %d times, want 1 — a file being offered was deleted", fresh)
	}
}

func backdateMongoClient(t *testing.T, engine *MongoDBEngine, client ClientInfo, when time.Time) {
	t.Helper()
	ctx, cancel := contextWithTimeout(engine)
	defer cancel()
	if _, err := engine.db.Collection("clients").UpdateOne(ctx, bson.M{"hash": client.Hash}, bsonSetTime("time_login", when)); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.db.Collection("sources").UpdateMany(ctx, bson.M{"client_hash": client.Hash}, bsonSetTime("time_offer", when)); err != nil {
		t.Fatal(err)
	}
}

func assertMongoCountersAfterSweep(t *testing.T, engine *MongoDBEngine, files []File, live ClientInfo) {
	t.Helper()
	ctx, cancel := contextWithTimeout(engine)
	defer cancel()
	wrong := 0
	for _, f := range files {
		var doc struct {
			Sources    int64 `bson:"sources"`
			SourceID   int64 `bson:"source_id"`
			SourcePort int64 `bson:"source_port"`
		}
		if err := engine.db.Collection("files").FindOne(ctx, bson.M{"hash": f.Hash, "size": f.Size}).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		if doc.Sources != 1 || doc.SourceID != int64(live.ID) || doc.SourcePort != int64(live.Port) {
			if wrong < 5 {
				t.Errorf("%s: sources=%d source=%d:%d, want 1 and %d:%d", f.Hash, doc.Sources, doc.SourceID, doc.SourcePort, live.ID, live.Port)
			}
			wrong++
		}
	}
	t.Logf("output: %d of %d files have sources=1 and the live client's address", len(files)-wrong, len(files))
}
