package storage

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"enode/tests"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// startMySQL brings up mysql:8.0 with the schema applied and returns a ready
// engine. 8.0 matters: ONLY_FULL_GROUP_BY and STRICT_TRANS_TABLES are both on by
// default there, which is exactly what H5 and H8 trip over.
func startMySQL(t *testing.T, database string) (*MySQLEngine, *sql.DB) {
	t.Helper()

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("docker not available: %v", err)
	}
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mysql",
		Tag:        "8.0",
		Env: []string{
			"MYSQL_ROOT_PASSWORD=root",
			"MYSQL_DATABASE=" + database,
		},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("start mysql container: %v", err)
	}
	t.Cleanup(func() { _ = pool.Purge(resource) })

	port := resource.GetPort("3306/tcp")
	dsn := fmt.Sprintf("root:root@tcp(localhost:%s)/%s?parseTime=true", port, database)

	var db *sql.DB
	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error {
		var e error
		db, e = sql.Open("mysql", dsn)
		if e != nil {
			return e
		}
		return db.Ping()
	}); err != nil {
		t.Fatalf("mysql not ready: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Init creates the schema from the resolved relative path on first connect, so
	// the raw db handle above stays for the direct assertions these tests make.
	engine, err := NewMySQLEngine(MySQLConfig{
		Host: "localhost", Port: mustAtoi(port), User: "root", Pass: "root", Database: database,
		MaxOpenConns: 4, MaxIdleConns: 2,
		SchemaFile: tests.FixRelativeTestingPath("misc/enode.sql"),
		// The container is MySQL, so the dialect must say so. The default, mariadb,
		// writes the grouped search without ANY_VALUE(), which this server's
		// ONLY_FULL_GROUP_BY rejects with ER_1055 — every search here returned nothing.
		Dialect: DialectMySQL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	// Confirm the modes that make these bugs reachable are actually on, so a
	// green run cannot mean "the container happened to be permissive".
	var mode string
	if err := db.QueryRow(`SELECT @@SESSION.sql_mode`).Scan(&mode); err != nil {
		t.Fatalf("read sql_mode: %v", err)
	}
	t.Logf("input: server sql_mode=%s", mode)
	if !strings.Contains(mode, "ONLY_FULL_GROUP_BY") {
		t.Fatal("ONLY_FULL_GROUP_BY is not enabled; this test could not detect H5")
	}
	if !strings.Contains(mode, "STRICT_TRANS_TABLES") {
		t.Fatal("STRICT_TRANS_TABLES is not enabled; this test could not detect H8")
	}
	return engine, db
}

// The twin of TestMongoFindBySearch that never existed for MySQL — which is why
// H5 went unnoticed. FindBySearch selects eight non-aggregated s.* columns while
// grouping by s.id_file, which ONLY_FULL_GROUP_BY rejects with ER_1055; the error
// was swallowed and the search returned no rows.
func TestMySQLFindBySearch(t *testing.T) {
	requireIntegration(t)
	engine, _ := startMySQL(t, "enode")

	client := ClientInfo{ID: 401, IPv4: 0x0100007f, Port: 4662, Hash: []byte("0123456789abcdef")}
	storeID, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = storeID

	seed := []File{
		{Hash: []byte("aaaaaaaaaaaaaaaa"), Name: "holiday movie.avi", Size: 700, Type: "Video", Completed: 1},
		{Hash: []byte("bbbbbbbbbbbbbbbb"), Name: "holiday song.mp3", Size: 800, Type: "Audio", Completed: 1},
		{Hash: []byte("cccccccccccccccc"), Name: "vacation movie.avi", Size: 900, Type: "Video", Completed: 1},
	}
	for _, f := range seed {
		engine.AddFile(f, client)
		t.Logf("input: seeded %q type=%s", f.Name, f.Type)
	}

	// A second source for one file, so id_file is genuinely non-unique in sources
	// — without this, MySQL might resolve the functional dependency and the bug
	// would not reproduce.
	second := ClientInfo{ID: 402, IPv4: 0x0100007f, Port: 4663, Hash: []byte("fedcba9876543210")}
	secondStore, err := engine.Connect(second)
	if err != nil {
		t.Fatal(err)
	}
	second.StoreID = secondStore
	engine.AddFile(seed[0], second)
	t.Logf("input: %q has two sources", seed[0].Name)

	cases := []struct {
		name  string
		expr  *SearchExpr
		want  int
		names []string
	}{
		{
			name:  "single term",
			expr:  &SearchExpr{Kind: SearchText, Text: "movie"},
			want:  2,
			names: []string{"holiday movie.avi", "vacation movie.avi"},
		},
		{
			name: "term AND type",
			expr: &SearchExpr{
				Kind:  SearchAnd,
				Left:  &SearchExpr{Kind: SearchText, Text: "holiday"},
				Right: &SearchExpr{Kind: SearchString, TagType: searchTypeFileType, ValueString: "Audio"},
			},
			want:  1,
			names: []string{"holiday song.mp3"},
		},
		{
			name: "OR of two terms",
			expr: &SearchExpr{
				Kind:  SearchOr,
				Left:  &SearchExpr{Kind: SearchText, Text: "song"},
				Right: &SearchExpr{Kind: SearchText, Text: "vacation"},
			},
			want:  2,
			names: []string{"holiday song.mp3", "vacation movie.avi"},
		},
		{
			name: "AND NOT",
			expr: &SearchExpr{
				Kind:  SearchAndNot,
				Left:  &SearchExpr{Kind: SearchText, Text: "movie"},
				Right: &SearchExpr{Kind: SearchText, Text: "vacation"},
			},
			want:  1,
			names: []string{"holiday movie.avi"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.FindBySearch(tc.expr)
			var names []string
			for _, f := range got {
				names = append(names, f.Name)
			}
			t.Logf("output: %d results %v", len(got), names)
			if len(got) != tc.want {
				t.Fatalf("got %d results %v, want %d %v", len(got), names, tc.want, tc.names)
			}
			// One row per file, not per source: the file with two sources must
			// still appear once.
			seen := map[string]bool{}
			for _, n := range names {
				if seen[n] {
					t.Fatalf("duplicate result for %q: GROUP BY did not collapse sources", n)
				}
				seen[n] = true
			}
			// Metadata must survive the ANY_VALUE() wrapping.
			for _, f := range got {
				if f.Name == "" {
					t.Fatal("result has an empty name; ANY_VALUE lost the column")
				}
			}
		})
	}
}

// TestMySQLFindBySearchEscapesWildcards pins L13 end to end: a % in a search term
// must match a literal %, the way the memory and Mongo engines already do — not act
// as a SQL wildcard. Against the pre-fix build `LIKE '%a%b%'` matches both "a%b"
// and "aXb"; with escaping only the literal "a%b" matches.
func TestMySQLFindBySearchEscapesWildcards(t *testing.T) {
	requireIntegration(t)
	engine, _ := startMySQL(t, "enode")

	client := ClientInfo{ID: 601, IPv4: 0x0100007f, Port: 4662, Hash: []byte("0123456789abcdef")}
	storeID, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = storeID

	seed := []File{
		{Hash: []byte("dddddddddddddddd"), Name: "a%b", Size: 100, Type: "Doc"},
		{Hash: []byte("eeeeeeeeeeeeeeee"), Name: "aXb", Size: 200, Type: "Doc"},
	}
	for _, f := range seed {
		engine.AddFile(f, client)
		t.Logf("input: seeded %q", f.Name)
	}

	got := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: "a%b"})
	var names []string
	for _, f := range got {
		names = append(names, f.Name)
	}
	t.Logf("output: search %q → %d result(s) %v", "a%b", len(got), names)
	if len(got) != 1 || names[0] != "a%b" {
		t.Fatalf("got %v, want exactly [\"a%%b\"] — %% must be a literal, not a wildcard", names)
	}
}

// Client tags are bound raw into varchar(8)/varchar(128)/varchar(255) and an
// ENUM. Under STRICT_TRANS_TABLES an over-length value or a non-member type
// aborts the whole sources INSERT, so the file is published but never becomes
// searchable — silently, because the error is only logged.
func TestMySQLAddFileWithHostileTags(t *testing.T) {
	requireIntegration(t)
	engine, db := startMySQL(t, "enode")

	client := ClientInfo{ID: 501, IPv4: 0x0100007f, Port: 4662, Hash: []byte("0123456789abcdef")}
	storeID, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = storeID

	hostile := File{
		Hash: []byte("1111111111111111"),
		// Over varchar(255), and an extension over varchar(8).
		Name: strings.Repeat("x", 400) + ".torrent-part001",
		Size: 4096,
		// Not an ENUM member: eMule sends this for collection files.
		Type:      "EmuleCollection",
		Title:     strings.Repeat("t", 300),
		Artist:    strings.Repeat("a", 300),
		Album:     strings.Repeat("b", 300),
		Codec:     strings.Repeat("c", 100),
		Completed: 1,
	}
	t.Logf("input: name=%d runes ext=%q type=%q codec=%d runes",
		len([]rune(hostile.Name)), Ext(hostile.Name), hostile.Type, len([]rune(hostile.Codec)))

	engine.AddFile(hostile, client)

	var (
		name, ext, typ, codec string
		count                 int
	)
	if err := db.QueryRow(`SELECT COUNT(*) FROM sources`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	t.Logf("output: %d source rows", count)
	if count == 0 {
		t.Fatal("hostile tags aborted the sources INSERT: the file is published but unsearchable")
	}
	if err := db.QueryRow(`SELECT name, ext, type, codec FROM sources LIMIT 1`).Scan(&name, &ext, &typ, &codec); err != nil {
		t.Fatal(err)
	}
	t.Logf("output: stored name=%d runes ext=%q type=%q codec=%d runes",
		len([]rune(name)), ext, typ, len([]rune(codec)))

	if len([]rune(name)) > maxNameLen {
		t.Fatalf("name exceeds varchar(%d): %d runes", maxNameLen, len([]rune(name)))
	}
	if len([]rune(ext)) > maxExtLen {
		t.Fatalf("ext exceeds varchar(%d): %q", maxExtLen, ext)
	}
	if _, ok := enumFileTypes[typ]; !ok {
		t.Fatalf("stored type %q is not an ENUM member", typ)
	}
	if len([]rune(codec)) > maxCodecLen {
		t.Fatalf("codec exceeds varchar(%d): %d runes", maxCodecLen, len([]rune(codec)))
	}

	// And the file must actually be findable, which is the point of the fix.
	found := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: strings.Repeat("x", 20)})
	t.Logf("output: search found %d results", len(found))
	if len(found) == 0 {
		t.Fatal("file with hostile tags was stored but is not searchable")
	}
}

// Sources were identified by (file, client_ed2k). The ed2k ID is per-session for
// LowIDs and follows the IP for HighIDs, so reconnecting produced a *second*
// source document; the first never matched Disconnect again and stayed online
// forever, inflating files.sources without bound.
func TestMongoSourceIdentitySurvivesEd2kIDChange(t *testing.T) {
	requireIntegration(t)

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
	defer func() { _ = pool.Purge(resource) }()

	uri := fmt.Sprintf("mongodb://localhost:%s", resource.GetPort("27017/tcp"))
	engine, err := NewMongoDBEngine(MongoConfig{
		URI: uri, Database: "enode_source_identity", Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error { return engine.Init() }); err != nil {
		t.Fatalf("mongo not ready: %v", err)
	}
	defer engine.Close()

	userHash := []byte("0123456789abcdef")
	file := File{Hash: []byte("dddddddddddddddd"), Name: "shared.avi", Size: 4096, Type: "Video", Completed: 1}

	// Session 1: LowID 1000.
	first := ClientInfo{ID: 1000, IPv4: 0x0100007f, Port: 4662, Hash: userHash}
	if _, err := engine.Connect(first); err != nil {
		t.Fatal(err)
	}
	engine.AddFile(file, first)
	t.Logf("input: session 1 offered %q with ed2k ID=%d", file.Name, first.ID)
	engine.Disconnect(first)

	// Session 2: same user, different ed2k ID — a new LowID slot or a new IP.
	second := ClientInfo{ID: 2000, IPv4: 0x0200007f, Port: 4663, Hash: userHash}
	if _, err := engine.Connect(second); err != nil {
		t.Fatal(err)
	}
	engine.AddFile(file, second)
	t.Logf("input: session 2 offered the same file with ed2k ID=%d", second.ID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	total, err := engine.db.Collection("sources").CountDocuments(ctx, bson.M{"file_hash": file.Hash})
	if err != nil {
		t.Fatal(err)
	}
	online, err := engine.db.Collection("sources").CountDocuments(ctx,
		bson.M{"file_hash": file.Hash, "online": true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: %d source documents, %d online", total, online)

	if total != 1 {
		t.Fatalf("reconnecting with a new ed2k ID created %d source documents, want 1", total)
	}
	if online != 1 {
		t.Fatalf("expected exactly 1 online source, got %d", online)
	}

	// The current address must have been refreshed on the surviving document.
	var doc struct {
		ClientED2K uint32 `bson:"client_ed2k"`
	}
	if err := engine.db.Collection("sources").FindOne(ctx, bson.M{"file_hash": file.Hash}).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	t.Logf("output: surviving document has client_ed2k=%d", doc.ClientED2K)
	if doc.ClientED2K != second.ID {
		t.Fatalf("client_ed2k not refreshed: got %d, want %d", doc.ClientED2K, second.ID)
	}

	// And it must resolve back to a usable source.
	sources := engine.GetSources(file.Hash, file.Size)
	t.Logf("output: GetSources returned %d sources", len(sources))
	if len(sources) != 1 {
		t.Fatalf("GetSources returned %d sources, want 1", len(sources))
	}
	if sources[0].ID != second.ID {
		t.Fatalf("source resolved to ed2k ID %d, want %d", sources[0].ID, second.ID)
	}

	// Disconnecting the live session must clear it, matching on hash.
	engine.Disconnect(second)
	stillOnline, err := engine.db.Collection("sources").CountDocuments(ctx,
		bson.M{"file_hash": file.Hash, "online": true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: after disconnect, %d sources still online", stillOnline)
	if stillOnline != 0 {
		t.Fatalf("%d sources remained online after disconnect", stillOnline)
	}
}

// TestMySQLAddFilesBatch runs offers through the batched write on mysql:8.0 — strict
// mode, ONLY_FULL_GROUP_BY — and checks what the per-file path guaranteed: a later
// duplicate wins, hostile tags still land and stay searchable, the counters count
// every client, and the stamped source address is the latest offering client's.
func TestMySQLAddFilesBatch(t *testing.T) {
	requireIntegration(t)
	engine, db := startMySQL(t, "enode")

	a := ClientInfo{ID: 701, IPv4: 0x0100007f, Port: 4662, Hash: []byte("aaaaaaaaaaaaaaaa")}
	b := ClientInfo{ID: 702, IPv4: 0x0200007f, Port: 4663, Hash: []byte("bbbbbbbbbbbbbbbb")}
	for _, c := range []*ClientInfo{&a, &b} {
		id, err := engine.Connect(*c)
		if err != nil {
			t.Fatal(err)
		}
		c.StoreID = id
	}

	h1, h2, h3 := []byte("1111111111111111"), []byte("2222222222222222"), []byte("3333333333333333")
	offerA := []File{
		{Hash: h1, Size: 100, Name: "alpha first.avi"},
		{Hash: h2, Size: 200, Name: "beta.mp3", Completed: 1},
		{Hash: h1, Size: 100, Name: "alpha renamed.avi"},
		{Hash: h3, Size: 4096, Name: strings.Repeat("x", 400) + ".torrent-part001",
			Type: "EmuleCollection", Codec: strings.Repeat("c", 100), Completed: 1},
	}
	offerB := []File{
		{Hash: h1, Size: 100, Name: "alpha b.avi"},
		{Hash: h2, Size: 200, Name: "beta.mp3"},
	}
	t.Logf("input: client A (id=701 port=4662) offers %d records: a duplicate h1/100 and a hostile h3", len(offerA))
	engine.AddFiles(offerA, a)
	t.Logf("input: client B (id=702 port=4663) offers h1/100 and h2/200")
	engine.AddFiles(offerB, b)

	var nFiles, nSources int
	if err := db.QueryRow(`SELECT COUNT(*) FROM files`).Scan(&nFiles); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sources`).Scan(&nSources); err != nil {
		t.Fatal(err)
	}
	var nameA string
	if err := db.QueryRow(`SELECT s.name FROM sources s JOIN files f ON f.id = s.id_file
		WHERE f.hash = ? AND f.size = ? AND s.id_client = ?`, h1, 100, a.StoreID).Scan(&nameA); err != nil {
		t.Fatal(err)
	}
	t.Logf("output: files=%d sources=%d; client A's h1/100 name=%q", nFiles, nSources, nameA)
	if nFiles != 3 || nSources != 5 {
		t.Fatalf("files=%d sources=%d, want 3 and 5", nFiles, nSources)
	}
	if nameA != "alpha renamed.avi" {
		t.Fatalf("client A's h1/100 is %q, want the later duplicate %q", nameA, "alpha renamed.avi")
	}

	cases := []struct {
		label              string
		hash               []byte
		size               uint64
		sources, completed int
		sourceID           uint32
		sourcePort         uint16
	}{
		{"h1/100 offered by both", h1, 100, 2, 0, 702, 4663},
		{"h2/200 complete at A only", h2, 200, 2, 1, 702, 4663},
		{"h3 hostile, A only", h3, 4096, 1, 1, 701, 4662},
	}
	for _, tc := range cases {
		var sources, completed int
		var sourceID uint32
		var sourcePort uint16
		if err := db.QueryRow(`SELECT sources, completed, source_id, source_port FROM files WHERE hash = ? AND size = ?`,
			tc.hash, tc.size).Scan(&sources, &completed, &sourceID, &sourcePort); err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		t.Logf("output: %s: sources=%d completed=%d source=%d:%d", tc.label, sources, completed, sourceID, sourcePort)
		if sources != tc.sources || completed != tc.completed || sourceID != tc.sourceID || sourcePort != tc.sourcePort {
			t.Errorf("%s: got sources=%d completed=%d source=%d:%d, want %d/%d %d:%d", tc.label,
				sources, completed, sourceID, sourcePort, tc.sources, tc.completed, tc.sourceID, tc.sourcePort)
		}
	}

	if got := len(engine.GetSources(h1, 100)); got != 2 {
		t.Errorf("GetSources(h1/100) returned %d, want 2", got)
	}
	found := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: strings.Repeat("x", 20)})
	t.Logf("output: hostile file search found %d", len(found))
	if len(found) != 1 {
		t.Errorf("hostile file search found %d results, want 1", len(found))
	}
}

// A size past int64 cannot be stored in files.size (bigint signed), so strict mode
// rejects the whole multi-row INSERT carrying it. Before batching only that record
// was lost; the per-file retry has to keep it that way.
func TestMySQLAddFilesBatchIsolatesARejectedRecord(t *testing.T) {
	requireIntegration(t)
	engine, db := startMySQL(t, "enode")

	client := ClientInfo{ID: 703, IPv4: 0x0100007f, Port: 4662, Hash: []byte("dddddddddddddddd")}
	id, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = id

	offer := []File{
		{Hash: []byte("1111111111111111"), Size: 100, Name: "good one.avi"},
		{Hash: []byte("2222222222222222"), Size: 1 << 63, Name: "impossible size.avi"},
		{Hash: []byte("3333333333333333"), Size: 300, Name: "good two.avi"},
	}
	t.Logf("input: 3 records, the middle one with size=%d (past int64)", uint64(1<<63))
	engine.AddFiles(offer, client)

	rows, err := db.Query(`SELECT s.name FROM sources s ORDER BY s.name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	t.Logf("output: stored sources=%q", names)
	if strings.Join(names, ",") != "good one.avi,good two.avi" {
		t.Fatalf("stored %q, want both good records and not the rejected one", names)
	}
}

// The MongoDB twin of TestMySQLAddFilesBatch.
func TestMongoAddFilesBatch(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_addfiles_batch")

	a := ClientInfo{ID: 701, IPv4: 0x0100007f, Port: 4662, Hash: []byte("aaaaaaaaaaaaaaaa")}
	b := ClientInfo{ID: 702, IPv4: 0x0200007f, Port: 4663, Hash: []byte("bbbbbbbbbbbbbbbb")}
	for _, c := range []*ClientInfo{&a, &b} {
		if _, err := engine.Connect(*c); err != nil {
			t.Fatal(err)
		}
	}

	h1, h2, h3 := []byte("1111111111111111"), []byte("2222222222222222"), []byte("3333333333333333")
	offerA := []File{
		{Hash: h1, Size: 100, Name: "alpha first.avi"},
		{Hash: h2, Size: 200, Name: "beta.mp3", Completed: 1},
		{Hash: h1, Size: 100, Name: "alpha renamed.avi"},
		{Hash: h3, Size: 4096, Name: strings.Repeat("x", 400) + ".torrent-part001",
			Type: "EmuleCollection", Codec: strings.Repeat("c", 100), Completed: 1},
	}
	offerB := []File{
		{Hash: h1, Size: 100, Name: "alpha b.avi"},
		{Hash: h2, Size: 200, Name: "beta.mp3"},
	}
	t.Logf("input: client A (id=701 port=4662) offers %d records: a duplicate h1/100 and a hostile h3", len(offerA))
	engine.AddFiles(offerA, a)
	t.Logf("input: client B (id=702 port=4663) offers h1/100 and h2/200")
	engine.AddFiles(offerB, b)

	ctx, cancel := contextWithTimeout(engine)
	defer cancel()
	nFiles, _ := engine.db.Collection("files").CountDocuments(ctx, bson.M{})
	nSources, _ := engine.db.Collection("sources").CountDocuments(ctx, bson.M{})
	var srcDoc struct {
		Name string `bson:"name"`
	}
	if err := engine.db.Collection("sources").FindOne(ctx,
		bson.M{"file_hash": h1, "file_size": 100, "client_hash": a.Hash}).Decode(&srcDoc); err != nil {
		t.Fatal(err)
	}
	t.Logf("output: files=%d sources=%d; client A's h1/100 name=%q", nFiles, nSources, srcDoc.Name)
	if nFiles != 3 || nSources != 5 {
		t.Fatalf("files=%d sources=%d, want 3 and 5", nFiles, nSources)
	}
	if srcDoc.Name != "alpha renamed.avi" {
		t.Fatalf("client A's h1/100 is %q, want the later duplicate %q", srcDoc.Name, "alpha renamed.avi")
	}

	cases := []struct {
		label                                    string
		hash                                     []byte
		size                                     uint64
		sources, completed, sourceID, sourcePort int64
	}{
		{"h1/100 offered by both", h1, 100, 2, 0, 702, 4663},
		{"h2/200 complete at A only", h2, 200, 2, 1, 702, 4663},
		{"h3 hostile, A only", h3, 4096, 1, 1, 701, 4662},
	}
	for _, tc := range cases {
		var doc struct {
			Sources    int64 `bson:"sources"`
			Completed  int64 `bson:"completed"`
			SourceID   int64 `bson:"source_id"`
			SourcePort int64 `bson:"source_port"`
		}
		if err := engine.db.Collection("files").FindOne(ctx, bson.M{"hash": tc.hash, "size": tc.size}).Decode(&doc); err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		t.Logf("output: %s: sources=%d completed=%d source=%d:%d", tc.label, doc.Sources, doc.Completed, doc.SourceID, doc.SourcePort)
		if doc.Sources != tc.sources || doc.Completed != tc.completed || doc.SourceID != tc.sourceID || doc.SourcePort != tc.sourcePort {
			t.Errorf("%s: got sources=%d completed=%d source=%d:%d, want %d/%d %d:%d", tc.label,
				doc.Sources, doc.Completed, doc.SourceID, doc.SourcePort, tc.sources, tc.completed, tc.sourceID, tc.sourcePort)
		}
	}
	if got := len(engine.GetSources(h1, 100)); got != 2 {
		t.Errorf("GetSources(h1/100) returned %d, want 2", got)
	}
}

// The driver cannot encode a size past int64, which fails the whole bulk write rather
// than one document in it. The per-file retry has to limit the loss to that record.
func TestMongoAddFilesBatchIsolatesARejectedRecord(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_addfiles_isolation")

	client := ClientInfo{ID: 703, IPv4: 0x0100007f, Port: 4662, Hash: []byte("dddddddddddddddd")}
	if _, err := engine.Connect(client); err != nil {
		t.Fatal(err)
	}
	offer := []File{
		{Hash: []byte("1111111111111111"), Size: 100, Name: "good one.avi"},
		{Hash: []byte("2222222222222222"), Size: 1 << 63, Name: "impossible size.avi"},
		{Hash: []byte("3333333333333333"), Size: 300, Name: "good two.avi"},
	}
	t.Logf("input: 3 records, the middle one with size=%d (past int64)", uint64(1<<63))
	engine.AddFiles(offer, client)

	ctx, cancel := contextWithTimeout(engine)
	defer cancel()
	cur, err := engine.db.Collection("sources").Find(ctx, bson.M{})
	if err != nil {
		t.Fatal(err)
	}
	var docs []struct {
		Name string `bson:"name"`
	}
	if err := cur.All(ctx, &docs); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range docs {
		names = append(names, d.Name)
	}
	sort.Strings(names)
	t.Logf("output: stored sources=%q", names)
	if strings.Join(names, ",") != "good one.avi,good two.avi" {
		t.Fatalf("stored %q, want both good records and not the rejected one", names)
	}
}

// FindBySearch joins files at one of three points depending on the query — before
// filtering, after grouping each file, or only for the returned page of a text
// search. Every path must report the same counters, and the non-text paths must
// keep ordering by source count.
func TestMongoFindBySearchCountersOnEveryPath(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_search_paths")

	files := []File{
		{Hash: []byte("pathfileAAAAAAAA"), Size: 100, Name: "pathword alpha.avi", Type: "Video"},
		{Hash: []byte("pathfileBBBBBBBB"), Size: 200, Name: "pathword bravo.avi", Type: "Video"},
		{Hash: []byte("pathfileCCCCCCCC"), Size: 300, Name: "pathword charlie.avi", Type: "Video"},
	}
	// File i is offered by 3-i clients; client 0 has every file complete.
	for c := 0; c < 3; c++ {
		client := ClientInfo{ID: uint32(880 + c), IPv4: 0x0100007f, Port: 4662, Hash: []byte(fmt.Sprintf("pathclient%06d", c))}
		if _, err := engine.Connect(client); err != nil {
			t.Fatal(err)
		}
		var offer []File
		for i, f := range files {
			if c < 3-i {
				if c == 0 {
					f.Completed = 1
				}
				offer = append(offer, f)
			}
		}
		engine.AddFiles(offer, client)
	}
	t.Logf("input: %s offered by 3, %s by 2, %s by 1 client; one client has each complete",
		files[0].Name, files[1].Name, files[2].Name)

	video := &SearchExpr{Kind: SearchString, TagType: searchTypeFileType, ValueString: "Video"}
	cases := []struct {
		name    string
		expr    *SearchExpr
		want    []string // expected names; in this order when ordered is set
		ordered bool
	}{
		{"text: joins only the returned page", &SearchExpr{Kind: SearchText, Text: "pathword"},
			[]string{"pathword alpha.avi", "pathword bravo.avi", "pathword charlie.avi"}, false},
		{"non-text: joins each file, sorted by sources", video,
			[]string{"pathword alpha.avi", "pathword bravo.avi", "pathword charlie.avi"}, true},
		{"sources term: joins every source first", &SearchExpr{Kind: SearchAnd, Left: video,
			Right: &SearchExpr{Kind: SearchUInt32, TagType: searchTypeSources, ValueUint: 1}},
			[]string{"pathword alpha.avi", "pathword bravo.avi"}, true},
	}
	wantSources := map[string]uint32{"pathword alpha.avi": 3, "pathword bravo.avi": 2, "pathword charlie.avi": 1}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.FindBySearch(tc.expr)
			var names []string
			for _, f := range got {
				names = append(names, f.Name)
				t.Logf("output: %s sources=%d completed=%d", f.Name, f.Sources, f.Completed)
				if f.Sources != wantSources[f.Name] || f.Completed != 1 {
					t.Errorf("%s: sources=%d completed=%d, want %d and 1", f.Name, f.Sources, f.Completed, wantSources[f.Name])
				}
			}
			if !tc.ordered {
				sort.Strings(names)
			}
			if strings.Join(names, ",") != strings.Join(tc.want, ",") {
				t.Errorf("results %q, want %q", names, tc.want)
			}
		})
	}
}
