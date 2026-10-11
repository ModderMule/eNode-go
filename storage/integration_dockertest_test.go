package storage

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"enode/tests"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func requireIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("ENODE_INTEGRATION") != "1" {
		t.Skip("set ENODE_INTEGRATION=1 to run integration tests")
	}
}

func TestMySQLEngineWithDockertest(t *testing.T) {
	requireIntegration(t)

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("docker not available: %v", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mysql",
		Tag:        "8.0",
		Env: []string{
			"MYSQL_ROOT_PASSWORD=root",
			"MYSQL_DATABASE=enode",
		},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("start mysql container: %v", err)
	}
	defer func() { _ = pool.Purge(resource) }()

	port := resource.GetPort("3306/tcp")

	// Init creates the schema on first connect from the resolved relative path
	// (tests run from storage/, so FixRelativeTestingPath walks up to the module
	// root), so this test no longer hand-maintains a duplicate of misc/enode.sql.
	engine, err := NewMySQLEngine(MySQLConfig{
		Host: "localhost", Port: mustAtoi(port), User: "root", Pass: "root", Database: "enode",
		MaxOpenConns: 4, MaxIdleConns: 2,
		SchemaFile: tests.FixRelativeTestingPath("misc/enode.sql"),
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error {
		return engine.Init()
	}); err != nil {
		t.Fatalf("mysql not ready: %v", err)
	}
	defer engine.Close()

	client := ClientInfo{
		ID: 101, IPv4: 0x0100007f, Port: 4662, Hash: []byte("0123456789abcdef"),
		CryptOptions: 0x03, // supports|requests — must round-trip through crypt_options
	}
	storeID, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = storeID
	if !engine.IsConnected(client) {
		t.Fatalf("expected connected client")
	}

	file := File{
		Hash: []byte("fedcba9876543210"), Name: "movie.mkv", Size: 1024,
		Completed: 1, SourceID: client.ID, SourcePort: client.Port,
	}
	engine.AddFile(file, client)
	if engine.FilesCount() < 1 {
		t.Fatalf("expected files count > 0")
	}
	// InnoDB's estimate is only as fresh as its statistics; ANALYZE refreshes them.
	if _, err := engine.db.Exec(`ANALYZE TABLE files`); err != nil {
		t.Fatal(err)
	}
	t.Logf("output: FilesCount=%d FilesCountEstimate=%d", engine.FilesCount(), engine.FilesCountEstimate())
	if engine.FilesCountEstimate() < 1 {
		t.Fatalf("expected files count estimate > 0 after ANALYZE")
	}
	sources := engine.GetSources(file.Hash, file.Size)
	if len(sources) == 0 {
		t.Fatalf("expected sources for file")
	}
	// N2: the client's crypt options must survive Connect -> GetSources via the
	// clients.crypt_options column. 0 here means the column was not read/written.
	t.Logf("output: source CryptOptions=0x%02x", sources[0].CryptOptions)
	if sources[0].CryptOptions != 0x03 {
		t.Fatalf("crypt options not round-tripped: got 0x%02x, want 0x03", sources[0].CryptOptions)
	}
	found := engine.FindByNameContains("movie")
	if len(found) == 0 {
		t.Fatalf("expected find results")
	}

	engine.Disconnect(client)
	if engine.IsConnected(client) {
		t.Fatalf("expected disconnected client")
	}
}

func TestMongoEngineWithDockertest(t *testing.T) {
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
		URI: uri, Database: "enode_test", Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error {
		return engine.Init()
	}); err != nil {
		t.Fatalf("mongo not ready: %v", err)
	}
	defer engine.Close()

	client := ClientInfo{
		ID: 202, IPv4: 0x0100007f, Port: 4662, Hash: []byte("0123456789abcdef"),
		CryptOptions: 0x03, // supports|requests — must round-trip through crypt_options
	}
	storeID, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = storeID
	if !engine.IsConnected(client) {
		t.Fatalf("expected connected client")
	}

	file := File{
		Hash: []byte("fedcba9876543210"), Name: "track.mp3", Size: 2048,
		Completed: 1, SourceID: client.ID, SourcePort: client.Port,
	}
	engine.AddFile(file, client)
	if engine.FilesCount() < 1 {
		t.Fatalf("expected files count > 0")
	}
	t.Logf("output: FilesCount=%d FilesCountEstimate=%d", engine.FilesCount(), engine.FilesCountEstimate())
	if engine.FilesCountEstimate() != engine.FilesCount() {
		t.Fatalf("estimate %d, want the count %d", engine.FilesCountEstimate(), engine.FilesCount())
	}
	sources := engine.GetSources(file.Hash, file.Size)
	if len(sources) == 0 {
		t.Fatalf("expected sources for file")
	}
	// N2: crypt options must survive Connect -> GetSources via the client document.
	t.Logf("output: source CryptOptions=0x%02x", sources[0].CryptOptions)
	if sources[0].CryptOptions != 0x03 {
		t.Fatalf("crypt options not round-tripped: got 0x%02x, want 0x03", sources[0].CryptOptions)
	}
	found := engine.FindByNameContains("track")
	if len(found) == 0 {
		t.Fatalf("expected find results")
	}

	engine.Disconnect(client)
	if engine.IsConnected(client) {
		t.Fatalf("expected disconnected client")
	}

	// sanity-check collections exist and have documents
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(context.Background())
	n, err := c.Database("enode_test").Collection("files").CountDocuments(ctx, bson.M{})
	if err != nil || n == 0 {
		t.Fatalf("expected mongodb files documents, got n=%d err=%v", n, err)
	}
}

// TestMongoFindBySearch exercises FindBySearch against a real MongoDB. Every case
// below returned zero results (or errored, silently) before the search pipeline
// was fixed: $text was emitted outside the first stage, $meta was referenced with
// no $text stage, and OR/AND-NOT were treated as a fatal condition.
func TestMongoFindBySearch(t *testing.T) {
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
		URI: uri, Database: "enode_search_test", Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error { return engine.Init() }); err != nil {
		t.Fatalf("mongo not ready: %v", err)
	}
	defer engine.Close()

	client := ClientInfo{ID: 303, IPv4: 0x0100007f, Port: 4662, Hash: []byte("fedcba9876543210")}
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
		t.Logf("input: seeded %q type=%s size=%d", f.Name, f.Type, f.Size)
	}

	movieText := &SearchExpr{Kind: SearchText, Text: "movie"}
	videoType := &SearchExpr{Kind: SearchString, TagType: searchTypeFileType, ValueString: "Video"}

	cases := []struct {
		name      string
		expr      *SearchExpr
		wantNames []string
	}{
		{
			// Hoisted $text at stage 0. Previously the same filter was emitted
			// twice, putting a $text in stage 2, which MongoDB rejects.
			name:      "bare text",
			expr:      movieText,
			wantNames: []string{"holiday movie.avi", "vacation movie.avi"},
		},
		{
			// Hoisted $text plus a later $match.
			name:      "text AND type",
			expr:      &SearchExpr{Kind: SearchAnd, Left: movieText, Right: videoType},
			wantNames: []string{"holiday movie.avi", "vacation movie.avi"},
		},
		{
			// Regex fallback: $text is illegal inside $or.
			name: "OR of two text terms",
			expr: &SearchExpr{Kind: SearchOr,
				Left:  &SearchExpr{Kind: SearchText, Text: "song"},
				Right: &SearchExpr{Kind: SearchText, Text: "vacation"}},
			wantNames: []string{"holiday song.mp3", "vacation movie.avi"},
		},
		{
			// Regex fallback: the eMule "-word" exclusion.
			name: "AND NOT",
			expr: &SearchExpr{Kind: SearchAndNot,
				Left:  &SearchExpr{Kind: SearchText, Text: "holiday"},
				Right: &SearchExpr{Kind: SearchText, Text: "song"}},
			wantNames: []string{"holiday movie.avi"},
		},
		{
			// Regex fallback: two text leaves cannot both be hoisted.
			name: "two text leaves",
			expr: &SearchExpr{Kind: SearchAnd,
				Left:  &SearchExpr{Kind: SearchText, Text: "holiday"},
				Right: &SearchExpr{Kind: SearchText, Text: "movie"}},
			wantNames: []string{"holiday movie.avi"},
		},
		{
			// No $text stage at all: previously the unconditional $meta made this
			// fail with "query requires text score metadata".
			name:      "non-text only",
			expr:      videoType,
			wantNames: []string{"holiday movie.avi", "vacation movie.avi"},
		},
		{
			// Exercises the $lookup path (file.sources lives on the files doc).
			name: "sources threshold via lookup",
			expr: &SearchExpr{Kind: SearchUInt32, TagType: searchTypeSources, ValueUint: 0},
			wantNames: []string{
				"holiday movie.avi", "holiday song.mp3", "vacation movie.avi",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.FindBySearch(tc.expr)
			names := make([]string, 0, len(got))
			for _, f := range got {
				names = append(names, f.Name)
			}
			sort.Strings(names)
			want := append([]string(nil), tc.wantNames...)
			sort.Strings(want)

			t.Logf("output: %d result(s): %v", len(got), names)

			if len(names) != len(want) {
				t.Fatalf("result count mismatch: got %v, want %v", names, want)
			}
			for i := range want {
				if names[i] != want[i] {
					t.Fatalf("result mismatch: got %v, want %v", names, want)
				}
			}
		})
	}

	// N1 regression: a plain text search must report the true (denormalized) source
	// count, not 0. FindBySearch used to only $lookup the files document when the
	// filter referenced file.* (a sources/complete threshold); a plain text search
	// took no lookup, so the $group read $file.sources from a source document that
	// has no such field and every result decoded Sources:0 / Completed:0. Seed one
	// file offered by three distinct clients and assert the count survives.
	//
	// Run last, after the exact-name cases above, so the extra file does not perturb
	// their assertions.
	t.Run("reports true source count", func(t *testing.T) {
		shared := File{Hash: []byte("shared1234567890"), Name: "zzqxword clip", Size: 111, Type: "Pro", Completed: 1}
		for i := 0; i < 3; i++ {
			extra := ClientInfo{
				ID: uint32(400 + i), IPv4: 0x0100007f, Port: uint16(5000 + i),
				Hash: []byte{byte('A' + i), '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'},
			}
			sid, err := engine.Connect(extra)
			if err != nil {
				t.Fatal(err)
			}
			extra.StoreID = sid
			engine.AddFile(shared, extra)
		}

		got := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: "zzqxword"})
		t.Logf("input: one file offered by 3 distinct clients, plain text search %q", "zzqxword")
		if len(got) != 1 {
			t.Fatalf("expected 1 file, got %d", len(got))
		}
		t.Logf("output: Sources=%d Completed=%d", got[0].Sources, got[0].Completed)
		if got[0].Sources != 3 {
			t.Fatalf("Sources=%d, want 3 — the denormalized count must survive a text search", got[0].Sources)
		}
		if got[0].Completed != 3 {
			t.Fatalf("Completed=%d, want 3", got[0].Completed)
		}
	})
}

func mustAtoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}
