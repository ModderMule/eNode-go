package storage

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"enode/tests"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

// ftSeedNames separates word-prefix from substring matching for the query
// "star": superstar and rockstar contain "star" only as an infix, so a
// word-prefix engine (mariadb) drops them while a substring engine (mysql/ngram,
// memory) keeps them.
var ftSeedNames = []string{
	"star.mkv", "stars.txt", "starcraft.iso", "stardust.flac",
	"superstar.mp3", "rockstar.avi",
}

// ftShortRunNames separate a short-run search from its indexable part: `x-men`
// must find X-Men but not Men.in.Black, which only contains the `men` run.
var ftShortRunNames = []string{"X-Men.avi", "Men.in.Black.avi"}

type ftDialectParams struct {
	repo, tag, dialect string
	env                []string
	want               []string // expected names for a search of "star"
}

// TestSQLFullTextSearchDialects proves both halves of the dialect switch on real
// servers: MariaDB word-prefix and MySQL ngram substring, each using the
// full-text index rather than a leading-`%` scan. Against the pre-fix build the
// query is `s.name LIKE '%star%'` (a scan that also returns superstar/rockstar on
// mariadb), so both the EXPLAIN assertion and the mariadb result set fail.
func TestSQLFullTextSearchDialects(t *testing.T) {
	requireIntegration(t)

	t.Run("mariadb word-prefix", func(t *testing.T) {
		runFTDialectTest(t, ftDialectParams{
			repo: "mariadb", tag: "10.11", dialect: DialectMariaDB,
			env: []string{"MARIADB_ROOT_PASSWORD=root", "MARIADB_DATABASE=enode"},
			// Only names with a word beginning "star".
			want: []string{"star.mkv", "stars.txt", "starcraft.iso", "stardust.flac"},
		})
	})

	t.Run("mysql ngram substring", func(t *testing.T) {
		runFTDialectTest(t, ftDialectParams{
			repo: "mysql", tag: "8.0", dialect: DialectMySQL,
			env: []string{"MYSQL_ROOT_PASSWORD=root", "MYSQL_DATABASE=enode"},
			// Every name containing "star", including the infixes.
			want: ftSeedNames,
		})
	})
}

// ftStopwordNames are file names built around words on InnoDB's default stopword
// list that carry meaning in a title. No name contains another query word as an
// infix, so substring matching (memory) and word-prefix matching (mariadb) must
// give the same answer for every query in ftStopwordQueries.
var ftStopwordNames = []string{
	"Doctor.Who.S01E01.avi",
	"The.Who.Live.at.Leeds.mp3",
	"Will.and.Grace.S02E03.avi",
	"About.Time.2013.mkv",
	"From.Dusk.Till.Dawn.1996.avi",
	"What.Women.Want.2000.avi",
	"Where.Eagles.Dare.1968.mkv",
	"When.Harry.Met.Sally.1989.avi",
	"This.Is.Spinal.Tap.1984.avi",
	"www.example.com.release.zip",
	"Gone.With.The.Wind.1939.mkv",
}

// ftStopwordQueries are searches a user would type for those names. Each holds a
// default stopword of at least three letters (shorter ones are below the index's
// token size anyway), alone and beside an ordinary word.
var ftStopwordQueries = []string{
	"who", "doctor who", "the who",
	"will", "will grace",
	"about", "about time",
	"from", "from dusk",
	"what", "what women",
	"where", "where eagles",
	"when", "when harry",
	"this", "this spinal",
	"with", "gone with wind",
	"www", "com", "example com",
}

// TestMariaDBFullTextStopwords records a known limit of the mariadb dialect: the
// word index built from misc/enode.sql keeps InnoDB's default stopword list, so a
// search holding a listed word returns nothing, while the memory engine finds the
// file. It pins that behaviour rather than the wanted one (see
// specializeFulltextIndex); if the index is ever built without stopwords this
// test fails and the expectation has to be turned around.
func TestMariaDBFullTextStopwords(t *testing.T) {
	requireIntegration(t)
	engine, port := startFTEngine(t, ftDialectParams{
		repo: "mariadb", tag: "10.11", dialect: DialectMariaDB,
		env: []string{"MARIADB_ROOT_PASSWORD=root", "MARIADB_DATABASE=enode"},
	})

	db, err := sql.Open("mysql", fmt.Sprintf("root:root@tcp(localhost:%d)/enode", port))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var enabled string
	if err := db.QueryRow(`SELECT @@GLOBAL.innodb_ft_enable_stopword`).Scan(&enabled); err != nil {
		t.Fatalf("read innodb_ft_enable_stopword: %v", err)
	}
	var stopwords []string
	rows, err := db.Query(`SELECT value FROM information_schema.INNODB_FT_DEFAULT_STOPWORD`)
	if err != nil {
		t.Fatalf("read default stopword list: %v", err)
	}
	for rows.Next() {
		var w string
		if err := rows.Scan(&w); err == nil {
			stopwords = append(stopwords, w)
		}
	}
	rows.Close()
	t.Logf("input: server innodb_ft_enable_stopword=%s, %d default stopwords %v", enabled, len(stopwords), stopwords)

	mem := NewMemoryEngine()
	client := ClientInfo{ID: 710, IPv4: 0x0100007f, Port: 4662, Hash: []byte("0123456789abcdef")}
	storeID, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = storeID
	memClient := client
	memClient.StoreID, _ = mem.Connect(memClient)
	for i, name := range ftStopwordNames {
		f := File{
			Hash: ftSeedHash(200 + i), Name: name, Size: uint64(3000 + i), Completed: 1,
			SourceID: client.ID, SourcePort: client.Port,
		}
		engine.AddFile(f, client)
		mem.AddFile(f, memClient)
		t.Logf("input: seeded %q", name)
	}

	for _, q := range ftStopwordQueries {
		expr := &SearchExpr{Kind: SearchText, Text: q}
		want := fileNames(mem.FindBySearch(expr))
		got := fileNames(engine.FindBySearch(expr))
		t.Logf("output: search=%q mariadb=%v memory=%v", q, got, want)
		if len(want) == 0 {
			t.Fatalf("search %q finds nothing on the memory engine; the seed is wrong", q)
		}
		if len(got) != 0 {
			t.Errorf("search %q: mariadb returned %v, want nothing while stopwords are on", q, got)
		}
	}
}

func runFTDialectTest(t *testing.T, p ftDialectParams) {
	engine, port := startFTEngine(t, p)

	client := ClientInfo{ID: 700, IPv4: 0x0100007f, Port: 4662, Hash: []byte("0123456789abcdef")}
	storeID, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = storeID

	for i, name := range ftSeedNames {
		f := File{
			Hash: ftSeedHash(i), Name: name, Size: uint64(1000 + i), Completed: 1,
			SourceID: client.ID, SourcePort: client.Port,
		}
		engine.AddFile(f, client)
		t.Logf("input: seeded %q", name)
	}

	expr := &SearchExpr{Kind: SearchText, Text: "star"}
	got := fileNames(engine.FindBySearch(expr))
	t.Logf("output: dialect=%s search=%q -> %v", p.dialect, "star", got)
	assertSameSet(t, "sql result", got, p.want)

	// Parity: the mysql/ngram dialect reproduces the substring reference (memory).
	if p.dialect == DialectMySQL {
		mem := NewMemoryEngine()
		mc := ClientInfo{ID: 700, IPv4: 0x0100007f, Port: 4662, Hash: []byte("0123456789abcdef")}
		sid, _ := mem.Connect(mc)
		mc.StoreID = sid
		for i, name := range ftSeedNames {
			mem.AddFile(File{Hash: ftSeedHash(i), Name: name, Size: uint64(1000 + i), Completed: 1}, mc)
		}
		memNames := fileNames(mem.FindBySearch(expr))
		t.Logf("output: memory search=%q -> %v", "star", memNames)
		assertSameSet(t, "mysql vs memory parity", got, memNames)
	}

	// No-scan proof: the generated search rides the fulltext index, not a scan.
	where, args := BuildSearchWhere(expr, p.dialect)
	assertFulltextPlan(t, port, where, args)

	// Short runs. Neither name contains "star", so the result above is unaffected.
	for i, name := range ftShortRunNames {
		f := File{
			Hash: ftSeedHash(100 + i), Name: name, Size: uint64(2000 + i), Completed: 1,
			SourceID: client.ID, SourcePort: client.Port,
		}
		engine.AddFile(f, client)
		t.Logf("input: seeded %q", name)
	}

	// The `x` of `x-men` is too short to index, so it rides on the `men` MATCH
	// as a residual LIKE: still indexed, and it still excludes Men.in.Black.
	xmen := &SearchExpr{Kind: SearchText, Text: "x-men"}
	got = fileNames(engine.FindBySearch(xmen))
	t.Logf("output: dialect=%s search=%q -> %v", p.dialect, "x-men", got)
	assertSameSet(t, "short-run result", got, []string{"X-Men.avi"})
	where, args = BuildSearchWhere(xmen, p.dialect)
	assertFulltextPlan(t, port, where, args)

	// A search with no indexable run at all would be a table scan: dropped.
	only := &SearchExpr{Kind: SearchText, Text: "x"}
	dropped := engine.FindBySearch(only)
	t.Logf("output: dialect=%s search=%q -> %v", p.dialect, "x", fileNames(dropped))
	if len(dropped) != 0 {
		t.Fatalf("search %q should be dropped, got %v", "x", fileNames(dropped))
	}
}

// assertFulltextPlan opens a raw connection and EXPLAINs a representative select
// built from the same WHERE the engine uses, asserting a `type: fulltext` access
// path (and never `ALL`). MySQL 8 and MariaDB 10 both label it `fulltext`.
func assertFulltextPlan(t *testing.T, port int, where string, args []any) {
	t.Helper()
	dsn := fmt.Sprintf("root:root@tcp(localhost:%d)/enode?parseTime=true", port)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("EXPLAIN SELECT s.id FROM sources s WHERE "+where, args...)
	if err != nil {
		t.Fatalf("EXPLAIN failed: %v", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	typeIdx := -1
	for i, c := range cols {
		if strings.EqualFold(c, "type") {
			typeIdx = i
		}
	}
	if typeIdx < 0 {
		t.Fatalf("EXPLAIN output has no type column: %v", cols)
	}

	usesFulltext := false
	for rows.Next() {
		raw := make([]sql.RawBytes, len(cols))
		ptrs := make([]any, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		typ := string(raw[typeIdx])
		t.Logf("EXPLAIN access type = %q", typ)
		if strings.EqualFold(typ, "ALL") {
			t.Fatalf("search does a full table scan (type=ALL), not a fulltext lookup")
		}
		if strings.EqualFold(typ, "fulltext") {
			usesFulltext = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !usesFulltext {
		t.Fatalf("search does not use the fulltext index (no type=fulltext row)")
	}
}

func ftSeedHash(i int) []byte {
	// 16 bytes: "ftseedhash" (10) + 6 digits.
	return []byte(fmt.Sprintf("ftseedhash%06d", i))
}

func fileNames(files []File) []string {
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	return names
}

func assertSameSet(t *testing.T, label string, got, want []string) {
	t.Helper()
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if len(g) != len(w) {
		t.Fatalf("%s: got %v, want %v", label, g, w)
	}
	for i := range w {
		if g[i] != w[i] {
			t.Fatalf("%s: got %v, want %v", label, g, w)
		}
	}
}

// startFTEngine starts the server p names in a container and returns an engine
// that has created its schema there, plus the published port.
func startFTEngine(t *testing.T, p ftDialectParams) (*MySQLEngine, int) {
	t.Helper()
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("docker not available: %v", err)
	}
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: p.repo, Tag: p.tag, Env: p.env,
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("start %s:%s container: %v", p.repo, p.tag, err)
	}
	t.Cleanup(func() { _ = pool.Purge(resource) })

	port := mustAtoi(resource.GetPort("3306/tcp"))
	engine, err := NewMySQLEngine(MySQLConfig{
		Host: "localhost", Port: port, User: "root", Pass: "root", Database: "enode",
		MaxOpenConns: 4, MaxIdleConns: 2, Dialect: p.dialect,
		SchemaFile: tests.FixRelativeTestingPath("misc/enode.sql"),
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.MaxWait = 3 * time.Minute
	if err := pool.Retry(func() error { return engine.Init() }); err != nil {
		t.Fatalf("%s not ready: %v", p.repo, err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine, port
}
