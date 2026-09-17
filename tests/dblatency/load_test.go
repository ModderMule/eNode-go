package dblatency

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enode/logging"
	"enode/storage"

	mysqldriver "github.com/go-sql-driver/mysql"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// TestMySQLLoad runs the concurrent workload against MariaDB 10.11.
func TestMySQLLoad(t *testing.T) {
	engine, proxy, direct := startMariaDB(t)
	runLoad(t, mysqlLoadTarget(engine, proxy, direct), loadConfigFromEnv(t))
}

// TestMongoLoad runs the concurrent workload against MongoDB 7.
func TestMongoLoad(t *testing.T) {
	engine, proxy, db := startMongo(t, "enode_load")
	runLoad(t, mongoLoadTarget(engine, proxy, db), loadConfigFromEnv(t))
}

// loadConfig sizes one load run. ENODE_LOAD_CLIENTS and ENODE_LOAD_DURATION override
// the worker count and the length of each phase.
type loadConfig struct {
	workers     int
	phase       time.Duration
	rtts        []time.Duration
	seedClients int
	popular     int
	sweepEvery  time.Duration
}

func loadConfigFromEnv(t *testing.T) loadConfig {
	t.Helper()
	cfg := loadConfig{
		workers:     64,
		phase:       10 * time.Second,
		rtts:        []time.Duration{0, 10 * time.Millisecond},
		seedClients: 300,
		popular:     2000,
		sweepEvery:  2 * time.Second,
	}
	if v := os.Getenv("ENODE_LOAD_CLIENTS"); v != "" {
		cfg.workers = mustAtoi(t, v)
	}
	if v := os.Getenv("ENODE_LOAD_DURATION"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("ENODE_LOAD_DURATION: %v", err)
		}
		cfg.phase = d
	}
	return cfg
}

// loadTarget is one database under load: the engine the workload drives, and direct
// access to the stored state for the checks, bypassing both the engine and the proxy.
type loadTarget struct {
	name   string
	engine storage.Engine
	proxy  *rttProxy
	// backdate ages departed clients and their sources past the sweep's maxAge.
	backdate func(ctx context.Context, clients []storage.ClientInfo) error
	// sourcesOf counts the source records stored for one client.
	sourcesOf func(ctx context.Context, client storage.ClientInfo) (int, error)
	// counterMismatches lists files whose sources/completed differ from their source records.
	counterMismatches func(ctx context.Context) (int, []string, error)
	// orphanSources lists source records whose file record is gone.
	orphanSources func(ctx context.Context) (int, []string, error)
}

// Search terms. Every file name carries words from this list, so one word matches a
// few percent of all files: enough to hit MaxSearchResults.
var loadVocabulary = []string{
	"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliett",
	"kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo", "sierra", "tango",
	"uniform", "victor", "whiskey", "xray", "yankee", "zulu", "amber", "basalt", "cobalt", "dune",
	"ember", "fjord", "glacier", "harbor", "iris", "jasper", "kelp", "lagoon", "meadow", "nebula",
	"orchid", "prairie", "quartz", "reef", "savanna", "tundra", "umber", "valley", "willow", "zephyr",
}

const (
	loadPopularExplicit  = 10 // popular files #0..#9, offered by every seed client
	loadPopularPerOffer  = 50 // Zipf-picked popular files per packet
	loadRecycledPerOffer = 20 // files of departed clients per packet
	loadRecycleRing      = 2000
)

// runLoad seeds the database, runs one phase per RTT, then checks the stored state.
//
// Every worker is a stream of client sessions: login, one 200-file offer, 20–50
// operations, logout, and a fresh identity. Offers overlap on Zipf-popular files, so
// concurrent writers keep meeting on the same file rows. A sweeper backdates the
// sessions that ended and runs the cleanup sweep every few seconds, deleting files
// left without sources — while offers keep re-offering exactly those files.
func runLoad(t *testing.T, target loadTarget, cfg loadConfig) {
	logPath := filepath.Join(t.TempDir(), "load.log")
	if err := logging.SetOutputFile(logPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.SetOutputFile("") })

	l := &loadRun{t: t, cfg: cfg, target: target, logPath: logPath}
	t.Logf("input: %s, %d workers, %s per phase at RTT %v, %d seed clients, %d popular files, sweep every %s",
		target.name, cfg.workers, cfg.phase, cfg.rtts, cfg.seedClients, cfg.popular, cfg.sweepEvery)

	start := time.Now()
	l.seed()
	t.Logf("seeded %d clients x %d files in %s", cfg.seedClients, packetFiles, time.Since(start).Round(time.Millisecond))

	for _, rtt := range cfg.rtts {
		l.phase(rtt)
	}
	l.checkInvariants()
}

// session is one client login and everything it offered.
type session struct {
	client  storage.ClientInfo
	offered map[offerKey]struct{}
	own     []storage.File
}

type offerKey struct {
	hash string
	size uint64
}

type loadRun struct {
	t       *testing.T
	cfg     loadConfig
	target  loadTarget
	logPath string

	nextClient atomic.Int64
	nextFile   atomic.Int64

	mu sync.Mutex
	// departed sessions are logged out and wait for the sweeper to age them.
	departed []storage.ClientInfo
	// recycle holds the own files of departed sessions, overwritten in a ring.
	recycle    []storage.File
	recyclePos int
	// online sessions stay logged in to the end; the lost-offer check reads them.
	online   []*session
	failures []string
}

func (l *loadRun) seed() {
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rand.New(rand.NewPCG(uint64(w), 0x5eed))
			z := rand.NewZipf(r, 1.1, 1, uint64(l.cfg.popular-1))
			stats := map[string][]time.Duration{}
			for range next {
				s := l.connect(stats)
				if s == nil {
					continue
				}
				l.offer(s, r, z, true, stats)
				l.mu.Lock()
				l.online = append(l.online, s)
				l.mu.Unlock()
			}
		}()
	}
	for i := 0; i < l.cfg.seedClients; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
}

func (l *loadRun) phase(rtt time.Duration) {
	t := l.t
	l.target.proxy.setRTT(rtt)
	defer l.target.proxy.setRTT(0)

	logOffset := fileSize(l.logPath)
	before := l.target.proxy.snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), l.cfg.phase)
	defer cancel()

	results := make([]map[string][]time.Duration, l.cfg.workers+1)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < l.cfg.workers; i++ {
		results[i] = map[string][]time.Duration{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.worker(ctx, i, results[i])
		}()
	}
	results[l.cfg.workers] = map[string][]time.Duration{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		l.sweeper(ctx, results[l.cfg.workers])
	}()
	wg.Wait()
	elapsed := time.Since(start)
	counts := l.target.proxy.snapshot().since(before)

	merged := map[string][]time.Duration{}
	total := 0
	for _, r := range results {
		for op, ds := range r {
			merged[op] = append(merged[op], ds...)
			total += len(ds)
		}
	}
	ops := make([]string, 0, len(merged))
	for op := range merged {
		ops = append(ops, op)
	}
	sort.Strings(ops)

	secs := elapsed.Seconds()
	t.Logf("")
	t.Logf("phase RTT=%s: %d workers for %s: %d ops (%.0f/s), %d round-trips (%.0f/s)",
		rtt, l.cfg.workers, elapsed.Round(time.Millisecond), total, float64(total)/secs,
		counts.roundTrips, float64(counts.roundTrips)/secs)
	t.Logf("  %-18s %7s %8s %9s %9s %9s %9s", "op", "count", "ops/s", "p50", "p95", "p99", "max")
	for _, op := range ops {
		ds := merged[op]
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		t.Logf("  %-18s %7d %8.1f %9s %9s %9s %9s", op, len(ds), float64(len(ds))/secs,
			pct(ds, 50), pct(ds, 95), pct(ds, 99), ds[len(ds)-1].Round(10*time.Microsecond))
	}
	warns, errs := l.readLog(logOffset)
	if len(warns) == 0 && len(errs) == 0 {
		t.Logf("  log: no WARN or ERROR lines")
	}
	for _, w := range sortedCounts(warns) {
		t.Logf("  WARN  x%-5d %s", warns[w], w)
	}
	for i, e := range errs {
		if i == 10 {
			t.Logf("  ERROR ... %d more", len(errs)-10)
			break
		}
		t.Logf("  ERROR %s", e)
	}
	if len(errs) > 0 {
		t.Errorf("phase RTT=%s logged %d ERROR lines", rtt, len(errs))
	}
}

func (l *loadRun) worker(ctx context.Context, id int, stats map[string][]time.Duration) {
	r := rand.New(rand.NewPCG(uint64(id), uint64(time.Now().UnixNano())))
	z := rand.NewZipf(r, 1.1, 1, uint64(l.cfg.popular-1))
	engine := l.target.engine
	for ctx.Err() == nil {
		s := l.connect(stats)
		if s == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		l.offer(s, r, z, false, stats)
		for n := 20 + r.IntN(31); n > 0; n-- {
			if ctx.Err() != nil {
				l.mu.Lock()
				l.online = append(l.online, s)
				l.mu.Unlock()
				return
			}
			switch p := r.IntN(100); {
			case p < 45:
				f := l.popularFile(int(z.Uint64()))
				timed(stats, "GetSources", func() { engine.GetSources(f.Hash, f.Size) })
			case p < 60:
				word := loadVocabulary[r.IntN(len(loadVocabulary))]
				timed(stats, "FindBySearch", func() {
					engine.FindBySearch(&storage.SearchExpr{Kind: storage.SearchText, Text: word})
				})
			case p < 75:
				l.offer(s, r, z, false, stats)
			case p < 90:
				timed(stats, "IsConnected", func() { engine.IsConnected(s.client) })
			default:
				f := l.popularFile(int(z.Uint64()))
				timed(stats, "GetSourcesByHash", func() { engine.GetSourcesByHash(f.Hash) })
			}
		}
		timed(stats, "Disconnect", func() { engine.Disconnect(s.client) })
		l.depart(s)
	}
}

func (l *loadRun) sweeper(ctx context.Context, stats map[string][]time.Duration) {
	ticker := time.NewTicker(l.cfg.sweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		l.mu.Lock()
		gone := l.departed
		l.departed = nil
		l.mu.Unlock()
		if len(gone) > 0 {
			bctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			err := l.target.backdate(bctx, gone)
			cancel()
			if err != nil {
				l.fail("backdate %d clients: %v", len(gone), err)
			}
		}
		var err error
		timed(stats, "CleanupStale", func() {
			// KeepZeroSourceFiles off: the sweep deletes files left without sources,
			// which is what races an offer of the same file.
			_, err = l.target.engine.CleanupStale(24*time.Hour, storage.CleanupOptions{BatchSize: 500})
		})
		if err != nil {
			l.fail("CleanupStale: %v", err)
		}
	}
}

func (l *loadRun) connect(stats map[string][]time.Duration) *session {
	n := l.nextClient.Add(1)
	id := uint32(0x0b000000 + n)
	client := storage.ClientInfo{ID: id, IPv4: id, Port: 4662, Hash: benchHash('C', int(n))}
	var storeID uint64
	var err error
	timed(stats, "Connect", func() { storeID, err = l.target.engine.Connect(client) })
	if err != nil {
		l.fail("Connect: %v", err)
		return nil
	}
	client.StoreID = storeID
	return &session{client: client, offered: map[offerKey]struct{}{}}
}

// offer sends one 200-file packet: popular files (all ten explicit ones when seeding),
// files of departed clients, and files only this client has.
func (l *loadRun) offer(s *session, r *rand.Rand, z *rand.Zipf, seeding bool, stats map[string][]time.Duration) {
	files := make([]storage.File, 0, packetFiles)
	picked := map[int]bool{}
	if seeding {
		for i := 0; i < loadPopularExplicit; i++ {
			picked[i] = true
			files = append(files, l.popularFile(i))
		}
	}
	for tries := 0; len(picked) < loadPopularExplicit+loadPopularPerOffer && tries < 1000; tries++ {
		if i := int(z.Uint64()); !picked[i] {
			picked[i] = true
			files = append(files, l.popularFile(i))
		}
	}
	if !seeding {
		files = append(files, l.recycled(r, loadRecycledPerOffer)...)
	}
	for len(files) < packetFiles {
		n := l.nextFile.Add(1)
		f := storage.File{
			Hash: benchHash('U', int(n)),
			Size: uint64(100_000 + n),
			Name: fmt.Sprintf("%s %s own %07d.mkv",
				loadVocabulary[r.IntN(len(loadVocabulary))], loadVocabulary[r.IntN(len(loadVocabulary))], n),
		}
		s.own = append(s.own, f)
		files = append(files, f)
	}
	for i := range files {
		if r.IntN(3) == 0 {
			files[i].Completed = 1
		}
		s.offered[offerKey{hash: string(files[i].Hash), size: files[i].Size}] = struct{}{}
	}
	timed(stats, "AddFiles", func() { l.target.engine.AddFiles(files, s.client) })
}

func (l *loadRun) popularFile(i int) storage.File {
	return storage.File{
		Hash: benchHash('P', i),
		Size: uint64(900_000_000 + i),
		Name: fmt.Sprintf("%s %s popular %05d.avi",
			loadVocabulary[i%len(loadVocabulary)], loadVocabulary[(i/len(loadVocabulary))%len(loadVocabulary)], i),
	}
}

func (l *loadRun) recycled(r *rand.Rand, n int) []storage.File {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.recycle) == 0 {
		return nil
	}
	out := make([]storage.File, 0, n)
	seen := map[int]bool{}
	for tries := 0; len(out) < n && tries < 4*n; tries++ {
		i := r.IntN(len(l.recycle))
		if !seen[i] {
			seen[i] = true
			out = append(out, l.recycle[i])
		}
	}
	return out
}

func (l *loadRun) depart(s *session) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.departed = append(l.departed, s.client)
	for _, f := range s.own {
		if len(l.recycle) < loadRecycleRing {
			l.recycle = append(l.recycle, f)
			continue
		}
		l.recycle[l.recyclePos] = f
		l.recyclePos = (l.recyclePos + 1) % loadRecycleRing
	}
}

func (l *loadRun) fail(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures = append(l.failures, fmt.Sprintf(format, args...))
}

// checkInvariants runs once every worker and the sweeper have stopped.
func (l *loadRun) checkInvariants() {
	t := l.t
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	t.Logf("")
	t.Logf("output: invariants after the load")

	if len(l.failures) > 0 {
		t.Errorf("%d engine calls returned an error, first: %s", len(l.failures), l.failures[0])
	} else {
		t.Logf("  engine errors returned:       0")
	}

	n, sample, err := l.target.counterMismatches(ctx)
	if err != nil {
		t.Fatalf("counter check: %v", err)
	}
	t.Logf("  files with wrong counters:    %d %s", n, strings.Join(sample, "; "))
	if n > 0 {
		t.Errorf("%d files have sources/completed that differ from their source records", n)
	}

	lost, lostSample := 0, []string(nil)
	for _, s := range l.online {
		got, err := l.target.sourcesOf(ctx, s.client)
		if err != nil {
			t.Fatalf("sources of %x: %v", s.client.Hash, err)
		}
		if got != len(s.offered) {
			lost++
			if len(lostSample) < 5 {
				lostSample = append(lostSample, fmt.Sprintf("client %x has %d of %d", s.client.Hash, got, len(s.offered)))
			}
		}
	}
	t.Logf("  online clients missing files: %d of %d %s", lost, len(l.online), strings.Join(lostSample, "; "))
	if lost > 0 {
		t.Errorf("%d online clients lost offered files", lost)
	}

	n, sample, err = l.target.orphanSources(ctx)
	if err != nil {
		t.Fatalf("orphan check: %v", err)
	}
	t.Logf("  sources without a file:       %d %s", n, strings.Join(sample, "; "))
	if n > 0 {
		t.Errorf("%d source records have no file record", n)
	}

	top := l.popularFile(0)
	got := len(l.target.engine.GetSources(top.Hash, top.Size))
	t.Logf("  GetSources(popular #0):       %d sources", got)
	if got != storage.MaxWireSources {
		t.Errorf("GetSources on a file with %d online sources returned %d, want %d",
			l.cfg.seedClients, got, storage.MaxWireSources)
	}
}

// readLog returns the WARN lines written since offset, counted by message, and the
// ERROR lines themselves.
func (l *loadRun) readLog(offset int64) (map[string]int, []string) {
	warns := map[string]int{}
	var errs []string
	f, err := os.Open(l.logPath)
	if err != nil {
		l.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		l.t.Fatal(err)
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "\t", 3)
		if len(parts) < 3 {
			continue
		}
		switch parts[1] {
		case "WARN":
			msg := parts[2]
			if i := strings.Index(msg, ": "); i > 0 {
				msg = msg[:i]
			}
			warns[msg]++
		case "ERROR":
			errs = append(errs, parts[2])
		}
	}
	return warns, errs
}

func mysqlLoadTarget(engine *storage.MySQLEngine, proxy *rttProxy, direct *sql.DB) loadTarget {
	return loadTarget{
		name: "mariadb:10.11", engine: engine, proxy: proxy,
		backdate: func(ctx context.Context, clients []storage.ClientInfo) error {
			for start := 0; start < len(clients); start += 500 {
				chunk := clients[start:min(start+500, len(clients))]
				ids := make([]any, len(chunk))
				for i, c := range chunk {
					ids[i] = c.StoreID
				}
				in := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
				for _, q := range []string{
					`UPDATE sources SET time_offer = NOW() - INTERVAL 48 HOUR WHERE id_client IN (` + in + `)`,
					`UPDATE clients SET time_login = NOW() - INTERVAL 48 HOUR WHERE id IN (` + in + `)`,
				} {
					if err := execRetryingLocks(ctx, direct, q, ids...); err != nil {
						return err
					}
				}
			}
			return nil
		},
		sourcesOf: func(ctx context.Context, client storage.ClientInfo) (int, error) {
			var n int
			err := direct.QueryRowContext(ctx, `SELECT COUNT(*) FROM sources WHERE id_client = ?`, client.StoreID).Scan(&n)
			return n, err
		},
		counterMismatches: func(ctx context.Context) (int, []string, error) {
			rows, err := direct.QueryContext(ctx, `
				SELECT f.hash, f.size, f.sources, f.completed, COALESCE(x.n, 0), COALESCE(x.c, 0)
				FROM files f
				LEFT JOIN (SELECT id_file, COUNT(*) AS n, SUM(complete) AS c FROM sources GROUP BY id_file) x
				       ON x.id_file = f.id
				WHERE f.sources <> COALESCE(x.n, 0) OR f.completed <> COALESCE(x.c, 0)`)
			if err != nil {
				return 0, nil, err
			}
			defer rows.Close()
			n, sample := 0, []string(nil)
			for rows.Next() {
				var hash []byte
				var size uint64
				var sources, completed, actualSources, actualCompleted int64
				if err := rows.Scan(&hash, &size, &sources, &completed, &actualSources, &actualCompleted); err != nil {
					return 0, nil, err
				}
				n++
				if len(sample) < 5 {
					sample = append(sample, fmt.Sprintf("%x/%d stored %d/%d actual %d/%d",
						hash, size, sources, completed, actualSources, actualCompleted))
				}
			}
			return n, sample, rows.Err()
		},
		orphanSources: func(ctx context.Context) (int, []string, error) {
			var n int
			err := direct.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM sources s LEFT JOIN files f ON f.id = s.id_file WHERE f.id IS NULL`).Scan(&n)
			return n, nil, err
		},
	}
}

func mongoLoadTarget(engine *storage.MongoDBEngine, proxy *rttProxy, db *mongo.Database) loadTarget {
	return loadTarget{
		name: "mongo:7", engine: engine, proxy: proxy,
		backdate: func(ctx context.Context, clients []storage.ClientInfo) error {
			hashes := make([]any, len(clients))
			for i, c := range clients {
				hashes[i] = c.Hash
			}
			old := time.Now().Add(-48 * time.Hour)
			if _, err := db.Collection("sources").UpdateMany(ctx, bson.M{"client_hash": bson.M{"$in": hashes}},
				bson.M{"$set": bson.M{"time_offer": old}}); err != nil {
				return err
			}
			_, err := db.Collection("clients").UpdateMany(ctx, bson.M{"hash": bson.M{"$in": hashes}},
				bson.M{"$set": bson.M{"time_login": old}})
			return err
		},
		sourcesOf: func(ctx context.Context, client storage.ClientInfo) (int, error) {
			n, err := db.Collection("sources").CountDocuments(ctx, bson.M{"client_hash": client.Hash})
			return int(n), err
		},
		counterMismatches: func(ctx context.Context) (int, []string, error) {
			files, sources, err := mongoLoadState(ctx, db)
			if err != nil {
				return 0, nil, err
			}
			n, sample := 0, []string(nil)
			for key, stored := range files {
				actual := sources[key]
				if stored != actual {
					n++
					if len(sample) < 5 {
						sample = append(sample, fmt.Sprintf("%x/%d stored %d/%d actual %d/%d",
							key.hash, key.size, stored.sources, stored.completed, actual.sources, actual.completed))
					}
				}
			}
			return n, sample, nil
		},
		orphanSources: func(ctx context.Context) (int, []string, error) {
			files, sources, err := mongoLoadState(ctx, db)
			if err != nil {
				return 0, nil, err
			}
			n, sample := 0, []string(nil)
			for key, actual := range sources {
				if _, ok := files[key]; !ok {
					n += int(actual.sources)
					if len(sample) < 5 {
						sample = append(sample, fmt.Sprintf("%x/%d has %d sources", key.hash, key.size, actual.sources))
					}
				}
			}
			return n, sample, nil
		},
	}
}

type fileCounters struct{ sources, completed int64 }

// mongoLoadState reads every file's stored counters and the counts its source
// documents actually add up to.
func mongoLoadState(ctx context.Context, db *mongo.Database) (map[offerKey]fileCounters, map[offerKey]fileCounters, error) {
	files := map[offerKey]fileCounters{}
	cur, err := db.Collection("files").Find(ctx, bson.M{},
		options.Find().SetProjection(bson.M{"hash": 1, "size": 1, "sources": 1, "completed": 1}))
	if err != nil {
		return nil, nil, err
	}
	var fileDocs []struct {
		Hash      []byte `bson:"hash"`
		Size      int64  `bson:"size"`
		Sources   int64  `bson:"sources"`
		Completed int64  `bson:"completed"`
	}
	if err := cur.All(ctx, &fileDocs); err != nil {
		return nil, nil, err
	}
	for _, d := range fileDocs {
		files[offerKey{hash: string(d.Hash), size: uint64(d.Size)}] = fileCounters{d.Sources, d.Completed}
	}

	cur, err = db.Collection("sources").Aggregate(ctx, mongo.Pipeline{
		{{Key: "$group", Value: bson.M{
			"_id":       bson.M{"hash": "$file_hash", "size": "$file_size"},
			"sources":   bson.M{"$sum": 1},
			"completed": bson.M{"$sum": bson.M{"$cond": []any{"$complete", 1, 0}}},
		}}},
	}, options.Aggregate().SetAllowDiskUse(true))
	if err != nil {
		return nil, nil, err
	}
	var groups []struct {
		ID struct {
			Hash []byte `bson:"hash"`
			Size int64  `bson:"size"`
		} `bson:"_id"`
		Sources   int64 `bson:"sources"`
		Completed int64 `bson:"completed"`
	}
	if err := cur.All(ctx, &groups); err != nil {
		return nil, nil, err
	}
	sources := make(map[offerKey]fileCounters, len(groups))
	for _, g := range groups {
		sources[offerKey{hash: string(g.ID.Hash), size: uint64(g.ID.Size)}] = fileCounters{g.Sources, g.Completed}
	}
	return files, sources, nil
}

// execRetryingLocks runs a test-side write, retrying the deadlocks it can hit against
// the workload it runs beside.
func execRetryingLocks(ctx context.Context, db *sql.DB, query string, args ...any) error {
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		if _, err = db.ExecContext(ctx, query, args...); err == nil {
			return nil
		}
		var mysqlErr *mysqldriver.MySQLError
		if !errors.As(err, &mysqlErr) || (mysqlErr.Number != 1213 && mysqlErr.Number != 1205) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return err
}

func timed(stats map[string][]time.Duration, op string, fn func()) {
	start := time.Now()
	fn()
	stats[op] = append(stats[op], time.Since(start))
}

// pct returns the p-th percentile of sorted durations.
func pct(sorted []time.Duration, p int) time.Duration {
	i := (len(sorted)*p + 99) / 100
	i = max(0, min(i-1, len(sorted)-1))
	return sorted[i].Round(10 * time.Microsecond)
}

func sortedCounts(counts map[string]int) []string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
