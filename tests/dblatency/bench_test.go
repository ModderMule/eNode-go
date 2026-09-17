package dblatency

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"enode/storage"

	"github.com/ory/dockertest/v3"
)

// rtts are the link latencies the wall-clock comparison injects: loopback, the same
// datacenter, a nearby region, another datacenter.
var rtts = []time.Duration{0, 2 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond}

// A conforming eMule sends at most this many files per OP_OFFERFILES
// (srchybrid/SharedFileList.cpp:832-834).
const packetFiles = 200

// Sizes of the large-read measurements.
const (
	// crowdSources is how many online clients share the file GetSources is timed on;
	// well past the MaxWireSources a reply may carry.
	crowdSources = 2000
	// wideFiles is how many distinct files match the wide search, past MaxSearchResults.
	wideFiles = 1200
	// crowdSearchClients each offer the same packet, so the crowd search matches
	// crowdSearchClients x packetFiles sources of only packetFiles files.
	crowdSearchClients = 50
)

func requireIntegration(t *testing.T) *dockertest.Pool {
	t.Helper()
	if os.Getenv("ENODE_INTEGRATION") != "1" {
		t.Skip("set ENODE_INTEGRATION=1 to run integration tests")
	}
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("docker not available: %v", err)
	}
	if err := pool.Client.Ping(); err != nil {
		t.Skipf("docker daemon not responding: %v", err)
	}
	pool.MaxWait = 3 * time.Minute
	return pool
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// bench logs one row per measured call: round-trips, what they were, and local time.
type bench struct {
	t     *testing.T
	proxy *rttProxy
}

func (b *bench) measure(label string, fn func()) proxyCounts {
	b.t.Helper()
	before := b.proxy.snapshot()
	start := time.Now()
	fn()
	elapsed := time.Since(start)
	delta := b.proxy.snapshot().since(before)
	b.t.Logf("%-36s %s  (%s)", label, delta, elapsed.Round(10*time.Microsecond))
	return delta
}

// benchHash returns a distinct 16-byte hash per (prefix, i), so every measurement can
// offer files no earlier one touched.
func benchHash(prefix byte, i int) []byte {
	h := make([]byte, 16)
	h[0] = prefix
	copy(h[1:8], "enodebn")
	binary.BigEndian.PutUint64(h[8:], uint64(i))
	return h
}

func benchFiles(prefix byte, first, n int) []storage.File {
	files := make([]storage.File, n)
	for i := range files {
		files[i] = storage.File{
			Hash: benchHash(prefix, first+i),
			Size: uint64(700_000_000 + first + i),
			Name: fmt.Sprintf("benchmark offer %c %05d.avi", prefix, first+i),
		}
	}
	return files
}

// compareOfferPaths times the old per-file path against one batch at each RTT and
// extrapolates both to one full OP_OFFERFILES packet.
func compareOfferPaths(t *testing.T, proxy *rttProxy, engine storage.Engine, client storage.ClientInfo) {
	t.Helper()
	const loopFiles = 50
	t.Logf("")
	t.Logf("wall-clock, injected RTT: AddFile x%d vs AddFiles(%d), both extrapolated to a %d-file packet",
		loopFiles, packetFiles, packetFiles)
	next := 0
	for i, rtt := range rtts {
		proxy.setRTT(rtt)
		prefix := byte('p' + i)

		loop := benchFiles(prefix, next, loopFiles)
		next += loopFiles
		start := time.Now()
		for _, f := range loop {
			engine.AddFile(f, client)
		}
		perFile := time.Since(start) / loopFiles

		batch := benchFiles(prefix, next, packetFiles)
		next += packetFiles
		start = time.Now()
		engine.AddFiles(batch, client)
		batched := time.Since(start)

		t.Logf("  RTT=%-5s AddFile %9s/file -> packet %9s | AddFiles packet %9s | %6.0fx",
			rtt, perFile.Round(10*time.Microsecond), (perFile * packetFiles).Round(time.Millisecond),
			batched.Round(100*time.Microsecond), float64(perFile*packetFiles)/float64(batched))
	}
	proxy.setRTT(0)
}

func labelSweep(n int) string {
	return fmt.Sprintf("CleanupStale, %d affected files", n)
}

// timeMedian runs fn n times and logs the median: the engine's own cost at RTT 0,
// without the noise of timing a single call.
func (b *bench) timeMedian(label string, n int, fn func()) time.Duration {
	b.t.Helper()
	times := make([]time.Duration, n)
	for i := range times {
		start := time.Now()
		fn()
		times[i] = time.Since(start)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	median := times[n/2]
	b.t.Logf("%-36s median %s over %d calls (min %s, max %s)", label,
		median.Round(10*time.Microsecond), n, times[0].Round(10*time.Microsecond), times[n-1].Round(10*time.Microsecond))
	return median
}

// largeReads holds the round-trip counts measureLargeReads asserts on.
type largeReads struct {
	getSources proxyCounts
	search     proxyCounts
}

// measureLargeReads measures reads whose result is bigger than a database's default
// first batch: a file with more sources than one reply may carry, a search capped at
// MaxSearchResults, and a search matching many sources of few files.
func measureLargeReads(t *testing.T, b *bench, engine storage.Engine) largeReads {
	t.Helper()
	var out largeReads

	crowd := benchFiles('g', 0, 1)
	seedCrowd(t, engine, 'G', crowdSources, func(int) []storage.File { return crowd })
	var sources []storage.Source
	out.getSources = b.measure(fmt.Sprintf("GetSources, %d online sources", crowdSources), func() {
		sources = engine.GetSources(crowd[0].Hash, crowd[0].Size)
	})
	if len(sources) != storage.MaxWireSources {
		t.Errorf("GetSources over %d online sources returned %d, want %d", crowdSources, len(sources), storage.MaxWireSources)
	}
	b.timeMedian(fmt.Sprintf("  server time, %d sources", crowdSources), 15, func() {
		engine.GetSources(crowd[0].Hash, crowd[0].Size)
	})

	seedCrowd(t, engine, 'W', wideFiles/packetFiles, func(i int) []storage.File {
		return namedFiles('w', i*packetFiles, packetFiles, "widesearch")
	})
	wide := &storage.SearchExpr{Kind: storage.SearchText, Text: "widesearch"}
	var hits []storage.File
	out.search = b.measure(fmt.Sprintf("FindBySearch, %d hits", storage.MaxSearchResults), func() {
		hits = engine.FindBySearch(wide)
	})
	if len(hits) != storage.MaxSearchResults {
		t.Errorf("search over %d matching files returned %d, want %d", wideFiles, len(hits), storage.MaxSearchResults)
	}

	crowdPacket := namedFiles('h', 0, packetFiles, "crowdsearch")
	seedCrowd(t, engine, 'H', crowdSearchClients, func(int) []storage.File { return crowdPacket })
	crowdSearch := &storage.SearchExpr{Kind: storage.SearchText, Text: "crowdsearch"}
	b.timeMedian(fmt.Sprintf("FindBySearch, %d sources of %d files", crowdSearchClients*packetFiles, packetFiles), 15, func() {
		hits = engine.FindBySearch(crowdSearch)
	})
	if len(hits) != packetFiles || hits[0].Sources != crowdSearchClients {
		t.Errorf("crowd search returned %d files, first with %d sources; want %d files with %d sources",
			len(hits), firstSources(hits), packetFiles, crowdSearchClients)
	}
	return out
}

// assertSweepFlat fails when a sweep costs more round-trips as it affects more files.
func assertSweepFlat(t *testing.T, sweeps ...proxyCounts) {
	t.Helper()
	for _, s := range sweeps[1:] {
		if s.roundTrips != sweeps[0].roundTrips {
			rts := make([]int, len(sweeps))
			for i, s := range sweeps {
				rts[i] = s.roundTrips
			}
			t.Errorf("CleanupStale round-trips by affected file count (10, 100, 1000...) = %v, want all equal — the sweep grows with its size", rts)
			return
		}
	}
}

// seedCrowd connects n clients, eight at a time, and has client i offer files(i).
func seedCrowd(t *testing.T, engine storage.Engine, prefix byte, n int, files func(i int) []storage.File) {
	t.Helper()
	next := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				client := benchClient(prefix, i)
				id, err := engine.Connect(client)
				if err != nil {
					mu.Lock()
					firstErr = err
					mu.Unlock()
					continue
				}
				client.StoreID = id
				engine.AddFiles(files(i), client)
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("seed %d clients: %v", n, firstErr)
	}
}

// benchClient returns client i of a group; prefix keeps groups apart.
func benchClient(prefix byte, i int) storage.ClientInfo {
	id := uint32(0x0a000000) | uint32(prefix)<<16 | uint32(i&0xffff)
	return storage.ClientInfo{ID: id, IPv4: id, Port: 4662, Hash: benchHash(prefix, 1<<48+i)}
}

// namedFiles is benchFiles with every name starting with word, so one search term
// matches exactly these files.
func namedFiles(prefix byte, first, n int, word string) []storage.File {
	files := benchFiles(prefix, first, n)
	for i := range files {
		files[i].Name = fmt.Sprintf("%s %c %05d.avi", word, prefix, first+i)
	}
	return files
}

func firstSources(files []storage.File) uint32 {
	if len(files) == 0 {
		return 0
	}
	return files[0].Sources
}
