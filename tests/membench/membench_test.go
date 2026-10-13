// Package membench measures the memory engine at scale: publish rate, heap per file
// and search latency. The workload is the one ed2k-server's examples/loadgen.rs
// generates, so its numbers compare directly with the Rust server's (see
// docs/memory-engine-benchmark.md).
package membench

import (
	"encoding/binary"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"enode/storage"
)

// kwPerFile is how many tokens each generated name carries, as in loadgen.rs.
const kwPerFile = 7

// benchFiles is the engine size the testing.B benchmarks search.
const benchFiles = 200_000

// workload is one generated index: N files over N/614 users, 70% unique names, and
// a vocabulary of 0.72·N words.
type workload struct {
	n, users, unique, vocab uint64
}

type queryKind struct {
	name string
	// needHits marks a query that must match something, so a broken index cannot
	// pass by timing empty answers.
	needHits bool
	mk       func(w workload, k uint64) *storage.SearchExpr
}

var queries = []queryKind{
	{"rare1", true, func(w workload, k uint64) *storage.SearchExpr {
		return text(word(w.tokens(w.pick(k))[0]))
	}},
	{"and2", true, func(w workload, k uint64) *storage.SearchExpr {
		t := w.tokens(w.pick(k))
		return &storage.SearchExpr{Kind: storage.SearchAnd, Left: text(word(t[1])), Right: text(word(t[2]))}
	}},
	// substr is a piece from inside a word, which only a substring match finds.
	{"substr", true, func(w workload, k uint64) *storage.SearchExpr {
		wd := word(w.tokens(w.pick(k))[3])
		if len(wd) > 5 {
			wd = wd[1:5]
		}
		return text(wd)
	}},
	{"common", true, func(workload, uint64) *storage.SearchExpr { return text("bin") }},
	{"miss", false, func(workload, uint64) *storage.SearchExpr { return text("zzqxv") }},
}

func TestMemoryEngineScale(t *testing.T) {
	if os.Getenv("ENODE_MEMBENCH") != "1" {
		t.Skip("set ENODE_MEMBENCH=1 to run the memory engine benchmark")
	}
	sizes := envList(t, "ENODE_MEMBENCH_FILES", []uint64{100_000, 1_000_000})
	q := envUint(t, "ENODE_MEMBENCH_QUERIES", 200)
	for _, n := range sizes {
		t.Run(strconv.FormatUint(n, 10), func(t *testing.T) {
			w := newWorkload(n)
			a0 := heapAlloc()
			start := time.Now()
			m := w.build()
			pub := time.Since(start).Seconds()
			a1 := heapAlloc()
			t.Logf("input: files=%d users=%d unique_names=%d vocab=%d queries=%d", w.n, w.users, w.unique, w.vocab, q)
			t.Logf("publish: %.2fs  %.0f files/s", pub, float64(n)/pub)
			t.Logf("mem: live=%.1f MB (%.1f B/file)  maxrss=%.1f MB",
				(a1-a0)/1048576, (a1-a0)/float64(n), maxrssMB())
			for _, qk := range queries {
				lat := make([]float64, 0, q)
				hits := 0
				for k := uint64(0); k < q; k++ {
					e := qk.mk(w, k)
					st := time.Now()
					r := m.FindBySearch(e)
					lat = append(lat, float64(time.Since(st).Nanoseconds())/1e3)
					hits += len(r)
				}
				sort.Float64s(lat)
				sum := 0.0
				for _, v := range lat {
					sum += v
				}
				t.Logf("search %-7s mean=%12.1fus p50=%12.1fus p99=%12.1fus avg_hits=%.1f",
					qk.name, sum/float64(len(lat)), lat[len(lat)/2], lat[len(lat)*99/100], float64(hits)/float64(q))
				if qk.needHits && hits == 0 {
					t.Errorf("search %s returned no hits over %d queries", qk.name, q)
				}
			}
			runtime.KeepAlive(m)
		})
	}
}

// TestHugeClient measures one session that shares a very large number of files: how
// fast it publishes, what a file costs, how long its disconnect takes and how long a
// search from another goroutine waits while the disconnect runs.
//
// The search timed is one that finds nothing, which costs well under a microsecond
// by itself: what it takes beyond that is the time it waited for the engine's lock.
func TestHugeClient(t *testing.T) {
	if os.Getenv("ENODE_MEMBENCH") != "1" {
		t.Skip("set ENODE_MEMBENCH=1 to run the memory engine benchmark")
	}
	n := envUint(t, "ENODE_MEMBENCH_HUGE", 100_000)
	const packet = 200
	// Background index, so the searches measured have real work to do.
	w := newWorkload(100_000)
	m := w.build()
	uh := make([]byte, 16)
	binary.LittleEndian.PutUint64(uh, mix(0xb16b00b5))
	big := storage.ClientInfo{ID: 0x0a0b0c0d, Port: 4662, Hash: uh, IPv6: make([]byte, 16), IPv6Reachable: true}
	big.IPv6[0] = 0x20
	big.StoreID, _ = m.Connect(big)
	share := func() []storage.File {
		files := make([]storage.File, n)
		for i := range files {
			h0, h1 := mix(uint64(i)^0x5151515151515151), mix(uint64(i)^0x7e7e7e7e7e7e7e7e)
			hash := make([]byte, 16)
			binary.LittleEndian.PutUint64(hash[0:], h0)
			binary.LittleEndian.PutUint64(hash[8:], h1)
			files[i] = storage.File{Hash: hash, Size: h1 | 1, Name: "huge " + w.name(uint64(i)%w.unique), Completed: 1}
		}
		return files
	}
	t.Logf("input: background_files=%d huge_client_files=%d packet=%d", w.n, n, packet)

	// The heap is read before the share is generated and after the generated slice
	// is dropped, so the difference is what the engine keeps of it, names included.
	a0 := heapAlloc()
	files := share()
	first := files[0].Hash
	start := time.Now()
	for i := 0; i < len(files); i += packet {
		m.AddFiles(files[i:min(i+packet, len(files))], big)
	}
	pub := time.Since(start).Seconds()
	files = nil
	a1 := heapAlloc()
	t.Logf("publish: %.3fs  %.0f files/s", pub, float64(n)/pub)
	t.Logf("mem: huge client live=%.1f MB (%.1f B/file)", (a1-a0)/1048576, (a1-a0)/float64(n))

	one := share()
	// No collection while latencies are taken: a search that waits out a GC phase
	// would be read as one that waited on the engine's lock.
	runtime.GC()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	idle := searchLatencies(m, 20000, nil)
	t.Logf("search idle: mean=%.2fus p99=%.1fus max=%.1fus", mean(idle), idle[len(idle)*99/100], idle[len(idle)-1])

	stop := make(chan struct{})
	done := make(chan []float64)
	go func() { done <- searchLatencies(m, 0, stop) }()
	time.Sleep(20 * time.Millisecond)
	start = time.Now()
	m.Disconnect(big)
	disc := time.Since(start)
	close(stop)
	busy := <-done
	t.Logf("disconnect: %.3fms for %d files", float64(disc.Nanoseconds())/1e6, n)
	t.Logf("search during disconnect: n=%d mean=%.2fus p99=%.1fus max=%.1fus (longest wait on the engine lock)",
		len(busy), mean(busy), busy[len(busy)*99/100], busy[len(busy)-1])
	if got := m.GetSourcesByHash(first); len(got) != 0 {
		t.Errorf("sources left after disconnect: %d", len(got))
	}

	// The same share crammed into one packet: how long one AddFiles holds off a search.
	big.StoreID, _ = m.Connect(big)
	stop = make(chan struct{})
	go func() { done <- searchLatencies(m, 0, stop) }()
	time.Sleep(20 * time.Millisecond)
	start = time.Now()
	m.AddFiles(one, big)
	add := time.Since(start)
	close(stop)
	busy = <-done
	t.Logf("one-packet offer of %d files: %.3fms; search during it: n=%d p99=%.1fus max=%.1fus",
		n, float64(add.Nanoseconds())/1e6, len(busy), busy[len(busy)*99/100], busy[len(busy)-1])
	m.Disconnect(big)
	runtime.KeepAlive(m)
}

var (
	benchOnce   sync.Once
	benchEngine *storage.MemoryEngine
	benchLoad   workload
)

func BenchmarkFindBySearch(b *testing.B) {
	benchOnce.Do(func() {
		benchLoad = newWorkload(benchFiles)
		benchEngine = benchLoad.build()
	})
	for _, qk := range queries {
		b.Run(qk.name, func(b *testing.B) {
			for i := 0; b.Loop(); i++ {
				benchEngine.FindBySearch(qk.mk(benchLoad, uint64(i)))
			}
		})
	}
}

func newWorkload(n uint64) workload {
	return workload{n: n, users: max(n/614, 1), unique: max(n*70/100, 1), vocab: max(n*72/100, 1)}
}

// build publishes every file through Connect and AddFile, the way sessions do.
func (w workload) build() *storage.MemoryEngine {
	m := storage.NewMemoryEngine()
	clients := make([]storage.ClientInfo, w.users)
	for u := range clients {
		uh := make([]byte, 16)
		binary.LittleEndian.PutUint64(uh, mix(uint64(u)))
		ci := storage.ClientInfo{ID: uint32(mix(uint64(u) ^ 0xdeadbeef)), Port: 4662, Hash: uh}
		ci.StoreID, _ = m.Connect(ci)
		clients[u] = ci
	}
	for i := uint64(0); i < w.n; i++ {
		h0, h1 := mix(i), mix(i^0xa5a5a5a55a5a5a5a)
		hash := make([]byte, 16)
		binary.LittleEndian.PutUint64(hash[0:], h0)
		binary.LittleEndian.PutUint64(hash[8:], h1)
		ci := clients[i%w.users]
		ci.ID = uint32(h0 >> 32)
		ci.Port = uint16(h1) | 1
		m.AddFile(storage.File{Hash: hash, Size: h1, Name: w.name(i % w.unique), Completed: 1}, ci)
	}
	return m
}

// pick is the name a query draws its words from.
func (w workload) pick(k uint64) uint64 { return mix(k^0x1234) % w.n % w.unique }

func (w workload) tokens(nameIdx uint64) []uint64 {
	s := mix(nameIdx ^ 0x9e3779b97f4a7c15)
	out := make([]uint64, kwPerFile)
	for i := range out {
		s = mix(s)
		out[i] = s % w.vocab
	}
	return out
}

func (w workload) name(nameIdx uint64) string {
	t := w.tokens(nameIdx)
	parts := make([]string, len(t))
	for i, x := range t {
		parts[i] = word(x)
	}
	return strings.Join(parts, " ") + ".bin"
}

func word(x uint64) string { return "w" + strconv.FormatUint(x, 10) }

func text(s string) *storage.SearchExpr {
	return &storage.SearchExpr{Kind: storage.SearchText, Text: s}
}

// mix is splitmix64's finalizer, identical to loadgen.rs.
func mix(z uint64) uint64 {
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func heapAlloc() float64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return float64(ms.HeapAlloc)
}

// maxrssMB is the peak resident set. Darwin reports ru_maxrss in bytes, Linux in KiB.
func maxrssMB() float64 {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	if runtime.GOOS == "darwin" {
		return float64(ru.Maxrss) / (1024 * 1024)
	}
	return float64(ru.Maxrss) / 1024
}

func envUint(t *testing.T, key string, def uint64) uint64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n == 0 {
		t.Fatalf("%s=%q: want a positive integer", key, v)
	}
	return n
}

func envList(t *testing.T, key string, def []uint64) []uint64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var out []uint64
	for _, f := range strings.Split(v, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(f), 10, 64)
		if err != nil || n == 0 {
			t.Fatalf("%s=%q: want comma-separated positive integers", key, v)
		}
		out = append(out, n)
	}
	return out
}

// searchLatencies runs a search that matches nothing and returns its latencies in
// microseconds, ascending: count of them, or until stop is closed when count is 0.
func searchLatencies(m *storage.MemoryEngine, count int, stop chan struct{}) []float64 {
	var lat []float64
	e := text("zzqxv")
	for {
		if count > 0 && len(lat) >= count {
			break
		}
		if stop != nil {
			select {
			case <-stop:
				sort.Float64s(lat)
				return lat
			default:
			}
		}
		st := time.Now()
		m.FindBySearch(e)
		lat = append(lat, float64(time.Since(st).Nanoseconds())/1e3)
	}
	sort.Float64s(lat)
	return lat
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}
