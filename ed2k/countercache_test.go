package ed2k

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enode/storage"
)

// countingEngine records how many count queries reach storage.
type countingEngine struct {
	storage.Engine
	clientsCalls atomic.Int64
	filesCalls   atomic.Int64
	// exactFilesCalls counts FilesCount, the scan the cache replaced.
	exactFilesCalls atomic.Int64
	delay           time.Duration
}

func (e *countingEngine) ClientsCount() int {
	e.clientsCalls.Add(1)
	if e.delay > 0 {
		time.Sleep(e.delay)
	}
	return 7
}

// FilesCount is the exact count, which the cache must never ask for: on a DB
// engine it is a full scan.
func (e *countingEngine) FilesCount() int {
	e.exactFilesCalls.Add(1)
	return 42
}

func (e *countingEngine) FilesCountEstimate() int {
	e.filesCalls.Add(1)
	if e.delay > 0 {
		time.Sleep(e.delay)
	}
	return 42
}

func (e *countingEngine) queries() int64 {
	return e.clientsCalls.Load() + e.filesCalls.Load()
}

// Repeated reads inside the TTL must cost one query pair, not one per read.
// The unauthenticated UDP status handler is the reason this matters: it ran two
// full table scans per inbound datagram.
func TestCounterCacheServesRepeatedReadsFromOneQuery(t *testing.T) {
	engine := &countingEngine{Engine: storage.NewMemoryEngine()}
	cache := newCounterCache(engine, time.Minute)

	const reads = 100
	for i := 0; i < reads; i++ {
		clients, files := cache.Counts()
		if clients != 7 || files != 42 {
			t.Fatalf("read %d returned clients=%d files=%d", i, clients, files)
		}
	}

	t.Logf("input: %d reads within the TTL", reads)
	t.Logf("output: storage queries=%d", engine.queries())

	if n := engine.exactFilesCalls.Load(); n != 0 {
		t.Fatalf("%d exact FilesCount calls, want 0: the cache must use the estimate", n)
	}
	if engine.queries() != 2 {
		t.Fatalf("%d queries for %d reads, want 2", engine.queries(), reads)
	}
}

// The cache must never cost *more* than not caching. A background refresh
// goroutine would: it queries every TTL regardless of demand, so on a quiet
// server it turns ~0.007 q/s into 0.2 q/s. Lazy refresh does no work until
// something asks.
func TestCounterCacheIssuesNoQueriesUntilRead(t *testing.T) {
	engine := &countingEngine{Engine: storage.NewMemoryEngine()}
	_ = newCounterCache(engine, 10*time.Millisecond)

	time.Sleep(60 * time.Millisecond)
	t.Logf("input: cache created, 60ms elapsed, nobody read it")
	t.Logf("output: storage queries=%d", engine.queries())

	if engine.queries() != 0 {
		t.Fatalf("%d queries with no reader — this is the background-ticker regression", engine.queries())
	}
}

// Concurrent readers on a cold cache must collapse onto a single query. Without
// single-flight, a burst of datagrams each starts its own refresh and the cache
// provides no protection against exactly the flood it exists to absorb.
func TestCounterCacheSingleFlight(t *testing.T) {
	engine := &countingEngine{Engine: storage.NewMemoryEngine(), delay: 50 * time.Millisecond}
	cache := newCounterCache(engine, time.Minute)

	const readers = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			clients, files := cache.Counts()
			if clients != 7 || files != 42 {
				t.Errorf("got clients=%d files=%d", clients, files)
			}
		}()
	}
	close(start)
	wg.Wait()

	t.Logf("input: %d concurrent readers against a cold cache", readers)
	t.Logf("output: storage queries=%d", engine.queries())

	if engine.queries() != 2 {
		t.Fatalf("%d queries for %d concurrent readers, want 2", engine.queries(), readers)
	}
}

// Values must still refresh once the TTL lapses, or the counts freeze forever.
func TestCounterCacheRefreshesAfterTTL(t *testing.T) {
	engine := &countingEngine{Engine: storage.NewMemoryEngine()}
	cache := newCounterCache(engine, 20*time.Millisecond)

	cache.Counts()
	first := engine.queries()
	cache.Counts()
	cached := engine.queries()

	time.Sleep(40 * time.Millisecond)
	cache.Counts()
	afterTTL := engine.queries()

	t.Logf("input: read, read again, sleep past a 20ms TTL, read once more")
	t.Logf("output: queries after first=%d after second=%d after TTL=%d", first, cached, afterTTL)

	if cached != first {
		t.Fatalf("the second read inside the TTL issued queries: %d -> %d", first, cached)
	}
	if afterTTL <= cached {
		t.Fatalf("the read after the TTL did not refresh: still %d queries", afterTTL)
	}
}

// The whole point is that cost stops tracking the number of clients. Each
// logged-in client owns a status ticker, so query load used to be 2N per
// interval; through the cache it is flat.
func TestCounterCacheCostDoesNotScaleWithClients(t *testing.T) {
	for _, clients := range []int{1, 10, 100} {
		engine := &countingEngine{Engine: storage.NewMemoryEngine()}
		cache := newCounterCache(engine, time.Minute)

		var wg sync.WaitGroup
		for i := 0; i < clients; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cache.Counts()
			}()
		}
		wg.Wait()

		t.Logf("input: %d clients each reading the counts -> output: %d queries", clients, engine.queries())
		if engine.queries() != 2 {
			t.Fatalf("%d clients caused %d queries, want 2", clients, engine.queries())
		}
	}
}

// The tests above exercise counterCache directly, so they would still pass if
// the handlers went back to querying storage themselves. This one drives the
// real UDP status path, which is the unauthenticated one an attacker reaches.
func TestUDPStatusRequestsUseTheCache(t *testing.T) {
	engine := &countingEngine{Engine: storage.NewMemoryEngine()}
	rt := NewServerRuntime(
		TCPRuntimeConfig{CounterCacheTTL: time.Minute},
		UDPRuntimeConfig{},
		engine,
	)
	handler := rt.UDPHandler(false)

	server, remote, _ := udpProbe(t)

	const datagrams = 50
	for i := 0; i < datagrams; i++ {
		handler([]byte{PrED2K, OpGlobServStatReq, 0x01, 0x02, 0x03, 0x04}, remote, server)
	}

	t.Logf("input: %d unauthenticated OP_GLOBSERVSTATREQ datagrams", datagrams)
	t.Logf("output: storage count queries=%d", engine.queries())

	if engine.queries() != 2 {
		t.Fatalf("%d datagrams caused %d count queries, want 2 — each one is a full table scan",
			datagrams, engine.queries())
	}
}

// And the TCP status path, which is the one that scales with client count.
func TestServerStatusUsesTheCache(t *testing.T) {
	engine := &countingEngine{Engine: storage.NewMemoryEngine()}
	rt := NewServerRuntime(
		TCPRuntimeConfig{CounterCacheTTL: time.Minute},
		UDPRuntimeConfig{},
		engine,
	)

	const clients = 20
	for i := 0; i < clients; i++ {
		server, client := net.Pipe()
		c := newTCPClient(rt, server, false)
		go func() {
			buf := make([]byte, 4096)
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			_, _ = client.Read(buf)
			client.Close()
		}()
		c.sendServerStatus()
		server.Close()
	}

	t.Logf("input: %d clients each sending OP_SERVERSTATUS", clients)
	t.Logf("output: storage count queries=%d", engine.queries())

	if engine.queries() != 2 {
		t.Fatalf("%d clients caused %d count queries, want 2", clients, engine.queries())
	}
}

func TestNewCounterCacheDefaultTTL(t *testing.T) {
	cache := newCounterCache(storage.NewMemoryEngine(), 0)
	t.Logf("output: ttl=%s", cache.ttl)
	if cache.ttl != time.Minute {
		t.Fatalf("ttl=%s, want %s", cache.ttl, time.Minute)
	}
}
