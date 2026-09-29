package ed2k

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Before the pool, RunUDPServer spawned one goroutine per datagram with no
// bound, and each handler could issue ~87 synchronous storage lookups. A flood
// of cheap datagrams therefore converted directly into unbounded concurrent
// work — the send cost nothing, the service cost was unbounded.
func TestRunUDPServerBoundsConcurrentHandlers(t *testing.T) {
	const (
		workers   = 4
		queueSize = 8
		flood     = 400
	)

	var (
		inFlight atomic.Int64
		peak     atomic.Int64
		handled  atomic.Int64
		release  = make(chan struct{})
		once     sync.Once
	)

	handler := func(data []byte, remote *net.UDPAddr, conn UDPReplyConn) {
		n := inFlight.Add(1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		// Hold each handler until the flood is over, so concurrency is observable
		// rather than a race between arrival and completion.
		<-release
		inFlight.Add(-1)
		handled.Add(1)
	}

	conn, err := RunUDPServer(UDPServerConfig{
		Address:   "127.0.0.1",
		Port:      0,
		Workers:   workers,
		QueueSize: queueSize,
	}, handler)
	if err != nil {
		t.Fatalf("run udp server: %v", err)
	}
	defer conn.Close()

	client, err := net.DialUDP("udp4", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	goroutinesBefore := runtime.NumGoroutine()
	t.Logf("input: %d datagrams into a pool of %d workers, queue %d", flood, workers, queueSize)

	for i := 0; i < flood; i++ {
		if _, err := client.Write([]byte{PrED2K, OpGlobServStatReq, byte(i)}); err != nil {
			break
		}
	}

	// Give the reader time to drain the socket and fill the queue.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && inFlight.Load() < int64(workers) {
		time.Sleep(5 * time.Millisecond)
	}

	goroutinesDuring := runtime.NumGoroutine()
	observedPeak := peak.Load()
	t.Logf("output: peak concurrent handlers=%d goroutines before=%d during=%d",
		observedPeak, goroutinesBefore, goroutinesDuring)

	once.Do(func() { close(release) })

	if observedPeak > int64(workers) {
		t.Fatalf("%d handlers ran concurrently with a pool of %d", observedPeak, workers)
	}
	if observedPeak == 0 {
		t.Fatal("no handler ran at all — the test proved nothing")
	}
	// Goroutine growth must not track datagram count.
	if growth := goroutinesDuring - goroutinesBefore; growth > flood/4 {
		t.Fatalf("goroutine count grew by %d for %d datagrams", growth, flood)
	}
}

// Shedding load must not wedge the reader: after a burst that overflows the
// queue, the server has to keep serving.
func TestRunUDPServerKeepsServingAfterOverflow(t *testing.T) {
	const (
		workers   = 2
		queueSize = 2
		flood     = 200
	)

	var handled atomic.Int64
	blocked := make(chan struct{})
	var unblockOnce sync.Once

	handler := func(data []byte, remote *net.UDPAddr, conn UDPReplyConn) {
		<-blocked
		handled.Add(1)
	}

	conn, err := RunUDPServer(UDPServerConfig{
		Address:   "127.0.0.1",
		Port:      0,
		Workers:   workers,
		QueueSize: queueSize,
	}, handler)
	if err != nil {
		t.Fatalf("run udp server: %v", err)
	}
	defer conn.Close()

	client, err := net.DialUDP("udp4", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	t.Logf("input: %d datagrams with all %d workers blocked, queue %d", flood, workers, queueSize)
	for i := 0; i < flood; i++ {
		if _, err := client.Write([]byte{PrED2K, OpGlobServStatReq}); err != nil {
			break
		}
	}
	time.Sleep(200 * time.Millisecond)

	unblockOnce.Do(func() { close(blocked) })

	// The reader must still be alive and accepting after the overflow.
	deadline := time.Now().Add(2 * time.Second)
	before := handled.Load()
	for i := 0; i < 20; i++ {
		_, _ = client.Write([]byte{PrED2K, OpGlobServStatReq})
	}
	for time.Now().Before(deadline) && handled.Load() <= before {
		time.Sleep(5 * time.Millisecond)
	}

	t.Logf("output: handled=%d (was %d before the follow-up burst)", handled.Load(), before)
	if handled.Load() <= before {
		t.Fatal("the server stopped serving after the queue overflowed")
	}
}

func TestUDPPoolSizeDefaults(t *testing.T) {
	cases := []struct {
		name          string
		cfg           UDPServerConfig
		wantWorkers   int
		wantQueueSize int
	}{
		{"zero uses the defaults", UDPServerConfig{}, runtime.NumCPU() * 4, defaultUDPQueueSize},
		{"negative uses the defaults", UDPServerConfig{Workers: -1, QueueSize: -1}, runtime.NumCPU() * 4, defaultUDPQueueSize},
		{"explicit values are honoured", UDPServerConfig{Workers: 3, QueueSize: 7}, 3, 7},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workers, queueSize := udpPoolSize(tc.cfg)
			t.Logf("input: workers=%d queue=%d -> output: workers=%d queue=%d",
				tc.cfg.Workers, tc.cfg.QueueSize, workers, queueSize)
			if workers != tc.wantWorkers || queueSize != tc.wantQueueSize {
				t.Fatalf("got workers=%d queue=%d, want workers=%d queue=%d",
					workers, queueSize, tc.wantWorkers, tc.wantQueueSize)
			}
		})
	}
}
