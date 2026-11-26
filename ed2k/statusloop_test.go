package ed2k

import (
	"testing"
	"time"

	"enode/storage"
)

// TestStatusLoopSendsStatusAndSweeps drives the shared status loop with one logged-in
// session: within one interval it must get an OP_SERVERSTATUS and lose its expired
// "More" rows, and the loop must stop once the session is gone.
func TestStatusLoopSendsStatusAndSweeps(t *testing.T) {
	client, conn := searchPagingClient(t, 1)
	rt := client.server
	tcp, udp := rt.TCPConfig(), rt.UDPConfig()
	tcp.ServerStatusInterval = 120 * time.Millisecond
	rt.ApplyRuntimeConfig(tcp, udp)
	client.pendingResults.Store(&pendingSearch{rows: make([]storage.File, 3), expires: time.Now().Add(-time.Second)})
	t.Logf("input: interval=%s step=%s, one logged-in session with 3 expired More rows",
		rt.tcp().ServerStatusInterval, rt.statusStep())

	rt.trackSession(client)
	deadline := time.Now().Add(2 * time.Second)
	var status []byte
	for status == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		conn.mu.Lock()
		for _, frame := range conn.written {
			if len(frame) >= 6 && frame[5] == OpServerStatus {
				status = frame
			}
		}
		conn.mu.Unlock()
	}
	t.Logf("output: status frame=%x pendingAfter=%v", status, client.pendingResults.Load())
	if status == nil {
		t.Fatal("no OP_SERVERSTATUS within the deadline")
	}
	if client.pendingResults.Load() != nil {
		t.Fatal("the status loop did not drop the expired rows")
	}

	rt.untrackSession(client)
	for time.Now().Before(deadline) {
		rt.liveMu.Lock()
		on := rt.statusLoopOn
		rt.liveMu.Unlock()
		if !on {
			t.Logf("output: loop stopped after the last session left")
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the status loop kept running with no session left")
}

// TestStatusLoopSkipsSessionsNotLoggedIn pins that a connection still in login gets
// no status packet, and that sessions spread over the slices.
func TestStatusLoopSkipsSessionsNotLoggedIn(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{Address: "127.0.0.1", Port: 4661}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	conn := &recordingConn{}
	idle := newTCPClient(rt, conn, false)

	slots := map[uint8]int{}
	for range statusSlices {
		c := newTCPClient(rt, &mockConn{}, false)
		rt.trackSession(c)
		slots[c.statusSlot]++
	}
	t.Logf("input: %d tracked sessions; output: %d distinct slots", statusSlices, len(slots))
	if len(slots) != statusSlices {
		t.Fatalf("sessions share slots: %v", slots)
	}

	rt.statusTick([]*tcpClient{idle}, time.Now())
	time.Sleep(20 * time.Millisecond)
	conn.mu.Lock()
	n := len(conn.written)
	conn.mu.Unlock()
	t.Logf("input: tick over a session not logged in; output: frames written=%d", n)
	if n != 0 {
		t.Fatal("a session not logged in got a status packet")
	}
}
