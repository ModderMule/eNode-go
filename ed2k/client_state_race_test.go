package ed2k

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"enode/storage"
)

// Exercises the cross-goroutine accesses to tcpClient state under -race.
//
// Three goroutines touch a connection's state concurrently in production and
// none of them was synchronised: the connection's own goroutine writes info and
// logged during login; the status loop reads logged; and any peer
// handling OP_CALLBACKREQUEST reaches this client through the shared LowIDs
// table, reading its info and calling writeRaw — which in turn reads the crypt
// state and the RC4 send key.
//
// The LowIDs map itself was always mutex-guarded. The *tcpClient it hands out
// was not, which is the actual defect.
//
// Run with -race; without the guards this reports a data race rather than
// failing an assertion.
func TestConcurrentLoginAndCallbackHaveNoRace(t *testing.T) {
	engine := storage.NewMemoryEngine()
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address:              "127.0.0.1",
		Port:                 4661,
		Hash:                 []byte("1111111111111111"),
		AllowLowIDs:          true,
		ConnectionTimeout:    5 * time.Millisecond,
		ServerStatusInterval: time.Millisecond,
	}, UDPRuntimeConfig{}, engine)

	const clients = 8
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Log a target in first so there is a LowID for the callers to chase.
	target := newTCPClient(rt, &mockConn{}, false)
	target.handlePacket(loginPacket(t, bytes.Repeat([]byte{0x01}, 16), 0, 4662))
	if !target.isLogged() {
		t.Fatal("target login failed")
	}
	targetID := target.snapshotInfo().ID
	t.Logf("input: target logged in with lowID=%d, %d concurrent peers", targetID, clients)

	// The status loop reads logged from a separate goroutine.
	rt.trackSession(target)
	defer rt.untrackSession(target)

	// Peers hammering OP_CALLBACKREQUEST at the target: each reads target.info
	// and writes to target's socket from its own goroutine.
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			peer := newTCPClient(rt, &mockConn{}, false)
			hash := bytes.Repeat([]byte{byte(0x10 + n)}, 16)
			peer.handlePacket(loginPacket(t, hash, 0, uint16(5000+n)))
			// Promote the peer to a HighID so handleCallbackRequest takes the
			// classic IPv4 branch and writes to the *target's* socket cross-
			// goroutine — the write this test exists to stress. Without this a
			// LowID requester now hits sendCallbackFailed on its own conn instead.
			peer.infoMu.Lock()
			peer.info.LowID = false
			peer.info.IPv4 = uint32(0x0100007f)
			peer.infoMu.Unlock()
			for {
				select {
				case <-stop:
					return
				default:
				}
				req := NewBuffer(4)
				_ = req.PutUInt32LE(targetID)
				req.Pos(0)
				peer.handleCallbackRequest(req)
			}
		}(i)
	}

	// Meanwhile the target's own goroutine keeps rewriting its identity, which
	// is what login does.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = target.snapshotInfo()
			target.infoMu.Lock()
			target.info.Port = uint16(4662 + i%16)
			target.infoMu.Unlock()
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()

	t.Logf("output: no race detected; target still logged=%t id=%d",
		target.isLogged(), target.snapshotInfo().ID)
}

// writeRaw is reachable from three goroutines. It reads the crypt state and the
// RC4 send key together, which must be atomic: RC4 is a stateful stream cipher,
// so pairing a stale state with a rotated key corrupts the rest of the stream
// rather than a single packet.
func TestConcurrentWritesDuringCryptHandshakeHaveNoRace(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address: "127.0.0.1",
		Port:    4661,
	}, UDPRuntimeConfig{}, storage.NewMemoryEngine())

	client := newTCPClient(rt, &mockConn{}, true)

	negIn := make([]byte, 0, 1+CryptPrimeSize+1)
	negIn = append(negIn, 0x7a)
	negIn = append(negIn, make([]byte, CryptPrimeSize)...)
	negIn = append(negIn, 0x00)
	negIn[1] = 0x02

	t.Logf("input: crypt handshake advancing while %d writers send concurrently", 4)

	var wg sync.WaitGroup
	start := make(chan struct{})

	// The owning goroutine advances the crypt state machine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		client.handleBytes(negIn)
	}()

	// Other goroutines write concurrently, as the status loop and callback
	// path do.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 50; j++ {
				_ = client.writeRaw([]byte{0xe3, 0x01, 0x00, 0x00, 0x00, 0x38})
			}
		}()
	}

	close(start)
	wg.Wait()
	t.Logf("output: no race detected; cryptState=%d", client.crypt.State())
}
