package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// freePort reserves a port and releases it, so the config can name one that is
// free right now.
func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

func writeRunConfig(t *testing.T, tcpPort, udpPort uint16) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "enode.config.yaml")
	body := fmt.Sprintf(`
name: "shutdown test"
address: "127.0.0.1"
dynIp: "127.0.0.1"
supportCrypt: false
logLevel: "error"
logFile: %q
tcp:
  port: %d
  portObfuscated: %d
udp:
  port: %d
  portObfuscated: %d
  # A fixed secret, so the test writes no data/udp.secret into the repo.
  serverKey: 305419896
natTraversal:
  enabled: false
# A free port, so the test does not collide with a dashboard (or a tunnel to one)
# already holding the default 4560.
admin:
  bindIP: "127.0.0.1"
  port: %d
storage:
  engine: memory
`, filepath.Join(dir, "enode.log"), tcpPort, tcpPort+1, udpPort, udpPort+1, freePort(t))

	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// main used to end in `select {}`, so run never returned and every defer —
// engine.Close(), the listener closes, the cleanup stoppers — was dead code that
// only looked like a graceful shutdown. Cancelling the context must return.
func TestRunReturnsOnContextCancel(t *testing.T) {
	tcpPort := freePort(t)
	udpPort := freePort(t)
	configPath := writeRunConfig(t, tcpPort, udpPort)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, configPath) }()

	// Wait until the server is actually listening before cancelling, so the test
	// exercises shutdown rather than a race with startup.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", tcpPort), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("input: server listening on tcp 127.0.0.1:%d, cancelling the context", tcpPort)

	start := time.Now()
	cancel()

	select {
	case err := <-done:
		t.Logf("output: run returned err=%v after %s", err, time.Since(start).Round(time.Millisecond))
		if err != nil {
			t.Fatalf("run returned an error on clean shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return within 5s of cancellation — the defers are unreachable")
	}

	// The listener defer must have run: the port has to be bindable again. This
	// is the observable proof that shutdown released resources rather than
	// leaving the process to be killed.
	deadline = time.Now().Add(3 * time.Second)
	var bindErr error
	for time.Now().Before(deadline) {
		l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", tcpPort))
		if err == nil {
			l.Close()
			bindErr = nil
			break
		}
		bindErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("output: rebinding tcp port %d after shutdown -> err=%v", tcpPort, bindErr)
	if bindErr != nil {
		t.Fatalf("tcp port %d was not released: %v", tcpPort, bindErr)
	}
}

// An already-cancelled context must not leave the server running.
func TestRunReturnsWhenContextAlreadyCancelled(t *testing.T) {
	configPath := writeRunConfig(t, freePort(t), freePort(t))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- run(ctx, configPath) }()

	select {
	case err := <-done:
		t.Logf("output: run returned err=%v with a pre-cancelled context", err)
		if err != nil {
			t.Fatalf("run returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return for an already-cancelled context")
	}
}

// A bad config must surface as a returned error, not an os.Exit deep inside.
// This is what makes the failure paths testable at all.
func TestRunReturnsErrorForMissingConfig(t *testing.T) {
	err := run(context.Background(), filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	t.Logf("output: err=%v", err)
	if err == nil {
		t.Fatal("a missing config file did not produce an error")
	}
}
