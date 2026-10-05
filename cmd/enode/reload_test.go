package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"enode/admin"
)

// reloadTestConfig is the config the reload test starts from and rewrites.
type reloadTestConfig struct {
	name      string
	tcpPort   uint16
	udpPort   uint16
	adminPort uint16
	gossip    bool
	seedPort  uint16
	// extraSeeds are further gossip seeds, on 127.0.0.2 upwards because a seed added by
	// a reload is refused when it sits on the server's own address. interval is
	// gossip.intervalSeconds (0 leaves the default).
	extraSeeds []uint16
	interval   int
}

func (c reloadTestConfig) write(t *testing.T, path string) {
	t.Helper()
	dir := filepath.Dir(path)
	var gossipExtra strings.Builder
	for i, p := range c.extraSeeds {
		fmt.Fprintf(&gossipExtra, "    - { ip: \"127.0.0.%d\", port: %d }\n", i+2, p)
	}
	if c.interval > 0 {
		fmt.Fprintf(&gossipExtra, "  intervalSeconds: %d\n", c.interval)
	}
	body := fmt.Sprintf(`
name: %q
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
admin:
  enabled: true
  bindIP: "127.0.0.1"
  port: %d
  checkUpdates: false
gossip:
  enabled: %t
  persist: false
  allowPrivatePeers: true
  seeds:
    - { ip: "127.0.0.1", port: %d }
%sstorage:
  engine: memory
`, c.name, filepath.Join(dir, "enode.log"), c.tcpPort, c.tcpPort+1, c.udpPort, c.udpPort+1,
		c.adminPort, c.gossip, c.seedPort, gossipExtra.String())
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// postReload presses the dashboard's "Reload config" button.
func postReload(t *testing.T, adminPort uint16) (int, admin.ReloadResult, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/api/reload-config", adminPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Enode-Admin", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/reload-config: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var res admin.ReloadResult
	_ = json.Unmarshal(raw, &res)
	return resp.StatusCode, res, strings.TrimSpace(string(raw))
}

func adminGet(t *testing.T, adminPort uint16, path string) string {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d%s", adminPort, path))
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return string(raw)
}

func gossipKnown(t *testing.T, adminPort uint16) int {
	t.Helper()
	var stats admin.LiveStats
	if err := json.Unmarshal([]byte(adminGet(t, adminPort, "/stats.json")), &stats); err != nil {
		t.Fatalf("stats.json: %v", err)
	}
	return stats.GossipKnown
}

// connStillOpen reports whether the server has left the connection open: a read that
// times out means it has, one that returns EOF or an error means it was dropped.
func connStillOpen(conn net.Conn) bool {
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	_, err := conn.Read(make([]byte, 1))
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// TestReloadConfigAppliesWithoutDroppingConnections runs the real server, opens a client
// connection, then reloads three edited config files through the admin endpoint. The
// connection has to survive all of them.
func TestReloadConfigAppliesWithoutDroppingConnections(t *testing.T) {
	cfg := reloadTestConfig{
		name: "before reload", tcpPort: freePort(t), udpPort: freePort(t), adminPort: freePort(t), seedPort: freePort(t),
	}
	path := filepath.Join(t.TempDir(), "enode.config.yaml")
	cfg.write(t, path)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, path) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("run did not return after cancel")
		}
	})

	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", cfg.tcpPort), 100*time.Millisecond)
		if err == nil {
			conn = c
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal("server did not start listening")
	}
	defer conn.Close()
	// The admin listener binds before the TCP one, so it is up by now.
	if page := adminGet(t, cfg.adminPort, "/"); !strings.Contains(page, "before reload") || !strings.Contains(page, `id="reload"`) {
		t.Fatal("dashboard must show the starting name and the reload button")
	}
	if n := gossipKnown(t, cfg.adminPort); n != 0 {
		t.Fatalf("gossip is off at start but reports %d peer(s)", n)
	}

	// 1. Rename, turn gossip on, and move the TCP port.
	edited := cfg
	edited.name, edited.gossip, edited.tcpPort = "after reload", true, freePort(t)
	edited.write(t, path)
	code, res, raw := postReload(t, cfg.adminPort)
	page := adminGet(t, cfg.adminPort, "/")
	known := gossipKnown(t, cfg.adminPort)
	open := connStillOpen(conn)
	_, newPortErr := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", edited.tcpPort), 200*time.Millisecond)
	t.Logf("input: name changed, gossip.enabled false -> true, tcp.port %d -> %d", cfg.tcpPort, edited.tcpPort)
	t.Logf("output: %d %s", code, raw)
	t.Logf("output: name shown=%t gossipKnown=%d connection open=%t new tcp port listening=%t",
		strings.Contains(page, "after reload"), known, open, newPortErr == nil)
	if code != http.StatusOK {
		t.Fatalf("reload failed: %d %s", code, raw)
	}
	for _, want := range []string{"name", "gossip.enabled"} {
		if !slices.Contains(res.Applied, want) {
			t.Errorf("applied %v does not list %q", res.Applied, want)
		}
	}
	if !slices.Contains(res.RestartRequired, "tcp.port") || slices.Contains(res.Applied, "tcp.port") {
		t.Errorf("tcp.port must be reported as needing a restart: applied=%v restart=%v", res.Applied, res.RestartRequired)
	}
	if !strings.Contains(page, "after reload") {
		t.Error("dashboard still shows the old name")
	}
	if known != 1 {
		t.Errorf("gossip was turned on with one seed but knows %d peer(s)", known)
	}
	if !open {
		t.Fatal("the reload dropped the client connection")
	}
	if newPortErr == nil {
		t.Error("tcp.port must not move without a restart")
	}

	// 2. A file that does not load changes nothing.
	if err := os.WriteFile(path, []byte("name: [unterminated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, raw = postReload(t, cfg.adminPort)
	page = adminGet(t, cfg.adminPort, "/")
	known, open = gossipKnown(t, cfg.adminPort), connStillOpen(conn)
	t.Logf("input: config file replaced by invalid YAML")
	t.Logf("output: %d %s; name kept=%t gossipKnown=%d connection open=%t",
		code, raw, strings.Contains(page, "after reload"), known, open)
	if code != http.StatusUnprocessableEntity || !strings.Contains(page, "after reload") || known != 1 || !open {
		t.Fatalf("an invalid file must leave the server unchanged: %d known=%d open=%t", code, known, open)
	}

	// 3. Back to the original file: gossip goes off again and nothing is pending.
	cfg.write(t, path)
	code, res, raw = postReload(t, cfg.adminPort)
	known, open = gossipKnown(t, cfg.adminPort), connStillOpen(conn)
	t.Logf("input: original config file restored")
	t.Logf("output: %d %s; gossipKnown=%d connection open=%t", code, raw, known, open)
	if code != http.StatusOK || known != 0 || !open {
		t.Fatalf("restoring the file: %d known=%d open=%t", code, known, open)
	}
	if !slices.Contains(res.Applied, "gossip.enabled") || len(res.RestartRequired) != 0 {
		t.Errorf("expected gossip.enabled applied and nothing pending: %+v", res)
	}

	// 4. The same file again is a no-op.
	code, res, raw = postReload(t, cfg.adminPort)
	t.Logf("input: reload with the file unchanged")
	t.Logf("output: %d %s", code, raw)
	if code != http.StatusOK || len(res.Applied) != 0 || len(res.RestartRequired) != 0 {
		t.Fatalf("an unchanged file must report nothing: %d %+v", code, res)
	}
}

// startReloadServer runs the real server on cfg and returns an open client connection.
func startReloadServer(t *testing.T, cfg reloadTestConfig, path string) net.Conn {
	t.Helper()
	cfg.write(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, path) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("run did not return after cancel")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", cfg.tcpPort), 100*time.Millisecond)
		if err == nil {
			t.Cleanup(func() { _ = conn.Close() })
			return conn
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server did not start listening")
	return nil
}

// TestRepeatedConfigReloads reloads the same running server many times in a row. Each
// reload has to be diffed against the previous one, not against the startup config; the
// gossip socket has to be bound and released on every on/off cycle; a pending restart
// has to stay reported until the file no longer asks for it; and the client connection
// has to outlive all of it.
func TestRepeatedConfigReloads(t *testing.T) {
	cfg := reloadTestConfig{
		name: "round 0", tcpPort: freePort(t), udpPort: freePort(t), adminPort: freePort(t),
		seedPort: freePort(t), gossip: true,
	}
	path := filepath.Join(t.TempDir(), "enode.config.yaml")
	conn := startReloadServer(t, cfg, path)

	reload := func(input string, c reloadTestConfig) admin.ReloadResult {
		t.Helper()
		c.write(t, path)
		code, res, raw := postReload(t, cfg.adminPort)
		t.Logf("input: %s", input)
		t.Logf("output: %d %s", code, raw)
		if code != http.StatusOK {
			t.Fatalf("reload failed: %d %s", code, raw)
		}
		if !connStillOpen(conn) {
			t.Fatalf("the reload dropped the client connection (%s)", input)
		}
		return res
	}

	// 1. Five reloads with gossip staying on: a new name and one more seed each time.
	// The peer table is kept, so it grows by exactly one per reload.
	cur := cfg
	for round := 1; round <= 5; round++ {
		cur.name = fmt.Sprintf("round %d", round)
		cur.extraSeeds = append(slices.Clone(cur.extraSeeds), freePort(t))
		res := reload(fmt.Sprintf("round %d: name changed, one seed added (%d seeds)", round, round+1), cur)
		page, known := adminGet(t, cfg.adminPort, "/"), gossipKnown(t, cfg.adminPort)
		t.Logf("output: name shown=%t gossipKnown=%d", strings.Contains(page, cur.name), known)
		if !slices.Equal(res.Applied, []string{"gossip.seeds", "name"}) || len(res.RestartRequired) != 0 {
			t.Fatalf("round %d: applied=%v restart=%v, want [gossip.seeds name] and nothing pending",
				round, res.Applied, res.RestartRequired)
		}
		if !strings.Contains(page, cur.name) {
			t.Fatalf("round %d: dashboard does not show %q", round, cur.name)
		}
		if known != round+1 {
			t.Fatalf("round %d: gossip knows %d peer(s), want %d", round, known, round+1)
		}
	}

	// 2. The gossip interval is baked into the loops, so each change restarts them.
	for _, interval := range []int{60, 90, 60} {
		cur.interval = interval
		res := reload(fmt.Sprintf("gossip.intervalSeconds -> %d", interval), cur)
		known := gossipKnown(t, cfg.adminPort)
		t.Logf("output: gossipKnown=%d", known)
		if !slices.Equal(res.Applied, []string{"gossip.intervalSeconds"}) {
			t.Fatalf("interval %d: applied=%v", interval, res.Applied)
		}
		if known != 6 {
			t.Fatalf("interval %d: restarting the loops changed the peer table to %d", interval, known)
		}
	}

	// 3. Three off/on cycles. Gossip has its own UDP socket here (no obfuscated one to
	// share), so every cycle closes it and binds the same port again.
	for cycle := 1; cycle <= 3; cycle++ {
		cur.gossip = false
		res := reload(fmt.Sprintf("cycle %d: gossip off", cycle), cur)
		known := gossipKnown(t, cfg.adminPort)
		t.Logf("output: gossipKnown=%d", known)
		if !slices.Equal(res.Applied, []string{"gossip.enabled"}) || known != 0 {
			t.Fatalf("cycle %d off: applied=%v known=%d", cycle, res.Applied, known)
		}
		cur.gossip = true
		res = reload(fmt.Sprintf("cycle %d: gossip on", cycle), cur)
		known = gossipKnown(t, cfg.adminPort)
		t.Logf("output: gossipKnown=%d", known)
		if !slices.Equal(res.Applied, []string{"gossip.enabled"}) || known != 6 {
			t.Fatalf("cycle %d on: applied=%v known=%d, want all 6 seeds back", cycle, res.Applied, known)
		}
	}

	// 4. A restart-only change stays reported on every later reload until the file drops
	// it, and is never applied in between.
	pending := cur
	pending.tcpPort = freePort(t)
	for round := 1; round <= 3; round++ {
		pending.name = fmt.Sprintf("pending %d", round)
		res := reload(fmt.Sprintf("pending round %d: tcp.port %d -> %d kept in the file, name changed", round, cfg.tcpPort, pending.tcpPort), pending)
		_, dialErr := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", pending.tcpPort), 200*time.Millisecond)
		t.Logf("output: new tcp port listening=%t", dialErr == nil)
		if !slices.Equal(res.Applied, []string{"name"}) {
			t.Fatalf("pending round %d: applied=%v, want [name]", round, res.Applied)
		}
		if !slices.Contains(res.RestartRequired, "tcp.port") {
			t.Fatalf("pending round %d: tcp.port no longer reported: %v", round, res.RestartRequired)
		}
		if dialErr == nil {
			t.Fatalf("pending round %d: tcp.port moved without a restart", round)
		}
	}
	cur.name = "settled"
	res := reload("tcp.port put back", cur)
	if !slices.Equal(res.Applied, []string{"name"}) || len(res.RestartRequired) != 0 {
		t.Fatalf("after restoring tcp.port: %+v", res)
	}

	// 5. Reloading an unchanged file any number of times reports nothing.
	for i := 0; i < 3; i++ {
		res := reload("file unchanged", cur)
		if len(res.Applied) != 0 || len(res.RestartRequired) != 0 {
			t.Fatalf("unchanged file reported %+v", res)
		}
	}
}
