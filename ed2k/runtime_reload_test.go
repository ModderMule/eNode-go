package ed2k

import (
	"net"
	"sync"
	"testing"
	"time"

	"enode/storage"
)

// TestRuntimeConfigSwapsWhileServing replaces every reloadable piece of the runtime
// while other goroutines read it the way connections and datagrams do. Run under -race
// it is the proof a config reload does not need the listeners stopped.
func TestRuntimeConfigSwapsWhileServing(t *testing.T) {
	rt, _ := dispatchRuntime(t, true, nil)
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4665}
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = rt.buildStatRes(1, 2, remote)
				_ = rt.advertisedAddress()
				_ = rt.advertisableServers()
				_ = rt.gossipOpcodeEnabled(0xa4, remote, true)
				_ = rt.decryptPeerReply([]byte{0x01, 0x02}, remote.IP)
				_ = rt.GossipStats()
				_ = rt.advertisedUsers(3)
			}
		}()
	}

	const rounds = 200
	for i := 0; i < rounds; i++ {
		name := "reloaded"
		if i%2 == 0 {
			name = "original"
		}
		rt.ApplyRuntimeConfig(
			TCPRuntimeConfig{Name: name, Address: "198.51.100.1", Port: 5555, MaxConnsPerIP: i % 3},
			UDPRuntimeConfig{Name: name, UDPServerKey: 0x12345678, UDPPortObf: 5569},
		)
		rt.SetStatsBoost(StatsBoost{Users: i})
		if i%2 == 0 {
			rt.SetGossipHandler(nil)
		} else {
			rt.SetGossipHandler(NewGossipHandler(GossipConfig{MaxServers: 10, MaxFailures: 5}, nil))
		}
	}
	close(stop)
	readers.Wait()

	got := rt.TCPConfig()
	t.Logf("input: %d config swaps against 4 reading goroutines", rounds)
	t.Logf("output: final name=%q statusInterval=%s boostUsers=%d gossipOn=%t",
		got.Name, got.ServerStatusInterval, rt.statsBoost().Users, rt.gossip() != nil)
	if got.Name != "reloaded" || rt.UDPConfig().Name != "reloaded" {
		t.Fatalf("last swap not in effect: tcp=%q udp=%q", got.Name, rt.UDPConfig().Name)
	}
	if got.ServerStatusInterval != defaultServerStatusInterval {
		t.Fatalf("status interval default lost on apply: %s", got.ServerStatusInterval)
	}
	if rt.statsBoost().Users != rounds-1 || rt.gossip() == nil {
		t.Fatalf("boost or gossip handler not the last one set")
	}
}

// TestConnSlotsSurviveLimitChange covers the reload case the per-IP counter used to get
// wrong: with the limit off it did not count at all, so turning the limit on later left
// open connections uncounted, and turning it off left their slots never released.
func TestConnSlotsSurviveLimitChange(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	setLimit := func(n int) { rt.ApplyRuntimeConfig(TCPRuntimeConfig{MaxConnsPerIP: n}, UDPRuntimeConfig{}) }
	const key = "203.0.113.5"

	// Two connections open while the limit is off.
	first, second := rt.acquireConnSlot(key), rt.acquireConnSlot(key)
	setLimit(2)
	third := rt.acquireConnSlot(key)
	t.Logf("input: 2 connections opened with no limit, then limit set to 2")
	t.Logf("output: first=%t second=%t third=%t counted=%d", first, second, third, rt.connsPerIP[key])
	if !first || !second || third {
		t.Fatalf("expected the two existing connections to fill the new limit, got %t %t %t", first, second, third)
	}

	// The limit goes off again; the two connections close and must leave nothing behind.
	setLimit(0)
	rt.releaseConnSlot(key)
	rt.releaseConnSlot(key)
	setLimit(1)
	again := rt.acquireConnSlot(key)
	t.Logf("input: limit off, both connections closed, limit set to 1")
	t.Logf("output: new connection accepted=%t counted=%d", again, rt.connsPerIP[key])
	if !again || rt.connsPerIP[key] != 1 {
		t.Fatalf("slots leaked across the limit change: accepted=%t counted=%d", again, rt.connsPerIP[key])
	}
}

func TestGossipUpdateConfigAndAddSeeds(t *testing.T) {
	self := net.ParseIP("198.51.100.1")
	g := NewGossipHandler(GossipConfig{SelfIPv4: self, SelfPort: 5555, MaxServers: 100, MaxFailures: 5},
		[]PeerAddr{{IP: net.ParseIP("203.0.113.1"), Port: 4661}})

	added := g.AddSeeds([]PeerAddr{
		{IP: net.ParseIP("203.0.113.1"), Port: 4661}, // already known
		{IP: net.ParseIP("203.0.113.2"), Port: 4232}, // new
		{IP: self, Port: 5555},                       // us
		{IP: nil, Port: 4661},                        // unusable
		{IP: net.ParseIP("203.0.113.3"), Port: 0},    // unusable
	})
	t.Logf("input: 5 seeds: one known, one new, ourselves, two unusable")
	t.Logf("output: added=%d known=%d", added, g.Stats().Known)
	if added != 1 || g.Stats().Known != 2 {
		t.Fatalf("added=%d known=%d, want 1 and 2", added, g.Stats().Known)
	}

	// Park the new seed under the old MaxFailures, then raise it.
	addr := PeerAddr{IP: NormalizeIP(net.ParseIP("203.0.113.2")), Port: 4232}
	for i := 0; i < 5; i++ {
		g.NoteRoundFailure(addr)
	}
	before := g.Stats().Parked
	cfg := g.Config()
	cfg.MaxFailures = 50
	cfg.Name = "renamed"
	g.UpdateConfig(cfg)
	after := g.Stats().Parked
	t.Logf("input: maxFailures 5 -> 50 after 5 failed rounds, name -> %q", cfg.Name)
	t.Logf("output: parked before=%d after=%d name=%q known=%d", before, after, g.Config().Name, g.Stats().Known)
	if before != 1 || after != 0 || g.Config().Name != "renamed" || g.Stats().Known != 2 {
		t.Fatalf("update not applied or peer table lost: parked %d->%d name=%q known=%d",
			before, after, g.Config().Name, g.Stats().Known)
	}
}

// TestIdleTimeoutFollowsReload checks an already-open session picks up a changed
// disconnect timeout on its next deadline refresh, without reconnecting.
func TestIdleTimeoutFollowsReload(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	rt := NewServerRuntime(TCPRuntimeConfig{DisconnectTimeout: time.Hour}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	c := newTCPClient(rt, server, false)

	before := c.server.tcp().DisconnectTimeout
	rt.ApplyRuntimeConfig(TCPRuntimeConfig{DisconnectTimeout: 2 * time.Minute}, UDPRuntimeConfig{})
	after := c.server.tcp().DisconnectTimeout
	t.Logf("input: disconnect timeout reloaded from %s to 2m with a session open", before)
	t.Logf("output: the session now reads %s", after)
	if after != 2*time.Minute {
		t.Fatalf("open session still sees %s", after)
	}
}
