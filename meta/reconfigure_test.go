package meta

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enode/config"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
)

// TestReconfigureKeepsUnchangedSource: a reload that changes only a network's limits
// keeps its source — client, feed subscription and counters — and the next search
// uses the new limits.
func TestReconfigureKeepsUnchangedSource(t *testing.T) {
	d := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("keep.seeded.mkv", 3), torrentEntry("keep.dead.mkv", 0)}}
	cfg := testConfig(t, true, false)
	cfg.Torrent.Feed.Enabled = true
	s, built := countingSearcher(cfg, map[string]*fakeDaemon{NetworkTorrent: d})
	stop := s.Start(context.Background())
	defer stop()
	waitUntil(t, "the feed subscription", func() bool { return d.subscribeCount() == 1 })

	before := s.sources()[0]
	s.Search(context.Background(), text("keep"), false, false)
	searches := before.counters.searchesTCP.Load()

	next := cfg
	next.Torrent.OnlyAvailable = true
	next.Torrent.MaxResults = 7
	prefix := "[t] "
	next.Torrent.NamePrefix = &prefix
	s.Reconfigure(next)
	after := s.sources()[0]
	got := s.Search(context.Background(), text("keep"), false, false)
	t.Logf("input: onlyAvailable, maxResults and namePrefix changed; output: same source=%t clients built=%d subscribes=%d rows=%s limit=%d",
		before == after, built.Load(), d.subscribeCount(), fileNames(got), d.lastSearch().GetLimit())
	if before != after || built.Load() != 1 || d.subscribeCount() != 1 {
		t.Fatalf("a limits-only reload rebuilt the source")
	}
	if after.counters.searchesTCP.Load() != searches+1 {
		t.Fatalf("counters were reset across the reload")
	}
	if len(got) != 1 || got[0].Name != "[t] keep.seeded.mkv" || d.lastSearch().GetLimit() != 7 || !d.lastSearch().GetAlive() {
		t.Fatalf("the search after the reload did not use the new limits")
	}
}

// TestReconfigureRebuildsChangedConnection: a new URL builds a new client, and its
// answers never come out of the old daemon's cache entries.
func TestReconfigureRebuildsChangedConnection(t *testing.T) {
	old := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("move.old.mkv", 3)}}
	moved := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("move.new.mkv", 3)}}
	cfg := testConfig(t, true, false)
	cfg.Cache.Enabled, cfg.Cache.MaxEntries, cfg.Cache.MaxRowsPerEntry, cfg.Cache.TTLSeconds = true, 10, 10, 60
	var built atomic.Int32
	s := NewWithClients(cfg, func(network string, c config.MetaNetworkConfig) metav1connect.MetaIngestClient {
		built.Add(1)
		if c.URL == "http://moved:9701" {
			return moved.client()
		}
		return old.client()
	})
	first := s.Search(context.Background(), text("move"), false, false)

	next := cfg
	next.Torrent.URL = "http://moved:9701"
	s.Reconfigure(next)
	second := s.Search(context.Background(), text("move"), false, false)
	t.Logf("input: url changed with the cache on; output: before=%s after=%s clients built=%d", fileNames(first), fileNames(second), built.Load())
	if built.Load() != 2 || len(second) != 1 || second[0].Name != "[torrent] move.new.mkv" {
		t.Fatalf("the reload did not switch to the new daemon")
	}
}

// TestReconfigureAddsAndRemovesNetworks: a network turned off stops its goroutines
// and leaves the searcher; one turned on starts its feed while the searcher runs.
func TestReconfigureAddsAndRemovesNetworks(t *testing.T) {
	torrent := &fakeDaemon{}
	usenet := &fakeDaemon{}
	cfg := testConfig(t, true, false)
	cfg.Torrent.Feed.Enabled = true
	s := searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: torrent, NetworkUsenet: usenet})
	stop := s.Start(context.Background())
	defer stop()
	waitUntil(t, "the torrent feed", func() bool { return torrent.subscribeCount() == 1 })

	next := testConfig(t, false, true)
	next.Usenet.Feed.Enabled = true
	done := make(chan struct{})
	go func() {
		s.Reconfigure(next)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Reconfigure did not return: the removed network's goroutines did not stop")
	}
	waitUntil(t, "the usenet feed", func() bool { return usenet.subscribeCount() == 1 })
	t.Logf("input: torrent off, usenet on; output: networks=%v usenet subscribes=%d", s.Networks(), usenet.subscribeCount())
	if got := s.Networks(); len(got) != 1 || got[0] != NetworkUsenet {
		t.Fatalf("networks %v, want only usenet", got)
	}
}

// TestReconfigureDuringSearches: searches running while the config changes see the
// old state or the new one, never a mix; run with -race.
func TestReconfigureDuringSearches(t *testing.T) {
	d := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("race.mkv", 3)}}
	cfg := testConfig(t, true, false)
	s := searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: d})

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				s.Search(context.Background(), text("race"), false, false)
				_ = s.Stats()
				_ = s.AdvertisedFiles()
			}
		}()
	}
	for i := range 50 {
		next := cfg
		next.Torrent.OnlyAvailable = i%2 == 0
		next.Torrent.MaxResults = 10 + i
		next.UDPMaxConcurrent = 1 + i%3
		s.Reconfigure(next)
	}
	wg.Wait()
	t.Logf("input: 50 reloads during 200 searches; output: %d daemon calls", d.searchCount())
}

// countingSearcher is searcherFor that counts the clients built.
func countingSearcher(cfg config.MetaSearchConfig, daemons map[string]*fakeDaemon) (*Searcher, *atomic.Int32) {
	var built atomic.Int32
	s := NewWithClients(cfg, func(network string, _ config.MetaNetworkConfig) metav1connect.MetaIngestClient {
		built.Add(1)
		return daemons[network].client()
	})
	return s, &built
}

// waitUntil polls cond for up to five seconds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
