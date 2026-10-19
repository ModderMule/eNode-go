package meta

import (
	"context"
	"strings"
	"testing"

	"enode/config"
	"enode/storage"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
)

// TestSearchOnlyAvailableRequest: with onlyAvailable a live Search asks the torrent,
// Kad and web daemons for alive releases and the Usenet daemon for complete ones,
// and the rows a daemon still sends that fail the check are dropped. Off, the request
// carries neither filter and every row is kept.
func TestSearchOnlyAvailableRequest(t *testing.T) {
	cases := []struct {
		network   string
		enable    func(*config.MetaSearchConfig) *config.MetaNetworkConfig
		live      *metav1.MetaEntry
		dead      *metav1.MetaEntry
		wantAlive bool
		wantFloor uint32
	}{
		{NetworkTorrent, func(c *config.MetaSearchConfig) *config.MetaNetworkConfig { return &c.Torrent },
			torrentEntry("avail.seeded.mkv", 4), torrentEntry("avail.dead.mkv", 0), true, 0},
		{NetworkKad, func(c *config.MetaSearchConfig) *config.MetaNetworkConfig { return &c.Kad },
			kadEntry("avail.sourced.avi", 2, 0), kadEntry("avail.dead.avi", 0, 0), true, 0},
		{NetworkWeb, func(c *config.MetaSearchConfig) *config.MetaNetworkConfig { return &c.Web },
			webEntry("avail.mirrored.mp4", 1), webEntry("avail.dead.mp4", 0), true, 0},
		{NetworkUsenet, func(c *config.MetaSearchConfig) *config.MetaNetworkConfig { return &c.Usenet },
			completeNZB("avail.complete.nzb"), nzbEntry("avail.partial.nzb"), false, fullCompletion},
	}
	for _, tc := range cases {
		for _, on := range []bool{false, true} {
			cfg := testConfig(t, false, false)
			n := tc.enable(&cfg)
			n.Enabled = true
			n.OnlyAvailable = on
			d := &fakeDaemon{entries: []*metav1.MetaEntry{tc.live, tc.dead}}
			s := searcherFor(cfg, map[string]*fakeDaemon{tc.network: d})

			got := s.Search(context.Background(), text("avail"), false, false)
			req := d.searches[0]
			t.Logf("input: %s onlyAvailable=%t, daemon sends %s + %s; output: %s alive=%t min_completion=%d",
				tc.network, on, tc.live.GetName(), tc.dead.GetName(), fileNames(got), req.GetAlive(), req.GetMinCompletion())

			wantAlive, wantFloor, wantRows := false, uint32(0), 2
			if on {
				wantAlive, wantFloor, wantRows = tc.wantAlive, tc.wantFloor, 1
			}
			if req.GetAlive() != wantAlive || req.GetMinCompletion() != wantFloor {
				t.Errorf("%s on=%t: request alive=%t min_completion=%d, want %t / %d",
					tc.network, on, req.GetAlive(), req.GetMinCompletion(), wantAlive, wantFloor)
			}
			if len(got) != wantRows {
				t.Errorf("%s on=%t: got %s, want %d rows", tc.network, on, fileNames(got), wantRows)
			}
			if on && len(got) == 1 && !strings.HasSuffix(got[0].Name, tc.live.GetName()) {
				t.Errorf("%s: kept %s, want %s", tc.network, got[0].Name, tc.live.GetName())
			}
		}
	}
}

// TestSearchOnlyAvailableFeed: a feed row is held to the same check, since no
// request filtered it, and a dead feed row does not use up the network's quota.
func TestSearchOnlyAvailableFeed(t *testing.T) {
	seeded, dead := torrentEntry("feedavail.seeded.mkv", 7), torrentEntry("feedavail.dead.mkv", 0)
	for _, on := range []bool{false, true} {
		cfg := testConfig(t, true, false)
		cfg.Torrent.Feed.Enabled = true
		cfg.Torrent.LiveSearch = new(bool) // the feed alone answers
		cfg.Torrent.OnlyAvailable = on
		s := searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: {}})
		s.sources()[0].feed.apply(&metav1.SubscribeResponse{Changes: []*metav1.ReleaseChange{upsert(1, seeded), upsert(2, dead)}, Cursor: 2})

		got := s.Search(context.Background(), text("feedavail"), false, false)
		t.Logf("input: feed holds a seeded and a dead torrent, onlyAvailable=%t; output: %s", on, fileNames(got))
		want := 2
		if on {
			want = 1
		}
		if len(got) != want {
			t.Errorf("onlyAvailable=%t: got %s, want %d rows", on, fileNames(got), want)
		}
	}
}

// TestSearchForwardsAvailabilityFloor: eMule's own availability field reaches the
// daemon as min_seeders, so dead rows do not fill the daemon's answer first.
func TestSearchForwardsAvailabilityFloor(t *testing.T) {
	d := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("floor.many.mkv", 9), torrentEntry("floor.few.mkv", 2)}}
	s := searcherFor(testConfig(t, true, false), map[string]*fakeDaemon{NetworkTorrent: d})

	expr := node(storage.SearchAnd, text("floor"), tagUint(sourcesLeaf(storage.SearchOpGreaterEqual), 5))
	got := s.Search(context.Background(), expr, false, false)
	t.Logf("input: floor AND sources>=5; output: %s min_seeders=%d", fileNames(got), d.searches[0].GetMinSeeders())
	if d.searches[0].GetMinSeeders() != 5 {
		t.Fatalf("min_seeders %d, want 5", d.searches[0].GetMinSeeders())
	}
	if len(got) != 1 || !strings.HasSuffix(got[0].Name, "floor.many.mkv") {
		t.Fatalf("got %s, want only the release with 9 sources", fileNames(got))
	}
}

// completeNZB is a Usenet row of a 100% complete release: its seeders says 99, the
// most a row can (amendment 9).
func completeNZB(name string) *metav1.MetaEntry {
	e := nzbEntry(name)
	e.Seeders = usenetCompleteSeeders
	return e
}
