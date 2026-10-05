package meta

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
)

// waitFor polls cond until it holds or two seconds pass.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestStatsReportsDaemonInfo: Start polls GetInfo, its figures reach Stats, and only
// a network with countInServerStatus adds its file count to AdvertisedFiles.
func TestStatsReportsDaemonInfo(t *testing.T) {
	torrent := &fakeDaemon{info: &metav1.GetInfoResponse{
		Daemon: "torrent-crawler-1", Version: "v1.2.3", Indexer: "dht", SearchAvailable: true,
		Catalogued: 1200, Published: 300, Files: 5000, LastSeq: 42,
	}}
	usenet := &fakeDaemon{info: &metav1.GetInfoResponse{Daemon: "usenet-crawler", Catalogued: 90, Files: 700}}
	cfg := testConfig(t, true, true)
	cfg.Torrent.CountInServerStatus = true
	s := searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: torrent, NetworkUsenet: usenet})

	stop := s.Start(context.Background())
	defer stop()
	waitFor(t, "both daemons polled", func() bool {
		st := s.Stats()
		return st[0].Reachable && st[1].Reachable
	})

	st := s.Stats()
	t.Logf("input: torrent files=5000 counted, usenet files=700 not counted; output: %+v / %+v advertised=%d",
		st[0], st[1], s.AdvertisedFiles())
	tr := st[0]
	if tr.Network != NetworkTorrent || tr.Daemon != "torrent-crawler-1" || tr.Version != "v1.2.3" ||
		tr.Catalogued != 1200 || tr.Published != 300 || tr.Files != 5000 || tr.LastSeq != 42 ||
		!tr.SearchAvailable || tr.InfoAt.IsZero() {
		t.Errorf("torrent figures not carried: %+v", tr)
	}
	if tr.Counted != 5000 || st[1].Counted != 0 || st[1].Files != 700 {
		t.Errorf("counted torrent=%d usenet=%d, want 5000/0", tr.Counted, st[1].Counted)
	}
	if s.AdvertisedFiles() != 5000 {
		t.Errorf("AdvertisedFiles=%d, want 5000", s.AdvertisedFiles())
	}
}

// TestAdvertisedFilesFromFeedWithoutLiveSearch: with live search off only the feed
// answers, so the counted figure is the feed's rows, not the daemon's catalogue.
func TestAdvertisedFilesFromFeedWithoutLiveSearch(t *testing.T) {
	a, b := torrentEntry("feed.a.mkv", 3), torrentEntry("feed.b.mkv", 4)
	d := &fakeDaemon{
		info: &metav1.GetInfoResponse{Files: 9999},
		feed: []*metav1.SubscribeResponse{
			{Reset_: true, Changes: []*metav1.ReleaseChange{upsert(1, a), upsert(2, b)}, Cursor: 2, SnapshotEnd: true, CaughtUp: true},
		},
	}
	cfg := testConfig(t, true, false)
	no := false
	cfg.Torrent.LiveSearch = &no
	cfg.Torrent.Feed.Enabled = true
	cfg.Torrent.CountInServerStatus = true
	s := searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: d})

	stop := s.Start(context.Background())
	defer stop()
	waitFor(t, "feed caught up and daemon polled", func() bool {
		st := s.Stats()[0]
		return st.FeedCaughtUp && st.Reachable
	})

	st := s.Stats()[0]
	t.Logf("input: liveSearch off, feed holds 2 rows, GetInfo files=9999; output: counted=%d feedRows=%d feedReleases=%d cursor=%d",
		st.Counted, st.FeedRows, st.FeedReleases, st.FeedCursor)
	if st.Counted != 2 || s.AdvertisedFiles() != 2 {
		t.Errorf("counted=%d advertised=%d, want the feed's 2 rows", st.Counted, s.AdvertisedFiles())
	}
	if st.FeedRows != 2 || st.FeedReleases != 2 || st.FeedCursor != 2 || !st.FeedEnabled {
		t.Errorf("feed figures wrong: %+v", st)
	}
}

// TestStatsKeepsFiguresWhenUnreachable: a failed poll marks the daemon unreachable
// with its error, and keeps the last figures rather than dropping the count to 0.
func TestStatsKeepsFiguresWhenUnreachable(t *testing.T) {
	d := &fakeDaemon{info: &metav1.GetInfoResponse{Files: 321}}
	cfg := testConfig(t, true, false)
	cfg.Torrent.CountInServerStatus = true
	s := searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: d})
	src := s.sources[0]

	src.refreshInfo(context.Background())
	before := s.Stats()[0]

	d.mu.Lock()
	d.infoErr = connect.NewError(connect.CodeUnavailable, "daemon restarting")
	d.mu.Unlock()
	src.refreshInfo(context.Background())
	after := s.Stats()[0]

	t.Logf("input: poll ok (files=321), then poll unavailable; output: before reachable=%t files=%d, after reachable=%t files=%d counted=%d err=%q",
		before.Reachable, before.Files, after.Reachable, after.Files, after.Counted, after.LastError)
	if !before.Reachable || after.Reachable || after.LastError == "" {
		t.Errorf("reachable before=%t after=%t err=%q", before.Reachable, after.Reachable, after.LastError)
	}
	if after.Files != 321 || after.Counted != 321 || after.InfoAt != before.InfoAt {
		t.Errorf("last figures not kept: %+v", after)
	}
}

// TestStatsStaleWhenSearchStillAnswers: a daemon whose GetInfo fails while it still
// answers searches is up with old figures, not unreachable. Without a recent search
// answer there is no such evidence, and an answer older than staleWindow is none.
func TestStatsStaleWhenSearchStillAnswers(t *testing.T) {
	d := &fakeDaemon{
		info:    &metav1.GetInfoResponse{Files: 321},
		entries: []*metav1.MetaEntry{torrentEntry("stale.mkv", 1)},
	}
	s := searcherFor(testConfig(t, true, false), map[string]*fakeDaemon{NetworkTorrent: d})
	src := s.sources[0]

	src.refreshInfo(context.Background())
	_ = s.Search(context.Background(), text("stale"), false)
	healthy := s.Stats()[0]

	d.mu.Lock()
	d.infoErr = connect.NewError(connect.CodeDeadlineExceeded, "counting files: context deadline exceeded")
	d.mu.Unlock()
	src.refreshInfo(context.Background())
	stale := s.Stats()[0]

	src.liveOK.Store(time.Now().Add(-staleWindow - time.Second).UnixNano())
	old := s.Stats()[0]

	t.Logf("input: poll ok + search ok, then poll deadline_exceeded, then the search answer aged past %s", staleWindow)
	t.Logf("output: healthy reachable=%t stale=%t; failed poll reachable=%t stale=%t liveOKAt=%s files=%d; aged reachable=%t stale=%t",
		healthy.Reachable, healthy.StatsStale, stale.Reachable, stale.StatsStale,
		stale.LiveOKAt.Format(time.RFC3339), stale.Files, old.Reachable, old.StatsStale)
	if !healthy.Reachable || healthy.StatsStale || healthy.LiveOKAt.IsZero() {
		t.Errorf("a good poll is reachable and not stale, with the search answer timed: %+v", healthy)
	}
	if stale.Reachable || !stale.StatsStale || stale.Files != 321 {
		t.Errorf("a failed poll with a recent search answer is stale, keeping its figures: %+v", stale)
	}
	if old.Reachable || old.StatsStale {
		t.Errorf("a search answer older than staleWindow is no evidence: %+v", old)
	}
}

// TestStatsNotStaleWithoutSearchAnswer: a failed poll with no search ever answered,
// or with searches failing, stays unreachable; and nothing is stale before a poll.
func TestStatsNotStaleWithoutSearchAnswer(t *testing.T) {
	d := &fakeDaemon{
		infoErr:   connect.NewError(connect.CodeUnavailable, "daemon restarting"),
		searchErr: errors.New("boom"),
	}
	s := searcherFor(testConfig(t, true, false), map[string]*fakeDaemon{NetworkTorrent: d})
	src := s.sources[0]

	unpolled := s.Stats()[0]
	src.refreshInfo(context.Background())
	_ = s.Search(context.Background(), text("failing"), false)
	failed := s.Stats()[0]

	t.Logf("input: no poll yet, then poll unavailable + search error; output: unpolled stale=%t, failed reachable=%t stale=%t liveOKAt.zero=%t liveErrors=%d",
		unpolled.StatsStale, failed.Reachable, failed.StatsStale, failed.LiveOKAt.IsZero(), failed.LiveErrors)
	if unpolled.StatsStale {
		t.Errorf("nothing is stale before the first poll: %+v", unpolled)
	}
	if failed.Reachable || failed.StatsStale || !failed.LiveOKAt.IsZero() {
		t.Errorf("a failed poll with no search answer is unreachable: %+v", failed)
	}
}

// TestStatsShutdownIsNotAFailure: a poll cut short by the process stopping leaves the
// daemon's state alone.
func TestStatsShutdownIsNotAFailure(t *testing.T) {
	d := &fakeDaemon{info: &metav1.GetInfoResponse{Files: 5}}
	s := searcherFor(testConfig(t, true, false), map[string]*fakeDaemon{NetworkTorrent: d})
	src := s.sources[0]
	src.refreshInfo(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src.refreshInfo(ctx)
	st := s.Stats()[0]
	t.Logf("input: poll ok, then a poll with a cancelled context; output: reachable=%t err=%q", st.Reachable, st.LastError)
	if !st.Reachable || st.LastError != "" {
		t.Errorf("a shutdown marked the daemon unreachable: %+v", st)
	}
}

// TestStatsSearchCounters: every search path moves its own counter.
func TestStatsSearchCounters(t *testing.T) {
	d := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("count.mkv", 1)}}
	cfg := testConfig(t, true, false)
	cfg.Cache.Enabled = true
	cfg.UDPMaxConcurrent = 1
	cfg.Torrent.SearchTimeoutMs = 50
	s := searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: d})

	_ = s.Search(context.Background(), text("count"), false) // miss, live call, 1 row
	_ = s.Search(context.Background(), text("count"), false) // hit, 1 row
	s.udpSlots <- struct{}{}
	_ = s.Search(context.Background(), text("count"), true) // slots full: skipped, cache hit, 1 row
	_ = s.Search(context.Background(), text("other"), true) // slots full: skipped, nothing cached
	<-s.udpSlots

	d.mu.Lock()
	d.searchErr = errors.New("boom")
	d.mu.Unlock()
	_ = s.Search(context.Background(), text("failing"), false) // miss, live call, error

	d.mu.Lock()
	d.searchErr, d.searchDelay = nil, time.Second
	d.mu.Unlock()
	_ = s.Search(context.Background(), text("slow"), false) // miss, live call, timeout

	st := s.Stats()[0]
	t.Logf("input: miss, hit, 2 UDP with slots full, error, timeout; output: tcp=%d udp=%d rows=%d live=%d errors=%d timeouts=%d hits=%d misses=%d udpSkipped=%d cacheEntries=%d",
		st.SearchesTCP, st.SearchesUDP, st.RowsServed, st.LiveCalls, st.LiveErrors, st.LiveTimeouts,
		st.CacheHits, st.CacheMisses, st.UDPSkipped, s.CacheEntries())
	want := NetworkStats{SearchesTCP: 4, SearchesUDP: 2, RowsServed: 3, LiveCalls: 3, LiveErrors: 1, LiveTimeouts: 1,
		CacheHits: 2, CacheMisses: 3, UDPSkipped: 2}
	got := NetworkStats{SearchesTCP: st.SearchesTCP, SearchesUDP: st.SearchesUDP, RowsServed: st.RowsServed,
		LiveCalls: st.LiveCalls, LiveErrors: st.LiveErrors, LiveTimeouts: st.LiveTimeouts,
		CacheHits: st.CacheHits, CacheMisses: st.CacheMisses, UDPSkipped: st.UDPSkipped}
	if got != want {
		t.Errorf("counters %+v, want %+v", got, want)
	}
	if s.CacheEntries() != 1 {
		t.Errorf("cache entries=%d, want 1 (failures are not cached)", s.CacheEntries())
	}
}
