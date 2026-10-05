package meta

import (
	"context"
	"strings"
	"testing"
	"time"

	"enode/storage"

	"connectrpc.com/connect/v2"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
)

// TestSearchMergesNetworksWithPrefixes: each network's rows carry its own prefix, the
// query reaches each daemon as keywords, and the prefix is not itself searchable.
func TestSearchMergesNetworksWithPrefixes(t *testing.T) {
	torrent := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("Night.Of.The.Torrent.Living.mkv", 12)}}
	usenet := &fakeDaemon{entries: []*metav1.MetaEntry{nzbEntry("Night.Of.The.Living.Dead.1968")}}
	s := searcherFor(testConfig(t, true, true), map[string]*fakeDaemon{NetworkTorrent: torrent, NetworkUsenet: usenet})

	got := s.Search(context.Background(), node(storage.SearchAnd, text("night"), text("living")), false, false)
	t.Logf("input: night AND living; output: %s", fileNames(got))
	t.Logf("daemon requests: torrent=%v usenet=%v", torrent.searches, usenet.searches)
	if len(got) != 2 {
		t.Fatalf("got %d rows, want one per network", len(got))
	}
	if !strings.HasPrefix(got[0].Name, "[torrent] ") || !strings.HasPrefix(got[1].Name, "[usenet] ") {
		t.Fatalf("names %q / %q lack their network prefix", got[0].Name, got[1].Name)
	}
	if q := torrent.searches[0].GetQuery(); q != "night living" {
		t.Fatalf("forwarded query %q, want the keywords", q)
	}

	// "torrent" only appears in one release's own name; the prefix on every torrent
	// row must not make them all match.
	got = s.Search(context.Background(), text("torrent"), false, false)
	t.Logf("input: torrent; output: %s", fileNames(got))
	if len(got) != 1 || !strings.Contains(got[0].Name, "Torrent.Living") {
		t.Fatalf("got %s, want only the release whose own name says torrent", fileNames(got))
	}
}

// TestSearchPostFiltersDaemonRows: the daemon answers a widened query, and the full
// tree — here an extension constraint the request cannot carry — decides.
func TestSearchPostFiltersDaemonRows(t *testing.T) {
	d := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("song.flac", 5), torrentEntry("song.mp3", 5)}}
	s := searcherFor(testConfig(t, true, false), map[string]*fakeDaemon{NetworkTorrent: d})

	got := s.Search(context.Background(), node(storage.SearchAnd, text("song"), tagString(storage.SearchExtTag, "mp3")), false, false)
	t.Logf("input: song AND ext=mp3, daemon returns flac+mp3; output: %s", fileNames(got))
	if len(got) != 1 || !strings.HasSuffix(got[0].Name, "song.mp3") {
		t.Fatalf("got %s, want only the mp3", fileNames(got))
	}
}

// TestSearchHonoursDeadline: a daemon slower than the deadline costs the deadline and
// contributes nothing.
func TestSearchHonoursDeadline(t *testing.T) {
	d := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("slow.mkv", 1)}, searchDelay: 2 * time.Second}
	cfg := testConfig(t, true, false)
	cfg.Torrent.SearchTimeoutMs = 80
	s := searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: d})

	start := time.Now()
	got := s.Search(context.Background(), text("slow"), false, false)
	elapsed := time.Since(start)
	t.Logf("input: daemon delay 2s, deadline 80ms; output: rows=%d after %s", len(got), elapsed)
	if len(got) != 0 {
		t.Fatalf("got %d rows from a daemon past its deadline", len(got))
	}
	if elapsed > time.Second {
		t.Fatalf("search took %s, the deadline was 80ms", elapsed)
	}
}

// TestSearchCapsPerNetworkAndPerTransport: maxResults bounds a TCP answer and the
// smaller maxUDPResults a UDP one.
func TestSearchCapsPerNetworkAndPerTransport(t *testing.T) {
	var entries []*metav1.MetaEntry
	for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
		entries = append(entries, torrentEntry("cap."+n+".mkv", 1))
	}
	d := &fakeDaemon{entries: entries}
	cfg := testConfig(t, true, false)
	cfg.Torrent.MaxResults, cfg.Torrent.MaxUDPResults = 4, 2
	s := searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: d})

	tcp := s.Search(context.Background(), text("cap"), false, false)
	udp := s.Search(context.Background(), text("cap"), true, false)
	t.Logf("input: 6 matching rows, maxResults=4 maxUDPResults=2; output: tcp=%d udp=%d", len(tcp), len(udp))
	if len(tcp) != 4 || len(udp) != 2 {
		t.Fatalf("tcp=%d udp=%d, want 4/2", len(tcp), len(udp))
	}
}

// TestSearchUDPSlotsExhausted: with every UDP slot taken, a UDP search makes no live
// call at all rather than queueing a pool worker behind the daemon.
func TestSearchUDPSlotsExhausted(t *testing.T) {
	d := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("busy.mkv", 1)}}
	cfg := testConfig(t, true, false)
	cfg.UDPMaxConcurrent = 1
	s := searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: d})
	s.udpSlots <- struct{}{} // the one slot is in use

	udp := s.Search(context.Background(), text("busy"), true, false)
	tcp := s.Search(context.Background(), text("busy"), false, false)
	t.Logf("input: udp slots full; output: udpRows=%d tcpRows=%d daemonCalls=%d", len(udp), len(tcp), d.searchCount())
	if len(udp) != 0 || d.searchCount() != 1 || len(tcp) != 1 {
		t.Fatalf("udp=%d tcp=%d calls=%d: UDP must skip the live call, TCP must not", len(udp), len(tcp), d.searchCount())
	}
}

// TestSearchUsesCache: a repeat query is answered from the cache, and a full UDP slot
// pool still gets the cached answer.
func TestSearchUsesCache(t *testing.T) {
	d := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("cached.mkv", 1)}}
	cfg := testConfig(t, true, false)
	cfg.Cache.Enabled = true
	cfg.UDPMaxConcurrent = 1
	s := searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: d})

	first := s.Search(context.Background(), text("cached"), false, false)
	second := s.Search(context.Background(), text("CACHED"), false, false)
	s.udpSlots <- struct{}{}
	udp := s.Search(context.Background(), text("cached"), true, false)
	t.Logf("input: same query x3 (TCP, TCP differently cased, UDP with slots full); output: rows=%d/%d/%d daemonCalls=%d",
		len(first), len(second), len(udp), d.searchCount())
	if d.searchCount() != 1 || len(second) != 1 || len(udp) != 1 {
		t.Fatalf("calls=%d second=%d udp=%d, want one call and cache hits", d.searchCount(), len(second), len(udp))
	}
}

// TestSearchPausesUnavailableDaemon: an answer that will not change on the next search
// (no search index here) pauses live calls instead of repeating them per search.
func TestSearchPausesUnavailableDaemon(t *testing.T) {
	d := &fakeDaemon{searchErr: connect.NewError(connect.CodeUnimplemented, "no search index")}
	s := searcherFor(testConfig(t, true, false), map[string]*fakeDaemon{NetworkTorrent: d})

	_ = s.Search(context.Background(), text("one"), false, false)
	_ = s.Search(context.Background(), text("two"), false, false)
	t.Logf("input: daemon answers unimplemented, two searches; output: daemonCalls=%d", d.searchCount())
	if d.searchCount() != 1 {
		t.Fatalf("daemon was asked %d times, want 1 then a pause", d.searchCount())
	}
}

// TestSearchWithoutKeywordsMakesNoCall: a tree with no forwardable keyword (an OR at
// the root) never reaches the daemon.
func TestSearchWithoutKeywordsMakesNoCall(t *testing.T) {
	d := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("x.mkv", 1)}}
	s := searcherFor(testConfig(t, true, false), map[string]*fakeDaemon{NetworkTorrent: d})
	got := s.Search(context.Background(), node(storage.SearchOr, text("x"), text("y")), false, false)
	t.Logf("input: x OR y; output: rows=%d daemonCalls=%d", len(got), d.searchCount())
	if d.searchCount() != 0 {
		t.Fatalf("daemon asked %d times for a query with no required keyword", d.searchCount())
	}
}

// TestSearchFeedAndLiveDeduplicate: a release held by the feed and returned live is
// sent once, and the feed alone fills a quota without a live call.
func TestSearchFeedAndLiveDeduplicate(t *testing.T) {
	shared := torrentEntry("shared.release.mkv", 40)
	d := &fakeDaemon{entries: []*metav1.MetaEntry{shared, torrentEntry("shared.other.mkv", 1)}}
	cfg := testConfig(t, true, false)
	cfg.Torrent.Feed.Enabled = true
	s := searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: d})
	s.sources[0].feed.apply(&metav1.SubscribeResponse{Changes: []*metav1.ReleaseChange{upsert(1, shared)}, Cursor: 1})

	got := s.Search(context.Background(), text("shared"), false, false)
	t.Logf("input: feed holds shared.release, live returns it plus shared.other; output: %s", fileNames(got))
	if len(got) != 2 {
		t.Fatalf("got %s, want the shared release once plus the other", fileNames(got))
	}

	cfg.Torrent.MaxResults = 1
	s = searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: d})
	s.sources[0].feed.apply(&metav1.SubscribeResponse{Changes: []*metav1.ReleaseChange{upsert(1, shared)}, Cursor: 1})
	before := d.searchCount()
	got = s.Search(context.Background(), text("shared"), false, false)
	t.Logf("input: maxResults=1 and the feed matches; output: %s daemonCalls=%d", fileNames(got), d.searchCount()-before)
	if len(got) != 1 || d.searchCount() != before {
		t.Fatalf("a full quota from the feed still called the daemon")
	}
}

// TestSearchMatchesSubFiles: the daemon returns every row of a release it found by
// name or by path; a file row is kept when "Release - path" matches and the release's
// own row does not, and the release's own row alone stands for a release it matches.
func TestSearchMatchesSubFiles(t *testing.T) {
	entries := packEntries(torrentEntry("Foo.Season.1", 50), "Disc1/S01E01.mkv", "Disc1/S01E02.mkv")
	entries = append(entries, torrentEntry("Other.S01E01.Show.mkv", 5))
	d := &fakeDaemon{entries: entries}
	s := searcherFor(testConfig(t, true, false), map[string]*fakeDaemon{NetworkTorrent: d})

	for _, tc := range []struct {
		name string
		expr *storage.SearchExpr
		want []string
	}{
		{"release name", text("foo"), []string{"[torrent] Foo.Season.1"}},
		{"file name", text("s01e01"), []string{"[torrent] Foo.Season.1 - Disc1/S01E01.mkv", "[torrent] Other.S01E01.Show.mkv"}},
		{"release and file", text("foo s01e01"), []string{"[torrent] Foo.Season.1 - Disc1/S01E01.mkv"}},
		{"folder", text("disc1"), []string{"[torrent] Foo.Season.1 - Disc1/S01E01.mkv", "[torrent] Foo.Season.1 - Disc1/S01E02.mkv"}},
		{"release name, ext excludes the whole set", node(storage.SearchAnd, text("foo"), tagString(storage.SearchExtTag, "mkv")),
			[]string{"[torrent] Foo.Season.1 - Disc1/S01E01.mkv", "[torrent] Foo.Season.1 - Disc1/S01E02.mkv"}},
	} {
		got := s.Search(context.Background(), tc.expr, false, false)
		t.Logf("input: %s; output: %s", tc.name, fileNames(got))
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %s, want %v", tc.name, fileNames(got), tc.want)
		}
		for i, name := range tc.want {
			if got[i].Name != name {
				t.Fatalf("%s: row %d named %q, want %q", tc.name, i, got[i].Name, name)
			}
		}
	}
}

// TestSearchKadNetwork: Kad rows come back with the configured prefix, a nativeOnly
// search asks the Kad daemon alone, an empty prefix sends the names bare, and Kad is
// a catalogue network of MetaApi.Search like the others.
func TestSearchKadNetwork(t *testing.T) {
	torrent := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("Night.Of.The.Torrent.mkv", 12)}}
	kad := &fakeDaemon{entries: []*metav1.MetaEntry{kadEntry("Night.Of.The.Living.Dead.avi", 40, 0)}}
	cfg := testConfig(t, true, false)
	cfg.Kad.Enabled = true
	prefix := "[kad emule-qt.org] "
	cfg.Kad.NamePrefix = &prefix
	s := searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: torrent, NetworkKad: kad})

	all := s.Search(context.Background(), text("night"), false, false)
	t.Logf("input: night, every network; output: %s", fileNames(all))
	if len(all) != 2 || all[1].Name != prefix+"Night.Of.The.Living.Dead.avi" || !all[1].Meta.Native() {
		t.Fatalf("got %s, want the torrent row then the prefixed Kad row", fileNames(all))
	}

	native := s.Search(context.Background(), text("night"), false, true)
	t.Logf("input: night, nativeOnly; output: %s; daemon searches torrent=%d kad=%d",
		fileNames(native), torrent.searchCount(), kad.searchCount())
	if len(native) != 1 || !native[0].Meta.Native() {
		t.Fatalf("got %s, want the Kad row alone", fileNames(native))
	}
	if torrent.searchCount() != 1 {
		t.Fatalf("the torrent daemon was asked %d times, want only the first search", torrent.searchCount())
	}

	// "kad" is only in the prefix, which must not be searchable.
	if got := s.Search(context.Background(), text("emule-qt"), false, false); len(got) != 0 {
		t.Fatalf("the prefix matched a search: %s", fileNames(got))
	}
	nets := s.CatalogNetworks()
	t.Logf("input: torrent and kad enabled; output: catalogue networks %v", nets)
	if len(nets) != 2 || nets[0] != NetworkTorrent || nets[1] != NetworkKad {
		t.Fatalf("catalogue networks %v, want torrent then kad", nets)
	}

	bare := ""
	cfg.Kad.NamePrefix = &bare
	s = searcherFor(cfg, map[string]*fakeDaemon{NetworkTorrent: torrent, NetworkKad: kad})
	got := s.Search(context.Background(), text("night"), false, true)
	t.Logf("input: namePrefix \"\"; output: %s", fileNames(got))
	if len(got) != 1 || got[0].Name != "Night.Of.The.Living.Dead.avi" {
		t.Fatalf("got %s, want the bare name", fileNames(got))
	}
}

// TestKadIsOffByDefault: a config that enables the other networks builds no Kad
// source, so the Kad daemon is never contacted.
func TestKadIsOffByDefault(t *testing.T) {
	kad := &fakeDaemon{entries: []*metav1.MetaEntry{kadEntry("Night.Of.The.Living.Dead.avi", 40, 0)}}
	torrent := &fakeDaemon{}
	s := searcherFor(testConfig(t, true, true), map[string]*fakeDaemon{NetworkTorrent: torrent, NetworkUsenet: torrent, NetworkKad: kad})

	got := s.Search(context.Background(), text("night"), false, false)
	native := s.Search(context.Background(), text("night"), false, true)
	t.Logf("input: torrent+usenet enabled, kad not set; output: networks=%v rows=%d nativeRows=%d kadSearches=%d",
		s.Networks(), len(got), len(native), kad.searchCount())
	if len(got) != 0 || len(native) != 0 || kad.searchCount() != 0 {
		t.Fatalf("rows=%d nativeRows=%d kadSearches=%d, want none", len(got), len(native), kad.searchCount())
	}
	for _, n := range s.Networks() {
		if n == NetworkKad {
			t.Fatal("kad is listed although it was never enabled")
		}
	}
}
