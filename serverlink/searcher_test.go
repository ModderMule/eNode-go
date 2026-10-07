package serverlink

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enode/storage"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
)

// TestSearcherAsksPeersLive: a search is answered by the peers, each file once
// with the larger counts and no source, a repeat comes from the cache, and a UDP
// search calls nobody.
func TestSearcherAsksPeersLive(t *testing.T) {
	a := startService(t, nil)
	b := startService(t, nil)
	// Peer b's users share one of the files more widely, and one file a lacks.
	extra := storage.ClientInfo{ID: 0x77000001, IPv4: 0x01000077, Port: 4700, Hash: []byte("user-hash-ddddd4")}
	id, err := b.engine.Connect(extra)
	if err != nil {
		t.Fatal(err)
	}
	extra.StoreID = id
	b.engine.AddFile(storage.File{Hash: []byte("file-hash-000001"), Name: "linux.distro0001.iso", Size: 1001, Type: "Pro"}, extra)
	b.engine.AddFile(storage.File{Hash: []byte("file-hash-only-b"), Name: "linux.only.on.b.iso", Size: 9000, Type: "Pro"}, extra)

	s := NewSearcher(liveConfig(a.peer(testToken), b.peer(testToken)))
	expr := textExpr("linux")

	rows := s.Search(context.Background(), expr, false)
	t.Logf("input:  %q asked of two peers holding the same ten files, one of them an eleventh", "linux")
	t.Logf("output: %v", describe(rows))
	if len(rows) != 11 {
		t.Fatalf("%d files, want 11 distinct ones", len(rows))
	}
	for _, f := range rows {
		if f.SourceID != 0 || f.SourcePort != 0 || f.Meta != nil {
			t.Errorf("%s carries a source or a meta block", f.Name)
		}
	}
	if f := find(rows, "linux.distro0001.iso"); f.Sources != 2 {
		t.Errorf("distro0001 has %d sources, want 2: the larger count, not the sum of 1 and 2", f.Sources)
	}

	again := s.Search(context.Background(), expr, false)
	calls := int64(0)
	for _, st := range s.Stats() {
		calls += st.LiveCalls
	}
	t.Logf("input:  the same search again")
	t.Logf("output: %d files, %d live calls in all", len(again), calls)
	if len(again) != 11 || calls != 2 {
		t.Errorf("repeat: %d files and %d calls, want 11 files and still 2 calls", len(again), calls)
	}

	udp := s.Search(context.Background(), textExpr("distro0002"), true)
	t.Logf("input:  a UDP search with no mirror")
	t.Logf("output: %d files", len(udp))
	if len(udp) != 0 {
		t.Errorf("a UDP search called a peer: %v", describe(udp))
	}
}

// TestSearcherPostFiltersWithTheTree: the request sent to a peer is narrower
// than the search tree, so the tree decides what comes back.
func TestSearcherPostFiltersWithTheTree(t *testing.T) {
	a := startService(t, nil)
	s := NewSearcher(liveConfig(a.peer(testToken)))

	// linux AND (distro0001 OR distro0002): the OR cannot be forwarded.
	expr := &storage.SearchExpr{Kind: storage.SearchAnd, Left: textExpr("linux"),
		Right: &storage.SearchExpr{Kind: storage.SearchOr, Left: textExpr("distro0001"), Right: textExpr("distro0002")}}
	rows := s.Search(context.Background(), expr, false)
	t.Logf("input:  linux AND (distro0001 OR distro0002)")
	t.Logf("output: %v", describe(rows))
	if len(rows) != 2 {
		t.Fatalf("%d files, want the two the tree matches", len(rows))
	}
}

// TestSearcherPausesAPeerThatRefuses: a peer that answers unauthenticated is
// left alone for a while instead of being asked on every search.
func TestSearcherPausesAPeerThatRefuses(t *testing.T) {
	a := startService(t, nil)
	s := NewSearcher(liveConfig(a.peer("not-the-token")))

	for i := range 3 {
		rows := s.Search(context.Background(), textExpr("linux", "attempt", string(rune('a'+i))), false)
		if len(rows) != 0 {
			t.Fatalf("a refused peer answered: %v", describe(rows))
		}
	}
	st := s.Stats()[0]
	t.Logf("input:  three different searches of a peer that refuses the token")
	t.Logf("output: %d calls, down=%t, last error %q", st.LiveCalls, st.Down, st.LastError)
	if st.LiveCalls != 1 || !st.Down || !strings.Contains(st.LastError, "unauthenticated") {
		t.Errorf("calls=%d down=%t error=%q, want one call, down, unauthenticated", st.LiveCalls, st.Down, st.LastError)
	}
}

// TestMirrorFollowsThePeer: the mirror fills from a walk, answers searches
// without calling the peer, and loses a file once a later walk completes without it.
func TestMirrorFollowsThePeer(t *testing.T) {
	a := startService(t, func(cfg *ServiceConfig) { cfg.BrowseMinInterval = 0 })
	cfg := mirrorConfig(a.peer(testToken))
	cfg.Live = true
	s := NewSearcher(cfg)
	stop := s.Start(context.Background())
	defer stop()

	waitFor(t, "the first walk", func() bool { return s.Stats()[0].Mirrored })
	st := s.Stats()[0]
	t.Logf("input:  a peer with 11 shared files, walked in pages of 4")
	t.Logf("output: mirrored=%t files=%d name=%q walks=%d", st.Mirrored, st.MirrorFiles, st.Name, st.Walks)
	if st.MirrorFiles != 11 || s.MirrorFiles() != 11 || st.Name != "test-server" || st.MirrorTrimmed {
		t.Fatalf("unexpected mirror state: %+v", st)
	}

	for _, udp := range []bool{false, true} {
		rows := s.Search(context.Background(), textExpr("linux"), udp)
		t.Logf("input:  %q, udp=%t", "linux", udp)
		t.Logf("output: %d files", len(rows))
		if len(rows) != 10 {
			t.Errorf("udp=%t: %d files from the mirror, want 10", udp, len(rows))
		}
	}
	if calls := s.Stats()[0].LiveCalls; calls != 0 {
		t.Errorf("%d live calls: a mirrored peer must not be called on a search", calls)
	}

	// The second client leaves: the even files drop to one source, and the song's
	// only sharer stays. Then the first leaves too and nothing is shared.
	a.engine.Disconnect(a.clients[1])
	waitFor(t, "the counts to follow", func() bool {
		return find(s.Search(context.Background(), textExpr("distro0002"), true), "linux.distro0002.iso").Sources == 1
	})
	a.engine.Disconnect(a.clients[0])
	waitFor(t, "the files to leave", func() bool { return s.MirrorFiles() == 0 })
	rows := s.Search(context.Background(), textExpr("linux"), true)
	t.Logf("input:  every client of the peer has left")
	t.Logf("output: %d files in the mirror, %d found", s.MirrorFiles(), len(rows))
	if len(rows) != 0 {
		t.Errorf("the mirror still answers for files the peer no longer has: %v", describe(rows))
	}
}

// TestWalkRetryBacksOff: a failed walk is tried again after ten seconds, then
// after twice as long for every further failure, and never later than walkRetry.
func TestWalkRetryBacksOff(t *testing.T) {
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		got := walkRetryAfter(i + 1)
		t.Logf("input:  %d failed walks in a row", i+1)
		t.Logf("output: next walk after %s", got)
		if got != w {
			t.Errorf("after %d failures: wait %s, want %s", i+1, got, w)
		}
	}
	if got := walkRetryAfter(1000); got != walkRetry {
		t.Errorf("after 1000 failures: wait %s, want %s", got, walkRetry)
	}
}

// TestMirrorThatIsFullDoesNotAnswerAlone: a mirror too small for a peer's
// catalogue says so, and the peer is still asked on a search.
func TestMirrorThatIsFullDoesNotAnswerAlone(t *testing.T) {
	a := startService(t, func(cfg *ServiceConfig) { cfg.BrowseMinInterval = 0 })
	cfg := mirrorConfig(a.peer(testToken))
	cfg.MaxFiles = 3
	cfg.Live = true
	s := NewSearcher(cfg)
	stop := s.Start(context.Background())
	defer stop()

	waitFor(t, "the first walk", func() bool { return s.Stats()[0].Walks > 0 })
	st := s.Stats()[0]
	rows := s.Search(context.Background(), textExpr("linux"), false)
	t.Logf("input:  a mirror of 3 files for a peer with 11")
	t.Logf("output: mirrored=%t trimmed=%t held=%d; a search finds %d", st.Mirrored, st.MirrorTrimmed, s.MirrorFiles(), len(rows))
	if st.Mirrored || !st.MirrorTrimmed || s.MirrorFiles() != 3 {
		t.Errorf("mirrored=%t trimmed=%t held=%d, want false, true, 3", st.Mirrored, st.MirrorTrimmed, s.MirrorFiles())
	}
	if len(rows) != 10 {
		t.Errorf("%d files, want all 10: the peer is asked because the mirror is partial", len(rows))
	}
}

// TestMirrorRestartsOnReset: a reset in the middle of a walk restarts it, and
// what the abandoned attempt read is not taken for the whole catalogue.
func TestMirrorRestartsOnReset(t *testing.T) {
	a := startService(t, func(cfg *ServiceConfig) { cfg.BrowseMinInterval = 0 })
	cfg := mirrorConfig(a.peer(testToken))
	var resetting *resetOnce
	cfg.NewClient = func(c ClientConfig) metav1connect.ServerSearchClient {
		resetting = &resetOnce{ServerSearchClient: NewClient(c), onCall: 2}
		return resetting
	}
	s := NewSearcher(cfg)
	stop := s.Start(context.Background())
	defer stop()

	waitFor(t, "the walk to complete", func() bool { return s.Stats()[0].Mirrored })
	st := s.Stats()[0]
	t.Logf("input:  a peer that answers reset to the second browse call")
	t.Logf("output: resets=%d walks=%d files=%d browse calls=%d", st.Resets, st.Walks, st.MirrorFiles, resetting.calls.Load())
	if st.Resets != 1 || st.MirrorFiles != 11 || s.MirrorFiles() != 11 {
		t.Errorf("resets=%d files=%d held=%d, want 1, 11, 11", st.Resets, st.MirrorFiles, s.MirrorFiles())
	}
}

// TestDiscoveredPeersComeAndGo: a peer that discovery stops returning is no
// longer asked, and its mirrored files go with it.
func TestDiscoveredPeersComeAndGo(t *testing.T) {
	a := startService(t, func(cfg *ServiceConfig) {
		cfg.BrowseMinInterval = 0
		cfg.Verified = func(ip net.IP) bool { return ip.IsLoopback() }
	})
	var mu sync.Mutex
	advertised := []ClientConfig{{URL: a.url}}
	cfg := mirrorConfig()
	cfg.DiscoverEvery = 20 * time.Millisecond
	cfg.Discover = func() []ClientConfig {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(advertised)
	}
	s := NewSearcher(cfg)
	stop := s.Start(context.Background())
	defer stop()

	waitFor(t, "the discovered peer to be mirrored", func() bool {
		st := s.Stats()
		return len(st) == 1 && st[0].Mirrored
	})
	st := s.Stats()[0]
	t.Logf("input:  discovery returns one peer, called without a token")
	t.Logf("output: static=%t mirrored=%t files=%d", st.Static, st.Mirrored, st.MirrorFiles)
	if st.Static || s.MirrorFiles() != 11 {
		t.Fatalf("static=%t held=%d", st.Static, s.MirrorFiles())
	}

	mu.Lock()
	advertised = nil
	mu.Unlock()
	waitFor(t, "the peer to be dropped", func() bool { return len(s.Stats()) == 0 && s.MirrorFiles() == 0 })
	t.Logf("input:  discovery no longer returns it")
	t.Logf("output: %d peers, %d mirrored files", len(s.Stats()), s.MirrorFiles())
}

// -- internals ---------------------------------------------------------------

// peer is the fixture as another server would configure it.
func (fx *fixture) peer(token string) ClientConfig {
	return ClientConfig{URL: fx.url, Token: token}
}

func liveConfig(peers ...ClientConfig) SearcherConfig {
	return SearcherConfig{
		Peers: peers, Live: true, Timeout: 5 * time.Second, MaxResults: 50,
		CacheEntries: 100, CacheTTL: time.Minute,
	}
}

func mirrorConfig(peers ...ClientConfig) SearcherConfig {
	return SearcherConfig{
		Peers: peers, Timeout: 5 * time.Second, MaxResults: 50,
		CacheEntries: 100, CacheTTL: time.Minute,
		Mirror: true, Interval: 30 * time.Millisecond, MaxFiles: 1000, PageSize: 4, Stale: time.Hour,
	}
}

func textExpr(words ...string) *storage.SearchExpr {
	return &storage.SearchExpr{Kind: storage.SearchText, Text: strings.Join(words, " ")}
}

func describe(files []storage.File) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Name)
	}
	slices.Sort(out)
	return out
}

func find(files []storage.File, name string) storage.File {
	for _, f := range files {
		if f.Name == name {
			return f
		}
	}
	return storage.File{}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// resetOnce answers reset to the onCall-th BrowseFiles call, as a server whose
// index was rebuilt under the walk would.
type resetOnce struct {
	metav1connect.ServerSearchClient
	onCall int64
	calls  atomic.Int64
}

func (r *resetOnce) BrowseFiles(ctx context.Context, req *metav1.BrowseFilesRequest) (*metav1.BrowseFilesResponse, error) {
	if r.calls.Add(1) == r.onCall {
		return &metav1.BrowseFilesResponse{Reset_: true}, nil
	}
	return r.ServerSearchClient.BrowseFiles(ctx, req)
}
