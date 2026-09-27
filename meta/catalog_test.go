package meta

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"enode/config"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectinprocess"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
)

// pagingDaemon answers Search with offset/limit paging over a fixed list of
// releases, capping each page at pageCap releases, as a real daemon does.
type pagingDaemon struct {
	metav1connect.UnimplementedMetaIngestHandler

	mu       sync.Mutex
	releases [][]*metav1.MetaEntry
	pageCap  int
	window   int
	err      error
	searches []*metav1.SearchRequest
}

func (d *pagingDaemon) Search(_ context.Context, req *metav1.SearchRequest) (*metav1.SearchResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.searches = append(d.searches, req)
	if d.err != nil {
		return nil, d.err
	}
	window := min(len(d.releases), d.window)
	start := min(int(req.GetOffset()), window)
	n := int(req.GetLimit())
	if d.pageCap > 0 {
		n = min(n, d.pageCap)
	}
	end := min(start+n, window)
	resp := &metav1.SearchResponse{Total: uint64(len(d.releases)), TotalExact: true}
	for _, rel := range d.releases[start:end] {
		resp.Entries = append(resp.Entries, rel...)
	}
	if end < window {
		resp.NextOffset = uint32(end)
	}
	return resp, nil
}

func (d *pagingDaemon) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.searches)
}

func (d *pagingDaemon) client() metav1connect.MetaIngestClient {
	server := connect.NewServer()
	metav1connect.RegisterMetaIngestHandler(server, d)
	return metav1connect.NewMetaIngestClient(connect.NewClient(connectinprocess.New(server)))
}

// torrentReleases returns n single-file torrent releases named prefix-0 … prefix-n-1.
func torrentReleases(prefix string, n int) [][]*metav1.MetaEntry {
	out := make([][]*metav1.MetaEntry, n)
	for i := range out {
		out[i] = []*metav1.MetaEntry{torrentEntry(fmt.Sprintf("%s-%d", prefix, i), 10)}
	}
	return out
}

// multiFileRelease is a two-file torrent: the whole-set row and one row per file.
func multiFileRelease(name string) []*metav1.MetaEntry {
	id := sha1.Sum([]byte(name))
	row := func(index uint32, path string, size uint64) *metav1.MetaEntry {
		return &metav1.MetaEntry{
			Kind: metav1.MetaKind_META_KIND_BT_V1, FileIndex: index, FilePath: path, Name: name,
			Size: size, TotalSize: 300, Type: "Video", Seeders: 5, Indexer: "dht",
			CatalogId: fmt.Sprintf("bt:v1:%X", id), Identity: id[:], FileCount: 2,
		}
	}
	return []*metav1.MetaEntry{row(0xFFFFFFFF, "", 300), row(0, name+"/a.mkv", 100), row(1, name+"/b.mkv", 200)}
}

func catalogSearcher(t *testing.T, torrent, usenet *pagingDaemon) *Searcher {
	t.Helper()
	cfg := testConfig(t, torrent != nil, usenet != nil)
	s := NewWithClients(cfg, func(network string, _ config.MetaNetworkConfig) metav1connect.MetaIngestClient {
		if network == NetworkTorrent {
			return torrent.client()
		}
		return usenet.client()
	})
	s.EnableCatalog(CatalogConfig{Timeout: time.Second, MaxEntries: 100, TTL: time.Minute})
	return s
}

func TestSearchCatalogChunksAndCaches(t *testing.T) {
	d := &pagingDaemon{releases: torrentReleases("ubuntu", 250), window: 1000}
	s := catalogSearcher(t, d, nil)
	req := &metav1.SearchRequest{Query: "Ubuntu ISO", Limit: 7, Offset: 3}

	for k, want := range []int{100, 100, 50} {
		chunk, err := s.SearchCatalog(context.Background(), NetworkTorrent, req, k)
		t.Logf("input: chunk %d; output: releases=%d total=%d exact=%t more=%t err=%v", k, len(chunk.Releases), chunk.Total, chunk.TotalExact, chunk.More, err)
		if err != nil || len(chunk.Releases) != want || chunk.Total != 250 || !chunk.TotalExact {
			t.Fatalf("chunk %d: %d releases total %d err %v, want %d of 250", k, len(chunk.Releases), chunk.Total, err, want)
		}
		if first := chunk.Releases[0][0].GetName(); first != fmt.Sprintf("ubuntu-%d", k*ChunkSize) {
			t.Fatalf("chunk %d starts at %s", k, first)
		}
		if len(chunk.Releases[0][0].GetMetaHash()) != 16 {
			t.Fatalf("entry has no minted meta_hash")
		}
		if (k < 2) != chunk.More {
			t.Fatalf("chunk %d more=%t", k, chunk.More)
		}
	}
	calls := d.calls()
	// The same search in another case and word order, another page: served from cache.
	_, err := s.SearchCatalog(context.Background(), NetworkTorrent, &metav1.SearchRequest{Query: "iso  ubuntu", Limit: 50}, 1)
	t.Logf("input: normalized repeat of chunk 1; output: daemon calls %d -> %d err=%v", calls, d.calls(), err)
	if err != nil || d.calls() != calls {
		t.Fatalf("repeat was not a cache hit: calls %d -> %d", calls, d.calls())
	}
	if got := d.searches[0]; got.GetOffset() != 0 || got.GetLimit() != ChunkSize || got.GetQuery() != "iso ubuntu" {
		t.Fatalf("daemon request %v, want offset 0 limit %d normalized query", got, ChunkSize)
	}
	st := s.Stats()[0]
	if st.CatalogCalls != 3 || st.CatalogCacheHits != 1 {
		t.Fatalf("counters calls=%d hits=%d, want 3 and 1", st.CatalogCalls, st.CatalogCacheHits)
	}
}

func TestSearchCatalogFollowsDaemonPageCap(t *testing.T) {
	d := &pagingDaemon{releases: torrentReleases("x", 180), pageCap: 40, window: 1000}
	s := catalogSearcher(t, d, nil)
	chunk, err := s.SearchCatalog(context.Background(), NetworkTorrent, &metav1.SearchRequest{Query: "x"}, 0)
	var offsets []uint32
	for _, r := range d.searches {
		offsets = append(offsets, r.GetOffset())
	}
	t.Logf("input: daemon caps pages at 40; output: releases=%d more=%t offsets=%v err=%v", len(chunk.Releases), chunk.More, offsets, err)
	if err != nil || len(chunk.Releases) != ChunkSize || !chunk.More || fmt.Sprint(offsets) != "[0 40 80]" {
		t.Fatalf("chunk %d more %t offsets %v", len(chunk.Releases), chunk.More, offsets)
	}
	next, _ := s.SearchCatalog(context.Background(), NetworkTorrent, &metav1.SearchRequest{Query: "x"}, 1)
	if len(next.Releases) != 80 || next.Releases[0][0].GetName() != "x-100" || next.More {
		t.Fatalf("chunk 1: %d releases from %s more %t", len(next.Releases), next.Releases[0][0].GetName(), next.More)
	}
}

func TestSearchCatalogGroupsReleasesAndDropsBadRows(t *testing.T) {
	bad := torrentEntry("broken", 1)
	bad.Identity = []byte{1, 2, 3}
	d := &pagingDaemon{window: 1000, releases: [][]*metav1.MetaEntry{
		multiFileRelease("season"), {bad}, {torrentEntry("single", 3)},
	}}
	s := catalogSearcher(t, d, nil)
	chunk, err := s.SearchCatalog(context.Background(), NetworkTorrent, &metav1.SearchRequest{Query: "s"}, 0)
	var sizes []int
	for _, r := range chunk.Releases {
		sizes = append(sizes, len(r))
	}
	t.Logf("input: multi-file release, invalid row, single; output: release sizes %v err=%v", sizes, err)
	if err != nil || fmt.Sprint(sizes) != "[3 1]" {
		t.Fatalf("release sizes %v, want [3 1]", sizes)
	}
}

func TestSearchCatalogNetworksAndErrors(t *testing.T) {
	d := &pagingDaemon{window: 1000, err: connect.NewError(connect.CodeUnavailable, "down")}
	s := catalogSearcher(t, d, nil)
	t.Logf("input: torrent only; output: networks=%v", s.CatalogNetworks())
	if fmt.Sprint(s.CatalogNetworks()) != "[torrent]" {
		t.Fatalf("networks %v", s.CatalogNetworks())
	}
	if _, err := s.SearchCatalog(context.Background(), NetworkUsenet, &metav1.SearchRequest{Query: "a"}, 0); !errors.Is(err, ErrNetworkDisabled) {
		t.Fatalf("disabled network: %v", err)
	}
	_, err := s.SearchCatalog(context.Background(), NetworkTorrent, &metav1.SearchRequest{Query: "a"}, 0)
	_, again := s.SearchCatalog(context.Background(), NetworkTorrent, &metav1.SearchRequest{Query: "b"}, 0)
	t.Logf("input: daemon unavailable twice; output: %v then %v (calls %d)", err, again, d.calls())
	if connect.CodeOf(err) != connect.CodeUnavailable || !errors.Is(again, ErrNetworkDown) || d.calls() != 1 {
		t.Fatalf("errors %v / %v calls %d, want unavailable then paused", err, again, d.calls())
	}

	off := NewWithClients(testConfig(t, true, false), func(string, config.MetaNetworkConfig) metav1connect.MetaIngestClient { return d.client() })
	if _, err := off.SearchCatalog(context.Background(), NetworkTorrent, &metav1.SearchRequest{Query: "a"}, 0); !errors.Is(err, ErrCatalogOff) {
		t.Fatalf("without EnableCatalog: %v", err)
	}
}

func TestMintEntryMatchesEntryToFile(t *testing.T) {
	pb := torrentEntry("mint", 4)
	entry, err := MintEntry(pb)
	file, ferr := EntryToFile(pb)
	t.Logf("input: %s; output: meta_hash=%x file hash=%x errs=%v/%v", pb.GetName(), entry.GetMetaHash(), file.Hash, err, ferr)
	if err != nil || ferr != nil || string(entry.GetMetaHash()) != string(file.Hash) {
		t.Fatalf("MintEntry and EntryToFile disagree")
	}
	if len(pb.GetMetaHash()) != 0 {
		t.Fatalf("MintEntry modified its input")
	}
}
