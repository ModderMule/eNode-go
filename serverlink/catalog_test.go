package serverlink

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"enode/meta"
	"enode/storage"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"google.golang.org/protobuf/proto"
)

// TestCatalogMergesOwnAndPeerFiles: the servers network of MetaApi.Search is this
// server's files and the other servers', each file once. The server's own row
// wins, with its own counts.
func TestCatalogMergesOwnAndPeerFiles(t *testing.T) {
	peer := startService(t, nil)
	// The peer's users share distro0001 more widely than this server's, and one
	// file this server lacks.
	extra := storage.ClientInfo{ID: 0x77000001, IPv4: 0x01000077, Port: 4700, Hash: []byte("user-hash-ddddd4")}
	id, err := peer.engine.Connect(extra)
	if err != nil {
		t.Fatal(err)
	}
	extra.StoreID = id
	peer.engine.AddFile(storage.File{Hash: []byte("file-hash-000001"), Name: "linux.distro0001.iso", Size: 1001, Type: "Pro"}, extra)
	peer.engine.AddFile(storage.File{Hash: []byte("file-hash-only-p"), Name: "linux.only.on.peer.iso", Size: 9000, Type: "Pro"}, extra)

	own, _ := seedEngine(t)
	s := NewSearcher(liveConfig(peer.peer(testToken)))
	s.EnableCatalog(catalogConfig(own))

	req := &metav1.SearchRequest{Query: "linux"}
	chunk, err := s.SearchCatalog(context.Background(), req, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input:  %q; this server shares ten linux files, the peer the same ten and an eleventh", req.Query)
	t.Logf("output: total=%d exact=%t more=%t %v", chunk.Total, chunk.TotalExact, chunk.More, describeReleases(chunk.Releases))
	if len(chunk.Releases) != 11 || chunk.Total != 11 || !chunk.TotalExact || chunk.More {
		t.Fatalf("%d releases, total %d, exact %t, more %t; want 11, 11, true, false", len(chunk.Releases), chunk.Total, chunk.TotalExact, chunk.More)
	}
	for _, release := range chunk.Releases {
		if len(release) != 1 {
			t.Fatalf("a release of %d entries; a file is one", len(release))
		}
		e := release[0]
		if e.GetKind() != metav1.MetaKind_META_KIND_ED2K || len(e.GetMetaHash()) != 16 ||
			!bytes.Equal(e.GetMetaHash(), e.GetIdentity()) || e.GetCatalogId() == "" || e.GetFileCount() != 1 {
			t.Errorf("%s is not shaped like a Kad row: %v", e.GetName(), e)
		}
	}
	if e := findEntry(chunk.Releases, "linux.distro0001.iso"); e.GetPeers() != 1 {
		t.Errorf("distro0001 has %d sources, want this server's 1 and not the peer's 2", e.GetPeers())
	}
	if e := findEntry(chunk.Releases, "linux.only.on.peer.iso"); e.GetPeers() != 1 {
		t.Errorf("the peer's own file has %d sources, want 1", e.GetPeers())
	}
	if first := chunk.Releases[0][0]; first.GetPeers() != 2 {
		t.Errorf("first is %s with %d sources; the most widely shared come first", first.GetName(), first.GetPeers())
	}

	again, err := s.SearchCatalog(context.Background(), &metav1.SearchRequest{Query: "LINUX", Limit: 5, Offset: 5}, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := s.Stats()[0].LiveCalls
	t.Logf("input:  the same search in another case and with paging fields")
	t.Logf("output: %d releases, %d calls to the peer in all", len(again.Releases), calls)
	if calls != 1 || !sameReleases(chunk.Releases, again.Releases) {
		t.Errorf("%d calls and a different answer; want the cached answer and 1 call", calls)
	}
}

// TestCatalogFiltersAndSorts: the request's filters and its size sort apply.
func TestCatalogFiltersAndSorts(t *testing.T) {
	own, _ := seedEngine(t)
	s := NewSearcher(SearcherConfig{})
	s.EnableCatalog(catalogConfig(own))

	cases := []struct {
		name string
		req  *metav1.SearchRequest
		want []string
	}{
		{"two sources at least", &metav1.SearchRequest{Query: "linux", MinSeeders: 2},
			[]string{"linux.distro0000.iso", "linux.distro0002.iso", "linux.distro0004.iso", "linux.distro0006.iso", "linux.distro0008.iso"}},
		{"a size range, largest first", &metav1.SearchRequest{Query: "linux", MinSize: 1003, MaxSize: 1005, Sort: metav1.SearchSort_SEARCH_SORT_SIZE},
			[]string{"linux.distro0005.iso", "linux.distro0004.iso", "linux.distro0003.iso"}},
		{"smallest first", &metav1.SearchRequest{Query: "linux", MaxSize: 1002, Sort: metav1.SearchSort_SEARCH_SORT_SIZE, SortAscending: true},
			[]string{"linux.distro0000.iso", "linux.distro0001.iso", "linux.distro0002.iso"}},
		{"an excluded word", &metav1.SearchRequest{Query: "linux", Exclude: []string{"distro0003"}, MinSize: 1003, MaxSize: 1004},
			[]string{"linux.distro0004.iso"}},
		{"a type", &metav1.SearchRequest{Query: "song", Type: "Audio"}, []string{"a.song.mp3"}},
		{"another type", &metav1.SearchRequest{Query: "song", Type: "Video"}, nil},
		{"a file whose only user left", &metav1.SearchRequest{Query: "departed"}, nil},
	}
	for _, tc := range cases {
		chunk, err := s.SearchCatalog(context.Background(), tc.req, 0)
		if err != nil {
			t.Fatal(err)
		}
		got := releaseNames(chunk.Releases)
		t.Logf("input:  %s: %v", tc.name, tc.req)
		t.Logf("output: %v", got)
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestCatalogChunksAndWindow: an answer is served in chunks of meta.ChunkSize and
// cut at the window.
func TestCatalogChunksAndWindow(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client := storage.ClientInfo{ID: 0x0A000001, IPv4: 0x0100000A, Port: 4662, Hash: []byte("user-hash-eeeee5")}
	id, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = id
	for i := range 260 {
		engine.AddFile(storage.File{Hash: []byte(fmt.Sprintf("many-hash-%06d", i)), Name: fmt.Sprintf("many.file%04d.bin", i), Size: uint64(100 + i)}, client)
	}
	s := NewSearcher(SearcherConfig{})
	cfg := catalogConfig(engine)
	cfg.Window = 250
	s.EnableCatalog(cfg)

	seen := map[string]bool{}
	for k := 0; ; k++ {
		chunk, err := s.SearchCatalog(context.Background(), &metav1.SearchRequest{Query: "many"}, k)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("input:  chunk %d of %q, 260 files shared, window 250", k, "many")
		t.Logf("output: %d releases, total=%d exact=%t more=%t", len(chunk.Releases), chunk.Total, chunk.TotalExact, chunk.More)
		for _, release := range chunk.Releases {
			if seen[release[0].GetName()] {
				t.Fatalf("%s came twice", release[0].GetName())
			}
			seen[release[0].GetName()] = true
		}
		if chunk.TotalExact || chunk.Total != 250 {
			t.Errorf("total %d exact %t; a cut answer is a lower bound of 250", chunk.Total, chunk.TotalExact)
		}
		if want := k < 2; chunk.More != want {
			t.Errorf("chunk %d: more=%t, want %t", k, chunk.More, want)
		}
		if !chunk.More {
			break
		}
		if len(chunk.Releases) != meta.ChunkSize {
			t.Errorf("chunk %d holds %d releases, want %d", k, len(chunk.Releases), meta.ChunkSize)
		}
	}
	if len(seen) != 250 {
		t.Errorf("%d files in all, want the window's 250", len(seen))
	}
}

// TestCatalogAnswersOwnFilesWhenAPeerIsDown: a peer that cannot be reached costs
// the answer its files and its exact total, nothing else.
func TestCatalogAnswersOwnFilesWhenAPeerIsDown(t *testing.T) {
	own, _ := seedEngine(t)
	cfg := liveConfig(ClientConfig{URL: "http://127.0.0.1:1", Token: testToken})
	cfg.Timeout = time.Second
	s := NewSearcher(cfg)
	s.EnableCatalog(catalogConfig(own))

	chunk, err := s.SearchCatalog(context.Background(), &metav1.SearchRequest{Query: "linux"}, 0)
	t.Logf("input:  %q with one configured peer that refuses connections", "linux")
	t.Logf("output: err=%v releases=%d exact=%t", err, len(chunk.Releases), chunk.TotalExact)
	if err != nil || len(chunk.Releases) != 10 || chunk.TotalExact {
		t.Errorf("want this server's 10 files, no error and a total that is not exact")
	}
}

// TestCatalogUsesTheMirror: a mirrored peer is answered from the mirror, without
// a call on the search.
func TestCatalogUsesTheMirror(t *testing.T) {
	peer := startService(t, func(cfg *ServiceConfig) { cfg.BrowseMinInterval = 0 })
	s := NewSearcher(mirrorConfig(peer.peer(testToken)))
	s.EnableCatalog(catalogConfig(nil))
	stop := s.Start(context.Background())
	defer stop()
	waitFor(t, "the first walk", func() bool { return s.Stats()[0].Mirrored })

	chunk, err := s.SearchCatalog(context.Background(), &metav1.SearchRequest{Query: "linux"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	st := s.Stats()[0]
	t.Logf("input:  %q with no files of this server's and one mirrored peer", "linux")
	t.Logf("output: %d releases, exact=%t, %d live calls", len(chunk.Releases), chunk.TotalExact, st.LiveCalls)
	if len(chunk.Releases) != 10 || !chunk.TotalExact || st.LiveCalls != 0 {
		t.Errorf("want the mirror's 10 files, an exact total and no live call")
	}
}

// TestCatalogIdentifiesNoClient: no entry of the servers network holds the
// address, port, id or user hash of a client, this server's or a peer's.
func TestCatalogIdentifiesNoClient(t *testing.T) {
	peer := startService(t, nil)
	own, clients := seedEngine(t)
	s := NewSearcher(liveConfig(peer.peer(testToken)))
	s.EnableCatalog(catalogConfig(own))

	resp := &metav1.SearchResponse{}
	for _, query := range []string{"linux", "song"} {
		chunk, err := s.SearchCatalog(context.Background(), &metav1.SearchRequest{Query: query}, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, release := range chunk.Releases {
			resp.Entries = append(resp.Entries, release...)
		}
	}
	if len(resp.Entries) == 0 {
		t.Fatal("the answer is empty, so it proves nothing")
	}
	wire, err := proto.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input:  %d entries, %d bytes on the wire", len(resp.Entries), len(wire))
	for _, c := range append(clients, peer.clients...) {
		secrets := map[string][]byte{
			"user hash":           c.Hash,
			"client id (LE)":      binary.LittleEndian.AppendUint32(nil, c.ID),
			"client id (BE)":      binary.BigEndian.AppendUint32(nil, c.ID),
			"IPv4 (LE)":           binary.LittleEndian.AppendUint32(nil, c.IPv4),
			"IPv4 (BE)":           binary.BigEndian.AppendUint32(nil, c.IPv4),
			"client id as varint": binary.AppendUvarint(nil, uint64(c.ID)),
			"IPv4 as varint":      binary.AppendUvarint(nil, uint64(c.IPv4)),
			"port as varint":      binary.AppendUvarint(nil, uint64(c.Port)),
			"port (LE)":           binary.LittleEndian.AppendUint16(nil, c.Port),
		}
		for what, secret := range secrets {
			if bytes.Contains(wire, secret) {
				t.Errorf("the answer holds a client's %s (% x)", what, secret)
			}
		}
	}
	t.Logf("output: none of the clients' address, port, id or user hash is in it")
}

// -- internals ---------------------------------------------------------------

func catalogConfig(own *storage.MemoryEngine) CatalogConfig {
	cfg := CatalogConfig{Window: 1000, Timeout: 5 * time.Second, MaxEntries: 100, TTL: time.Minute}
	if own != nil { // never a typed nil in the interface
		cfg.Own = own
	}
	return cfg
}

func releaseNames(releases []meta.Release) []string {
	var out []string
	for _, release := range releases {
		out = append(out, release[0].GetName())
	}
	return out
}

func describeReleases(releases []meta.Release) []string {
	out := make([]string, 0, len(releases))
	for _, release := range releases {
		e := release[0]
		out = append(out, fmt.Sprintf("%s size=%d sources=%d complete=%d", e.GetName(), e.GetSize(), e.GetPeers(), e.GetSeeders()))
	}
	return out
}

func findEntry(releases []meta.Release, name string) *metav1.MetaEntry {
	for _, release := range releases {
		if release[0].GetName() == name {
			return release[0]
		}
	}
	return nil
}

func sameReleases(a, b []meta.Release) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !proto.Equal(a[i][0], b[i][0]) {
			return false
		}
	}
	return true
}
