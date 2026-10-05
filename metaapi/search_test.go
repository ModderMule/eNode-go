package metaapi

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"enode/meta"
	"enode/storage"

	"connectrpc.com/connect/v2"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
)

// fakeCatalog serves each network's releases in chunks of meta.ChunkSize, as
// meta.Searcher does, and counts the chunk loads.
type fakeCatalog struct {
	mu       sync.Mutex
	releases map[string][]meta.Release
	errs     map[string]error
	loads    map[string]int
	requests []*metav1.SearchRequest
	// inexact makes a network's count a lower bound.
	inexact map[string]bool
}

func newFakeCatalog() *fakeCatalog {
	return &fakeCatalog{releases: map[string][]meta.Release{}, errs: map[string]error{}, loads: map[string]int{}, inexact: map[string]bool{}}
}

func (c *fakeCatalog) CatalogNetworks() []string {
	var out []string
	for _, n := range []string{networkTorrent, networkUsenet, networkKad} {
		if _, ok := c.releases[n]; ok {
			out = append(out, n)
		}
	}
	return out
}

func (c *fakeCatalog) SearchCatalog(_ context.Context, network string, req *metav1.SearchRequest, k int) (meta.Chunk, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loads[network]++
	c.requests = append(c.requests, req)
	if err := c.errs[network]; err != nil {
		return meta.Chunk{}, err
	}
	all := c.releases[network]
	start, end := min(k*meta.ChunkSize, len(all)), min((k+1)*meta.ChunkSize, len(all))
	return meta.Chunk{Releases: all[start:end], Total: uint64(len(all)), TotalExact: !c.inexact[network], More: end < len(all)}, nil
}

func (c *fakeCatalog) loadCount(network string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loads[network]
}

// releases returns n one-row releases named prefix0 … prefix(n-1).
func releases(prefix string, n int) []meta.Release {
	out := make([]meta.Release, n)
	for i := range out {
		id := fmt.Sprintf("%s%d", prefix, i)
		out[i] = meta.Release{{Name: id, CatalogId: id}}
	}
	return out
}

func searchConfig(cat CatalogSource) *SearchConfig {
	return &SearchConfig{Catalog: cat, RequireAccount: true, MaxLimit: 100, Window: 1000}
}

func searchService(cat CatalogSource) *Service {
	return NewService(ServiceConfig{MaxMetafileBytes: 1 << 20, Search: searchConfig(cat)}, newTestFetcher(newFakeSource()), nil)
}

// names lists the names of a response's entries.
func names(resp *metav1.SearchResponse) []string {
	var out []string
	for _, e := range resp.GetEntries() {
		out = append(out, e.GetName())
	}
	return out
}

func TestSearchAlternatesNetworks(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkTorrent] = releases("t", 5)
	cat.releases[networkUsenet] = releases("u", 2)
	svc := searchService(cat)

	for _, tc := range []struct {
		offset, limit uint32
		want          string
		next          uint32
	}{
		{0, 4, "[t0 u0 t1 u1]", 4},
		{4, 4, "[t2 t3 t4]", 0},
		{2, 3, "[t1 u1 t2]", 5},
		{7, 4, "[]", 0},
	} {
		resp, err := svc.Search(context.Background(), &metav1.SearchRequest{Query: "x", Offset: tc.offset, Limit: tc.limit})
		got := fmt.Sprint(names(resp))
		t.Logf("input: offset=%d limit=%d; output: %s next=%d total=%d err=%v", tc.offset, tc.limit, got, resp.GetNextOffset(), resp.GetTotal(), err)
		if err != nil || got != tc.want || resp.GetNextOffset() != tc.next || resp.GetTotal() != 7 {
			t.Fatalf("got %s next %d total %d, want %s next %d total 7", got, resp.GetNextOffset(), resp.GetTotal(), tc.want, tc.next)
		}
	}
}

// TestSearchAlternatesThreeNetworks covers Kad beside the other two: one release
// from each in turn, torrent, Usenet, Kad, and a network that runs out drops out.
func TestSearchAlternatesThreeNetworks(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkTorrent] = releases("t", 3)
	cat.releases[networkUsenet] = releases("u", 1)
	cat.releases[networkKad] = releases("k", 4)
	svc := searchService(cat)

	for _, tc := range []struct {
		offset, limit uint32
		want          string
		next          uint32
	}{
		{0, 5, "[t0 u0 k0 t1 k1]", 5},
		{5, 5, "[t2 k2 k3]", 0},
		{2, 2, "[k0 t1]", 4},
	} {
		resp, err := svc.Search(context.Background(), &metav1.SearchRequest{Query: "x", Offset: tc.offset, Limit: tc.limit})
		got := fmt.Sprint(names(resp))
		t.Logf("input: offset=%d limit=%d; output: %s next=%d total=%d err=%v", tc.offset, tc.limit, got, resp.GetNextOffset(), resp.GetTotal(), err)
		if err != nil || got != tc.want || resp.GetNextOffset() != tc.next || resp.GetTotal() != 8 {
			t.Fatalf("got %s next %d total %d, want %s next %d total 8", got, resp.GetNextOffset(), resp.GetTotal(), tc.want, tc.next)
		}
	}
}

// kadFiles returns one-row eD2K releases named prefix0 … with the given sizes and
// ages. total_size is left unset, which the contract allows a native row.
func kadFiles(prefix string, sizes, ages []uint64) []meta.Release {
	out := make([]meta.Release, len(sizes))
	for i := range out {
		id := fmt.Sprintf("%s%d", prefix, i)
		out[i] = meta.Release{{Kind: metav1.MetaKind_META_KIND_ED2K, Name: id, CatalogId: id, Size: sizes[i], AgeDays: uint32(ages[i])}}
	}
	return out
}

// TestSearchMergesKadByKey covers the keyed sorts with a Kad network in the mix: a
// file's size stands in for the total size it does not carry.
func TestSearchMergesKadByKey(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkTorrent] = sized("t", []uint64{900, 100}, []uint64{3, 9})
	cat.releases[networkUsenet] = sized("u", []uint64{800}, []uint64{0})
	cat.releases[networkKad] = kadFiles("k", []uint64{850, 50}, []uint64{1, 20})
	svc := searchService(cat)

	for _, tc := range []struct {
		name      string
		sort      metav1.SearchSort
		ascending bool
		want      string
	}{
		{"size", metav1.SearchSort_SEARCH_SORT_SIZE, false, "[t0 k0 u0 t1 k1]"},
		{"date", metav1.SearchSort_SEARCH_SORT_DATE, false, "[u0 k0 t0 t1 k1]"},
		{"relevance alternates", metav1.SearchSort_SEARCH_SORT_UNSPECIFIED, false, "[t0 u0 k0 t1 k1]"},
	} {
		resp, err := svc.Search(context.Background(), &metav1.SearchRequest{Query: "x", Sort: tc.sort, SortAscending: tc.ascending, Limit: 10})
		got := fmt.Sprint(names(resp))
		t.Logf("%s: input sort=%s asc=%t; output %s err=%v", tc.name, tc.sort, tc.ascending, got, err)
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

// sized returns one-row releases named prefix0 … with the given sizes and ages.
func sized(prefix string, sizes, ages []uint64) []meta.Release {
	out := make([]meta.Release, len(sizes))
	for i := range out {
		id := fmt.Sprintf("%s%d", prefix, i)
		out[i] = meta.Release{{Name: id, CatalogId: id, TotalSize: sizes[i], AgeDays: uint32(ages[i])}}
	}
	return out
}

// TestSearchMergesSortedNetworksByKey covers the sorts every network answers:
// each daemon's page arrives in that order, and the merge keeps it across them.
// Any other sort alternates, since one network's answer is in relevance order.
func TestSearchMergesSortedNetworksByKey(t *testing.T) {
	cat := newFakeCatalog()
	// Each network in size-descending order, which is what the daemons return for
	// SIZE; the ages are chosen so DATE puts them in another order.
	cat.releases[networkTorrent] = sized("t", []uint64{900, 500, 100}, []uint64{3, 1, 9})
	cat.releases[networkUsenet] = sized("u", []uint64{800, 200}, []uint64{0, 5})
	svc := searchService(cat)

	for _, tc := range []struct {
		name          string
		sort          metav1.SearchSort
		ascending     bool
		offset, limit uint32
		want          string
	}{
		{"size", metav1.SearchSort_SEARCH_SORT_SIZE, false, 0, 10, "[t0 u0 t1 u1 t2]"},
		{"size, second page", metav1.SearchSort_SEARCH_SORT_SIZE, false, 2, 2, "[t1 u1]"},
		{"seeders is torrent-only, so it alternates", metav1.SearchSort_SEARCH_SORT_SEEDERS, false, 0, 10, "[t0 u0 t1 u1 t2]"},
		{"relevance alternates", metav1.SearchSort_SEARCH_SORT_UNSPECIFIED, false, 0, 3, "[t0 u0 t1]"},
	} {
		resp, err := svc.Search(context.Background(), &metav1.SearchRequest{
			Query: "x", Sort: tc.sort, SortAscending: tc.ascending, Offset: tc.offset, Limit: tc.limit,
		})
		got := fmt.Sprint(names(resp))
		t.Logf("%s: input sort=%s asc=%t offset=%d limit=%d; output %s err=%v", tc.name, tc.sort, tc.ascending, tc.offset, tc.limit, got, err)
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}

	// DATE: each network newest first, as the daemons return it.
	cat.releases[networkTorrent] = sized("t", []uint64{1, 1, 1}, []uint64{1, 3, 9})
	cat.releases[networkUsenet] = sized("u", []uint64{1, 1}, []uint64{0, 5})
	resp, err := svc.Search(context.Background(), &metav1.SearchRequest{Query: "x", Sort: metav1.SearchSort_SEARCH_SORT_DATE, Limit: 10})
	got := fmt.Sprint(names(resp))
	t.Logf("date: output %s err=%v", got, err)
	if err != nil || got != "[u0 t0 t1 u1 t2]" {
		t.Fatalf("date: got %s, want [u0 t0 t1 u1 t2]", got)
	}

	// DATE ascending: each network oldest first.
	cat.releases[networkTorrent] = sized("t", []uint64{1, 1, 1}, []uint64{9, 3, 1})
	cat.releases[networkUsenet] = sized("u", []uint64{1, 1}, []uint64{5, 0})
	resp, err = svc.Search(context.Background(), &metav1.SearchRequest{Query: "x", Sort: metav1.SearchSort_SEARCH_SORT_DATE, SortAscending: true, Limit: 10})
	got = fmt.Sprint(names(resp))
	t.Logf("date ascending: output %s err=%v", got, err)
	if err != nil || got != "[t0 u0 t1 t2 u1]" {
		t.Fatalf("date ascending: got %s, want [t0 u0 t1 t2 u1]", got)
	}
}

// TestSearchSaysWhetherTheTotalIsACount covers total_exact and window: the merged
// total is a count only when every network's was.
func TestSearchSaysWhetherTheTotalIsACount(t *testing.T) {
	for _, tc := range []struct {
		name    string
		inexact string
		exact   bool
	}{
		{"every network counted", "", true},
		{"one network bounded", networkUsenet, false},
	} {
		cat := newFakeCatalog()
		cat.releases[networkTorrent] = releases("t", 5)
		cat.releases[networkUsenet] = releases("u", 2)
		if tc.inexact != "" {
			cat.inexact[tc.inexact] = true
		}

		resp, err := searchService(cat).Search(context.Background(), &metav1.SearchRequest{Query: "x", Limit: 4})
		t.Logf("%s: input inexact=%q; output total=%d exact=%t window=%d err=%v",
			tc.name, tc.inexact, resp.GetTotal(), resp.GetTotalExact(), resp.GetWindow(), err)
		if err != nil || resp.GetTotal() != 7 || resp.GetTotalExact() != tc.exact || resp.GetWindow() != 1000 {
			t.Fatalf("%s: got total %d exact %t window %d, want 7 exact %t window 1000",
				tc.name, resp.GetTotal(), resp.GetTotalExact(), resp.GetWindow(), tc.exact)
		}
	}
}

func TestSearchPagesWithoutGapsOrDuplicates(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkTorrent] = releases("t", 250)
	cat.releases[networkUsenet] = releases("u", 120)
	// A multi-file release: three rows that must share a page.
	cat.releases[networkUsenet][60] = meta.Release{{Name: "multi", CatalogId: "m"}, {Name: "multi/a", CatalogId: "m"}, {Name: "multi/b", CatalogId: "m"}}
	svc := searchService(cat)

	seen := map[string]bool{}
	var offset uint32
	pages := 0
	for {
		resp, err := svc.Search(context.Background(), &metav1.SearchRequest{Query: "x", Offset: offset, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, e := range resp.GetEntries() {
			if seen[e.GetName()] {
				t.Fatalf("page %d repeats %s", pages, e.GetName())
			}
			seen[e.GetName()] = true
		}
		t.Logf("input: offset=%d; output: %d rows next=%d loads torrent=%d usenet=%d",
			offset, len(resp.GetEntries()), resp.GetNextOffset(), cat.loadCount(networkTorrent), cat.loadCount(networkUsenet))
		if resp.GetNextOffset() == 0 {
			break
		}
		offset = resp.GetNextOffset()
	}
	if pages != 4 || len(seen) != 372 || !seen["multi/b"] {
		t.Fatalf("pages=%d rows=%d, want 4 pages and 370 releases (372 rows)", pages, len(seen))
	}
}

func TestSearchNetworkAndKindSelection(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkTorrent] = releases("t", 3)
	cat.releases[networkUsenet] = releases("u", 3)
	svc := searchService(cat)

	for _, tc := range []struct {
		name    string
		network metav1.MetaNetwork
		kinds   []metav1.MetaKind
		want    string
	}{
		{"both", metav1.MetaNetwork_META_NETWORK_UNSPECIFIED, nil, "[t0 u0 t1 u1 t2 u2]"},
		{"torrent", metav1.MetaNetwork_META_NETWORK_TORRENT, nil, "[t0 t1 t2]"},
		{"usenet", metav1.MetaNetwork_META_NETWORK_USENET, nil, "[u0 u1 u2]"},
		{"nzb kind", metav1.MetaNetwork_META_NETWORK_UNSPECIFIED, []metav1.MetaKind{metav1.MetaKind_META_KIND_NZB}, "[u0 u1 u2]"},
		{"torrent network, nzb kind", metav1.MetaNetwork_META_NETWORK_TORRENT, []metav1.MetaKind{metav1.MetaKind_META_KIND_NZB}, "[]"},
		{"unknown network", metav1.MetaNetwork(9), nil, "[]"},
	} {
		resp, err := svc.Search(context.Background(), &metav1.SearchRequest{Query: "x", Network: tc.network, Kinds: tc.kinds})
		got := fmt.Sprint(names(resp))
		t.Logf("input: %s; output: %s err=%v", tc.name, got, err)
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
	// A request with kinds reaches each network with that network's kinds only.
	cat.requests = nil
	_, _ = svc.Search(context.Background(), &metav1.SearchRequest{Query: "y", Kinds: []metav1.MetaKind{metav1.MetaKind_META_KIND_BT_V2, metav1.MetaKind_META_KIND_NZB}})
	for _, r := range cat.requests {
		t.Logf("input: kinds BT_V2+NZB; output: forwarded kinds %v", r.GetKinds())
		if len(r.GetKinds()) != 1 {
			t.Fatalf("forwarded kinds %v, want one per network", r.GetKinds())
		}
	}

	// Kad is a network like the others, and ED2K is its kind.
	cat.releases[networkKad] = releases("k", 2)
	for _, tc := range []struct {
		name    string
		network metav1.MetaNetwork
		kinds   []metav1.MetaKind
		want    string
	}{
		{"all three", metav1.MetaNetwork_META_NETWORK_UNSPECIFIED, nil, "[t0 u0 k0 t1 u1 k1 t2 u2]"},
		{"kad", metav1.MetaNetwork_META_NETWORK_KAD, nil, "[k0 k1]"},
		{"ed2k kind", metav1.MetaNetwork_META_NETWORK_UNSPECIFIED, []metav1.MetaKind{metav1.MetaKind_META_KIND_ED2K}, "[k0 k1]"},
		{"torrent network, ed2k kind", metav1.MetaNetwork_META_NETWORK_TORRENT, []metav1.MetaKind{metav1.MetaKind_META_KIND_ED2K}, "[]"},
		{"kad network, nzb kind", metav1.MetaNetwork_META_NETWORK_KAD, []metav1.MetaKind{metav1.MetaKind_META_KIND_NZB}, "[]"},
	} {
		resp, err := svc.Search(context.Background(), &metav1.SearchRequest{Query: "z", Network: tc.network, Kinds: tc.kinds})
		got := fmt.Sprint(names(resp))
		t.Logf("input: %s; output: %s err=%v", tc.name, got, err)
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
	// Caps lists Kad as a network to search, and no kind for it: kinds are the
	// metafiles the server can serve, and an eD2K file has none.
	caps, _ := svc.GetCaps(context.Background(), &metav1.GetCapsRequest{})
	t.Logf("input: three networks; output: caps.networks=%v caps.kinds=%v", caps.GetNetworks(), caps.GetKinds())
	if fmt.Sprint(caps.GetNetworks()) != "[META_NETWORK_TORRENT META_NETWORK_USENET META_NETWORK_KAD]" {
		t.Fatalf("caps.networks %v, want all three", caps.GetNetworks())
	}
	for _, kind := range caps.GetKinds() {
		if kind == metav1.MetaKind_META_KIND_ED2K {
			t.Fatalf("caps.kinds %v lists ED2K, which has no metafile", caps.GetKinds())
		}
	}

	// Only torrent enabled: a Usenet search finds nothing, and Caps lists torrent only.
	only := newFakeCatalog()
	only.releases[networkTorrent] = releases("t", 1)
	svc = searchService(only)
	resp, err := svc.Search(context.Background(), &metav1.SearchRequest{Query: "x", Network: metav1.MetaNetwork_META_NETWORK_USENET})
	caps, _ = svc.GetCaps(context.Background(), &metav1.GetCapsRequest{})
	t.Logf("input: usenet search, torrent-only server; output: %d entries err=%v caps.networks=%v", len(resp.GetEntries()), err, caps.GetNetworks())
	if err != nil || len(resp.GetEntries()) != 0 || fmt.Sprint(caps.GetNetworks()) != "[META_NETWORK_TORRENT]" || !caps.GetSearchAvailable() {
		t.Fatalf("torrent-only: %v %v caps %v", resp, err, caps)
	}
}

func TestSearchFailures(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkTorrent] = releases("t", 3)
	cat.releases[networkUsenet] = releases("u", 3)
	cat.errs[networkUsenet] = meta.ErrNetworkDown
	svc := searchService(cat)

	resp, err := svc.Search(context.Background(), &metav1.SearchRequest{Query: "x"})
	t.Logf("input: usenet down; output: %v total=%d err=%v", names(resp), resp.GetTotal(), err)
	if err != nil || fmt.Sprint(names(resp)) != "[t0 t1 t2]" || resp.GetTotal() != 0 {
		t.Fatalf("partial answer: %v total %d err %v", names(resp), resp.GetTotal(), err)
	}

	cat.errs[networkTorrent] = connect.NewError(connect.CodeUnavailable, "daemon detail that must not leak")
	_, err = svc.Search(context.Background(), &metav1.SearchRequest{Query: "x"})
	t.Logf("input: both down; output: %v", err)
	if connect.CodeOf(err) != connect.CodeUnavailable || errorInfo(t, err).GetMsgCode() != CodeSearchUnavailable || strings.Contains(err.Error(), "leak") {
		t.Fatalf("both down: %v", err)
	}
}

func TestSearchValidationAndLimits(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkTorrent] = releases("t", 300)
	svc := NewService(ServiceConfig{Search: &SearchConfig{Catalog: cat, MaxLimit: 20, Window: 50}}, newTestFetcher(newFakeSource()), nil)
	ctx := context.Background()

	for _, tc := range []struct {
		query string
		code  string
	}{
		{"   ", CodeSearchQueryRequired},
		{strings.Repeat("a", maxQueryBytes+1), CodeSearchQueryTooLong},
	} {
		_, err := svc.Search(ctx, &metav1.SearchRequest{Query: tc.query})
		t.Logf("input: query of %d bytes; output: %v", len(tc.query), err)
		if connect.CodeOf(err) != connect.CodeInvalidArgument || errorInfo(t, err).GetMsgCode() != tc.code {
			t.Fatalf("query %q: %v, want %s", tc.query, err, tc.code)
		}
	}

	resp, _ := svc.Search(ctx, &metav1.SearchRequest{Query: "x", Limit: 500})
	t.Logf("input: limit 500 with maxLimit 20; output: %d entries next=%d", len(resp.GetEntries()), resp.GetNextOffset())
	if len(resp.GetEntries()) != 20 || resp.GetNextOffset() != 20 {
		t.Fatalf("limit cap: %d entries next %d", len(resp.GetEntries()), resp.GetNextOffset())
	}
	resp, _ = svc.Search(ctx, &metav1.SearchRequest{Query: "x", Offset: 40, Limit: 20})
	t.Logf("input: offset 40 limit 20 window 50; output: %d entries next=%d", len(resp.GetEntries()), resp.GetNextOffset())
	if len(resp.GetEntries()) != 10 || resp.GetNextOffset() != 0 {
		t.Fatalf("window end: %d entries next %d", len(resp.GetEntries()), resp.GetNextOffset())
	}
	resp, _ = svc.Search(ctx, &metav1.SearchRequest{Query: "x", Offset: 50})
	if len(resp.GetEntries()) != 0 || resp.GetNextOffset() != 0 {
		t.Fatalf("past the window: %v", resp)
	}

	off := NewService(ServiceConfig{}, newTestFetcher(newFakeSource()), nil)
	_, err := off.Search(ctx, &metav1.SearchRequest{Query: "x"})
	caps, _ := off.GetCaps(ctx, &metav1.GetCapsRequest{})
	t.Logf("input: search off; output: %v caps.search_available=%t", err, caps.GetSearchAvailable())
	if connect.CodeOf(err) != connect.CodeUnimplemented || errorInfo(t, err).GetMsgCode() != CodeSearchDisabled || caps.GetSearchAvailable() {
		t.Fatalf("search off: %v caps %v", err, caps)
	}
}

func TestSearchRequiresAccount(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkTorrent] = releases("t", 2)
	fx := start(t, true, false, 0, searchConfig(cat))
	fx.stepOpen.open = true
	ctx := context.Background()
	if _, err := fx.accts.Register(ctx, "sam", "", "password1"); err != nil {
		t.Fatal(err)
	}

	anon, _ := fx.grpcClients("")
	caps, _ := anon.GetCaps(ctx, &metav1.GetCapsRequest{})
	_, err := anon.Search(ctx, &metav1.SearchRequest{Query: "x"})
	info := errorInfo(t, err)
	t.Logf("input: anonymous search, requireAccount; output: %s %v caps.search_requires_account=%t", connect.CodeOf(err), info, caps.GetSearchRequiresAccount())
	if connect.CodeOf(err) != connect.CodeUnauthenticated || info.GetRegistrationUrl() == "" || !caps.GetSearchRequiresAccount() {
		t.Fatalf("anonymous: %v caps %v", err, caps)
	}

	user, _ := fx.grpcClients("Basic " + base64.StdEncoding.EncodeToString([]byte("sam:password1")))
	_, err = user.Search(ctx, &metav1.SearchRequest{Query: "x"})
	t.Logf("input: pending account; output: %s", connect.CodeOf(err))
	if connect.CodeOf(err) != connect.CodePermissionDenied || len(errorInfo(t, err).GetPendingSteps()) != 1 {
		t.Fatalf("pending: %v", err)
	}

	fx.stepOpen.open = false
	resp, err := user.Search(ctx, &metav1.SearchRequest{Query: "x"})
	t.Logf("input: active account; output: %v err=%v", names(resp), err)
	if err != nil || len(resp.GetEntries()) != 2 {
		t.Fatalf("active: %v", err)
	}
}

func TestSearchPublicWhileDownloadsNeedAccount(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkUsenet] = releases("u", 1)
	cfg := searchConfig(cat)
	cfg.RequireAccount = false
	cfg.PerIPPerMinute = 1
	fx := start(t, true, true, 0, cfg)
	ctx := context.Background()

	anon, _ := fx.grpcClients("")
	caps, _ := anon.GetCaps(ctx, &metav1.GetCapsRequest{})
	resp, err := anon.Search(ctx, &metav1.SearchRequest{Query: "x"})
	_, dlErr := anon.GetMetaFile(ctx, &metav1.GetMetaFileRequest{MetaHash: fx.hash, CatalogId: "cat-7"})
	t.Logf("input: requireAccount=false; output: search %v err=%v, download %s, caps.search_requires_account=%t",
		names(resp), err, connect.CodeOf(dlErr), caps.GetSearchRequiresAccount())
	if err != nil || len(resp.GetEntries()) != 1 || connect.CodeOf(dlErr) != connect.CodeUnauthenticated || caps.GetSearchRequiresAccount() {
		t.Fatalf("public search: %v / download %v / caps %v", err, dlErr, caps)
	}

	// Search has its own limit: the second search is refused.
	_, err = anon.Search(ctx, &metav1.SearchRequest{Query: "x"})
	t.Logf("input: second search at 1/min; output: %s", connect.CodeOf(err))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("search rate limit: %v", err)
	}

}

func TestSearchOverConnectJSON(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkTorrent] = releases("t", 2)
	cat.releases[networkUsenet] = releases("u", 2)
	fx := start(t, false, true, 0, searchConfig(cat))

	// The Connect protocol on the HTTP endpoint takes a curl-shaped JSON POST.
	body := `{"query":"x","network":"META_NETWORK_USENET","limit":1}`
	res, err := http.Post(fx.httpURL+"/enode.meta.v1.MetaApi/Search", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out struct {
		Entries []struct {
			Name     string `json:"name"`
			MetaHash string `json:"metaHash"`
		} `json:"entries"`
		NextOffset int `json:"nextOffset"`
	}
	err = json.NewDecoder(res.Body).Decode(&out)
	t.Logf("input: POST %s; output: %d %+v err=%v", body, res.StatusCode, out, err)
	if res.StatusCode != http.StatusOK || len(out.Entries) != 1 || out.Entries[0].Name != "u0" || out.NextOffset != 1 {
		t.Fatalf("connect JSON search: %d %+v", res.StatusCode, out)
	}
}

// TestSearchKadOverConnectJSON asks for the Kad network alone the way curl would.
func TestSearchKadOverConnectJSON(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkTorrent] = releases("t", 2)
	cat.releases[networkKad] = releases("k", 2)
	fx := start(t, false, true, 0, searchConfig(cat))

	body := `{"query":"x","network":"META_NETWORK_KAD"}`
	res, err := http.Post(fx.httpURL+"/enode.meta.v1.MetaApi/Search", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out struct {
		Entries []struct {
			Name string `json:"name"`
		} `json:"entries"`
		Total string `json:"total"`
	}
	err = json.NewDecoder(res.Body).Decode(&out)
	t.Logf("input: POST %s; output: %d %+v err=%v", body, res.StatusCode, out, err)
	if res.StatusCode != http.StatusOK || len(out.Entries) != 2 || out.Entries[0].Name != "k0" || out.Entries[1].Name != "k1" {
		t.Fatalf("connect JSON kad search: %d %+v", res.StatusCode, out)
	}
}

// fakeOwnFiles is the server's file store as ownFilesWin asks it: the files it is
// told are shared, and how often it was asked.
type fakeOwnFiles struct {
	files []storage.File
	asked [][][]byte
}

func (f *fakeOwnFiles) SharedFiles(hashes [][]byte) []storage.File {
	f.asked = append(f.asked, hashes)
	var out []storage.File
	for _, file := range f.files {
		for _, hash := range hashes {
			if string(hash) == string(file.Hash) {
				out = append(out, file)
				break
			}
		}
	}
	return out
}

// kadHash is the MD4 a Kad row named name stands for in these tests.
func kadHash(name string) []byte {
	sum := md5.Sum([]byte(name))
	return sum[:]
}

// kadRows returns one-row eD2K releases as kademlia-crawler sends them: the file's
// MD4 as both meta_hash and identity, peers the sources Kad reported and seeders the
// complete ones.
func kadRows(prefix string, n int) []meta.Release {
	out := make([]meta.Release, n)
	for i := range out {
		name := fmt.Sprintf("%s%d", prefix, i)
		hash := kadHash(name)
		out[i] = meta.Release{{
			Kind: metav1.MetaKind_META_KIND_ED2K, MetaHash: hash, Identity: hash,
			Name: name, CatalogId: fmt.Sprintf("ed2k:%X", hash), Size: uint64(1000 + i), Peers: 40, Seeders: 4,
		}}
	}
	return out
}

// describe lists a response's entries as name/peers/seeders.
func describe(resp *metav1.SearchResponse) []string {
	var out []string
	for _, e := range resp.GetEntries() {
		out = append(out, fmt.Sprintf("%s/%d/%d", e.GetName(), e.GetPeers(), e.GetSeeders()))
	}
	return out
}

// TestSearchAnswersWithTheServersOwnFile: a Kad row for a file a user shares on this
// server comes back once, where it was, with the server's name and source counts. The
// same hash at another size is another file, and a row nobody here shares is the
// daemon's.
func TestSearchAnswersWithTheServersOwnFile(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkTorrent] = releases("t", 2)
	cat.releases[networkKad] = kadRows("k", 3)
	own := &fakeOwnFiles{files: []storage.File{
		{Hash: kadHash("k0"), Name: "own name.iso", Size: 1000, Sources: 2, Completed: 1},
		{Hash: kadHash("k1"), Name: "another size.iso", Size: 9999, Sources: 7, Completed: 7},
	}}
	cfg := searchConfig(cat)
	cfg.OwnFiles = own
	svc := NewService(ServiceConfig{MaxMetafileBytes: 1 << 20, Search: cfg}, newTestFetcher(newFakeSource()), nil)

	resp, err := svc.Search(context.Background(), &metav1.SearchRequest{Query: "x", Limit: 10})
	got := fmt.Sprint(describe(resp))
	t.Logf("input:  torrent t0 t1; Kad k0 k1 k2 with 40 sources, 4 complete; the server shares k0 at its size and k1's hash at another")
	t.Logf("output: %s total=%d exact=%t next=%d err=%v; lookups=%d of %d hash(es)",
		got, resp.GetTotal(), resp.GetTotalExact(), resp.GetNextOffset(), err, len(own.asked), len(own.asked[0]))

	if want := "[t0/0/0 own name.iso/2/1 t1/0/0 k1/40/4 k2/40/4]"; err != nil || got != want {
		t.Fatalf("got %s, want %s (err %v)", got, want, err)
	}
	if resp.GetTotal() != 5 || !resp.GetTotalExact() || resp.GetNextOffset() != 0 {
		t.Fatalf("total %d exact %t next %d, want 5, exact, no next page: the row keeps its place",
			resp.GetTotal(), resp.GetTotalExact(), resp.GetNextOffset())
	}
	if len(own.asked) != 1 || len(own.asked[0]) != 3 {
		t.Fatalf("the file store was asked %d time(s), want once for the page's 3 eD2K hashes", len(own.asked))
	}
	entry := resp.GetEntries()[1]
	if string(entry.GetMetaHash()) != string(kadHash("k0")) || entry.GetSize() != 1000 || entry.GetKind() != metav1.MetaKind_META_KIND_ED2K {
		t.Fatalf("the rewritten entry lost what identifies it: %v", entry)
	}

	// The catalogue's rows are cached and shared: a search made once the user has
	// left must see the Kad figures again.
	own.files = nil
	resp, err = svc.Search(context.Background(), &metav1.SearchRequest{Query: "x", Limit: 10})
	got = fmt.Sprint(describe(resp))
	t.Logf("input:  the same search with nothing shared any more")
	t.Logf("output: %s err=%v", got, err)

	if want := "[t0/0/0 k0/40/4 t1/0/0 k1/40/4 k2/40/4]"; err != nil || got != want {
		t.Fatalf("got %s, want %s (err %v): the rewrite reached the shared rows", got, want, err)
	}
}

// TestSearchAsksTheFileStoreOnlyAboutED2KRows: a page of torrent and Usenet rows has
// nothing the server could hold, and costs no lookup.
func TestSearchAsksTheFileStoreOnlyAboutED2KRows(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkTorrent] = releases("t", 2)
	cat.releases[networkUsenet] = releases("u", 2)
	own := &fakeOwnFiles{}
	cfg := searchConfig(cat)
	cfg.OwnFiles = own
	svc := NewService(ServiceConfig{MaxMetafileBytes: 1 << 20, Search: cfg}, newTestFetcher(newFakeSource()), nil)

	resp, err := svc.Search(context.Background(), &metav1.SearchRequest{Query: "x", Limit: 10})
	t.Logf("input:  torrent t0 t1, Usenet u0 u1, no Kad network")
	t.Logf("output: %v err=%v; lookups=%d", names(resp), err, len(own.asked))

	if err != nil || len(resp.GetEntries()) != 4 {
		t.Fatalf("got %v, err %v", names(resp), err)
	}
	if len(own.asked) != 0 {
		t.Fatalf("the file store was asked %d time(s) about a page with no eD2K row", len(own.asked))
	}
}
