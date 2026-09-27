package metaapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"enode/meta"

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
	for _, n := range []string{networkTorrent, networkUsenet} {
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

	// Only torrent enabled: a Usenet search finds nothing, and Caps lists torrent only.
	only := newFakeCatalog()
	only.releases[networkTorrent] = releases("t", 1)
	svc = searchService(only)
	resp, err := svc.Search(context.Background(), &metav1.SearchRequest{Query: "x", Network: metav1.MetaNetwork_META_NETWORK_USENET})
	caps, _ := svc.GetCaps(context.Background(), &metav1.GetCapsRequest{})
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
