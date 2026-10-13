package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// fakeViews records what the write routes did and serves fixed rows.
type fakeViews struct {
	features     Features
	clients      []ClientRow
	disconnected string
	servers      []ServerRow
	bans         []BanRow
	reloaded     bool
	updated      bool
}

func (f *fakeViews) Features() Features   { return f.features }
func (f *fakeViews) Clients() []ClientRow { return f.clients }
func (f *fakeViews) DisconnectClient(hash string) error {
	if hash != "aa" {
		return ErrNotFound
	}
	f.disconnected = hash
	return nil
}
func (f *fakeViews) Files(q FileQuery) (FilePage, error) {
	return FilePage{Rows: []FileRow{{Hash: "h1", Name: q.Search + "|" + q.Cursor, Size: uint64(q.Limit)}}, Next: "n1"}, nil
}
func (f *fakeViews) FileSources(hash string) ([]SourceRow, error) {
	if hash == "bad" {
		return nil, errors.New("invalid file hash")
	}
	return nil, nil
}
func (f *fakeViews) Peers() PeersView { return PeersView{Static: f.servers} }
func (f *fakeViews) AddServer(ip string, port uint16) error {
	f.servers = append(f.servers, ServerRow{IP: ip, Port: port})
	return nil
}
func (f *fakeViews) RemoveServer(ip string, port uint16) error {
	for i, s := range f.servers {
		if s.IP == ip && s.Port == port {
			f.servers = append(f.servers[:i], f.servers[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}
func (f *fakeViews) Filter() FilterView  { return FilterView{} }
func (f *fakeViews) ReloadFilter() error { f.reloaded = true; return nil }
func (f *fakeViews) UpdateFilter(context.Context) ([]FilterUpdateRow, error) {
	f.updated = true
	return []FilterUpdateRow{{Name: "hash ban list", Entries: 3}}, nil
}
func (f *fakeViews) Bans() ([]BanRow, error) { return f.bans, nil }
func (f *fakeViews) AddBan(key string, minutes int) error {
	if !strings.HasPrefix(key, "ip:") && !strings.HasPrefix(key, "hash:") {
		return errors.New("bad ban key")
	}
	f.bans = append(f.bans, BanRow{Key: key, RemainingSeconds: int64(minutes) * 60})
	return nil
}
func (f *fakeViews) RemoveBan(key string) error {
	for i, b := range f.bans {
		if b.Key == key {
			f.bans = append(f.bans[:i], f.bans[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}
func (f *fakeViews) Bots() []BotRow       { return nil }
func (f *fakeViews) Blocks() []BlockRow   { return []BlockRow{{Reason: "rate limit", Count: 4}} }
func (f *fakeViews) Health() HealthView   { return HealthView{} }
func (f *fakeViews) Runtime() RuntimeView { return RuntimeView{GoVersion: "go-test"} }
func (f *fakeViews) Config() (ConfigView, error) {
	return ConfigView{Path: "/etc/enode/enode.config.yaml", YAML: "name: t\n"}, nil
}

func newViewServer(user, pass string) (*Server, *fakeViews) {
	s, _ := newAuthServer(user, pass)
	fv := &fakeViews{features: Features{Bans: true, Bots: true, FilterReload: true, FilterUpdate: true}}
	s.SetViews(fv)
	return s, fv
}

// write marks a request as a same-origin admin write, with an optional JSON body.
func write(body string) func(*http.Request) {
	return func(r *http.Request) {
		r.Header.Set(adminWriteHeader, "1")
		if body != "" {
			r.Body = http.NoBody
			r2, _ := http.NewRequest(r.Method, r.URL.String(), strings.NewReader(body))
			r.Body, r.ContentLength = r2.Body, r2.ContentLength
		}
	}
}

// viewReadRoutes are every GET route of the tabs.
var viewReadRoutes = []string{
	"/api/clients", "/api/clients/summary", "/api/files", "/api/files/aa/sources", "/api/peers",
	"/api/filter", "/api/bans", "/api/bots", "/api/blocks", "/api/health", "/api/runtime", "/api/config",
}

func TestViewRoutesAreSensitive(t *testing.T) {
	open, _ := newViewServer("", "")
	locked, _ := newViewServer("root", "s3cret")
	remote := "192.0.2.7:4000"
	for _, path := range viewReadRoutes {
		local := do(open, "GET", path, "", nil).Code
		anon := do(open, "GET", path, remote, nil).Code
		noAuth := do(locked, "GET", path, remote, nil).Code
		auth := do(locked, "GET", path, remote, func(r *http.Request) { r.SetBasicAuth("root", "s3cret") }).Code
		t.Logf("input: GET %s output: loopback=%d remote-without-credentials-configured=%d remote-unauthenticated=%d remote-authenticated=%d",
			path, local, anon, noAuth, auth)
		if local != 200 || anon != 403 || noAuth != 401 || auth != 200 {
			t.Errorf("GET %s: loopback=%d anon=%d noAuth=%d auth=%d, want 200 403 401 200", path, local, anon, noAuth, auth)
		}
	}
}

func TestViewRoutesAbsentWithoutViews(t *testing.T) {
	s, _ := newAuthServer("", "")
	for _, path := range viewReadRoutes {
		code := do(s, "GET", path, "", nil).Code
		t.Logf("input: GET %s with no views attached output: %d", path, code)
		if code != 404 {
			t.Errorf("GET %s: %d, want 404", path, code)
		}
	}
}

func TestViewWritesNeedHeaderAndSameOrigin(t *testing.T) {
	writes := []struct{ method, path, body string }{
		{"POST", "/api/clients/aa/disconnect", ""},
		{"POST", "/api/servers", `{"ip":"203.0.113.5","port":4661}`},
		{"DELETE", "/api/servers/203.0.113.5/4661", ""},
		{"POST", "/api/filter/reload", ""},
		{"POST", "/api/filter/update", ""},
		{"POST", "/api/bans", `{"key":"ip:203.0.113.9","minutes":60}`},
		{"DELETE", "/api/bans/ip:203.0.113.9", ""},
	}
	for _, c := range writes {
		s, fv := newViewServer("", "")
		fv.servers = []ServerRow{{IP: "203.0.113.5", Port: 4661}}
		fv.bans = []BanRow{{Key: "ip:203.0.113.9"}}

		bare := do(s, c.method, c.path, "", nil).Code
		foreign := do(s, c.method, c.path, "", func(r *http.Request) {
			write(c.body)(r)
			r.Header.Set("Origin", "https://evil.example")
		}).Code
		untouched := fv.disconnected == "" && !fv.reloaded && !fv.updated && len(fv.servers) == 1 && len(fv.bans) == 1
		remote := do(s, c.method, c.path, "192.0.2.7:4000", write(c.body)).Code
		ok := do(s, c.method, c.path, "", write(c.body))
		t.Logf("input: %s %s output: no-header=%d cross-origin=%d untouched=%t remote=%d same-origin=%d %s",
			c.method, c.path, bare, foreign, untouched, remote, ok.Code, strings.TrimSpace(ok.Body.String()))
		if bare != 403 || foreign != 403 || !untouched {
			t.Errorf("%s %s reached without the admin header or cross-origin: %d %d untouched=%t", c.method, c.path, bare, foreign, untouched)
		}
		if remote != 403 {
			t.Errorf("%s %s from a remote without credentials: %d, want 403", c.method, c.path, remote)
		}
		if ok.Code != 200 {
			t.Errorf("%s %s same-origin: %d %s", c.method, c.path, ok.Code, ok.Body)
		}
	}
}

func TestViewWritesChangeState(t *testing.T) {
	s, fv := newViewServer("", "")

	do(s, "POST", "/api/clients/aa/disconnect", "", write(""))
	missing := do(s, "POST", "/api/clients/bb/disconnect", "", write("")).Code
	do(s, "POST", "/api/servers", "", write(`{"ip":"203.0.113.5","port":4661}`))
	badServer := do(s, "POST", "/api/servers", "", write(`{"ip":"not-an-ip","port":4661}`)).Code
	do(s, "POST", "/api/bans", "", write(`{"key":"ip:2001:db8::/64","minutes":30}`))
	badBan := do(s, "POST", "/api/bans", "", write(`{"key":"ip:203.0.113.9","minutes":0}`)).Code
	t.Logf("input: disconnect aa, disconnect bb, add server, add bad server, ban a /64, ban for 0 minutes")
	t.Logf("output: disconnected=%q missing=%d servers=%+v badServer=%d bans=%+v badBan=%d",
		fv.disconnected, missing, fv.servers, badServer, fv.bans, badBan)
	if fv.disconnected != "aa" || missing != 404 {
		t.Errorf("disconnect: got %q, unknown client -> %d", fv.disconnected, missing)
	}
	if len(fv.servers) != 1 || badServer != 400 {
		t.Errorf("servers = %+v, bad address -> %d", fv.servers, badServer)
	}
	if len(fv.bans) != 1 || fv.bans[0].RemainingSeconds != 1800 || badBan != 400 {
		t.Errorf("bans = %+v, zero minutes -> %d", fv.bans, badBan)
	}

	// The key of an IPv6 ban holds a slash, which must survive the URL.
	code := do(s, "DELETE", "/api/bans/ip:2001:db8::/64", "", write("")).Code
	gone := do(s, "DELETE", "/api/bans/ip:2001:db8::/64", "", write("")).Code
	t.Logf("input: lift ip:2001:db8::/64 twice output: %d then %d, bans=%+v", code, gone, fv.bans)
	if code != 200 || gone != 404 || len(fv.bans) != 0 {
		t.Errorf("lifting the ban: %d then %d, bans=%+v", code, gone, fv.bans)
	}
}

func TestFilterButtonsFollowFeatures(t *testing.T) {
	s, fv := newViewServer("", "")
	fv.features = Features{}
	reload := do(s, "POST", "/api/filter/reload", "", write("")).Code
	update := do(s, "POST", "/api/filter/update", "", write("")).Code
	page := do(s, "GET", "/", "", nil).Body.String()
	t.Logf("input: no filter enabled output: reload=%d update=%d reloaded=%t updated=%t", reload, update, fv.reloaded, fv.updated)
	if reload != 404 || update != 404 || fv.reloaded || fv.updated {
		t.Errorf("filter writes ran with no filter enabled: %d %d", reload, update)
	}
	for _, id := range []string{`id="flReload"`, `id="flUpdate"`, `id="tab-bans"`, `id="tab-bots"`} {
		if strings.Contains(page, id) {
			t.Errorf("page renders %s with its feature off", id)
		}
	}

	fv.features = Features{Bans: true, Bots: true, FilterReload: true, FilterUpdate: true}
	page = do(s, "GET", "/", "", nil).Body.String()
	for _, id := range []string{`id="flReload"`, `id="flUpdate"`, `id="tab-bans"`, `id="tab-bots"`, `id="tab-accounts"`,
		`id="tab-status"`, `id="tab-clients"`, `id="tab-files"`, `id="tab-peers"`, `id="tab-filter"`, `id="tab-blocks"`,
		`id="tab-health"`, `id="tab-runtime"`, `id="tab-config"`} {
		if !strings.Contains(page, id) {
			t.Errorf("page is missing %s with every feature on", id)
		}
	}
}

func TestPageWithoutViewsHasNoTabs(t *testing.T) {
	s := New(Config{}, StaticInfo{Name: "t"}, func() LiveStats { return LiveStats{} })
	page := do(s, "GET", "/", "", nil).Body.String()
	t.Logf("input: no views attached output: %d bytes, tab bar=%t status=%t", len(page),
		strings.Contains(page, `id="tabs"`), strings.Contains(page, `id="tab-status"`))
	if strings.Contains(page, `id="tabs"`) || strings.Contains(page, `id="tab-clients"`) {
		t.Errorf("the tab bar is rendered without views")
	}
	if !strings.Contains(page, `id="tab-status"`) || !strings.Contains(page, `id="clients"`) {
		t.Errorf("the status page is missing")
	}
}

func TestPageClients(t *testing.T) {
	rows := []ClientRow{
		{Hash: "a1", IP: "82.48.1.9", Nick: "Alice", Software: "eMule 0.50a", Country: "IT", Files: 10, ConnectedSeconds: 300},
		{Hash: "b2", IP: "82.48.7.7", Nick: "bob", Software: "aMule 2.3.3", Country: "IT", Files: 900, LowID: true, ConnectedSeconds: 100},
		{Hash: "c3", IP: "203.0.113.4", Nick: "carol", Software: "eMule 0.60d", Country: "DE", Files: 50, IPv6: "2001:db8::4", ConnectedSeconds: 200},
	}
	cases := []struct {
		name string
		q    clientQuery
		want []string
	}{
		{"default is longest connected first", clientQuery{}, []string{"a1", "c3", "b2"}},
		{"ascending files", clientQuery{Sort: "files", Ascending: true}, []string{"a1", "c3", "b2"}},
		{"cidr", clientQuery{Search: "82.48.0.0/16", Sort: "ip", Ascending: true}, []string{"a1", "b2"}},
		{"nick substring ignores case", clientQuery{Search: "ALI"}, []string{"a1"}},
		{"ipv6 substring", clientQuery{Search: "2001:db8"}, []string{"c3"}},
		{"country and software family", clientQuery{Country: "IT", Software: "eMule"}, []string{"a1"}},
		{"low id only", clientQuery{ID: "low"}, []string{"b2"}},
		{"second page", clientQuery{Offset: 2, Limit: 2}, []string{"b2"}},
		{"offset past the end", clientQuery{Offset: 9}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page := pageClients(rows, tc.q)
			got := []string{}
			for _, r := range page.Rows {
				got = append(got, r.Hash)
			}
			t.Logf("input: %+v", tc.q)
			t.Logf("output: total=%d matched=%d rows=%v", page.Total, page.Matched, got)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("rows = %v, want %v", got, tc.want)
			}
			if page.Total != len(rows) {
				t.Fatalf("total = %d, want %d", page.Total, len(rows))
			}
		})
	}
}

func TestSummarizeClients(t *testing.T) {
	sum := summarizeClients([]ClientRow{
		{Software: "eMule 0.50a", Country: "IT"}, {Software: "eMule 0.60d", Country: "DE"}, {Software: "aMule 2.3.3", Country: "IT"},
	})
	out, _ := json.Marshal(sum)
	t.Logf("input: 2 eMule (IT, DE) and 1 aMule (IT)")
	t.Logf("output: %s", out)
	if sum.Total != 3 || sum.Software[0] != (CountRow{Name: "eMule", Count: 2}) || sum.Countries[0] != (CountRow{Name: "IT", Count: 2}) {
		t.Fatalf("summary = %+v", sum)
	}
}

func TestFilesQueryIsClamped(t *testing.T) {
	s, _ := newViewServer("", "")
	w := do(s, "GET", "/api/files?q=+linux+&cursor=abc&limit=99999", "", nil)
	var page FilePage
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	t.Logf("input: q=' linux ' cursor=abc limit=99999 output: %d %+v", w.Code, page)
	if w.Code != 200 || len(page.Rows) != 1 || page.Rows[0].Name != "linux|abc" || page.Rows[0].Size != maxFilePage || page.Next != "n1" {
		t.Fatalf("files page = %+v", page)
	}
	if code := do(s, "GET", "/api/files/bad/sources", "", nil).Code; code != 400 {
		t.Fatalf("a bad hash answered %d, want 400", code)
	}
}
