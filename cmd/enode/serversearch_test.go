package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"enode/admin"
	"enode/serverlink"
	"enode/storage"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
)

// serverSearchTestConfig is one of the two servers of the end-to-end test.
type serverSearchTestConfig struct {
	name       string
	tcpPort    uint16
	udpPort    uint16
	adminPort  uint16
	searchPort uint16
	// metaPort is the Meta API's HTTP listener, with the servers network on.
	metaPort uint16
	// seed fills the engine from the debug fixtures.
	seed bool
	// peerPort, when set, is the other server's search port: this one mirrors it
	// and asks it on a search.
	peerPort uint16
	token    string
}

func (c serverSearchTestConfig) write(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	fixtures, err := filepath.Abs("../../tests/data/debug_fixtures.yaml")
	if err != nil {
		t.Fatal(err)
	}
	peers, consume := "[]", "false"
	if c.peerPort != 0 {
		peers = fmt.Sprintf("\n    - { url: \"http://127.0.0.1:%d\", token: %q }", c.peerPort, c.token)
		consume = "true"
	} else {
		peers = fmt.Sprintf("\n    - { token: %q }", c.token)
	}
	body := fmt.Sprintf(`
name: %q
address: "127.0.0.1"
dynIp: "127.0.0.1"
supportCrypt: false
logLevel: "error"
logFile: %q
tcp:
  port: %d
  portObfuscated: %d
udp:
  port: %d
  portObfuscated: %d
  serverKey: 305419896
natTraversal:
  enabled: false
admin:
  enabled: true
  bindIP: "127.0.0.1"
  port: %d
  checkUpdates: false
gossip:
  enabled: false
serverSearch:
  enabled: true
  listen: "127.0.0.1:%d"
  serve:
    browseMinIntervalSeconds: 0
  peers: %s
  search:
    enabled: %s
  mirror:
    enabled: %s
metaApi:
  enabled: true
  grpc:
    enabled: false
  http:
    enabled: true
    listen: "127.0.0.1:%d"
  search:
    servers: true
debug:
  seedFixtures: %t
  fixturesFile: %q
storage:
  engine: memory
`, c.name, filepath.Join(dir, "enode.log"), c.tcpPort, c.tcpPort+1, c.udpPort, c.udpPort+1,
		c.adminPort, c.searchPort, peers, consume, consume, c.metaPort, c.seed, fixtures)
	path := filepath.Join(dir, "enode.config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func startRun(t *testing.T, path string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, path) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("run returned %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("run did not return after cancel")
		}
	})
}

func serverSearchStats(t *testing.T, adminPort uint16) *admin.ServerSearchStats {
	t.Helper()
	var stats admin.LiveStats
	if err := json.Unmarshal([]byte(adminGet(t, adminPort, "/stats.json")), &stats); err != nil {
		t.Fatalf("stats.json: %v", err)
	}
	return stats.ServerSearch
}

// TestServerSearchBetweenTwoServers runs two real servers. One holds the debug
// fixtures and serves them; the other is configured with it as a peer, mirrors its
// catalogue and shows it on the dashboard. A third party with the token can search
// the first, and one without it cannot.
func TestServerSearchBetweenTwoServers(t *testing.T) {
	const token = "end-to-end-test-token"
	a := serverSearchTestConfig{name: "serving", tcpPort: freePort(t), udpPort: freePort(t), adminPort: freePort(t),
		searchPort: freePort(t), metaPort: freePort(t), seed: true, token: token}
	b := serverSearchTestConfig{name: "asking", tcpPort: freePort(t), udpPort: freePort(t), adminPort: freePort(t),
		searchPort: freePort(t), metaPort: freePort(t), peerPort: a.searchPort, token: token}
	startRun(t, a.write(t))

	url := fmt.Sprintf("http://127.0.0.1:%d", a.searchPort)
	client := serverlink.NewClient(serverlink.ClientConfig{URL: url, Token: token})
	var info *metav1.ServerInfo
	deadline := time.Now().Add(10 * time.Second)
	for {
		var err error
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		info, err = client.GetServerInfo(ctx, &metav1.GetServerInfoRequest{})
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the serving server's search listener never answered: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("input:  GetServerInfo on the serving server")
	t.Logf("output: %v", info)
	if info.Name != "serving" || !info.SearchAvailable || !info.BrowseAvailable || info.Files == 0 {
		t.Fatalf("unexpected info: %v", info)
	}

	res, err := client.SearchFiles(context.Background(), &metav1.ServerSearchRequest{Query: "debian"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input:  SearchFiles %q with the token", "debian")
	t.Logf("output: %v", res)
	if len(res.Files) != 1 || res.Files[0].Name != "Debian-13-amd64-netinst.iso" || res.Files[0].Sources != 3 {
		t.Fatalf("search answered %v, want the Debian image with its 3 sources", res)
	}

	_, err = serverlink.NewClient(serverlink.ClientConfig{URL: url}).
		SearchFiles(context.Background(), &metav1.ServerSearchRequest{Query: "debian"})
	t.Logf("input:  the same search without a token")
	t.Logf("output: %v", err)
	if serverlink.MsgCodeOf(err) != serverlink.CodeUnauthorized {
		t.Fatalf("a caller without a token got %v, want %s", err, serverlink.CodeUnauthorized)
	}

	// The asking server starts only now that the serving one answers: a first walk
	// that is refused is not retried within the time this test waits. It then walks
	// the serving one on its own.
	startRun(t, b.write(t))
	waitListening(t, b.adminPort)
	var asking *admin.ServerSearchStats
	deadline = time.Now().Add(15 * time.Second)
	for {
		asking = serverSearchStats(t, b.adminPort)
		if asking != nil && len(asking.Peers) == 1 && asking.Peers[0].Mirrored {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the asking server never mirrored its peer: %+v", asking)
		}
		time.Sleep(50 * time.Millisecond)
	}
	peer := asking.Peers[0]
	t.Logf("input:  the asking server's dashboard figures")
	t.Logf("output: mode=%s mirrorFiles=%d peer=%+v", asking.Mode, asking.MirrorFiles, peer)
	if asking.Mode != "allowlist" || asking.MirrorFiles != 4 || peer.MirrorFiles != 4 ||
		peer.Name != "serving" || !peer.Static || peer.URL != url {
		t.Errorf("unexpected mirror state: %+v / %+v", asking, peer)
	}

	serving := serverSearchStats(t, a.adminPort)
	t.Logf("input:  the serving server's dashboard figures")
	t.Logf("output: %+v", serving)
	if serving == nil || serving.Browses == 0 || serving.FilesServed < 5 || serving.AuthFailures != 1 || len(serving.Peers) != 0 {
		t.Errorf("unexpected serving figures: %+v", serving)
	}

	// MetaApi.Search on either server, neither of which has a catalogue daemon: the
	// serving one answers with its own users' file, the asking one with its peer's.
	for _, srv := range []serverSearchTestConfig{a, b} {
		api := metav1connect.NewMetaApiClient(connect.NewClient(
			connecthttp.NewTransport(http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d", srv.metaPort))))
		caps, err := api.GetCaps(context.Background(), &metav1.GetCapsRequest{})
		if err != nil {
			t.Fatalf("%s: GetCaps: %v", srv.name, err)
		}
		found, err := api.Search(context.Background(), &metav1.SearchRequest{
			Query: "debian", Network: metav1.MetaNetwork_META_NETWORK_SERVERS,
		})
		if err != nil {
			t.Fatalf("%s: MetaApi.Search: %v", srv.name, err)
		}
		t.Logf("input:  MetaApi.Search %q on the servers network of the %s server", "debian", srv.name)
		t.Logf("output: networks=%v total=%d exact=%t entries=%v", caps.GetNetworks(), found.GetTotal(), found.GetTotalExact(), found.GetEntries())
		if !slices.Equal(caps.GetNetworks(), []metav1.MetaNetwork{metav1.MetaNetwork_META_NETWORK_SERVERS}) {
			t.Errorf("%s: networks %v, want the servers network alone", srv.name, caps.GetNetworks())
		}
		if len(found.GetEntries()) != 1 {
			t.Fatalf("%s: %d entries, want the Debian image", srv.name, len(found.GetEntries()))
		}
		e := found.GetEntries()[0]
		if e.GetName() != "Debian-13-amd64-netinst.iso" || e.GetKind() != metav1.MetaKind_META_KIND_ED2K ||
			len(e.GetMetaHash()) != 16 || e.GetPeers() != 3 || !found.GetTotalExact() {
			t.Errorf("%s: unexpected entry %v", srv.name, e)
		}
	}
}

// waitListening waits until something accepts TCP connections on the local port.
func waitListening(t *testing.T, port uint16) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing listens on port %d: %v", port, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fakeRows is a catalogue searcher that returns fixed rows.
type fakeRows struct {
	rows       []storage.File
	nativeOnly []bool
}

func (f *fakeRows) Search(_ context.Context, _ *storage.SearchExpr, _, nativeOnly bool) []storage.File {
	f.nativeOnly = append(f.nativeOnly, nativeOnly)
	return slices.Clone(f.rows)
}
func (f *fakeRows) AdvertisedFiles() int    { return 7 }
func (f *fakeRows) NetworkUsers(string) int { return 9 }

// TestCombinedSearcher: what the runtime attaches is nil when there is nothing to
// ask, the catalogue searcher itself when there is no server to ask, and otherwise
// both, with only the catalogue counted in the advertised figures.
func TestCombinedSearcher(t *testing.T) {
	if got := newCombinedSearcher(nil, nil); got != nil {
		t.Errorf("nothing to ask must attach nothing, got %T", got)
	}
	catalogue := &fakeRows{rows: []storage.File{{Hash: []byte("meta-row-hash-01"), Name: "a.catalogue.row"}}}
	if got := newCombinedSearcher(catalogue, nil); got != catalogue {
		t.Errorf("without a server searcher the catalogue searcher is attached as it is, got %T", got)
	}

	servers := serverlink.NewSearcher(serverlink.SearcherConfig{})
	both := newCombinedSearcher(catalogue, servers)
	rows := both.Search(context.Background(), &storage.SearchExpr{Kind: storage.SearchText, Text: "row"}, false, true)
	t.Logf("input:  a search of a catalogue with one row and a server searcher with no peers")
	t.Logf("output: %d rows, advertised files=%d, kad users=%d, nativeOnly passed on=%v",
		len(rows), both.AdvertisedFiles(), both.NetworkUsers("kad"), catalogue.nativeOnly)
	if len(rows) != 1 || both.AdvertisedFiles() != 7 || both.NetworkUsers("kad") != 9 || !slices.Equal(catalogue.nativeOnly, []bool{true}) {
		t.Errorf("rows=%d files=%d users=%d nativeOnly=%v", len(rows), both.AdvertisedFiles(), both.NetworkUsers("kad"), catalogue.nativeOnly)
	}

	alone := newCombinedSearcher(nil, servers)
	if rows := alone.Search(context.Background(), &storage.SearchExpr{Kind: storage.SearchText, Text: "row"}, false, false); len(rows) != 0 {
		t.Errorf("no peers, yet %d rows", len(rows))
	}
	if alone.AdvertisedFiles() != 0 || alone.NetworkUsers("kad") != 0 {
		t.Errorf("another server's files must not be advertised as ours")
	}
}
