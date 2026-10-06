package serverlink

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"enode/storage"

	"connectrpc.com/connect/v2"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
	"google.golang.org/protobuf/proto"
)

const testToken = "a-long-random-test-token"

// TestSearchFilesPagesAndFilters: a search returns the matching files in pages
// that follow next_offset, and applies type, size, source and exclude filters.
func TestSearchFilesPagesAndFilters(t *testing.T) {
	fx := startService(t, nil)
	client := fx.client(testToken, "")

	var names []string
	req := &metav1.ServerSearchRequest{Query: "linux", Limit: 4}
	for page := 0; ; page++ {
		res, err := client.SearchFiles(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("input:  query=%q limit=%d offset=%d", req.Query, req.Limit, req.Offset)
		t.Logf("output: %d files, total=%d, next_offset=%d", len(res.Files), res.Total, res.NextOffset)
		if res.Total != 10 {
			t.Fatalf("total %d, want the 10 linux files", res.Total)
		}
		for _, f := range res.Files {
			names = append(names, f.Name)
		}
		if res.NextOffset == 0 {
			break
		}
		if page > 10 {
			t.Fatal("paging does not end")
		}
		req.Offset = res.NextOffset
	}
	if len(names) != 10 || len(slices.Compact(slices.Sorted(slices.Values(names)))) != 10 {
		t.Fatalf("paged through %v, want 10 distinct files", names)
	}

	cases := []struct {
		name string
		req  *metav1.ServerSearchRequest
		want int
	}{
		{"two sources or more", &metav1.ServerSearchRequest{Query: "linux", MinSources: 2}, 5},
		{"at least 1005 bytes", &metav1.ServerSearchRequest{Query: "linux", MinSize: 1005}, 5},
		{"at most 1002 bytes", &metav1.ServerSearchRequest{Query: "linux", MaxSize: 1002}, 3},
		{"type Audio", &metav1.ServerSearchRequest{Query: "song", Type: "Audio"}, 1},
		{"type Video", &metav1.ServerSearchRequest{Query: "song", Type: "Video"}, 0},
		{"exclude", &metav1.ServerSearchRequest{Query: "linux", Exclude: []string{"distro0003"}}, 9},
		{"no match", &metav1.ServerSearchRequest{Query: "nosuchword"}, 0},
		{"left the server", &metav1.ServerSearchRequest{Query: "departed"}, 0},
	}
	for _, c := range cases {
		res, err := client.SearchFiles(context.Background(), c.req)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		t.Logf("input:  %s: %v", c.name, c.req)
		t.Logf("output: %d files", len(res.Files))
		if len(res.Files) != c.want {
			t.Errorf("%s: %d files, want %d", c.name, len(res.Files), c.want)
		}
	}

	res, err := client.SearchFiles(context.Background(), &metav1.ServerSearchRequest{Query: "song"})
	if err != nil || len(res.Files) != 1 {
		t.Fatalf("song: %v, %v", res, err)
	}
	song := res.Files[0]
	t.Logf("output: %v", song)
	if song.Artist != "The Artist" || song.Title != "The Title" || song.Album != "The Album" ||
		song.RuntimeSeconds != 215 || song.Bitrate != 320 || song.Codec != "mp3" || song.Type != "Audio" {
		t.Errorf("media tags were lost: %v", song)
	}
}

// TestSearchFilesRejects: a query without a keyword or too long is refused with
// its MsgCode, and a server that does not serve search says so.
func TestSearchFilesRejects(t *testing.T) {
	fx := startService(t, nil)
	client := fx.client(testToken, "")

	cases := []struct {
		query string
		code  connect.Code
		msg   string
	}{
		{"   ", connect.CodeInvalidArgument, CodeSearchQueryRequired},
		{string(bytes.Repeat([]byte("x"), maxQueryBytes+1)), connect.CodeInvalidArgument, CodeSearchQueryTooLong},
	}
	for _, c := range cases {
		_, err := client.SearchFiles(context.Background(), &metav1.ServerSearchRequest{Query: c.query})
		t.Logf("input:  a query of %d bytes", len(c.query))
		t.Logf("output: %v", err)
		expectError(t, err, c.code, c.msg)
	}

	off := startService(t, func(cfg *ServiceConfig) { cfg.Search, cfg.Browse = false, false })
	offClient := off.client(testToken, "")
	_, err := offClient.SearchFiles(context.Background(), &metav1.ServerSearchRequest{Query: "linux"})
	t.Logf("input:  a search on a server that serves none")
	t.Logf("output: %v", err)
	expectError(t, err, connect.CodeUnimplemented, CodeSearchDisabled)

	_, err = offClient.BrowseFiles(context.Background(), &metav1.BrowseFilesRequest{})
	t.Logf("input:  a browse on a server that serves none")
	t.Logf("output: %v", err)
	expectError(t, err, connect.CodeUnimplemented, CodeBrowseDisabled)

	info, err := offClient.GetServerInfo(context.Background(), &metav1.GetServerInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: %v", info)
	if info.SearchAvailable || info.BrowseAvailable {
		t.Errorf("the info still advertises search=%t browse=%t", info.SearchAvailable, info.BrowseAvailable)
	}
}

// TestBrowseFilesWalksTheCatalogue: a walk in small pages returns every shared
// file once, a token of another epoch answers reset, and one that was never
// issued is refused.
func TestBrowseFilesWalksTheCatalogue(t *testing.T) {
	fx := startService(t, nil)
	client := fx.client(testToken, "")

	info, err := client.GetServerInfo(context.Background(), &metav1.GetServerInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: %v", info)
	if info.ContractVersion != 1 || info.Name != "test-server" || info.CatalogEpoch == 0 ||
		!info.BrowseAvailable || info.MaxBrowseLimit != 5 || info.BrowseMinIntervalSeconds != 2 {
		t.Fatalf("unexpected info: %v", info)
	}

	var names []string
	var token, firstToken []byte
	pages := 0
	for {
		res, err := client.BrowseFiles(context.Background(), &metav1.BrowseFilesRequest{PageToken: token, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		t.Logf("input:  page %d, token of %d bytes", pages, len(token))
		t.Logf("output: %d files, next token of %d bytes, epoch=%d", len(res.Files), len(res.NextPageToken), res.CatalogEpoch)
		if len(res.Files) > 5 {
			t.Fatalf("a page of %d files passes the server's cap of 5", len(res.Files))
		}
		if res.Reset_ || res.CatalogEpoch != info.CatalogEpoch {
			t.Fatalf("unexpected reset=%t epoch=%d", res.Reset_, res.CatalogEpoch)
		}
		for _, f := range res.Files {
			names = append(names, f.Name)
		}
		if len(res.NextPageToken) == 0 {
			break
		}
		if firstToken == nil {
			firstToken = res.NextPageToken
		}
		if pages > 50 {
			t.Fatal("the walk does not end")
		}
		token = res.NextPageToken
	}
	slices.Sort(names)
	t.Logf("output: walked %d files in %d pages", len(names), pages)
	if len(names) != 11 || len(slices.Compact(slices.Clone(names))) != 11 {
		t.Fatalf("walked %v, want the 11 shared files once each", names)
	}
	if slices.Contains(names, "departed.iso") {
		t.Error("a file whose only source left the server was served")
	}

	stale := slices.Clone(firstToken)
	binary.BigEndian.PutUint64(stale, binary.BigEndian.Uint64(stale)+2)
	res, err := client.BrowseFiles(context.Background(), &metav1.BrowseFilesRequest{PageToken: stale})
	t.Logf("input:  a token of another epoch")
	t.Logf("output: %v, %v", res, err)
	if err != nil || !res.Reset_ || len(res.Files) != 0 || len(res.NextPageToken) != 0 {
		t.Fatalf("a token of another epoch answered %v, %v; want a reset", res, err)
	}

	_, err = client.BrowseFiles(context.Background(), &metav1.BrowseFilesRequest{PageToken: []byte{1, 2, 3}})
	t.Logf("input:  a token that was never issued")
	t.Logf("output: %v", err)
	expectError(t, err, connect.CodeInvalidArgument, CodeCursorInvalid)
}

// TestAnswersIdentifyNoClient is the privacy rule of the service, checked on the
// wire: no answer holds the address, the port, the client id or the user hash of
// a client that shares a file.
func TestAnswersIdentifyNoClient(t *testing.T) {
	fx := startService(t, func(cfg *ServiceConfig) { cfg.MaxBrowseLimit = 1000 })
	client := fx.client(testToken, "")

	search, err := client.SearchFiles(context.Background(), &metav1.ServerSearchRequest{Query: "linux", Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	browse, err := client.BrowseFiles(context.Background(), &metav1.BrowseFilesRequest{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(search.Files) == 0 || len(browse.Files) == 0 {
		t.Fatal("the answers are empty, so they prove nothing")
	}

	for name, msg := range map[string]proto.Message{"SearchFiles": search, "BrowseFiles": browse} {
		wire, err := proto.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("input:  %s answer, %d bytes on the wire", name, len(wire))
		for _, c := range fx.clients {
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
					t.Errorf("%s holds a client's %s (% x)", name, what, secret)
				}
			}
		}
		t.Logf("output: none of %d clients' address, port, id or user hash is in it", len(fx.clients))
	}
}

// TestAdmit: who may call, in both modes.
func TestAdmit(t *testing.T) {
	verified := func(ip net.IP) bool { return ip.IsLoopback() }

	cases := []struct {
		name     string
		gossip   bool
		token    string
		wantCode connect.Code // 0: admitted
	}{
		{"allowlist, the peer's token", false, testToken, 0},
		{"allowlist, no token", false, "", connect.CodeUnauthenticated},
		{"allowlist, a wrong token", false, "not-the-token", connect.CodeUnauthenticated},
		{"gossip, a verified server without a token", true, "", 0},
		{"gossip, the peer's token", true, testToken, 0},
		{"gossip, a verified server with a wrong token", true, "not-the-token", connect.CodeUnauthenticated},
	}
	for _, c := range cases {
		fx := startService(t, func(cfg *ServiceConfig) {
			if c.gossip {
				cfg.Verified = verified
			}
		})
		_, err := fx.client(c.token, "").GetServerInfo(context.Background(), &metav1.GetServerInfoRequest{})
		t.Logf("input:  %s", c.name)
		t.Logf("output: %v", err)
		if c.wantCode == 0 {
			if err != nil {
				t.Errorf("%s: refused: %v", c.name, err)
			}
			continue
		}
		expectError(t, err, c.wantCode, CodeUnauthorized)
	}

	blocked := startService(t, func(cfg *ServiceConfig) { cfg.Blocked = func(net.IP) bool { return true } })
	_, err := blocked.client(testToken, "").GetServerInfo(context.Background(), &metav1.GetServerInfoRequest{})
	t.Logf("input:  a caller the access filter blocks, with a good token")
	t.Logf("output: %v", err)
	expectError(t, err, connect.CodePermissionDenied, CodeUnauthorized)
	if n := blocked.svc.Stats().AuthFailures.Load(); n != 1 {
		t.Errorf("auth failures = %d, want 1", n)
	}
}

// TestRateLimits: the per-address limit stops a caller before it is identified,
// the per-peer limit after.
func TestRateLimits(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(*ServiceConfig)
	}{
		{"per address", func(cfg *ServiceConfig) { cfg.PerIPPerMinute = 3 }},
		{"per peer", func(cfg *ServiceConfig) { cfg.PerPeerPerMinute = 3 }},
	} {
		fx := startService(t, c.set)
		client := fx.client(testToken, "")
		var last error
		passed := 0
		for range 6 {
			if _, last = client.GetServerInfo(context.Background(), &metav1.GetServerInfoRequest{}); last == nil {
				passed++
			}
		}
		t.Logf("input:  6 calls against a limit of 3 %s", c.name)
		t.Logf("output: %d passed, then %v", passed, last)
		if passed != 3 {
			t.Errorf("%s: %d calls passed, want 3", c.name, passed)
		}
		expectError(t, last, connect.CodeResourceExhausted, CodeRateLimited)
		if n := fx.svc.Stats().RateLimited.Load(); n != 3 {
			t.Errorf("%s: rate limited = %d, want 3", c.name, n)
		}
	}
}

// TestClientPinsTheFingerprint: over TLS with a self-signed certificate, the
// client reaches the server with the right pin and refuses it with a wrong one
// or with none.
func TestClientPinsTheFingerprint(t *testing.T) {
	cert, key := selfSignedCert(t)
	fx := startServiceTLS(t, cert, key)
	pin := fx.server.Fingerprint()
	t.Logf("input:  a server with a self-signed certificate, fingerprint %s", pin)
	if len(pin) < 20 {
		t.Fatalf("no fingerprint: %q", pin)
	}

	info, err := fx.client(testToken, pin).GetServerInfo(context.Background(), &metav1.GetServerInfoRequest{})
	t.Logf("output: with the pin: %v, %v", info, err)
	if err != nil {
		t.Fatalf("the pinned client was refused: %v", err)
	}

	_, err = fx.client(testToken, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").
		GetServerInfo(context.Background(), &metav1.GetServerInfoRequest{})
	t.Logf("output: with another pin: %v", err)
	if err == nil || !errors.Is(err, ErrFingerprint) {
		t.Errorf("a wrong pin gave %v, want ErrFingerprint", err)
	}

	_, err = fx.client(testToken, "").GetServerInfo(context.Background(), &metav1.GetServerInfoRequest{})
	t.Logf("output: without a pin: %v", err)
	if err == nil {
		t.Error("a self-signed certificate was accepted without a pin")
	}
}

// -- internals ---------------------------------------------------------------

type fixture struct {
	t       *testing.T
	svc     *Service
	server  *Server
	engine  *storage.MemoryEngine
	clients []storage.ClientInfo
	url     string
}

// client returns a real client of the fixture's listener.
func (fx *fixture) client(token, fingerprint string) metav1connect.ServerSearchClient {
	return NewClient(ClientConfig{URL: fx.url, Token: token, Fingerprint: fingerprint})
}

// startService runs the service on a loopback port over a memory engine holding
// ten "linux" files (the even ones from two clients), one song with media tags,
// and one file whose only client has left.
func startService(t *testing.T, adjust func(*ServiceConfig)) *fixture {
	t.Helper()
	return startFixture(t, adjust, "", "")
}

func startServiceTLS(t *testing.T, cert, key string) *fixture {
	t.Helper()
	return startFixture(t, nil, cert, key)
}

func startFixture(t *testing.T, adjust func(*ServiceConfig), cert, key string) *fixture {
	t.Helper()
	engine, clients := seedEngine(t)
	cfg := ServiceConfig{
		Name:              func() string { return "test-server" },
		Search:            true,
		Browse:            true,
		MaxSearchLimit:    200,
		MaxBrowseLimit:    5,
		BrowseMinInterval: 2 * time.Second,
		CacheEntries:      100,
		CacheTTL:          time.Minute,
		Tokens:            []string{"another-peers-token", testToken},
	}
	if adjust != nil {
		adjust(&cfg)
	}
	fx := &fixture{t: t, engine: engine, clients: clients, svc: NewService(cfg, engine)}
	srv, err := NewServer(ServerConfig{Listen: "127.0.0.1:0", CertFile: cert, KeyFile: key}, fx.svc)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	fx.server = srv
	scheme := "http"
	if cert != "" {
		scheme = "https"
	}
	fx.url = scheme + "://" + srv.Addr().String()
	return fx
}

// seedEngine fills a memory engine and returns it with the clients that offered
// the files, whose identities no answer may hold.
func seedEngine(t *testing.T) (*storage.MemoryEngine, []storage.ClientInfo) {
	t.Helper()
	engine := storage.NewMemoryEngine()
	clients := []storage.ClientInfo{
		{ID: 0xC0A8F1E2, IPv4: 0xE2F1A8C0, Port: 47291, Hash: []byte("user-hash-aaaaa1")},
		{ID: 0x5BD37A91, IPv4: 0x917AD35B, Port: 51873, Hash: []byte("user-hash-bbbbb2")},
		{ID: 0x2E94C6D3, IPv4: 0xD3C6942E, Port: 39417, Hash: []byte("user-hash-ccccc3")},
	}
	for i := range clients {
		id, err := engine.Connect(clients[i])
		if err != nil {
			t.Fatal(err)
		}
		clients[i].StoreID = id
	}
	a, b, c := clients[0], clients[1], clients[2]
	for i := range 10 {
		f := storage.File{
			Hash: []byte(fmt.Sprintf("file-hash-%06d", i)),
			Name: fmt.Sprintf("linux.distro%04d.iso", i),
			Size: uint64(1000 + i),
			Type: "Pro",
		}
		engine.AddFile(f, a)
		if i%2 == 0 {
			engine.AddFile(f, b)
		}
	}
	engine.AddFile(storage.File{
		Hash: []byte("file-hash-song01"), Name: "a.song.mp3", Size: 5000, Type: "Audio",
		Title: "The Title", Artist: "The Artist", Album: "The Album", Runtime: 215, Bitrate: 320, Codec: "mp3",
	}, a)
	engine.AddFile(storage.File{Hash: []byte("file-hash-gone01"), Name: "departed.iso", Size: 7000, Type: "Pro"}, c)
	engine.Disconnect(c)
	return engine, clients
}

// expectError fails unless err is a connect error of code carrying msgCode.
func expectError(t *testing.T, err error, code connect.Code, msgCode string) {
	t.Helper()
	if err == nil {
		t.Errorf("no error, want %s / %s", code, msgCode)
		return
	}
	if got := connect.CodeOf(err); got != code {
		t.Errorf("code %s, want %s (%v)", got, code, err)
	}
	if got := MsgCodeOf(err); got != msgCode {
		t.Errorf("msg_code %q, want %q", got, msgCode)
	}
}

// selfSignedCert writes a self-signed certificate for 127.0.0.1 and returns the
// paths of the certificate and its key.
func selfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "serverlink test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
