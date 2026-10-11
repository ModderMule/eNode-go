package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enode/config"
	"enode/contentfilter"
	"enode/ed2k"
	"enode/storage"
)

func writeHashList(t *testing.T, path string, hashes ...[]byte) {
	t.Helper()
	var body string
	for _, h := range hashes {
		body += hex.EncodeToString(h) + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestFilteredFilesWithholdsOnEveryRead covers the store handed to the server-to-server
// service and the Meta API: search, browse and the shared-files lookup.
func TestFilteredFilesWithholdsOnEveryRead(t *testing.T) {
	engine := storage.NewMemoryEngine()
	owner := storage.ClientInfo{Hash: []byte("0123456789abcdef"), ID: 0x0100007F, Port: 4662}
	if _, err := engine.Connect(owner); err != nil {
		t.Fatal(err)
	}
	clean, listed, named := []byte("aaaaaaaaaaaaaaaa"), []byte("bbbbbbbbbbbbbbbb"), []byte("cccccccccccccccc")
	engine.AddFile(storage.File{Hash: clean, Size: 1, Name: "share clean.bin"}, owner)
	engine.AddFile(storage.File{Hash: listed, Size: 2, Name: "share listed.bin"}, owner)
	engine.AddFile(storage.File{Hash: named, Size: 3, Name: "share badword.bin"}, owner)

	list := filepath.Join(t.TempDir(), "hash_filter.txt")
	writeHashList(t, list, listed)
	filter, err := contentfilter.New(context.Background(), contentfilter.Config{Keywords: "badword", FilterFile: list})
	if err != nil {
		t.Fatal(err)
	}
	served := withFilter(engine, filter)

	found := served.FindBySearch(&storage.SearchExpr{Kind: storage.SearchText, Text: "share"})
	browsed, _, err := served.BrowseFiles(nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	shared := served.SharedFiles([][]byte{clean, listed, named})
	t.Logf("input: 3 files, one on the filter list, one named with a keyword; output: search=%d browse=%d shared=%d raw=%d",
		len(found), len(browsed), len(shared), len(engine.FindBySearch(&storage.SearchExpr{Kind: storage.SearchText, Text: "share"})))
	for name, got := range map[string][]storage.File{"FindBySearch": found, "BrowseFiles": browsed, "SharedFiles": shared} {
		if len(got) != 1 || !bytes.Equal(got[0].Hash, clean) {
			t.Errorf("%s served %d file(s), want only the clean one", name, len(got))
		}
	}
	if served.FilesCount() != 3 {
		t.Errorf("FilesCount = %d, want the engine's own 3", served.FilesCount())
	}
	if served.FilesCountEstimate() != 3 {
		t.Errorf("FilesCountEstimate = %d, want the engine's own 3", served.FilesCountEstimate())
	}
	if withFilter(engine, nil) != storage.Engine(engine) {
		t.Error("with no filter the engine must be passed through unwrapped")
	}
}

// TestRunUpdateFilters drives `enode -update-filters` against a fake update service,
// with the access key the real server would present for its reference IP.
func TestRunUpdateFilters(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(strings.Repeat("0123456789abcdef", 2) + " ; a name\n")
	sig := ed25519.Sign(priv, body)
	const reference = "203.0.113.9"
	// udp.serverKey selects the legacy secret, which makes the expected key computable
	// here without touching data/udp.secret.
	const serverKey = 0x12345678
	wantKey := fmt.Sprintf("%08x", ed2k.DeriveUDPKey(ed2k.LegacyUDPSecret(serverKey), net.ParseIP(reference)))

	var gotKeys []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKeys = append(gotKeys, r.Header.Get(contentfilter.DefaultKeyHeader))
		if r.Header.Get(contentfilter.DefaultKeyHeader) != wantKey {
			http.Error(w, "missing or malformed X-Server-Key", http.StatusForbidden)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".sig") {
			_, _ = w.Write(sig)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	dir := t.TempDir()
	list := filepath.Join(dir, "hash_banlist.txt")
	write := func(referenceIP string, enabled bool) string {
		path := filepath.Join(dir, "enode.config.yaml")
		cfg := fmt.Sprintf(`address: 127.0.0.1
udp:
  serverKey: %d
filter:
  hashBanlist:
    enabled: true
    file: %q
  update:
    enabled: %t
    referenceIP: %q
    publicKey: %q
    banlistURL: %q
`, serverKey, list, enabled, referenceIP, hex.EncodeToString(pub), server.URL+"/files/hash_banlist.txt")
		if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	var out bytes.Buffer
	err = runUpdateFilters(context.Background(), write(reference, true), &out)
	t.Logf("input: -update-filters with referenceIP %s; output: err=%v keys=%q stdout=%q", reference, err, gotKeys, out.String())
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}
	if !strings.Contains(out.String(), "hash ban list: installed, 1 hash(es) (was no file)") {
		t.Errorf("stdout = %q", out.String())
	}
	if installed, err := os.ReadFile(list); err != nil || !bytes.Equal(installed, body) {
		t.Fatalf("installed list differs from the served one (err=%v)", err)
	}

	// Another reference IP derives another key, which the service refuses.
	out.Reset()
	err = runUpdateFilters(context.Background(), write("203.0.113.10", true), &out)
	t.Logf("input: a different referenceIP; output: err=%v stdout=%q", err, out.String())
	if err == nil || !strings.Contains(out.String(), "FAILED") || !strings.Contains(out.String(), "allow list") {
		t.Fatalf("err=%v stdout=%q, want a refusal that explains the 403", err, out.String())
	}

	err = runUpdateFilters(context.Background(), write(reference, false), &out)
	t.Logf("input: filter.update.enabled=false; output: err=%v", err)
	if err == nil {
		t.Fatal("with updates off the command must say so rather than succeed silently")
	}
}

// TestFilterReferenceIP covers the default: an empty filter.update.referenceIP stands
// for this server's own primary IPv4, address first and dynIp second.
func TestFilterReferenceIP(t *testing.T) {
	cases := []struct {
		name, reference, address, dynIP, want string
	}{
		{"configured wins", "203.0.113.9", "198.51.100.1", "198.51.100.2", "203.0.113.9"},
		{"empty uses address", "", "198.51.100.1", "198.51.100.2", "198.51.100.1"},
		{"wildcard address falls to dynIp", "", "0.0.0.0", "198.51.100.2", "198.51.100.2"},
		{"v6 bind falls to dynIp", "", "::", "198.51.100.2", "198.51.100.2"},
		{"nothing known", "", "0.0.0.0", "", ""},
		{"configured v6 is refused", "2001:db8::1", "198.51.100.1", "", ""},
	}
	for _, tc := range cases {
		cfg := config.Config{Address: tc.address, DynIP: tc.dynIP}
		cfg.Filter.Update.ReferenceIP = tc.reference
		got, err := filterReferenceIP(cfg)
		t.Logf("input: %s (referenceIP=%q address=%q dynIp=%q); output: ip=%v err=%v", tc.name, tc.reference, tc.address, tc.dynIP, got, err)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s: got %v, want an error", tc.name, got)
			}
			continue
		}
		if err != nil || got.String() != tc.want {
			t.Errorf("%s: got %v err=%v, want %s", tc.name, got, err, tc.want)
		}
	}
}
