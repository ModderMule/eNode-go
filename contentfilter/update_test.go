package contentfilter

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testAccessKey = 0x0a1b2c3d

// updateService is a fake ed2k-server update service: it serves one list and its
// signature, and refuses a request without the expected access key the way the real
// one does.
type updateService struct {
	body     []byte
	sig      []byte
	truncate bool // declare the full length, send half
	requests []string
}

func (s *updateService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests = append(s.requests, r.URL.Path+" key="+r.Header.Get(DefaultKeyHeader)+" ua="+r.Header.Get("User-Agent"))
	if r.Header.Get(DefaultKeyHeader) != "0a1b2c3d" {
		http.Error(w, "missing or malformed X-Server-Key", http.StatusForbidden)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, ".sig"):
		_, _ = w.Write(s.sig)
	case s.truncate:
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write(s.body[:len(s.body)/2])
	default:
		_, _ = w.Write(s.body)
	}
}

// newUpdateFixture returns a running fake service, the updater pointed at it, and the
// path the list installs to.
func newUpdateFixture(t *testing.T, accessKey uint32, hashes ...byte) (*updateService, *Updater, string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := &updateService{}
	for _, b := range hashes {
		svc.body = append(svc.body, testHashLine(b)+" ; name\n"...)
	}
	svc.sig = ed25519.Sign(priv, svc.body)
	server := httptest.NewServer(svc)
	t.Cleanup(server.Close)

	path := filepath.Join(t.TempDir(), "lists", "hash_banlist.txt")
	updater := NewUpdater(UpdateConfig{
		Targets:      []UpdateTarget{{Name: "hash ban list", URL: server.URL + "/files/hash_banlist.txt", Path: path}},
		PublicKey:    pub,
		AccessKey:    accessKey,
		UserAgent:    "eNode-go/test",
		Interval:     time.Hour,
		MinKeepRatio: 0.5,
	}, nil)
	return svc, updater, path, priv
}

func TestUpdateInstallsAVerifiedList(t *testing.T) {
	svc, updater, path, _ := newUpdateFixture(t, testAccessKey, 1, 2, 3)
	reloaded := 0
	updater.onInstalled = func() { reloaded++ }

	results := updater.UpdateAll(context.Background())
	t.Logf("input: signed list of 3 hashes output: %+v requests=%q", results, svc.requests)
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("update failed: %+v", results)
	}
	if results[0].Entries != 3 || results[0].Previous != -1 {
		t.Errorf("entries=%d previous=%d, want 3 and -1 (no file before)", results[0].Entries, results[0].Previous)
	}
	list, err := LoadHashList(path)
	if err != nil || list.Len() != 3 {
		t.Fatalf("installed list: len=%d err=%v, want 3", list.Len(), err)
	}
	if reloaded != 1 {
		t.Errorf("onInstalled ran %d time(s), want 1", reloaded)
	}
	if len(svc.requests) != 2 || !strings.Contains(svc.requests[0], "ua=eNode-go/test") {
		t.Errorf("want one list and one signature request with our User-Agent, got %q", svc.requests)
	}
	if st := updater.Status(); !st.OK || st.Last.IsZero() {
		t.Errorf("status = %+v, want OK with a time", st)
	}
}

func TestUpdateAcceptsAHexSignature(t *testing.T) {
	svc, updater, path, _ := newUpdateFixture(t, testAccessKey, 1)
	svc.sig = []byte(hex.EncodeToString(svc.sig) + "\n")
	results := updater.UpdateAll(context.Background())
	t.Logf("input: hex signature file output: %+v", results)
	if results[0].Err != nil {
		t.Fatalf("a hex signature must verify: %v", results[0].Err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

// TestUpdateRefusals: every way a download can be wrong leaves the installed list as it
// was and reports why.
func TestUpdateRefusals(t *testing.T) {
	cases := []struct {
		name    string
		key     uint32
		break_  func(svc *updateService, other ed25519.PrivateKey)
		wantErr string
	}{
		{"wrong access key", 0xdeadbeef, func(*updateService, ed25519.PrivateKey) {}, `"missing or malformed X-Server-Key"`},
		{"signature from another key", testAccessKey, func(svc *updateService, other ed25519.PrivateKey) {
			svc.sig = ed25519.Sign(other, svc.body)
		}, "does not verify"},
		{"body changed after signing", testAccessKey, func(svc *updateService, _ ed25519.PrivateKey) {
			svc.body = append(svc.body, testHashLine(0x99)+"\n"...)
		}, "does not verify"},
		{"malformed signature file", testAccessKey, func(svc *updateService, _ ed25519.PrivateKey) {
			svc.sig = []byte("not a signature")
		}, "signature file"},
		{"truncated download", testAccessKey, func(svc *updateService, _ ed25519.PrivateKey) {
			svc.truncate = true
		}, "hash_banlist.txt"},
	}
	_, other, _ := ed25519.GenerateKey(nil)
	for _, tc := range cases {
		svc, updater, path, _ := newUpdateFixture(t, tc.key, 1, 2, 3, 4)
		installed := writeList(t, mustMkdir(t, filepath.Dir(path)), filepath.Base(path), 7, 8)
		tc.break_(svc, other)

		results := updater.UpdateAll(context.Background())
		list, _ := LoadHashList(installed)
		t.Logf("input: %s output: err=%v installedLen=%d status=%+v", tc.name, results[0].Err, list.Len(), updater.Status())
		if results[0].Err == nil || !strings.Contains(results[0].Err.Error(), tc.wantErr) {
			t.Errorf("%s: err=%v, want one mentioning %q", tc.name, results[0].Err, tc.wantErr)
		}
		if list.Len() != 2 || !list.Contains(testHash(7)) {
			t.Errorf("%s: the installed list was touched (len=%d)", tc.name, list.Len())
		}
		if updater.Status().OK {
			t.Errorf("%s: status reports success", tc.name)
		}
		leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "*.tmp-*"))
		if len(leftovers) != 0 {
			t.Errorf("%s: temp files left behind: %v", tc.name, leftovers)
		}
	}
}

// TestUpdateRefusesACollapse: a validly signed list that is far shorter than the
// installed one is the shape a stale or half-published file has.
func TestUpdateRefusesACollapse(t *testing.T) {
	_, updater, path, _ := newUpdateFixture(t, testAccessKey, 1)
	writeList(t, mustMkdir(t, filepath.Dir(path)), filepath.Base(path), 1, 2, 3, 4)

	results := updater.UpdateAll(context.Background())
	list, _ := LoadHashList(path)
	t.Logf("input: 1 hash would replace 4, minKeepRatio 0.5 output: err=%v installedLen=%d", results[0].Err, list.Len())
	if results[0].Err == nil || !strings.Contains(results[0].Err.Error(), "minKeepRatio") {
		t.Fatalf("err=%v, want a shrink refusal", results[0].Err)
	}
	if list.Len() != 4 {
		t.Fatalf("installed list has %d hashes, want the original 4", list.Len())
	}
}

func TestUpdateReplacesAnInstalledList(t *testing.T) {
	_, updater, path, _ := newUpdateFixture(t, testAccessKey, 1, 2, 3)
	writeList(t, mustMkdir(t, filepath.Dir(path)), filepath.Base(path), 7, 8)

	results := updater.UpdateAll(context.Background())
	list, _ := LoadHashList(path)
	t.Logf("input: 3 hashes replace 2 output: %+v installedLen=%d", results[0], list.Len())
	if results[0].Err != nil || results[0].Previous != 2 || list.Len() != 3 || list.Contains(testHash(7)) {
		t.Fatalf("result=%+v installedLen=%d, want a clean replace of 2 by 3", results[0], list.Len())
	}
}

func TestFirstDelay(t *testing.T) {
	_, updater, path, _ := newUpdateFixture(t, testAccessKey, 1)
	missing := updater.firstDelay()

	writeList(t, mustMkdir(t, filepath.Dir(path)), filepath.Base(path), 1)
	fresh := updater.firstDelay()

	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	stale := updater.firstDelay()
	t.Logf("input: interval 1h output: missing=%s fresh=%s stale=%s", missing, fresh, stale)
	if missing != 0 || stale != 0 {
		t.Errorf("a missing or stale list must update at once, got %s and %s", missing, stale)
	}
	if fresh < 50*time.Minute || fresh > time.Hour {
		t.Errorf("a fresh list waits about the interval, got %s", fresh)
	}
}

func TestParsePublicKey(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"102f8ec039fb6fcfe75dfd00cfc5cfed76d1f006aa03f0825e69f30e8c2d836d", false},
		{"102f8ec0", true},
		{"not hex", true},
		{"", true},
	}
	for _, tc := range cases {
		key, err := ParsePublicKey(tc.in)
		t.Logf("input: %q output: len=%d err=%v", tc.in, len(key), err)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParsePublicKey(%q) err=%v, wantErr=%t", tc.in, err, tc.wantErr)
		}
	}
}

func mustMkdir(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}
