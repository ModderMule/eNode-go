package netfilter

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNilFilterBlocksNothing pins the contract that lets the protocol layer call
// Blocked unconditionally: a disabled filter is a nil *Filter, and every method on it
// must be safe.
func TestNilFilterBlocksNothing(t *testing.T) {
	var f *Filter
	blocked, reason := f.Blocked(net.ParseIP("8.8.8.8"))
	byIP, byGeo := f.Stats()
	t.Logf("input: nil *Filter, 8.8.8.8")
	t.Logf("output: blocked=%v reason=%q country=%q stats=(%d,%d) close=%v",
		blocked, reason, f.Country(net.ParseIP("8.8.8.8")), byIP, byGeo, f.Close())
	if blocked {
		t.Fatal("a nil filter must block nothing")
	}
}

// TestNewAllDisabledReturnsNil covers the same contract from the constructor side.
func TestNewAllDisabledReturnsNil(t *testing.T) {
	f, err := New(context.Background(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: Config{} (both halves off); output: filter=%v err=%v", f, err)
	if f != nil {
		t.Fatal("an all-disabled config must yield a nil *Filter, not an empty one")
	}
}

// TestNewMissingIPFilterFileIsFatal pins the deliberate asymmetry between the two
// halves: naming an ipfilter file that does not exist is an operator error worth
// refusing to boot over, because the alternative is silently allowing everything the
// operator meant to block.
func TestNewMissingIPFilterFileIsFatal(t *testing.T) {
	_, err := New(context.Background(), Config{
		IPFilterEnabled: true,
		IPFilterFile:    filepath.Join(t.TempDir(), "does-not-exist.dat"),
	})
	t.Logf("input: ipfilter.enabled with a nonexistent file; output: err=%v", err)
	if err == nil {
		t.Fatal("a missing ipfilter file must be an error, not a silent empty filter")
	}
}

// TestNewMissingGeoIPDatabaseIsNotFatal is the other side of that asymmetry: GeoIP
// depends on a download from a third party, so an absent database leaves country
// matching inactive rather than stopping the server.
func TestNewMissingGeoIPDatabaseIsNotFatal(t *testing.T) {
	f, err := New(context.Background(), Config{
		GeoIPEnabled:     true,
		GeoIPDatabase:    filepath.Join(t.TempDir(), "data", "GeoLite2-Country.mmdb"),
		BlockedCountries: []string{"XX"},
		// Account nil: never download, use only a local file. Keeps the test offline.
	})
	if err != nil {
		t.Fatalf("a missing GeoIP database must not be fatal: %v", err)
	}
	if f == nil {
		t.Fatal("expected a filter even with no database")
	}
	loaded, denied := f.geo.Ready()
	blocked, reason := f.Blocked(net.ParseIP("8.8.8.8"))
	t.Logf("input: geoip.enabled, no database, no credentials")
	t.Logf("output: loaded=%v denied=%d Blocked(8.8.8.8)=%v %q", loaded, denied, blocked, reason)
	if loaded {
		t.Fatal("no database should be loaded")
	}
	if blocked {
		t.Fatal("with no database loaded nothing may be blocked (fail open)")
	}
}

// TestFilterConsultsIPFilterAndCountsHits wires a real range list through New and
// checks both the verdict and the counter the admin surface reads.
func TestFilterConsultsIPFilterAndCountsHits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ipfilter.dat")
	const list = "198.51.100.0 - 198.51.100.255 , 0 , Documentation range\n"
	if err := os.WriteFile(path, []byte(list), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := New(context.Background(), Config{IPFilterEnabled: true, IPFilterFile: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: %q", strings.TrimSpace(list))

	blocked, reason := f.Blocked(net.ParseIP("198.51.100.7"))
	t.Logf("output: Blocked(198.51.100.7) = %v %q", blocked, reason)
	if !blocked {
		t.Fatal("address inside the range must be blocked")
	}
	if !strings.HasPrefix(reason, "ipfilter ") {
		t.Errorf("reason should name the deciding half, got %q", reason)
	}

	allowed, _ := f.Blocked(net.ParseIP("198.51.101.7"))
	t.Logf("output: Blocked(198.51.101.7) = %v", allowed)
	if allowed {
		t.Fatal("address outside the range must be allowed")
	}

	byIP, byGeo := f.Stats()
	t.Logf("output: stats byIPFilter=%d byGeoIP=%d", byIP, byGeo)
	if byIP != 1 || byGeo != 0 {
		t.Errorf("stats = (%d,%d), want (1,0)", byIP, byGeo)
	}
}

// TestCurrentDatabaseMD5MissingFileForcesDownload pins the contract the whole
// conditional-download scheme rests on. If a missing file returned an error or a
// non-empty hash instead of "", the first run would report "no update available" and
// never fetch a database at all.
func TestCurrentDatabaseMD5MissingFileForcesDownload(t *testing.T) {
	g := NewGeoIP(filepath.Join(t.TempDir(), "absent.mmdb"), nil, nil, 0)
	sum, err := g.currentDatabaseMD5()
	t.Logf("input: nonexistent database path; output: md5=%q err=%v", sum, err)
	if err != nil {
		t.Fatalf("a missing file must not be an error: %v", err)
	}
	if sum != "" {
		t.Fatalf("md5 = %q, want \"\" so the download is unconditional", sum)
	}
}

// TestCurrentDatabaseMD5HashesRealContent covers the other branch: an existing file
// must hash to a stable value, since that value is what suppresses a redundant
// multi-megabyte transfer on every weekly tick.
func TestCurrentDatabaseMD5HashesRealContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake.mmdb")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := NewGeoIP(path, nil, nil, 0)
	sum, err := g.currentDatabaseMD5()
	if err != nil {
		t.Fatal(err)
	}
	// md5("hello"), computed outside this package so the test cannot drift with the
	// implementation.
	const want = "5d41402abc4b2a76b9719d911017c592"
	t.Logf("input: file containing %q; output: md5=%s", "hello", sum)
	if sum != want {
		t.Fatalf("md5 = %s, want %s", sum, want)
	}
}

// TestUpdateDatabaseWithoutCredentialsIsANoop guarantees the tests — and any
// deployment with no MaxMind account — never reach out to the network.
func TestUpdateDatabaseWithoutCredentialsIsANoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.mmdb")
	g := NewGeoIP(path, []string{"XX"}, nil, 0)
	err := g.UpdateDatabase(context.Background())
	_, statErr := os.Stat(path)
	t.Logf("input: GeoIP with account=nil; output: err=%v, file created=%v", err, statErr == nil)
	if err != nil {
		t.Fatalf("no credentials must be a silent no-op, got %v", err)
	}
	if statErr == nil {
		t.Fatal("no file should have been written")
	}
}

// TestUpdateDatabaseRejectsNonNumericAccountID checks the config value is validated
// where it is used. AccountID is carried as a string to match the config and MaxMind's
// own presentation, so the conversion has to fail loudly somewhere.
func TestUpdateDatabaseRejectsNonNumericAccountID(t *testing.T) {
	g := NewGeoIP(filepath.Join(t.TempDir(), "x.mmdb"), []string{"XX"},
		&WebServiceAccount{AccountID: "not-a-number", LicenseKey: "k"}, 0)
	err := g.UpdateDatabase(context.Background())
	t.Logf("input: accountID=%q; output: err=%v", "not-a-number", err)
	if err == nil {
		t.Fatal("a non-numeric accountID must be reported")
	}
	if !strings.Contains(err.Error(), "not numeric") {
		t.Errorf("error should explain the problem, got %q", err)
	}
}

// TestGeoIPDeniedCountriesAreNormalised covers the config-hygiene path: operators
// write "de", " DE ", or a stray empty entry, and all of them must behave the same as
// "DE" without needing a live database to prove it.
func TestGeoIPDeniedCountriesAreNormalised(t *testing.T) {
	g := NewGeoIP("unused.mmdb", []string{"de", " fr ", "", "  ", "Ru"}, nil, 0)
	got := make([]string, 0, len(g.denied))
	for c := range g.denied {
		got = append(got, c)
	}
	t.Logf("input: [de, ' fr ', '', '  ', Ru]; output: %d code(s) %v", len(g.denied), got)
	if len(g.denied) != 3 {
		t.Fatalf("denied set size = %d, want 3 (DE, FR, RU)", len(g.denied))
	}
	for _, want := range []string{"DE", "FR", "RU"} {
		if _, ok := g.denied[want]; !ok {
			t.Errorf("missing normalised code %s", want)
		}
	}
}

// TestNilGeoIPIsSafe mirrors the nil-Filter contract one layer down: a Filter with
// GeoIP disabled holds a nil *GeoIP and calls straight through it.
func TestNilGeoIPIsSafe(t *testing.T) {
	var g *GeoIP
	blocked, reason := g.Blocked(net.ParseIP("8.8.8.8"))
	loaded, denied := g.Ready()
	t.Logf("output: blocked=%v reason=%q country=%q loaded=%v denied=%d close=%v",
		blocked, reason, g.Lookup(net.ParseIP("8.8.8.8")), loaded, denied, g.Close())
	if blocked || loaded || denied != 0 {
		t.Fatal("a nil *GeoIP must be inert")
	}
}
