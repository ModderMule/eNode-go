package contentfilter

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeList writes a hash list holding the given hashes and returns its path.
func writeList(t *testing.T, dir, name string, hashes ...byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	var body string
	for _, b := range hashes {
		body += testHashLine(b) + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// newTestFilter builds a filter with a ban list {1,4}, a filter list {2,4} and a
// whitelist {4,5}, plus the keyword "blocked".
func newTestFilter(t *testing.T) *Filter {
	t.Helper()
	dir := t.TempDir()
	f, err := New(context.Background(), Config{
		Keywords:      "blocked",
		BanlistFile:   writeList(t, dir, "ban.txt", 1, 4),
		FilterFile:    writeList(t, dir, "filter.txt", 2, 4),
		WhitelistFile: writeList(t, dir, "white.txt", 4, 5),
		BanThreshold:  3,
		BanMinutes:    10,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestNewNothingConfiguredReturnsNil(t *testing.T) {
	f, err := New(context.Background(), Config{})
	t.Logf("input: empty config output: filter=%v err=%v", f, err)
	if f != nil || err != nil {
		t.Fatalf("New = %v, %v; want nil, nil", f, err)
	}
}

func TestNilFilterRefusesNothing(t *testing.T) {
	var f *Filter
	refused, sanction := f.CheckOffer(testHash(1), "blocked.avi")
	t.Logf("input: nil filter output: refused=%t sanction=%t withheld=%t query=%t banned=%t threshold=%d",
		refused, sanction, f.Withheld(testHash(1), "x"), f.QueryBlocked([]string{"blocked"}),
		f.Banned(testHash(9), net.IPv4(1, 2, 3, 4)), f.BanThreshold())
	if refused || sanction || f.Withheld(testHash(1), "x") || f.QueryBlocked([]string{"blocked"}) ||
		f.Banned(testHash(9), net.IPv4(1, 2, 3, 4)) || f.BanThreshold() != 0 {
		t.Fatal("a nil filter must refuse nothing")
	}
	f.Ban(testHash(9), net.IPv4(1, 2, 3, 4))
	if err := f.Reload(); err != nil || f.Stats() != (Stats{}) {
		t.Fatal("a nil filter must reload and report as empty")
	}
}

// TestCheckOfferLayerOrder pins which layer answers, and that only the ban list
// sanctions the publisher.
func TestCheckOfferLayerOrder(t *testing.T) {
	f := newTestFilter(t)
	cases := []struct {
		name         string
		hash         byte
		file         string
		wantRefused  bool
		wantSanction bool
	}{
		{"clean file", 9, "holiday.avi", false, false},
		{"ban list", 1, "holiday.avi", true, true},
		{"filter list", 2, "holiday.avi", true, false},
		{"keyword", 9, "some.BLOCKED.thing.avi", true, false},
		{"filter list beats keyword", 2, "blocked.avi", true, false},
		{"whitelist beats both lists", 4, "holiday.avi", false, false},
		{"whitelist beats keyword", 5, "blocked.avi", false, false},
	}
	for _, tc := range cases {
		refused, sanction := f.CheckOffer(testHash(tc.hash), tc.file)
		t.Logf("input: %s hash=%02x.. name=%q output: refused=%t sanction=%t", tc.name, tc.hash, tc.file, refused, sanction)
		if refused != tc.wantRefused || sanction != tc.wantSanction {
			t.Errorf("%s: refused=%t sanction=%t, want %t/%t", tc.name, refused, sanction, tc.wantRefused, tc.wantSanction)
		}
	}
	st := f.Stats()
	t.Logf("output: stats=%+v", st)
	if st.RefusedBanlist != 1 || st.RefusedFilter != 2 || st.RefusedKeyword != 1 {
		t.Errorf("refusal counters = %d/%d/%d, want 1/2/1", st.RefusedBanlist, st.RefusedFilter, st.RefusedKeyword)
	}
	if st.BanlistEntries != 2 || st.FilterEntries != 2 || st.WhitelistEntries != 2 || st.Keywords != 1 {
		t.Errorf("list sizes = %d/%d/%d keywords=%d, want 2/2/2 and 1", st.BanlistEntries, st.FilterEntries, st.WhitelistEntries, st.Keywords)
	}
}

func TestWithheldHashOnlyIgnoresKeywords(t *testing.T) {
	f := newTestFilter(t)
	cases := []struct {
		hash byte
		name string
		want bool
	}{
		{1, "", true},
		{2, "", true},
		{4, "", false},
		{9, "", false},
		{9, "blocked.avi", true},
	}
	for _, tc := range cases {
		got := f.Withheld(testHash(tc.hash), tc.name)
		t.Logf("input: hash=%02x.. name=%q output: withheld=%t", tc.hash, tc.name, got)
		if got != tc.want {
			t.Errorf("Withheld(%02x.., %q) = %t, want %t", tc.hash, tc.name, got, tc.want)
		}
	}
	if got := f.Stats().WithheldServed; got != 3 {
		t.Errorf("WithheldServed = %d, want 3", got)
	}
}

func TestQueryBlocked(t *testing.T) {
	f := newTestFilter(t)
	cases := []struct {
		terms []string
		want  bool
	}{
		{[]string{"holiday", "2026"}, false},
		{[]string{"holiday", "Blocked"}, true},
		{[]string{"unblocked"}, false},
		{nil, false},
	}
	for _, tc := range cases {
		got := f.QueryBlocked(tc.terms)
		t.Logf("input: terms=%q output: blocked=%t", tc.terms, got)
		if got != tc.want {
			t.Errorf("QueryBlocked(%q) = %t, want %t", tc.terms, got, tc.want)
		}
	}
}

func TestMissingListIsFatalUnlessAllowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.txt")
	_, err := New(context.Background(), Config{BanlistFile: path})
	t.Logf("input: absent ban list, AllowMissing=false output: err=%v", err)
	if err == nil {
		t.Fatal("an enabled list with no file must stop startup")
	}

	f, err := New(context.Background(), Config{BanlistFile: path, AllowMissing: true})
	t.Logf("input: absent ban list, AllowMissing=true output: filter!=nil=%t err=%v", f != nil, err)
	if err != nil || f == nil {
		t.Fatalf("with the updater on a missing list must start empty, got %v, %v", f, err)
	}
	if refused, _ := f.CheckOffer(testHash(1), "x"); refused {
		t.Fatal("an empty list refuses nothing")
	}

	// The updater installs the file and calls Reload.
	writeList(t, filepath.Dir(path), "absent.txt", 1)
	if err := f.Reload(); err != nil {
		t.Fatal(err)
	}
	refused, sanction := f.CheckOffer(testHash(1), "x")
	t.Logf("output after install+Reload: refused=%t sanction=%t", refused, sanction)
	if !refused || !sanction {
		t.Fatal("Reload must pick up the installed list")
	}
}

// TestFailedReloadKeepsPreviousList: an operator mid-edit, or a list deleted by
// mistake, must not disarm the filter.
func TestFailedReloadKeepsPreviousList(t *testing.T) {
	dir := t.TempDir()
	path := writeList(t, dir, "ban.txt", 1)
	f, err := New(context.Background(), Config{BanlistFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	err = f.Reload()
	refused, _ := f.CheckOffer(testHash(1), "x")
	t.Logf("input: list removed, Reload output: err=%v stillRefused=%t", err, refused)
	if err == nil {
		t.Fatal("Reload must report the missing list")
	}
	if !refused {
		t.Fatal("the previous list must stay in force")
	}
}

func TestReloadSwapsEqualSizedList(t *testing.T) {
	dir := t.TempDir()
	path := writeList(t, dir, "ban.txt", 1)
	f, err := New(context.Background(), Config{BanlistFile: path})
	if err != nil {
		t.Fatal(err)
	}
	// Same entry count, different hash: counts alone would call this unchanged.
	writeList(t, dir, "ban.txt", 2)
	if err := f.Reload(); err != nil {
		t.Fatal(err)
	}
	old, _ := f.CheckOffer(testHash(1), "x")
	replaced, _ := f.CheckOffer(testHash(2), "x")
	t.Logf("input: list {1} replaced by {2} output: refuses1=%t refuses2=%t", old, replaced)
	if old || !replaced {
		t.Fatal("a reload must swap in the new set even when its size is the same")
	}
}

func TestBanExpiresAndCoversHashAndAddress(t *testing.T) {
	f := newTestFilter(t)
	now := time.Unix(1_700_000_000, 0)
	f.bans.now = func() time.Time { return now }

	user, ip := testHash(0x77), net.IPv4(203, 0, 113, 7)
	other, otherIP := testHash(0x78), net.IPv4(203, 0, 113, 8)
	f.Ban(user, ip)

	t.Logf("input: ban user=%x ip=%s for 10m output: sameHash=%t sameIP=%t unrelated=%t bans=%d",
		user[:2], ip, f.Banned(user, otherIP), f.Banned(other, ip), f.Banned(other, otherIP), f.Stats().Bans)
	if !f.Banned(user, otherIP) {
		t.Error("the user hash must be banned from any address")
	}
	if !f.Banned(other, ip) {
		t.Error("the address must be banned under any user hash")
	}
	if f.Banned(other, otherIP) {
		t.Error("an unrelated client must not be banned")
	}
	if f.Stats().Bans != 2 {
		t.Errorf("Bans = %d, want 2 (hash and address)", f.Stats().Bans)
	}

	now = now.Add(11 * time.Minute)
	t.Logf("output after 11m: banned=%t remaining=%d", f.Banned(user, ip), f.bans.sweep())
	if f.Banned(user, ip) {
		t.Error("the ban must run out after BanMinutes")
	}
}

func TestBanCoversAnIPv6Slash64(t *testing.T) {
	f := newTestFilter(t)
	f.Ban(nil, net.ParseIP("2001:db8:1:2::1"))
	same := f.Banned(nil, net.ParseIP("2001:db8:1:2:ffff::9"))
	next := f.Banned(nil, net.ParseIP("2001:db8:1:3::1"))
	t.Logf("input: ban 2001:db8:1:2::1 output: same/64=%t next/64=%t", same, next)
	if !same || next {
		t.Fatalf("same /64 banned=%t, neighbouring /64 banned=%t; want true/false", same, next)
	}
}

func TestBadKeywordIsAnError(t *testing.T) {
	_, err := New(context.Background(), Config{Keywords: "ok|--"})
	t.Logf("input: keywords %q output: err=%v", "ok|--", err)
	if err == nil {
		t.Fatal("a keyword with no letter or digit must be refused")
	}
}
