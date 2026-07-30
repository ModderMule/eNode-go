package ed2k

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestServerMetRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.met")
	in := []ServerMetEntry{
		{IP: net.ParseIP("1.2.3.4"), Port: 4661, Name: "lugdunum-ref", Description: "reference server"},
		{IP: net.ParseIP("203.0.113.9"), Port: 5555, Name: "eNode"},
		{IP: net.ParseIP("198.51.100.1"), Port: 4242}, // no tags at all
	}
	if err := WriteServerMet(path, in); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input:  %d entries", len(in))
	t.Logf("output: %d bytes, version byte 0x%02x, % x", len(raw), raw[0], raw[:min(len(raw), 40)])

	if raw[0] != serverMetVersion {
		t.Fatalf("version byte = 0x%02x, want 0x%02x", raw[0], serverMetVersion)
	}

	got, err := ReadServerMet(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("parsed: %d entries", len(got))
	for _, e := range got {
		t.Logf("  %s:%d name=%q desc=%q", e.IP, e.Port, e.Name, e.Description)
	}
	if len(got) != 3 {
		t.Fatalf("read %d entries, want 3", len(got))
	}
	for i := range in {
		if !got[i].IP.Equal(in[i].IP) || got[i].Port != in[i].Port {
			t.Errorf("entry %d address = %s:%d, want %s:%d", i, got[i].IP, got[i].Port, in[i].IP, in[i].Port)
		}
		if got[i].Name != in[i].Name || got[i].Description != in[i].Description {
			t.Errorf("entry %d tags = %q/%q, want %q/%q",
				i, got[i].Name, got[i].Description, in[i].Name, in[i].Description)
		}
	}
}

// TestServerMetMissingFileIsNotAnError pins the first-boot contract: no peer file yet
// is the normal state, and the caller falls back to its configured seeds. Returning an
// error here would make a fresh install log a failure on every start.
func TestServerMetMissingFileIsNotAnError(t *testing.T) {
	got, err := ReadServerMet(filepath.Join(t.TempDir(), "absent.met"))
	t.Logf("input: nonexistent path; output: entries=%v err=%v", got, err)
	if err != nil {
		t.Fatalf("a missing server.met must not be an error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil entries, got %v", got)
	}
}

// TestServerMetAcceptsBothVersionBytes covers eMule's reader, which tolerates 0xE0 and
// MET_HEADER 0x0E (srchybrid/ServerList.cpp:142). We always write 0xE0 but must read a
// file produced by something that chose the other.
func TestServerMetAcceptsBothVersionBytes(t *testing.T) {
	for _, version := range []uint8{serverMetVersion, serverMetVersionAlt} {
		path := filepath.Join(t.TempDir(), "server.met")
		// version + count(1) + ip + port + tagcount(0)
		raw := []byte{version, 1, 0, 0, 0, 1, 2, 3, 4, 0x35, 0x12, 0, 0, 0, 0}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := ReadServerMet(path)
		t.Logf("version 0x%02x -> entries=%v err=%v", version, got, err)
		if err != nil {
			t.Errorf("version 0x%02x must be accepted: %v", version, err)
			continue
		}
		if len(got) != 1 || got[0].IP.String() != "1.2.3.4" || got[0].Port != 4661 {
			t.Errorf("version 0x%02x: parsed %v", version, got)
		}
	}
}

func TestServerMetRejectsBadVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.met")
	if err := os.WriteFile(path, []byte{0x42, 0, 0, 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ReadServerMet(path)
	t.Logf("input: version byte 0x42; output: err=%v", err)
	if err == nil {
		t.Fatal("an unrecognised version byte must be rejected: the rest of the file cannot be trusted")
	}
}

// TestServerMetRejectsImpossibleCount is the allocation guard. A corrupt or hostile
// count field must be rejected against the bytes actually present, before anything is
// allocated for it.
func TestServerMetRejectsImpossibleCount(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{
			// Declares 1000 entries in a 9-byte file.
			name: "count exceeds file size",
			raw:  []byte{serverMetVersion, 0xe8, 0x03, 0x00, 0x00, 1, 2, 3, 4},
		},
		{
			// 0xFFFFFFFF entries: above maxServerMetEntries.
			name: "count above the hard ceiling",
			raw:  []byte{serverMetVersion, 0xff, 0xff, 0xff, 0xff},
		},
		{
			name: "truncated before the count",
			raw:  []byte{serverMetVersion, 0x01},
		},
		{
			name: "empty file",
			raw:  []byte{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.met")
			if err := os.WriteFile(path, c.raw, 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := ReadServerMet(path)
			t.Logf("input: % x; output: err=%v", c.raw, err)
			if err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

// TestServerMetSkipsDynIPPlaceholders covers eMule's convention of writing IP 0 for a
// dynIP server ("don't write potentially outdated IPs", ServerList.cpp:605). We have no
// hostname field to resolve such an entry from, so it carries no contactable address —
// but its tags must still be consumed so the following entries stay aligned.
func TestServerMetSkipsDynIPPlaceholders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.met")
	// Entry 1: ip=0 with one name tag. Entry 2: a real address with no tags.
	raw := []byte{serverMetVersion, 2, 0, 0, 0}
	// ip=0, port=4661, tagcount=1, tag: type=string(0x02) namelen=1 code=0x01 len=3 "dyn"
	raw = append(raw, 0, 0, 0, 0, 0x35, 0x12, 1, 0, 0, 0,
		TypeString, 1, 0, TagName, 3, 0, 'd', 'y', 'n')
	// ip=1.2.3.4, port=5555, tagcount=0
	raw = append(raw, 1, 2, 3, 4, 0xb3, 0x15, 0, 0, 0, 0)

	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadServerMet(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: entry with ip=0 (dynIP placeholder) followed by a real entry")
	t.Logf("output: %d entries %v", len(got), got)
	if len(got) != 1 {
		t.Fatalf("expected the placeholder skipped and 1 entry kept, got %d", len(got))
	}
	if got[0].IP.String() != "1.2.3.4" || got[0].Port != 5555 {
		t.Fatalf("the entry after the placeholder was misread: %s:%d — the tag block was not consumed",
			got[0].IP, got[0].Port)
	}
}

// TestWriteServerMetSkipsIPv6 pins that the file stays in the format eMule reads. The
// address field is four bytes wide, so a v6 entry cannot be represented; writing one
// would shift every following entry.
func TestWriteServerMetSkipsIPv6(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.met")
	in := []ServerMetEntry{
		{IP: net.ParseIP("2001:db8::1"), Port: 4661, Name: "v6-only"},
		{IP: net.ParseIP("1.2.3.4"), Port: 4661, Name: "v4"},
	}
	if err := WriteServerMet(path, in); err != nil {
		t.Fatal(err)
	}
	got, err := ReadServerMet(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: 1 v6 + 1 v4 entry; output: %d entries %v", len(got), got)
	if len(got) != 1 || got[0].Name != "v4" {
		t.Fatalf("expected only the v4 entry to be persisted, got %v", got)
	}
}

// TestWriteServerMetIsAtomic checks the rename-into-place behaviour by confirming no
// temporary files survive a successful write. A crash mid-write must not be able to
// leave a truncated peer list, which is the whole reason the file exists.
func TestWriteServerMetIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.met")
	in := []ServerMetEntry{{IP: net.ParseIP("1.2.3.4"), Port: 4661, Name: "x"}}
	if err := WriteServerMet(path, in); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	t.Logf("input: 1 entry; output: directory contains %v", names)
	if len(names) != 1 || names[0] != "server.met" {
		t.Fatalf("expected only server.met to remain, found %v — a temp file leaked", names)
	}
}

// TestWriteServerMetCreatesDirectory covers the data/ convention: the directory may not
// exist on a fresh install, and the first persistence tick must create it rather than
// failing every 225 seconds.
func TestWriteServerMetCreatesDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "server.met")
	in := []ServerMetEntry{{IP: net.ParseIP("1.2.3.4"), Port: 4661}}
	if err := WriteServerMet(path, in); err != nil {
		t.Fatalf("a missing parent directory must be created: %v", err)
	}
	got, err := ReadServerMet(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: path under a nonexistent data/ dir; output: wrote and read back %d entries", len(got))
	if len(got) != 1 {
		t.Fatalf("read %d entries, want 1", len(got))
	}
}

// TestServerMetSizeMatchesWrittenBytes guards serverMetSize. Buffer is fixed-length —
// PutUInt* fails past the end rather than growing — so an undersized estimate turns
// into a write error and an oversized one into trailing zero bytes that the reader
// would then try to parse as another entry.
func TestServerMetSizeMatchesWrittenBytes(t *testing.T) {
	cases := [][]ServerMetEntry{
		{},
		{{IP: net.ParseIP("1.2.3.4"), Port: 4661}},
		{{IP: net.ParseIP("1.2.3.4"), Port: 4661, Name: "n"}},
		{{IP: net.ParseIP("1.2.3.4"), Port: 4661, Name: "name", Description: "a longer description"}},
		{
			{IP: net.ParseIP("1.2.3.4"), Port: 4661, Name: "one"},
			{IP: net.ParseIP("5.6.7.8"), Port: 4662, Description: "two"},
			{IP: net.ParseIP("9.10.11.12"), Port: 4663},
		},
		// Multi-byte UTF-8: PutString writes bytes, so the size must count bytes too.
		{{IP: net.ParseIP("1.2.3.4"), Port: 4661, Name: "服务器", Description: "描述"}},
	}
	for i, in := range cases {
		path := filepath.Join(t.TempDir(), "server.met")
		if err := WriteServerMet(path, in); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := serverMetSize(in)
		t.Logf("case %d: %d entries -> serverMetSize=%d, file=%d bytes", i, len(in), want, len(raw))
		if len(raw) != want {
			t.Errorf("case %d: file is %d bytes but serverMetSize said %d", i, len(raw), want)
		}
		// And it must still round-trip.
		got, err := ReadServerMet(path)
		if err != nil {
			t.Errorf("case %d: read back failed: %v", i, err)
			continue
		}
		if len(got) != len(in) {
			t.Errorf("case %d: read %d entries, want %d", i, len(got), len(in))
		}
	}
}

func TestWriteServerMetRejectsEmptyPath(t *testing.T) {
	err := WriteServerMet("", nil)
	t.Logf("input: empty path; output: err=%v", err)
	if err == nil {
		t.Fatal("an empty path must be reported rather than writing somewhere unexpected")
	}
}
