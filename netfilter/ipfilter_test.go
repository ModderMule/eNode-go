package netfilter

import (
	"net"
	"os"
	"strings"
	"testing"

	"enode/tests"
)

func TestParseIPFilterLineForms(t *testing.T) {
	cases := []struct {
		name       string
		line       string
		wantLo     string
		wantHi     string
		wantLevel  int
		wantDesc   string
		wantParsed bool
	}{
		{
			name:   "emule dat zero padded range", // net.ParseIP rejects 000.000.000.000
			line:   "000.000.000.000 - 000.255.255.255 , 000 , Private-Use Networks",
			wantLo: "0.0.0.0", wantHi: "0.255.255.255", wantLevel: 0,
			wantDesc: "Private-Use Networks", wantParsed: true,
		},
		{
			name:   "emule dat with level 100",
			line:   "1.2.3.4 - 1.2.3.10 , 100 , Some ISP",
			wantLo: "1.2.3.4", wantHi: "1.2.3.10", wantLevel: 100,
			wantDesc: "Some ISP", wantParsed: true,
		},
		{
			// The whitespace form has to find the level by scanning for the first
			// numeric field, since the address itself may contain spaces. Runs of
			// whitespace inside the description collapse to single spaces as a result;
			// the description only ever reaches a log line, so that is fine.
			name:   "lugdunum netmask whitespace form",
			line:   "192.168.0.0/255.255.0.0     1       Private-Use Networks   [RFC1918]",
			wantLo: "192.168.0.0", wantHi: "192.168.255.255", wantLevel: 1,
			wantDesc: "Private-Use Networks [RFC1918]", wantParsed: true,
		},
		{
			name:   "cidr prefix comma form",
			line:   "10.0.0.0/8 , 0 , Private",
			wantLo: "10.0.0.0", wantHi: "10.255.255.255", wantLevel: 0,
			wantDesc: "Private", wantParsed: true,
		},
		{
			name:   "prefix 32 is a single address",
			line:   "8.8.8.8/32 , 0 , One host",
			wantLo: "8.8.8.8", wantHi: "8.8.8.8", wantLevel: 0,
			wantDesc: "One host", wantParsed: true,
		},
		{
			name:   "prefix 0 is everything",
			line:   "0.0.0.0/0 , 0 , All",
			wantLo: "0.0.0.0", wantHi: "255.255.255.255", wantLevel: 0,
			wantDesc: "All", wantParsed: true,
		},
		{
			name:   "bare single address defaults to level 0",
			line:   "203.0.113.7",
			wantLo: "203.0.113.7", wantHi: "203.0.113.7", wantLevel: 0,
			wantParsed: true,
		},
		{
			name:   "reversed bounds are swapped not dropped",
			line:   "1.2.3.10 - 1.2.3.4 , 0 , Backwards",
			wantLo: "1.2.3.4", wantHi: "1.2.3.10", wantLevel: 0,
			wantDesc: "Backwards", wantParsed: true,
		},
		{
			name:   "range with no level keeps whole expression",
			line:   "5.6.7.0 - 5.6.7.255",
			wantLo: "5.6.7.0", wantHi: "5.6.7.255", wantLevel: 0,
			wantParsed: true,
		},
		// Malformed inputs must be reported as unparseable rather than defaulting to
		// level 0, which is the most aggressive setting and would block them.
		{name: "octet out of range", line: "1.2.3.999 - 1.2.3.4 , 0 , x"},
		{name: "not enough octets", line: "1.2.3 - 1.2.3.4 , 0 , x"},
		{name: "non numeric level", line: "1.2.3.4 - 1.2.3.5 , high , x"},
		{name: "prefix out of range", line: "1.2.3.4/33 , 0 , x"},
		{name: "garbage", line: "this is not a filter line"},
		{name: "empty after comment strip", line: "# just a comment"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rng, level, ok := parseIPFilterLine(c.line)
			t.Logf("input:  %q", c.line)
			if !ok {
				t.Logf("output: unparseable")
				if c.wantParsed {
					t.Fatalf("expected the line to parse")
				}
				return
			}
			lo, hi := u32ToIP(rng.lo), u32ToIP(rng.hi)
			t.Logf("output: %s-%s level=%d desc=%q", lo, hi, level, rng.desc)
			if !c.wantParsed {
				t.Fatalf("expected the line to be rejected, got %s-%s", lo, hi)
			}
			if lo.String() != c.wantLo || hi.String() != c.wantHi {
				t.Errorf("range = %s-%s, want %s-%s", lo, hi, c.wantLo, c.wantHi)
			}
			if level != c.wantLevel {
				t.Errorf("level = %d, want %d", level, c.wantLevel)
			}
			if rng.desc != c.wantDesc {
				t.Errorf("desc = %q, want %q", rng.desc, c.wantDesc)
			}
		})
	}
}

// TestIPFilterMinLevelBoundary pins the inverted threshold convention: a range is
// blocked when its level is strictly BELOW minLevel. Getting the comparison backwards
// or making it inclusive silently changes which half of a real guarding.p2p list is
// enforced, which is invisible until someone is wrongly banned.
func TestIPFilterMinLevelBoundary(t *testing.T) {
	const input = `
1.0.0.0 - 1.0.0.255 , 99  , below threshold
2.0.0.0 - 2.0.0.255 , 100 , exactly at threshold
3.0.0.0 - 3.0.0.255 , 101 , above threshold
`
	f, err := ParseIPFilter(strings.NewReader(input), 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: 3 ranges at levels 99/100/101, minLevel=100")
	t.Logf("output: parsed=%d blocking=%d merged=%d", f.Parsed, f.Blocking, f.Len())

	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"1.0.0.1", true},  // level 99  < 100 -> blocked
		{"2.0.0.1", false}, // level 100 is NOT < 100 -> allowed
		{"3.0.0.1", false}, // level 101 -> allowed
		{"4.0.0.1", false}, // not listed at all
	} {
		got, desc := f.Blocked(net.ParseIP(c.ip))
		t.Logf("Blocked(%s) = %v %s", c.ip, got, desc)
		if got != c.want {
			t.Errorf("Blocked(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// TestIPFilterMergesOverlapAndAdjacency covers the load-time normalisation that lets
// Blocked be a single binary search. Without merging, a nested range would sort after
// the range containing it and the lookup would miss.
func TestIPFilterMergesOverlapAndAdjacency(t *testing.T) {
	const input = `
10.0.0.0 - 10.0.0.255 , 0 , first
10.0.1.0 - 10.0.255.255 , 0 , adjacent to first
10.0.0.100 - 10.0.0.200 , 0 , nested inside first
192.0.2.0 - 192.0.2.255 , 0 , disjoint
`
	f, err := ParseIPFilter(strings.NewReader(input), 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: 4 ranges (one adjacent, one nested, one disjoint)")
	t.Logf("output: blocking=%d merged=%d", f.Blocking, f.Len())
	if f.Blocking != 4 {
		t.Fatalf("Blocking = %d, want 4", f.Blocking)
	}
	if f.Len() != 2 {
		t.Fatalf("merged range count = %d, want 2 (10.0.0.0-10.0.255.255 and 192.0.2.0/24)", f.Len())
	}
	for _, ip := range []string{"10.0.0.1", "10.0.0.150", "10.0.1.1", "10.0.255.255", "192.0.2.9"} {
		if blocked, desc := f.Blocked(net.ParseIP(ip)); !blocked {
			t.Errorf("Blocked(%s) = false, want true", ip)
		} else {
			t.Logf("Blocked(%s) = true %s", ip, desc)
		}
	}
	for _, ip := range []string{"9.255.255.255", "10.1.0.0", "192.0.3.1"} {
		if blocked, _ := f.Blocked(net.ParseIP(ip)); blocked {
			t.Errorf("Blocked(%s) = true, want false", ip)
		} else {
			t.Logf("Blocked(%s) = false", ip)
		}
	}
}

// TestIPFilterMergeDoesNotWrapAtBroadcast guards the hi+1 adjacency test against
// uint32 overflow: with 255.255.255.255 as an upper bound, a naive hi+1 wraps to 0
// and would merge an unrelated low range into the top one.
func TestIPFilterMergeDoesNotWrapAtBroadcast(t *testing.T) {
	const input = `
255.255.255.255 - 255.255.255.255 , 0 , broadcast
0.0.0.0 - 0.0.0.0 , 0 , unspecified
`
	f, err := ParseIPFilter(strings.NewReader(input), 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: 0.0.0.0/32 and 255.255.255.255/32; output: merged=%d", f.Len())
	if f.Len() != 2 {
		t.Fatalf("merged range count = %d, want 2 — hi+1 wrapped past the broadcast address", f.Len())
	}
	if blocked, _ := f.Blocked(net.ParseIP("128.0.0.1")); blocked {
		t.Fatal("128.0.0.1 must not be blocked: the two /32 entries were merged into one span")
	}
}

// TestIPFilterIPv6IsOutOfScope documents that ipfilter.dat is an IPv4 format. A v6
// peer is neither blocked nor allow-listed here; the GeoIP layer covers it.
func TestIPFilterIPv6IsOutOfScope(t *testing.T) {
	f, err := ParseIPFilter(strings.NewReader("0.0.0.0/0 , 0 , everything\n"), 100)
	if err != nil {
		t.Fatal(err)
	}
	blocked, _ := f.Blocked(net.ParseIP("2001:db8::1"))
	t.Logf("input: filter blocking 0.0.0.0/0; Blocked(2001:db8::1) = %v", blocked)
	if blocked {
		t.Fatal("a v4 catch-all range must not block an IPv6 peer")
	}
	// A mapped v4 address is a v4 peer and must still be blocked.
	if blocked, _ := f.Blocked(net.ParseIP("::ffff:8.8.8.8")); !blocked {
		t.Fatal("mapped IPv4 must be tested as IPv4")
	}
}

func TestNilIPFilterBlocksNothing(t *testing.T) {
	var f *IPFilter
	blocked, desc := f.Blocked(net.ParseIP("8.8.8.8"))
	t.Logf("nil filter: Blocked(8.8.8.8) = %v %q, Len = %d", blocked, desc, f.Len())
	if blocked {
		t.Fatal("a nil filter must block nothing")
	}
}

func TestParseIPFilterCountsSkippedLines(t *testing.T) {
	const input = `
# a comment
; another comment
// a third
1.2.3.4 - 1.2.3.5 , 0 , good

total garbage here
1.2.3.999 , 0 , bad octet
`
	f, err := ParseIPFilter(strings.NewReader(input), 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: 3 comments, 1 good line, 2 malformed lines, 2 blank")
	t.Logf("output: parsed=%d blocking=%d skipped=%d", f.Parsed, f.Blocking, f.Skipped)
	if f.Parsed != 1 {
		t.Errorf("Parsed = %d, want 1", f.Parsed)
	}
	if f.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2", f.Skipped)
	}
}

// TestParseRealLugdunumIPFilter parses the genuine ipfilter.srv shipped by Lugdunum,
// recovered alongside the eserver 17.14 binary. Synthetic fixtures only prove the
// grammar we thought of; this proves the grammar the original server actually reads.
//
// The reference tree lives at the module root and is gitignored (it is 25 MB of
// third-party binaries), so this skips when it is absent — which is the normal state of
// a fresh clone. Resolved through FixRelativeTestingPath rather than a "../" literal so
// the path is stated once, relative to the module root, as everywhere else in the suite.
func TestParseRealLugdunumIPFilter(t *testing.T) {
	path := tests.FixRelativeTestingPath("lugdunum-eserver/conf/ipfilter.srv")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("Lugdunum reference tree not present: %v", err)
	}
	f, err := LoadIPFilter(path, DefaultMinLevel)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: %s", path)
	t.Logf("output: parsed=%d blocking=%d merged=%d skipped=%d",
		f.Parsed, f.Blocking, f.Len(), f.Skipped)

	// Every line in this file is a reserved or private range at level 1, so all of
	// them must parse. A skipped line means our grammar misses a form eserver reads.
	if f.Skipped != 0 {
		t.Errorf("Skipped = %d, want 0: the real file contains a line form we do not parse", f.Skipped)
	}
	if f.Parsed == 0 {
		t.Fatal("parsed no ranges from the real file")
	}

	// Spot-check addresses the file's own ranges cover, and one that none of them do.
	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},  // 192.168.0.0/255.255.0.0
		{"10.1.2.3", true},     // 10.0.0.0/255.0.0.0
		{"127.0.0.1", true},    // 127.0.0.0/255.0.0.0
		{"172.20.0.1", true},   // 172.16.0.0/255.192.0.0
		{"169.254.5.5", true},  // 169.254.0.0/255.255.0.0
		{"192.0.2.9", true},    // Test-Net
		{"224.0.0.1", true},    // multicast
		{"8.8.8.8", false},     // routable, not in the file
		{"203.0.113.1", false}, // routable
	} {
		got, desc := f.Blocked(net.ParseIP(c.ip))
		t.Logf("Blocked(%-14s) = %-5v %s", c.ip, got, desc)
		if got != c.want {
			t.Errorf("Blocked(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func u32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4()
}
