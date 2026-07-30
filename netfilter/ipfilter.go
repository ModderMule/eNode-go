// Package netfilter decides whether a peer address may talk to the server at all.
//
// Two independent sources, both operator-supplied and both optional:
//
//   - an eMule/eserver ipfilter.dat range list (static, hand-curated anti-P2P and
//     abuse ranges), and
//   - a MaxMind GeoLite2 country database with a deny-list of ISO codes.
//
// Callers ask Filter.Blocked before parsing anything off the wire, so a blocked
// address costs one binary search and nothing else. The package deliberately does
// not implement dynamic/behavioural bans — see docs/access-filters.md for why the
// static half is the half worth having here.
package netfilter

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// DefaultMinLevel is eMule's default IP-filter threshold: a range is blocked when
// its level is *below* this value. The convention is inverted from what the name
// suggests — a low level means "high confidence this range is bad" — so raising the
// threshold blocks more, not less.
const DefaultMinLevel = 100

// ipRange is one blocked span, held as inclusive uint32 bounds in *big-endian*
// (numeric) order so ranges sort and compare arithmetically. This is the opposite
// byte order from the eD2K ClientID convention (ed2k.IPv4ToUint32LE), which is
// deliberately not used here: that order makes 10.0.0.0 numerically larger than
// 11.0.0.0 and would break every comparison below.
type ipRange struct {
	lo, hi uint32
	desc   string
}

// IPFilter is a sorted, non-overlapping set of blocked IPv4 ranges. Build one with
// LoadIPFilter or ParseIPFilter and swap it in wholesale; never mutate a live one.
//
// The level threshold is applied at *load* time, not at lookup time, and that is
// what keeps lookups cheap. Filtering first means the ranges that survive are all
// "blocked", so overlaps can be merged into a disjoint list and a lookup is a single
// binary search. Carrying levels into the search structure would forbid merging —
// two overlapping ranges may disagree on level — and force a backward scan over
// every candidate range on the *miss* path, which is the common path on a hot UDP
// socket.
type IPFilter struct {
	ranges []ipRange
	// Parsed and Blocking count how many lines produced a range and how many of
	// those were at or below the threshold, so a load can report "read 120k ranges,
	// 4k blocking" — the two numbers an operator needs to see that minLevel is set
	// the way they think it is.
	Parsed   int
	Blocking int
	// Skipped counts lines that parsed as neither form. Reported once after a load
	// rather than logged per line: a stale ipfilter.dat can carry thousands of
	// comment styles we do not recognise, and a per-line warning would bury the log.
	Skipped int
}

// LoadIPFilter reads and parses an ipfilter file. A missing file is an error, not a
// silent empty filter: the operator asked for filtering by naming the file, so
// quietly allowing everything would be the wrong failure mode.
func LoadIPFilter(path string, minLevel int) (*IPFilter, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ipfilter %s: %w", path, err)
	}
	defer f.Close()
	return ParseIPFilter(f, minLevel)
}

// ParseIPFilter parses the two line forms found in the wild. Both are accepted from
// the same file, because both exist among the lists operators actually feed a server:
//
//	eMule / guarding.p2p ipfilter.dat:
//	    000.000.000.000 - 000.255.255.255 , 000 , Description
//	Lugdunum ipfilter.srv (netmask) and CIDR:
//	    192.168.0.0/255.255.0.0   1   Private-Use Networks
//	    10.0.0.0/8 , 0 , Private
//
// Fields may be separated by commas or whitespace; a leading '#', ';' or '//' is a
// comment. The level and description are both optional — a bare range line defaults
// to level 0, which is the most-blocked level and matches how hand-written LAN
// exclusion lists are usually written.
func ParseIPFilter(r io.Reader, minLevel int) (*IPFilter, error) {
	if minLevel <= 0 {
		minLevel = DefaultMinLevel
	}
	out := &IPFilter{}
	var blocking []ipRange

	scanner := bufio.NewScanner(r)
	// ipfilter.dat descriptions can be long; the default 64 KiB token limit is
	// plenty, but raise the cap so one pathological line cannot abort the load.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || strings.HasPrefix(line, "//") {
			continue
		}
		rng, level, ok := parseIPFilterLine(line)
		if !ok {
			out.Skipped++
			continue
		}
		out.Parsed++
		if level < minLevel {
			blocking = append(blocking, rng)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read ipfilter: %w", err)
	}
	out.Blocking = len(blocking)
	out.ranges = mergeRanges(blocking)
	return out, nil
}

// Len reports how many disjoint blocked ranges the filter holds after merging.
func (f *IPFilter) Len() int {
	if f == nil {
		return 0
	}
	return len(f.ranges)
}

// Blocked reports whether ip falls in a blocked range, returning a description for
// the log. A nil filter blocks nothing, so a disabled filter needs no branch at the
// call site.
//
// IPv6 is never blocked here: ipfilter.dat is an IPv4 format and has no v6 form, so
// a v6 peer is out of this filter's scope rather than implicitly allowed or denied.
func (f *IPFilter) Blocked(ip net.IP) (bool, string) {
	if f == nil || len(f.ranges) == 0 {
		return false, ""
	}
	v4 := ip.To4()
	if v4 == nil {
		return false, ""
	}
	addr := binary.BigEndian.Uint32(v4)

	// Ranges are disjoint and sorted, so exactly one candidate can contain addr: the
	// last one whose lo <= addr. One binary search, no scan, on hit and miss alike.
	i := sort.Search(len(f.ranges), func(k int) bool { return f.ranges[k].lo > addr })
	if i == 0 {
		return false, ""
	}
	rng := f.ranges[i-1]
	if rng.hi < addr {
		return false, ""
	}
	return true, rng.describe()
}

func (r ipRange) describe() string {
	lo := make(net.IP, 4)
	hi := make(net.IP, 4)
	binary.BigEndian.PutUint32(lo, r.lo)
	binary.BigEndian.PutUint32(hi, r.hi)
	if r.desc == "" {
		return fmt.Sprintf("%s-%s", lo, hi)
	}
	return fmt.Sprintf("%s-%s %s", lo, hi, r.desc)
}

// mergeRanges sorts and coalesces overlapping or adjacent spans into a disjoint
// list. Adjacent spans are joined too (hi+1 == next.lo), since a list that splits
// 10.0.0.0-10.0.0.255 and 10.0.1.0-10.0.255.255 describes one contiguous block.
//
// The surviving description is the first contributing range's. Concatenating them
// would produce megabyte-long strings on a real guarding.p2p list, and the
// description exists only to make one log line intelligible.
func mergeRanges(in []ipRange) []ipRange {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].lo != in[j].lo {
			return in[i].lo < in[j].lo
		}
		return in[i].hi < in[j].hi
	})
	out := make([]ipRange, 0, len(in))
	cur := in[0]
	for _, rng := range in[1:] {
		// hi == MaxUint32 would make hi+1 wrap to 0 and merge everything after it, so
		// the adjacency test is written as a subtraction that cannot overflow.
		adjacent := cur.hi < ^uint32(0) && rng.lo == cur.hi+1
		if rng.lo <= cur.hi || adjacent {
			if rng.hi > cur.hi {
				cur.hi = rng.hi
			}
			continue
		}
		out = append(out, cur)
		cur = rng
	}
	return append(out, cur)
}

// parseIPFilterLine parses one line into a range plus its level, reporting false for
// anything it cannot make sense of. Kept separate from ParseIPFilter so the line
// grammar is testable on its own.
func parseIPFilterLine(line string) (ipRange, int, bool) {
	// Strip a trailing comment. Done before field splitting so a '#' inside a
	// description does not become part of the level or the address.
	if idx := strings.IndexAny(line, "#;"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if line == "" {
		return ipRange{}, 0, false
	}

	// Pick the field separator by whether the comma split actually yields a parseable
	// address, not by whether the line contains a comma anywhere.
	//
	// Testing for a comma alone is wrong, and the real Lugdunum ipfilter.srv proves
	// it: its whitespace-separated lines carry commas inside the *description* —
	//
	//	127.0.0.0/255.0.0.0   1   Loopback   [RFC1700, page 5]
	//
	// — so a contains-a-comma test splits at "[RFC1700" and leaves the netmask glued
	// to the level and description. That silently skipped the loopback and 0.0.0.0
	// ranges. Probing the address field instead is unambiguous: it parses under
	// exactly one of the two grammars.
	var addrField, levelField, descField string
	commaForm := false
	if before, rest, found := strings.Cut(line, ","); found {
		if _, _, ok := parseRangeField(strings.TrimSpace(before)); ok {
			commaForm = true
			addrField = strings.TrimSpace(before)
			levelField, descField, _ = strings.Cut(rest, ",")
			levelField = strings.TrimSpace(levelField)
			descField = strings.TrimSpace(descField)
		}
	}
	if !commaForm {
		addrField, levelField, descField = splitWhitespaceForm(line)
	}

	lo, hi, ok := parseRangeField(addrField)
	if !ok {
		return ipRange{}, 0, false
	}
	level := 0
	if levelField != "" {
		// A non-numeric level is a malformed line, not a level-0 line: treating it as
		// 0 would silently block the range at the most aggressive setting.
		n, err := strconv.Atoi(levelField)
		if err != nil {
			return ipRange{}, 0, false
		}
		level = n
	}
	return ipRange{lo: lo, hi: hi, desc: descField}, level, true
}

// splitWhitespaceForm splits the space-separated variant. The address may itself be
// "a.b.c.d - e.f.g.h", so the leading fields are rejoined until a numeric level is
// found; everything after it is the description.
func splitWhitespaceForm(line string) (addr, level, desc string) {
	fields := strings.Fields(line)
	for i := 1; i < len(fields); i++ {
		if _, err := strconv.Atoi(fields[i]); err == nil {
			return strings.Join(fields[:i], " "), fields[i], strings.Join(fields[i+1:], " ")
		}
	}
	// No numeric level anywhere: the whole line is the address expression.
	return line, "", ""
}

// parseRangeField parses the address half of a line in any of its shapes:
// "lo - hi", "ip/netmask", "ip/prefixlen", or a bare single address.
func parseRangeField(field string) (lo, hi uint32, ok bool) {
	if field == "" {
		return 0, 0, false
	}
	if loStr, hiStr, found := strings.Cut(field, "-"); found {
		loIP := parseV4(strings.TrimSpace(loStr))
		hiIP := parseV4(strings.TrimSpace(hiStr))
		if loIP == nil || hiIP == nil {
			return 0, 0, false
		}
		l, h := binary.BigEndian.Uint32(loIP), binary.BigEndian.Uint32(hiIP)
		if l > h {
			// Reversed bounds appear in hand-edited lists. Swapping is safer than
			// dropping the line: the operator's intent is unambiguous.
			l, h = h, l
		}
		return l, h, true
	}
	if baseStr, suffixStr, found := strings.Cut(field, "/"); found {
		base := parseV4(strings.TrimSpace(baseStr))
		if base == nil {
			return 0, 0, false
		}
		suffix := strings.TrimSpace(suffixStr)
		var mask uint32
		if strings.Contains(suffix, ".") {
			// Netmask form, as Lugdunum's ipfilter.srv uses: 10.0.0.0/255.0.0.0
			m := parseV4(suffix)
			if m == nil {
				return 0, 0, false
			}
			mask = binary.BigEndian.Uint32(m)
		} else {
			bits, err := strconv.Atoi(suffix)
			if err != nil || bits < 0 || bits > 32 {
				return 0, 0, false
			}
			if bits > 0 {
				mask = ^uint32(0) << (32 - uint(bits))
			}
		}
		n := binary.BigEndian.Uint32(base)
		return n & mask, (n & mask) | ^mask, true
	}
	single := parseV4(field)
	if single == nil {
		return 0, 0, false
	}
	n := binary.BigEndian.Uint32(single)
	return n, n, true
}

// parseV4 parses a dotted quad, tolerating the zero-padded octets ipfilter.dat uses
// ("000.000.000.000"). net.ParseIP rejects those on Go 1.17+ because a leading zero
// once meant octal, so each octet is parsed explicitly as decimal.
func parseV4(s string) net.IP {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}
	out := make(net.IP, 4)
	for i, p := range parts {
		if p == "" || len(p) > 3 {
			return nil
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil || n > 255 {
			return nil
		}
		out[i] = byte(n)
	}
	return out
}
