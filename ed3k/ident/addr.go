package ident

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Endpoint is an address and UDP port.
type Endpoint = netip.AddrPort

// EncodeEndpoint writes ip ‖ port(BE): 6 bytes for IPv4, 18 for IPv6
// (Protocol.md §5.4). An invalid endpoint encodes as nil.
func EncodeEndpoint(ep Endpoint) []byte {
	if !ep.IsValid() {
		return nil
	}
	a := ep.Addr().Unmap()
	var out []byte
	if a.Is4() {
		b := a.As4()
		out = append(out, b[:]...)
	} else {
		b := a.As16()
		out = append(out, b[:]...)
	}
	return binary.BigEndian.AppendUint16(out, ep.Port())
}

// DecodeEndpoint reads a 6- or 18-byte endpoint. An empty slice is no endpoint
// (ok false, no error).
func DecodeEndpoint(b []byte) (Endpoint, bool, error) {
	switch len(b) {
	case 0:
		return Endpoint{}, false, nil
	case 6:
		a := netip.AddrFrom4([4]byte(b[:4]))
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(b[4:])), true, nil
	case 18:
		a := netip.AddrFrom16([16]byte(b[:16]))
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(b[16:])), true, nil
	}
	return Endpoint{}, false, errors.New("ed3k: endpoint is not 6 or 18 bytes")
}

// Private reports the private addresses of Protocol.md §8.2 (8).
func Private(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range privatePrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Acceptable reports whether an address may be stored, handed out or dialled
// (Protocol.md §8.2 (7)); in a named network private addresses are acceptable
// too (§8.2 (8)). An IPv6 address must lie inside 2000::/3 and outside the
// special blocks there; Go's IsGlobalUnicast alone is too loose for IPv6 (it
// accepts ::81.2.3.4, 4000::1 and fec0::1). An IPv4-mapped IPv6 address is judged by the IPv4 address
// inside it; callers that hold a wire endpoint reject the mapped form first
// (AcceptableEndpoint).
func Acceptable(a netip.Addr, named bool) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if named && Private(a) {
		return true
	}
	for _, p := range rejectedPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	if a.Is6() {
		return global6.Contains(a)
	}
	return a.IsGlobalUnicast()
}

// AcceptableEndpoint applies §8.2 (7) to an endpoint as it arrived on the wire:
// port 0 and an 18-byte IPv4-mapped address are refused.
func AcceptableEndpoint(ep Endpoint, named bool) bool {
	if !ep.IsValid() || ep.Port() == 0 || ep.Addr().Is4In6() {
		return false
	}
	return Acceptable(ep.Addr(), named)
}

// HostKey is the host group of an address (extensions/ip-diversity.md §1): the
// IPv4 /32 or the IPv6 /64. In a named network a private address counts as /32
// or /128.
func HostKey(a netip.Addr, named bool) netip.Prefix {
	a = a.Unmap()
	if a.Is4() || (named && Private(a)) {
		p, _ := a.Prefix(a.BitLen())
		return p
	}
	p, _ := a.Prefix(64)
	return p
}

// SiteKey is the site group of an address: the IPv4 /24 or the IPv6 /48.
func SiteKey(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, _ := a.Prefix(bits)
	return p
}

var privatePrefixes = mustPrefixes(
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8",
	"::1/128", "fe80::/10", "fc00::/7",
)

var rejectedPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"192.88.99.0/24", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	// IPv6 outside 2000::/3 (::/8, fe80::/10, fec0::/10, fc00::/7, 5f00::/16,
	// ff00::/8, ...) is refused by global6; these are the blocks inside it.
	"2001::/32", "2001:2::/48", "2001:10::/28", "2002::/16", "2001:db8::/32", "3fff::/20",
)

var global6 = netip.MustParsePrefix("2000::/3")

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}
