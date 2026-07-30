package ed2k

import (
	"encoding/binary"
	"net"
)

// Address helpers operate on net.IP rather than dotted-quad strings.
//
// A dual-stack listener reports an IPv4 peer as the mapped form ::ffff:a.b.c.d.
// The string parser IPv4ToInt32LE (misc.go) rejects that and callers substitute
// 0, so on a dual-stack bind every IPv4 client would silently lose its address.
// These helpers normalise the family first, so a mapped v4 peer is treated as
// plain IPv4 and a genuine v6 peer yields its 16 raw bytes.

// NormalizeIP collapses an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its
// 4-byte IPv4 form and returns genuine IPv6 addresses in 16-byte form. It
// returns nil for a nil/invalid input.
func NormalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// IPv4ToUint32LE packs an IPv4 (or IPv4-mapped) address into the eD2K ClientID
// convention: the first octet is the low byte, matching the string parser
// IPv4ToInt32LE and eMule's GetIP(). It reports false for a genuine IPv6 address,
// which has no 32-bit representation and therefore no HighID.
func IPv4ToUint32LE(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.LittleEndian.Uint32(v4), true
}

// IPv6Bytes returns the 16 raw network-order bytes of a genuine IPv6 address —
// the exact form carried in the CT_MOD_IP_V6 tag and the sentinel source. It
// reports false for an IPv4 or IPv4-mapped address, which belongs in the uint32
// field instead; callers must not conflate the two, since a mapped-form blob
// would compare unequal to the semantically identical IPv4 on the client side.
func IPv6Bytes(ip net.IP) ([16]byte, bool) {
	var out [16]byte
	if ip == nil || ip.To4() != nil {
		return out, false
	}
	v6 := ip.To16()
	if v6 == nil {
		return out, false
	}
	copy(out[:], v6)
	return out, true
}

// IsPublicIPv6 reports whether ip is a globally routable IPv6 address suitable to
// record as a reachable source. It rejects IPv4/mapped addresses, the loopback,
// link-local (fe80::/10), unique-local (fc00::/7), multicast and the unspecified
// address — none of which another peer could connect to.
func IsPublicIPv6(ip net.IP) bool {
	if ip == nil || ip.To4() != nil || ip.To16() == nil {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// ParsePublicIPv6 parses a textual IPv6 address and returns its 16 bytes only if
// it is globally routable. Used for the server's configured/auto-detected public
// IPv6.
func ParsePublicIPv6(s string) ([16]byte, bool) {
	var out [16]byte
	ip := net.ParseIP(s)
	if !IsPublicIPv6(ip) {
		return out, false
	}
	return IPv6Bytes(ip)
}

// IsLANIP reports whether an IPv4 address is on a private or otherwise non-routable
// network. It is the union of the two reference implementations, which split the
// same set differently:
//
//   - srchybrid/OtherFunctions.cpp:2071 IsLANIP covers 0.*, 10.*, 172.16-31.* and
//     192.168.* — it leaves 127.* to IsGoodIP, which rejects it outright.
//   - src/core/utils/OtherFunctions.cpp isLanIP folds 127.* and 169.254.* in.
//
// Taking the union satisfies both: 127.* is rejected either way, and 169.254.*
// link-local is unreachable for a peer whichever function is asked. A genuine IPv6
// address is not a LAN IP here — IsPublicIPv6 is the v6 predicate.
func IsLANIP(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	switch {
	case v4[0] == 0: // "this" network
		return true
	case v4[0] == 10: // class A
		return true
	case v4[0] == 127: // loopback
		return true
	case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31: // class B
		return true
	case v4[0] == 192 && v4[1] == 168: // class C
		return true
	case v4[0] == 169 && v4[1] == 254: // link-local
		return true
	}
	return false
}

// IsGoodIP reports whether an IPv4 address is usable as a peer contact address, as
// eMule's IsGoodIP does (srchybrid/OtherFunctions.cpp:2051-2068):
//
//	if (nIP == 0 || (uint8)nIP == 127 || (uint8)nIP >= 224) {
//	#ifdef _DEBUG
//	    return ((uint8)nIP == 127 && thePrefs.GetAllowLocalHostIP());
//	#else
//	    return false;
//	#endif
//	}
//	return (!thePrefs.FilterLANIPs() && !forceCheck) || !IsLANIP(nIP);
//
// Unconditionally rejected, whatever allowLAN says: the unspecified address, any 0.*
// address, and everything from 224.0.0.0 up — multicast, reserved-for-future-use and
// the broadcast address. None of those is a host that could answer, and the reference
// is explicit that skipping the 224+ test lets a peer hand us multicast addresses as
// contacts.
//
// allowLAN gates the two categories that are unreachable only *from elsewhere*:
// RFC1918/link-local addresses and 127.* loopback. It stands in for both of eMule's
// escape hatches — FilterLANIPs() being off, which exists so a private-network server
// can be added for LAN test setups (src/core/server/ServerList.cpp:1070-1073), and
// GetAllowLocalHostIP(), which is what re-admits loopback above. Here both are driven
// by gossip.allowPrivatePeers. Loopback has to be included: without it a peer on this
// same host — the Lugdunum reference container, say — could not be gossiped with at
// all, which is precisely the case the knob exists for.
//
// A genuine IPv6 address is judged by IsPublicIPv6 instead and returns false here:
// this function's whole contract is the 32-bit octet tests above.
func IsGoodIP(ip net.IP, allowLAN bool) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4[0] == 0 || v4[0] >= 224 {
		return false
	}
	return allowLAN || !IsLANIP(ip)
}

// IsGoodIPPort reports whether an address/port pair is usable as a contact,
// matching eMule's IsGoodIPPort (srchybrid/OtherFunctions.cpp:2092-2095): a good IP
// and a non-zero port. Port 0 is what an entry carries when the sender does not
// actually know where the server listens.
func IsGoodIPPort(ip net.IP, port uint16, allowLAN bool) bool {
	return port != 0 && IsGoodIP(ip, allowLAN)
}

// IsGoodServerEntry is eMule's admission test for a server-list entry,
// CServerList::IsGoodServerIP (srchybrid/ServerList.cpp:322-325):
//
//	port != 0 && (hasDynIP || IsGoodIP(ip))
//
// The dynIP exemption matters: a server published under a dynamic hostname is
// expected to have a stale recorded address, so its IP is not evidence about
// whether the entry is worth keeping. A v6 entry is admitted on IsPublicIPv6, which
// already excludes loopback, link-local, ULA and multicast.
func IsGoodServerEntry(ip net.IP, port uint16, hasDynIP, allowLAN bool) bool {
	if port == 0 {
		return false
	}
	if hasDynIP {
		return true
	}
	if ip.To4() == nil {
		return IsPublicIPv6(ip)
	}
	return IsGoodIP(ip, allowLAN)
}
