//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"enode/ed2k"
)

// localIPv6Candidates lists the host's public IPv6 addresses with their state from
// GetAdaptersAddresses. A random interface identifier (SuffixOriginRandom) is a
// privacy/temporary address; DadState carries deprecated and tentative.
func localIPv6Candidates() []ipv6Candidate {
	size := uint32(15 * 1024)
	var buf []byte
	for attempt := 0; attempt < 3; attempt++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET6,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || attempt == 2 {
			return fallbackIPv6Candidates()
		}
	}
	var out []ipv6Candidate
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			ip := ua.Address.IP()
			if ip == nil || !ed2k.IsPublicIPv6(ip) {
				continue
			}
			out = append(out, ipv6Candidate{
				IP:         ip,
				Temporary:  ua.SuffixOrigin == windows.IpSuffixOriginRandom,
				Deprecated: ua.DadState == windows.IpDadStateDeprecated,
				Tentative:  ua.DadState == windows.IpDadStateTentative || ua.DadState == windows.IpDadStateDuplicate,
				FlagsKnown: true,
			})
		}
	}
	return out
}
