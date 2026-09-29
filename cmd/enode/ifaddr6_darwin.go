//go:build darwin

package main

import (
	"net"
	"syscall"
	"unsafe"

	"enode/ed2k"
)

// Darwin's netinet6/in6_var.h values; x/sys/unix does not export them.
const (
	// _IOWR('i', 73, struct in6_ifreq) with sizeof(struct in6_ifreq) == 288.
	darwinSIOCGIFAFLAG_IN6 = 0xc1206949
	darwinIn6IfreqSize     = 288

	darwinIN6_IFF_TENTATIVE  = 0x02
	darwinIN6_IFF_DUPLICATED = 0x04
	darwinIN6_IFF_DETACHED   = 0x08
	darwinIN6_IFF_DEPRECATED = 0x10
	darwinIN6_IFF_TEMPORARY  = 0x80
)

// localIPv6Candidates lists the host's public IPv6 addresses with their flags from
// SIOCGIFAFLAG_IN6. Best effort: if the ioctl is unavailable the addresses are
// returned with FlagsKnown=false, which reproduces the flag-blind behaviour.
func localIPv6Candidates() []ipv6Candidate {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fallbackIPv6Candidates()
	}
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fallbackIPv6Candidates()
	}
	defer syscall.Close(fd)

	var out []ipv6Candidate
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || !ed2k.IsPublicIPv6(ipNet.IP) {
				continue
			}
			c := ipv6Candidate{IP: ipNet.IP}
			if flags, ok := darwinIn6AddrFlags(fd, ifi.Name, ipNet.IP); ok {
				c.FlagsKnown = true
				c.Temporary = flags&darwinIN6_IFF_TEMPORARY != 0
				c.Deprecated = flags&darwinIN6_IFF_DEPRECATED != 0
				c.Tentative = flags&(darwinIN6_IFF_TENTATIVE|darwinIN6_IFF_DUPLICATED|darwinIN6_IFF_DETACHED) != 0
			}
			out = append(out, c)
		}
	}
	return out
}

// darwinIn6AddrFlags fills a struct in6_ifreq (ifr_name[16] followed by a
// sockaddr_in6 in the union) and returns ifru_flags6 from the reply.
func darwinIn6AddrFlags(fd int, ifname string, ip net.IP) (uint32, bool) {
	if len(ifname) >= 16 {
		return 0, false
	}
	var req [darwinIn6IfreqSize]byte
	copy(req[:16], ifname)
	sa := req[16:]
	sa[0] = syscall.SizeofSockaddrInet6
	sa[1] = syscall.AF_INET6
	copy(sa[8:24], ip.To16())
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), darwinSIOCGIFAFLAG_IN6, uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		return 0, false
	}
	return *(*uint32)(unsafe.Pointer(&req[16])), true
}
