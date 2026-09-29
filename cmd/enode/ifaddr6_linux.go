//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"syscall"

	"golang.org/x/sys/unix"

	"enode/ed2k"
)

// localIPv6Candidates lists the host's public IPv6 addresses with their kernel
// flags, read over rtnetlink (RTM_GETADDR). net.InterfaceAddrs cannot tell a
// privacy/temporary address from a stable one; netlink can.
//
// The 8-bit ifa_flags in the header truncates the flag set, so the 32-bit IFA_FLAGS
// attribute is preferred when the kernel sends it (Linux >= 3.14).
func localIPv6Candidates() []ipv6Candidate {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETADDR, unix.AF_INET6)
	if err != nil {
		return fallbackIPv6Candidates()
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return fallbackIPv6Candidates()
	}
	var out []ipv6Candidate
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type != unix.RTM_NEWADDR || len(m.Data) < unix.SizeofIfAddrmsg {
			continue
		}
		if m.Data[0] != unix.AF_INET6 {
			continue
		}
		flags := uint32(m.Data[2])
		attrs, err := syscall.ParseNetlinkRouteAttr(m)
		if err != nil {
			continue
		}
		var addr, local net.IP
		for _, a := range attrs {
			switch a.Attr.Type {
			case unix.IFA_ADDRESS:
				addr = net.IP(append([]byte(nil), a.Value...))
			case unix.IFA_LOCAL:
				local = net.IP(append([]byte(nil), a.Value...))
			case unix.IFA_FLAGS:
				if len(a.Value) >= 4 {
					flags = binary.NativeEndian.Uint32(a.Value)
				}
			}
		}
		// IFA_LOCAL is the local end on point-to-point links; otherwise only
		// IFA_ADDRESS is sent and it is the local address.
		ip := addr
		if local != nil {
			ip = local
		}
		if len(ip) != net.IPv6len || !ed2k.IsPublicIPv6(ip) {
			continue
		}
		out = append(out, ipv6Candidate{
			IP:         ip,
			Temporary:  flags&unix.IFA_F_TEMPORARY != 0,
			Deprecated: flags&unix.IFA_F_DEPRECATED != 0,
			Tentative:  flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0,
			FlagsKnown: true,
		})
	}
	return out
}
