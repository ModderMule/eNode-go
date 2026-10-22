package ident

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// NodeLink is an ed3k:node link (Protocol.md §13.2): a node ID and at most one
// endpoint per family.
type NodeLink struct {
	ID  NodeID
	EP4 Endpoint
	EP6 Endpoint
}

// String writes ed3k:node?id=<hex>&ep=<ip:port>[&ep=[ip6]:port], IPv4 first.
func (l NodeLink) String() string {
	var b strings.Builder
	b.WriteString("ed3k:node?id=")
	b.WriteString(l.ID.String())
	for _, ep := range []Endpoint{l.EP4, l.EP6} {
		if ep.IsValid() {
			b.WriteString("&ep=")
			b.WriteString(ep.String())
		}
	}
	return b.String()
}

// ParseNodeLink reads an ed3k:node link. named says whether the link is used in
// a named network, where private addresses are acceptable.
func ParseNodeLink(s string, named bool) (NodeLink, error) {
	var l NodeLink
	scheme, rest, ok := strings.Cut(s, ":")
	if !ok || !strings.EqualFold(scheme, "ed3k") {
		return l, errors.New("ed3k: not an ed3k link")
	}
	kind, query, _ := strings.Cut(rest, "?")
	if kind != "node" {
		return l, errors.New("ed3k: not an ed3k:node link")
	}
	haveID := false
	for _, kv := range strings.Split(query, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		v, err := url.PathUnescape(v)
		if err != nil {
			return l, errors.New("ed3k: bad percent-encoding")
		}
		switch k {
		case "id":
			if haveID {
				return l, errors.New("ed3k: id repeated")
			}
			if l.ID, err = ParseNodeID(v); err != nil {
				return l, err
			}
			haveID = true
		case "ep":
			ep, err := parseLinkEndpoint(v)
			if err != nil {
				return l, err
			}
			if !AcceptableEndpoint(ep, named) {
				return l, errors.New("ed3k: endpoint not acceptable")
			}
			if ep.Addr().Is4() {
				if l.EP4.IsValid() {
					return l, errors.New("ed3k: two IPv4 endpoints")
				}
				l.EP4 = ep
			} else {
				if l.EP6.IsValid() {
					return l, errors.New("ed3k: two IPv6 endpoints")
				}
				l.EP6 = ep
			}
		}
	}
	if !haveID {
		return l, errors.New("ed3k: node link without id")
	}
	if !l.EP4.IsValid() && !l.EP6.IsValid() {
		return l, errors.New("ed3k: node link without ep")
	}
	return l, nil
}

func parseLinkEndpoint(v string) (Endpoint, error) {
	host, port, ok := strings.Cut(v, "]:")
	bracketed := strings.HasPrefix(v, "[") && ok
	if bracketed {
		host = host[1:]
	} else {
		i := strings.LastIndexByte(v, ':')
		if i < 0 {
			return Endpoint{}, errors.New("ed3k: endpoint without port")
		}
		host, port = v[:i], v[i+1:]
		if strings.Contains(host, ":") {
			return Endpoint{}, errors.New("ed3k: IPv6 endpoint without brackets")
		}
	}
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return Endpoint{}, errors.New("ed3k: bad endpoint address")
	}
	if bracketed && a.Is4() {
		// `[ip6]:port` is for IPv6 only (§13.2).
		return Endpoint{}, errors.New("ed3k: IPv4 endpoint in brackets")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return Endpoint{}, errors.New("ed3k: bad endpoint port")
	}
	return netip.AddrPortFrom(a, uint16(p)), nil
}
