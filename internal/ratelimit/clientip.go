package ratelimit

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP returns the address to rate-limit a request by: the connection's peer,
// or with trustForwardedFor the first X-Forwarded-For entry, which is only
// trustworthy when a reverse proxy in front sets it.
func ClientIP(r *http.Request, trustForwardedFor bool) string {
	if trustForwardedFor {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			first := strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0])
			if ip := net.ParseIP(first); ip != nil {
				return ip.String()
			}
		}
	}
	return PeerIP(r.RemoteAddr)
}

// PeerIP strips the port from a host:port peer address.
func PeerIP(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
