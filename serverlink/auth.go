package serverlink

import (
	"context"
	"crypto/subtle"
	"net"
	"strconv"
	"strings"

	"enode/internal/ratelimit"

	"connectrpc.com/connect/v2"
)

// admit decides whether the caller is a server this one answers, and returns the
// key its calls are counted under.
//
// A token names a configured peer. Without one the caller is admitted only in
// gossip mode, and only from an address the gossip peer table has verified as a
// server. A wrong token is refused even from such an address: a caller that
// presents a credential is judged by it.
func (s *Service) admit(ctx context.Context) (string, error) {
	auth, ip := callAuth(ctx, s.cfg.TrustForwardedFor)
	addr := net.ParseIP(ip)
	if s.cfg.Blocked != nil && addr != nil && s.cfg.Blocked(addr) {
		s.stats.AuthFailures.Add(1)
		return "", connectError(connect.CodePermissionDenied, CodeUnauthorized)
	}
	if !s.ipLimit.Allow(ip) {
		s.stats.RateLimited.Add(1)
		return "", connectError(connect.CodeResourceExhausted, CodeRateLimited)
	}
	peer, ok := s.identify(auth, addr)
	if !ok {
		s.stats.AuthFailures.Add(1)
		return "", connectError(connect.CodeUnauthenticated, CodeUnauthorized)
	}
	if !s.peerLimit.Allow(peer) {
		s.stats.RateLimited.Add(1)
		return "", connectError(connect.CodeResourceExhausted, CodeRateLimited)
	}
	return peer, nil
}

// identify names the caller: "t:<n>" for the n-th configured token, "g:<ip>" for
// a gossip-verified server.
func (s *Service) identify(auth string, addr net.IP) (string, bool) {
	if token, ok := bearer(auth); ok {
		// Every token is compared, whichever matches, so the time taken does not
		// say how many peers there are or which one came close.
		found := -1
		for i, known := range s.cfg.Tokens {
			if subtle.ConstantTimeCompare([]byte(token), []byte(known)) == 1 {
				found = i
			}
		}
		if found < 0 {
			return "", false
		}
		return tokenPeerKey(found), true
	}
	if s.cfg.Verified != nil && addr != nil && s.cfg.Verified(addr) {
		return "g:" + addr.String(), true
	}
	return "", false
}

// callAuth reads the Authorization header and the caller's address of a connect
// call.
func callAuth(ctx context.Context, trustForwardedFor bool) (auth, ip string) {
	info, ok := connect.CallInfoForServerContext(ctx)
	if !ok {
		return "", ""
	}
	auth = info.RequestHeader().Get("Authorization")
	ip = ratelimit.PeerIP(info.PeerAddr)
	if trustForwardedFor {
		if fwd := info.RequestHeader().Get("X-Forwarded-For"); fwd != "" {
			ip = strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0])
		}
	}
	return auth, ip
}

func bearer(auth string) (string, bool) {
	const prefix = "Bearer "
	if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		return strings.TrimSpace(auth[len(prefix):]), true
	}
	return "", false
}

func tokenPeerKey(n int) string {
	return "t:" + strconv.Itoa(n)
}
