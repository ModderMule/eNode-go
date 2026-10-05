package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"

	"enode/internal/ratelimit"
	"enode/logging"
)

// Access rules. A request from loopback is the operator on the machine itself and
// always gets in. Any other request needs the configured Basic-auth credentials; with
// none configured it may still see the status page, as before this gate existed, but
// never account data or account actions.
//
// "From loopback" means the peer is loopback and the request carries no proxy
// header: a reverse proxy on the same machine would otherwise make every visitor from
// the internet look local.

// proxyHeaders mark a request that a proxy relayed.
var proxyHeaders = []string{"X-Forwarded-For", "Forwarded", "X-Real-Ip", "X-Forwarded-Host"}

// adminWriteHeader must accompany every state-changing request. A cross-site form
// cannot set a custom header, and a cross-site script would need a CORS preflight
// the dashboard never answers, so this blocks CSRF even for the unauthenticated
// loopback case.
const adminWriteHeader = "X-Enode-Admin"

// IsLocalRequest reports whether r comes straight from loopback, not through a proxy.
func IsLocalRequest(r *http.Request) bool {
	for _, h := range proxyHeaders {
		if r.Header.Get(h) != "" {
			return false
		}
	}
	ip := net.ParseIP(ratelimit.PeerIP(r.RemoteAddr))
	return ip != nil && ip.IsLoopback()
}

// guard applies the access rules. sensitive routes (accounts) need loopback or
// credentials; the others need credentials only when some are configured.
func (s *Server) guard(sensitive bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsLocalRequest(r) {
			username, password := s.credentials()
			if !s.authLimit.Allow(ratelimit.PeerIP(r.RemoteAddr)) {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			switch {
			case username != "":
				if !checkBasic(r, username, password) {
					w.Header().Set("WWW-Authenticate", `Basic realm="eNode admin", charset="UTF-8"`)
					http.Error(w, "authentication required", http.StatusUnauthorized)
					return
				}
			case sensitive:
				http.Error(w, "administration is available from loopback, or with admin.username and admin.password configured",
					http.StatusForbidden)
				return
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOriginWrite(r) {
			http.Error(w, "missing "+adminWriteHeader+" header or cross-origin request", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func checkBasic(r *http.Request, username, password string) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	// Hashing first makes the comparison constant-time regardless of length.
	u1, u2 := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(username))
	p1, p2 := sha256.Sum256([]byte(pass)), sha256.Sum256([]byte(password))
	good := subtle.ConstantTimeCompare(u1[:], u2[:]) & subtle.ConstantTimeCompare(p1[:], p2[:])
	if good != 1 {
		logging.Warnf("admin dashboard: failed login from %s", r.RemoteAddr)
	}
	return good == 1
}

// sameOriginWrite checks a state-changing request carries the admin header and, if
// the browser sent an Origin, that it is this dashboard.
func sameOriginWrite(r *http.Request) bool {
	if r.Header.Get(adminWriteHeader) != "1" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}
