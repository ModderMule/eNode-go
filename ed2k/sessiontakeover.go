package ed2k

import (
	"crypto/rand"
	"crypto/subtle"
	"net"
	"sync"

	"enode/logging"
	"enode/storage"
)

// takeoverHow says why a login may take over the live session of its hash.
type takeoverHow string

const (
	// takeoverByToken: the login sent the TagNatToken the live session was issued.
	takeoverByToken takeoverHow = "token"
	// takeoverDualStack: an IPv6 login from the CT_MOD_IP_V6 the live IPv4 session
	// advertised, same listen port.
	takeoverDualStack takeoverHow = "dual-stack"
)

// takeoverFrom returns the live session for hash this login may replace once it is
// accepted, so the client is never offline in between. Two proofs count, both of
// which a peer knowing only the public hash and port cannot fake:
//   - the session's token (TagNatToken, ed2k-server's ST_NATT_TOKEN), which only
//     ever went out over that
//     session's own TCP: any address and family, any port (a recheck may bring a
//     newly mapped one);
//   - an IPv6 login from the address the IPv4 session advertised, same port.
//
// An IPv4 login claiming an IPv6 session's address proves nothing: CT_MOD_IP_V6 is the
// newcomer's own word. Nil when neither holds; the login is then refused as usual.
func (c *tcpClient) takeoverFrom(hash []byte, port uint16, token []byte) (*tcpClient, takeoverHow) {
	old := c.server.sessionByHash(hash)
	if old == nil || old == c {
		return nil, ""
	}
	if len(token) == 16 {
		if have := old.issuedSessionToken(); len(have) == 16 && subtle.ConstantTimeCompare(have, token) == 1 {
			return old, takeoverByToken
		}
	}
	if !c.connectedV6 || c.peerIP == nil || old.connectedV6 {
		return nil, ""
	}
	info := old.snapshotInfo()
	if len(info.IPv6) != 16 || info.Port != port || !net.IP(info.IPv6).Equal(c.peerIP) {
		return nil, ""
	}
	return old, takeoverDualStack
}

// completeTakeover releases the session an accepted login takes over, right before the
// new storage row is written: the old row must go first, as in replaceSameIPSession.
// Re-derived here rather than remembered from the login check. False when the hash is
// online from a session this login may not take over; it is then refused like any
// duplicate.
func (c *tcpClient) completeTakeover() bool {
	info := c.snapshotInfo()
	if len(info.Hash) != 16 || !c.server.Storage.IsConnected(storage.ClientInfo{Hash: info.Hash}) {
		return true
	}
	if old, how := c.takeoverFrom(info.Hash, info.Port, c.server.sessionTokens.claimed(c)); old != nil {
		oldInfo := old.snapshotInfo()
		logging.Infof("login replaces live session remote=%s hash=%x by=%s oldRemote=%s oldID=%d",
			c.remoteHost, info.Hash, how, old.remoteHost, oldInfo.ID)
		reason := "replaced-by-takeover"
		if how == takeoverDualStack {
			reason = "replaced-by-ipv6-session"
		}
		old.closeWithReason(reason)
		old.releaseSession()
	}
	if c.server.Storage.IsConnected(storage.ClientInfo{Hash: info.Hash}) {
		logging.Warnf("login rejected remote=%s hash=%x: already connected", c.remoteHost, info.Hash)
		c.sendServerMessage("Already connected from another session.")
		c.closeWithReason("duplicate-login")
		return false
	}
	return true
}

// issueSessionToken gives the logged-in session a fresh token, sent as TagNatToken in
// its OP_SERVERIDENT: NAT-T proof and takeover token in one, as ed2k-server issues one
// per login. Every session gets one; the claim its login made is spent.
func (c *tcpClient) issueSessionToken() {
	c.server.sessionTokens.drop(c)
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		logging.Warnf("session token not issued remote=%s err=%v", c.remoteHost, err)
		return
	}
	c.server.natCallback.setToken(c, token)
}

// issuedSessionToken is the token issueSessionToken gave, nil before that.
func (c *tcpClient) issuedSessionToken() []byte {
	return c.server.natCallback.token(c)
}

// sessionTokenState maps a logging-in session to the token its login claimed, until
// handShake issues its own. Dropped with the session. Issued tokens live in
// natCallbackState, so a process handoff does not carry them: a takeover after one is
// refused as before.
type sessionTokenState struct {
	mu sync.Mutex
	m  map[*tcpClient][16]byte
}

func (s *sessionTokenState) setClaimed(c *tcpClient, token []byte) {
	if len(token) != 16 {
		s.drop(c)
		return
	}
	s.mu.Lock()
	if s.m == nil {
		s.m = make(map[*tcpClient][16]byte)
	}
	s.m[c] = [16]byte(token)
	s.mu.Unlock()
}

func (s *sessionTokenState) claimed(c *tcpClient) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.m[c]
	if !ok {
		return nil
	}
	return append([]byte(nil), t[:]...)
}

func (s *sessionTokenState) drop(c *tcpClient) {
	s.mu.Lock()
	delete(s.m, c)
	s.mu.Unlock()
}

// loginSessionToken is the TagNatToken of a login, nil when absent or malformed.
func loginSessionToken(tags []NamedTag) []byte {
	for _, t := range tags {
		if t.Name != "sessiontoken" {
			continue
		}
		if b, ok := t.Value.([]byte); ok && len(b) == 16 && t.Type == TypeHash {
			return append([]byte(nil), b...)
		}
		return nil
	}
	return nil
}
