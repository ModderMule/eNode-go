package ed2k

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"enode/logging"
	"enode/storage"
)

// A handover moves every TCP session to a successor process (internal/handoff).
// This file is the runtime's part of it: park the sessions between two reads,
// write out what each one holds, and on the other side rebuild them around the
// same sockets. See docs/server-handoff.md.

// SessionState is everything a TCP session holds beyond its socket, as it crosses
// to the successor. Gob-encoded: a field added later decodes as its zero value from
// an older predecessor, and one removed is skipped.
type SessionState struct {
	// Obfuscated says which listener accepted the session: it decides whether a
	// crypt state machine exists at all.
	Obfuscated bool
	Crypt      *CryptState
	Packet     PacketState
	// HeaderBuf is the start of a packet header that arrived without the rest.
	HeaderBuf []byte

	Logged   bool
	HasLowID bool
	Info     storage.ClientInfo
	Nick     string
	Software string
	Mod      string

	ConnectedAt time.Time
	IPv6Capable bool
	MetaCapable bool
	// PendingResults is the rest of the last search, for OP_QUERY_MORE_RESULT.
	PendingResults []storage.File

	SoftLimitWarned  bool
	HardLimitHit     bool
	BanlistDropped   bool
	LoginGateTripped bool
	BanlistHits      [][16]byte
	KeywordHits      [][16]byte
}

// CryptState is the obfuscation state machine of one session. The RC4 keys carry
// the keystream position, so the successor continues the stream at the exact byte
// the predecessor stopped at; anything else garbles it for good.
type CryptState struct {
	State   int
	Pending []byte
	SendKey *RC4Key
	RecvKey *RC4Key
}

// PacketState is a packet half received when the session parked.
type PacketState struct {
	Status   int
	Protocol uint8
	Code     uint8
	Size     uint32
	Recv     []byte
}

// EncodeSessionState and DecodeSessionState are the wire form of a SessionState.
func EncodeSessionState(st SessionState) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(st); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func DecodeSessionState(raw []byte) (SessionState, error) {
	var st SessionState
	err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&st)
	return st, err
}

// parkPoll is how often ParkSessions looks for sessions still to park, and
// interrupts their reads again.
const parkPoll = 20 * time.Millisecond

// parkRound is one handover's parking. Sessions park into it and wait on resume;
// handoff says, when resume closes, whether they moved to the successor.
type parkRound struct {
	resume  chan struct{}
	handoff bool
	mu      sync.Mutex
	parked  map[*tcpClient]struct{}
}

// ParkedSessions are the sessions a handover holds still. Exactly one of Resume
// and HandOff ends it.
type ParkedSessions struct {
	rt    *ServerRuntime
	round *parkRound
	// clients are the parked sessions, each with its writeMu held so nothing is
	// written to it — the status ticker, a peer's callback request — while its
	// RC4 state is read out and after.
	clients []*tcpClient
	// exported are the ones Export handed out; the rest were closed.
	exported []*tcpClient
	// Stragglers counts the sessions that did not park in time and were dropped.
	Stragglers int
}

// ParkSessions stops every TCP session at its next read and waits, up to timeout,
// for all of them to get there. The caller should already have closed the TCP
// gates, so no new session joins.
//
// A session busy in a handler — a login waiting on its firewall probe, an offer
// writing to a slow database — parks when the handler returns. One that does not
// within timeout is closed and released as if it had disconnected: its client
// reconnects, which is what every client did on a restart before.
func (s *ServerRuntime) ParkSessions(timeout time.Duration) *ParkedSessions {
	round := &parkRound{resume: make(chan struct{}), parked: map[*tcpClient]struct{}{}}
	s.parking.Store(round)
	deadline := time.Now().Add(timeout)
	// Two clean passes in a row: a session accepted just before the gates closed
	// may be tracked a moment after the first pass found nothing to wait for.
	clean := 0
	for clean < 2 && time.Now().Before(deadline) {
		pending := 0
		for _, c := range s.liveSessions() {
			if round.isParked(c) {
				continue
			}
			pending++
			// Again every pass: the read loop sets its own deadline before each read,
			// and may have overwritten this one in between.
			_ = c.conn.SetReadDeadline(gatePast)
		}
		if pending == 0 {
			clean++
		} else {
			clean = 0
		}
		time.Sleep(parkPoll)
	}
	p := &ParkedSessions{rt: s, round: round}
	for _, c := range s.liveSessions() {
		if !round.isParked(c) {
			p.Stragglers++
			info := c.snapshotInfo()
			logging.Warnf("handoff: session did not park in %s, dropping it remote=%s id=%d", timeout, c.remoteHost, info.ID)
			c.closeWithReason("handoff-park-timeout")
			c.releaseSession()
			continue
		}
		c.writeMu.Lock()
		p.clients = append(p.clients, c)
	}
	return p
}

// Export returns each parked session's state and a duplicate of its socket, in the
// same order. A session whose socket is gone by now — closed by its client between
// parking and here — is released instead, so the storage written next no longer
// holds it.
func (p *ParkedSessions) Export() ([]SessionState, []*os.File, error) {
	states := make([]SessionState, 0, len(p.clients))
	files := make([]*os.File, 0, len(p.clients))
	for _, c := range p.clients {
		f, err := connFile(c.conn)
		if err != nil {
			logging.Debugf("handoff: session not handed over remote=%s: %v", c.remoteHost, err)
			c.releaseSession()
			continue
		}
		states = append(states, c.exportState())
		files = append(files, f)
		p.exported = append(p.exported, c)
	}
	// A session that was tracked only after ParkSessions made its list — accepted a
	// moment before the gates closed — is not handed over. It is released now, before
	// the storage export, so the successor does not inherit a row nobody serves.
	held := make(map[*tcpClient]struct{}, len(p.clients))
	for _, c := range p.clients {
		held[c] = struct{}{}
	}
	for _, c := range p.rt.liveSessions() {
		if _, ok := held[c]; !ok {
			c.closeWithReason("handoff-late-session")
			c.releaseSession()
		}
	}
	return states, files, nil
}

// Resume puts every parked session back to serving, after a handover that failed.
func (p *ParkedSessions) Resume() {
	for _, c := range p.clients {
		c.writeMu.Unlock()
	}
	p.rt.parking.Store(nil)
	close(p.round.resume)
}

// HandOff ends the sessions in this process without ending them for the client:
// each read loop exits, closing only this process's copy of its socket. The write
// locks stay held, so a stray writer blocks rather than advancing a keystream the
// successor now owns, and parking stays set, so nothing reads either.
func (p *ParkedSessions) HandOff() {
	for _, c := range p.exported {
		c.handedOff.Store(true)
	}
	p.round.handoff = true
	close(p.round.resume)
}

// RestoredSessions are the sessions a successor rebuilt from its predecessor's
// states. They are not served until Start.
type RestoredSessions struct {
	rt      *ServerRuntime
	clients []*tcpClient
}

// RestoreSessions rebuilds sessions around the sockets the predecessor passed, in
// the order Export produced them, and registers them — LowID, hash index — so they
// can be reached the moment they start. Storage must already hold their rows. It
// takes ownership of files.
func (s *ServerRuntime) RestoreSessions(states []SessionState, files []*os.File) (*RestoredSessions, error) {
	if len(states) != len(files) {
		for _, f := range files {
			_ = f.Close()
		}
		return nil, fmt.Errorf("handoff: %d session states for %d sockets", len(states), len(files))
	}
	r := &RestoredSessions{rt: s}
	for i, st := range states {
		conn, err := net.FileConn(files[i])
		_ = files[i].Close()
		if err != nil {
			logging.Warnf("handoff: session %d not restored: %v", i, err)
			s.Storage.Disconnect(st.Info)
			continue
		}
		c := newTCPClient(s, conn, st.Obfuscated)
		c.applyState(st)
		if st.HasLowID && st.Info.ID != 0 && !s.LowIDs.Restore(st.Info.ID, c) {
			// Cannot happen with a fresh table, but if it did, two sessions answering
			// to one LowID would get each other's callbacks. Drop this one, without
			// freeing the LowID the other holds.
			logging.Warnf("handoff: LowID %d taken twice, dropping remote=%s", st.Info.ID, c.remoteHost)
			c.hasLowID = false
			c.closeWithReason("handoff-lowid-conflict")
			c.releaseSession()
			continue
		}
		if st.Logged {
			s.registerSession(st.Info.Hash, c)
		}
		r.clients = append(r.clients, c)
	}
	return r, nil
}

// Len is how many sessions were restored.
func (r *RestoredSessions) Len() int { return len(r.clients) }

// Start serves the restored sessions.
func (r *RestoredSessions) Start() {
	for _, c := range r.clients {
		r.rt.trackSession(c)
		go r.rt.serveRestored(c)
	}
}

// Close drops the restored sessions without touching storage or the client: the
// predecessor still owns both. Only for a successor that is giving up.
func (r *RestoredSessions) Close() {
	for _, c := range r.clients {
		_ = c.conn.Close()
	}
}

// LiveSessions is how many TCP sessions have a running read loop.
func (s *ServerRuntime) LiveSessions() int {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	return len(s.live)
}

// trackSession and untrackSession maintain the set ParkSessions walks.
func (s *ServerRuntime) trackSession(c *tcpClient) {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	if s.live == nil {
		s.live = map[*tcpClient]struct{}{}
	}
	s.live[c] = struct{}{}
}

func (s *ServerRuntime) untrackSession(c *tcpClient) {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	delete(s.live, c)
}

func (s *ServerRuntime) liveSessions() []*tcpClient {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	out := make([]*tcpClient, 0, len(s.live))
	for c := range s.live {
		out = append(out, c)
	}
	return out
}

// serveRestored is TCPHandler for a session that arrived by handover: the same
// bookkeeping around the read loop, minus what only a new connection needs. The
// per-IP slot is taken without the limit — the session was admitted already — and
// the status ticker starts again, since the predecessor's went with it.
func (s *ServerRuntime) serveRestored(c *tcpClient) {
	defer s.untrackSession(c)
	if c.peerIP != nil {
		key := addressKey(c.peerIP)
		s.connsMu.Lock()
		if s.connsPerIP == nil {
			s.connsPerIP = map[string]int{}
		}
		s.connsPerIP[key]++
		s.connsMu.Unlock()
		defer s.releaseConnSlot(key)
		if g := s.gossip(); g != nil {
			g.NoteClient(c.peerIP)
		}
	}
	if c.isLogged() {
		c.startPeriodicServerStatus()
	}
	c.run()
}

// park holds the session's read loop until the round ends, and reports whether it
// is to go on serving. Called only from the session's own goroutine.
func (c *tcpClient) park(round *parkRound) bool {
	round.mu.Lock()
	round.parked[c] = struct{}{}
	round.mu.Unlock()
	<-round.resume
	if round.handoff {
		c.setCloseReason("handed-off")
		return false
	}
	// ParkSessions left a deadline in the past, and the read loop sets none of its
	// own when no idle timeout is configured.
	_ = c.conn.SetReadDeadline(time.Time{})
	return true
}

// exportState reads the session out. The session is parked and its writeMu held,
// so nothing else touches the fields read here.
func (c *tcpClient) exportState() SessionState {
	c.infoMu.RLock()
	st := SessionState{
		Logged:      c.logged,
		HasLowID:    c.hasLowID,
		Info:        c.info,
		Nick:        c.nick,
		Software:    c.software,
		Mod:         c.mod,
		IPv6Capable: c.ipv6Capable,
	}
	c.infoMu.RUnlock()
	st.Info.Hash = append([]byte(nil), st.Info.Hash...)
	st.Info.IPv6 = append([]byte(nil), st.Info.IPv6...)
	st.Obfuscated = c.crypt != nil
	if c.crypt != nil {
		st.Crypt = c.crypt.exportState()
	}
	st.Packet = PacketState{
		Status:   c.packet.Status,
		Protocol: c.packet.Protocol,
		Code:     c.packet.Code,
		Size:     c.packet.Size,
		Recv:     append([]byte(nil), c.packet.recv...),
	}
	st.HeaderBuf = append([]byte(nil), c.headerBuf...)
	st.ConnectedAt = c.connectedAt
	st.MetaCapable = c.metaCapable
	st.PendingResults = c.pendingResults
	st.SoftLimitWarned = c.softLimitWarned
	st.HardLimitHit = c.hardLimitHit
	st.BanlistDropped = c.banlistDropped
	st.LoginGateTripped = c.loginGateTripped
	st.BanlistHits = hashSetList(c.banlistHits)
	st.KeywordHits = hashSetList(c.keywordHits)
	return st
}

// applyState is exportState's inverse, on a session newTCPClient has just built.
func (c *tcpClient) applyState(st SessionState) {
	c.infoMu.Lock()
	c.logged = st.Logged
	c.hasLowID = st.HasLowID
	c.info = st.Info
	c.nick, c.software, c.mod = st.Nick, st.Software, st.Mod
	c.ipv6Capable = st.IPv6Capable
	c.infoMu.Unlock()
	if c.crypt != nil && st.Crypt != nil {
		c.crypt.importState(st.Crypt)
	}
	c.packet.Status = st.Packet.Status
	c.packet.Protocol = st.Packet.Protocol
	c.packet.Code = st.Packet.Code
	c.packet.Size = st.Packet.Size
	c.packet.recv = st.Packet.Recv
	if len(st.HeaderBuf) > 0 {
		c.headerBuf = st.HeaderBuf
	}
	if !st.ConnectedAt.IsZero() {
		c.connectedAt = st.ConnectedAt
	}
	c.metaCapable = st.MetaCapable
	c.pendingResults = st.PendingResults
	c.softLimitWarned = st.SoftLimitWarned
	c.hardLimitHit = st.HardLimitHit
	c.banlistDropped = st.BanlistDropped
	c.loginGateTripped = st.LoginGateTripped
	c.banlistHits = hashSetOf(st.BanlistHits)
	c.keywordHits = hashSetOf(st.KeywordHits)
}

// connFile duplicates a session's socket for the successor.
func connFile(conn net.Conn) (*os.File, error) {
	fc, ok := conn.(interface{ File() (*os.File, error) })
	if !ok {
		return nil, fmt.Errorf("%T has no socket to hand over", conn)
	}
	return fc.File()
}

func hashSetList(set map[[16]byte]struct{}) [][16]byte {
	if len(set) == 0 {
		return nil
	}
	out := make([][16]byte, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	return out
}

func hashSetOf(list [][16]byte) map[[16]byte]struct{} {
	if len(list) == 0 {
		return nil
	}
	out := make(map[[16]byte]struct{}, len(list))
	for _, h := range list {
		out[h] = struct{}{}
	}
	return out
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

func (r *parkRound) isParked(c *tcpClient) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.parked[c]
	return ok
}
