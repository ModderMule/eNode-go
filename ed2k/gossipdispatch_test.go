package ed2k

import (
	"net"
	"reflect"
	"sort"
	"testing"

	"enode/storage"
)

// dispatchRuntime builds a runtime with gossip attached, for driving UDPHandler directly.
func dispatchRuntime(t *testing.T, gossipOn bool, mutate func(*GossipConfig)) (*ServerRuntime, *GossipHandler) {
	t.Helper()
	rt := NewServerRuntime(
		TCPRuntimeConfig{Name: "test", Description: "d", Address: "198.51.100.1", Port: 5555},
		UDPRuntimeConfig{Name: "test", Description: "d", UDPServerKey: 0x12345678, UDPPortObf: 5569},
		storage.NewMemoryEngine(),
	)
	if !gossipOn {
		return rt, nil
	}
	cfg := GossipConfig{
		SelfIPv4: net.ParseIP("198.51.100.1"), SelfPort: 5555,
		MaxServers: 100, MaxFailures: 5, PublishIPv6: true,
		UDPPortObf: 5569, TCPPortObf: 5565,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	h := NewGossipHandler(cfg, nil)
	rt.SetGossipHandler(h)
	return rt, h
}

// dispatchConn binds a throwaway UDP socket for the dispatcher to answer through.
//
// A real socket rather than nil: several handlers reply (0xA0 answers with our peer
// list), and net.(*UDPConn).WriteToUDP panics on a nil receiver. The replies go to
// TEST-NET-3 addresses and are simply dropped by the stack, which is all these tests
// need — they assert on the resulting peer-table state, not on what was sent.
func dispatchConn(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind a throwaway UDP socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// feed drives one datagram through the UDP dispatcher. obfuscate wraps it with the key
// the server derives for that source IP, which is exactly what a real peer holding our
// published ServerKey would do.
func feed(t *testing.T, rt *ServerRuntime, conn *net.UDPConn, from string, packet []byte, obfuscate bool) {
	t.Helper()
	remote := &net.UDPAddr{IP: net.ParseIP(from), Port: 4675}
	if obfuscate {
		crypt := NewUDPCrypt(true, deriveUDPKey(LegacyUDPSecret(rt.udp().UDPServerKey), remote.IP))
		packet = crypt.EncryptAsClient(packet)
	}
	// enableCrypt=true models the gossip/obfuscated listener.
	rt.UDPHandler(true)(packet, remote, conn)
}

// TestDispatchObfuscatedRegistrationVerifies covers the happy path through the
// dispatcher: an obfuscated 0xA0 both admits and verifies the sender.
func TestDispatchObfuscatedRegistrationVerifies(t *testing.T) {
	rt, g := dispatchRuntime(t, true, nil)
	conn := dispatchConn(t)
	pkt, err := BuildServerListReqPacket(net.ParseIP("203.0.113.5"), 4661, 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	feed(t, rt, conn, "203.0.113.5", pkt.Bytes(), true)

	p, ok := g.PeerByIP(net.ParseIP("203.0.113.5"))
	t.Logf("input: obfuscated 0xA0 from 203.0.113.5 announcing port 4661")
	t.Logf("output: known=%v state=%s verified=%d", ok, p.State, len(g.Verified()))
	if !ok || p.State != peerVerified {
		t.Fatalf("expected a verified peer, got known=%v state=%s", ok, p.State)
	}
	if p.Addr.Port != 4661 {
		t.Errorf("port = %d, want the announced 4661", p.Addr.Port)
	}
}

// TestDispatchPlaintextRegistrationDoesNotVerify is the discriminating case for the
// obfuscation gate. It is the reason the dispatcher computes `obfuscated` from the raw
// first byte rather than from which listener received the frame: Decrypt deliberately
// passes a plaintext eD2K frame straight through, so without that check a plaintext 0xA0
// aimed at the gossip port would be indistinguishable from an authenticated one.
func TestDispatchPlaintextRegistrationDoesNotVerify(t *testing.T) {
	rt, g := dispatchRuntime(t, true, nil)
	conn := dispatchConn(t)
	pkt, err := BuildServerListReqPacket(net.ParseIP("203.0.113.6"), 4661, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Same listener (enableCrypt=true), but sent in the clear.
	feed(t, rt, conn, "203.0.113.6", pkt.Bytes(), false)

	p, ok := g.PeerByIP(net.ParseIP("203.0.113.6"))
	stats := g.Stats()
	t.Logf("input: PLAINTEXT 0xA0 on the obfuscated listener")
	t.Logf("output: known=%v state=%s verified=%d rejectedPlaintext=%d",
		ok, p.State, len(g.Verified()), stats.RejectedPlaintext)
	if !ok {
		t.Fatal("a plaintext 0xA0 should still be recorded as a hint")
	}
	if p.State != peerSeen {
		t.Fatalf("state = %s, want seen: plaintext must never verify a peer", p.State)
	}
	if stats.RejectedPlaintext != 1 {
		t.Errorf("RejectedPlaintext = %d, want 1", stats.RejectedPlaintext)
	}
}

// TestDispatchListFromUnknownSenderIsDropped confirms the dispatcher routes 0xA1 through
// the same policy the handler applies directly.
func TestDispatchListFromUnknownSenderIsDropped(t *testing.T) {
	rt, g := dispatchRuntime(t, true, nil)
	conn := dispatchConn(t)
	pkt, err := BuildServerListResPacket([]PeerAddr{{IP: net.ParseIP("192.0.2.9"), Port: 4661}})
	if err != nil {
		t.Fatal(err)
	}
	feed(t, rt, conn, "203.0.113.7", pkt.Bytes(), true)

	stats := g.Stats()
	t.Logf("input: obfuscated 0xA1 from a sender we never handshook with")
	t.Logf("output: known=%d rejectedUnsolicited=%d", stats.Known, stats.RejectedUnsolicited)
	if stats.Known != 0 {
		t.Fatal("no peer should have been admitted")
	}
	if stats.RejectedUnsolicited != 1 {
		t.Errorf("RejectedUnsolicited = %d, want 1", stats.RejectedUnsolicited)
	}
}

// TestDispatchStatResKeysPeer walks the phase-2 reply through the dispatcher and checks
// the challenge match is enforced end to end.
func TestDispatchStatResKeysPeer(t *testing.T) {
	rt, g := dispatchRuntime(t, true, nil)
	conn := dispatchConn(t)
	addr := PeerAddr{IP: net.ParseIP("203.0.113.8"), Port: 4661}
	g.mu.Lock()
	g.peers[addr.String()] = &PeerServer{Addr: addr, State: peerSeen}
	g.mu.Unlock()
	g.SetOurChallenge(addr, 0xFEEDFACE)

	// A reply echoing the wrong challenge must be refused.
	bad, _ := BuildGlobServStatResPacket(0xDEADBEEF, UDPConfig{
		UDPPortObf: 4675, TCPPortObf: 4661, UDPServerKey: 0xBAD1,
	}, 0, 0, 0)
	feed(t, rt, conn, "203.0.113.8", bad.Bytes(), true)
	p, _ := g.PeerByIP(addr.IP)
	t.Logf("input: 0x97 echoing 0xDEADBEEF where we sent 0xFEEDFACE")
	t.Logf("output: state=%s ServerKey=0x%08x", p.State, p.ServerKey)
	if p.State != peerSeen || p.ServerKey != 0 {
		t.Fatalf("a mismatched challenge must be refused: state=%s key=0x%08x", p.State, p.ServerKey)
	}

	// The matching reply keys the peer.
	good, _ := BuildGlobServStatResPacket(0xFEEDFACE, UDPConfig{
		UDPPortObf: 4675, TCPPortObf: 4661, UDPServerKey: 0xC0FFEE,
	}, 0, 0, 0)
	feed(t, rt, conn, "203.0.113.8", good.Bytes(), true)
	p, _ = g.PeerByIP(addr.IP)
	t.Logf("input: 0x97 echoing the correct 0xFEEDFACE")
	t.Logf("output: state=%s ServerKey=0x%08x portUDPOBF=%d", p.State, p.ServerKey, p.UDPPortObf)
	if p.State != peerKeyed {
		t.Fatalf("state = %s, want keyed", p.State)
	}
	if p.ServerKey != 0xC0FFEE || p.UDPPortObf != 4675 {
		t.Errorf("learned key=0x%08x port=%d, want 0xc0ffee/4675", p.ServerKey, p.UDPPortObf)
	}
}

// TestDispatchDescResPromotesPeer walks the phase-4 admission test through the
// dispatcher, in both the extended and old reply forms.
func TestDispatchDescResPromotesPeer(t *testing.T) {
	for _, form := range []string{"extended", "old"} {
		t.Run(form, func(t *testing.T) {
			rt, g := dispatchRuntime(t, true, nil)
			conn := dispatchConn(t)
			addr := PeerAddr{IP: net.ParseIP("203.0.113.9"), Port: 4661}
			g.mu.Lock()
			g.peers[addr.String()] = &PeerServer{Addr: addr, State: peerKeyed, ServerKey: 1}
			g.mu.Unlock()

			var pkt *Buffer
			var err error
			if form == "extended" {
				pkt, err = BuildServerDescResPacket(0x1234, UDPConfig{
					Name: "lugdunum-ref", Description: "reference server",
				})
			} else {
				pkt, err = BuildServerDescResOldPacket("lugdunum-ref", "reference server")
			}
			if err != nil {
				t.Fatal(err)
			}
			feed(t, rt, conn, "203.0.113.9", pkt.Bytes(), true)

			p, _ := g.PeerByIP(addr.IP)
			t.Logf("input: %s-form 0xA3 with name=%q desc=%q", form, "lugdunum-ref", "reference server")
			t.Logf("output: state=%s name=%q desc=%q", p.State, p.Name, p.Desc)
			if p.State != peerDescribed {
				t.Fatalf("state = %s, want described", p.State)
			}
			if p.Name != "lugdunum-ref" {
				t.Errorf("name = %q, want lugdunum-ref", p.Name)
			}
			if p.Desc != "reference server" {
				t.Errorf("desc = %q, want %q", p.Desc, "reference server")
			}
		})
	}
}

// TestParseServerDescResFormDiscrimination pins the discriminator directly. The extended
// form is tried first because an old-form payload read as extended puts two string-length
// bytes into the challenge and then reads a tag count out of name bytes, which is
// essentially never a plausible small count — whereas the reverse ambiguity is real.
func TestParseServerDescResFormDiscrimination(t *testing.T) {
	ext, err := BuildServerDescResPacket(0xAABBCCDD, UDPConfig{Name: "n1", Description: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	old, err := BuildServerDescResOldPacket("n2", "d2")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		label      string
		packet     *Buffer
		name, desc string
	}{
		{"extended", ext, "n1", "d1"},
		{"old", old, "n2", "d2"},
	} {
		gotName, gotDesc, err := ParseServerDescRes(NewBufferFromBytes(c.packet.Bytes()[2:]))
		t.Logf("%s form: % x", c.label, c.packet.Bytes())
		t.Logf("  -> name=%q desc=%q err=%v", gotName, gotDesc, err)
		if err != nil {
			t.Errorf("%s: %v", c.label, err)
			continue
		}
		if gotName != c.name || gotDesc != c.desc {
			t.Errorf("%s: got %q/%q, want %q/%q", c.label, gotName, gotDesc, c.name, c.desc)
		}
	}
}

// TestDispatchIgnoresGossipOpcodesWhenDisabled pins that a server with gossip off is
// unchanged: the opcodes are not merely inert, they never reach a handler.
func TestDispatchIgnoresGossipOpcodesWhenDisabled(t *testing.T) {
	rt, _ := dispatchRuntime(t, false, nil)
	conn := dispatchConn(t)
	if rt.gossip() != nil {
		t.Fatal("expected gossip to be off")
	}
	pkt, err := BuildServerListReqPacket(net.ParseIP("203.0.113.5"), 4661, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Must not panic on the nil handler — the gate is what prevents that.
	feed(t, rt, conn, "203.0.113.5", pkt.Bytes(), true)
	list, err := BuildServerListResPacket([]PeerAddr{{IP: net.ParseIP("192.0.2.1"), Port: 4661}})
	if err != nil {
		t.Fatal(err)
	}
	feed(t, rt, conn, "203.0.113.5", list.Bytes(), true)
	t.Logf("input: 0xA0 and 0xA1 with gossip disabled; output: no panic, servers=%d",
		len(rt.advertisableServers()))
}

// TestDispatchIPv6ListGatedOnPublishIPv6 keeps the 0xa7/0xa8 extension off when the
// operator turned it off, so a mesh configured for v4 only stays that way.
func TestDispatchIPv6ListGatedOnPublishIPv6(t *testing.T) {
	for _, on := range []bool{false, true} {
		rt, g := dispatchRuntime(t, true, func(c *GossipConfig) { c.PublishIPv6 = on })
		conn := dispatchConn(t)
		// Key the sender so its list would be trusted if the opcode were dispatched.
		addr := PeerAddr{IP: net.ParseIP("203.0.113.10"), Port: 4661}
		g.mu.Lock()
		g.peers[addr.String()] = &PeerServer{Addr: addr, State: peerKeyed, ServerKey: 1}
		g.mu.Unlock()

		pkt, err := BuildServerListResIPv6Packet([]PeerAddr{{IP: net.ParseIP("2001:db8::99"), Port: 4661}})
		if err != nil {
			t.Fatal(err)
		}
		feed(t, rt, conn, "203.0.113.10", pkt.Bytes(), true)

		known := g.Stats().Known
		t.Logf("publishIPv6=%v -> peers known after a 0xA8 = %d", on, known)
		// 1 is the sender itself; 2 means the v6 entry was merged.
		want := 1
		if on {
			want = 2
		}
		if known != want {
			t.Errorf("publishIPv6=%v: known=%d, want %d", on, known, want)
		}
	}
}

// TestAdvertisableServersMergesConfigAndGossip covers what clients actually receive.
// Configured entries are always present — an operator naming a peer has asserted it
// exists, and an empty list for the first minutes after every restart would be worse
// than a slightly optimistic one — while gossip adds only verified peers.
func TestAdvertisableServersMergesConfigAndGossip(t *testing.T) {
	rt, g := dispatchRuntime(t, true, nil)
	rt.Storage.AddServer(storage.Server{IP: "192.0.2.10", Port: 4661})
	rt.Storage.AddServer(storage.Server{IP: "192.0.2.11", Port: 4661})

	// One verified peer, one merely keyed, and one duplicate of a configured entry.
	for _, spec := range []struct {
		ip    string
		state peerState
	}{
		{"203.0.113.20", peerVerified},
		{"203.0.113.21", peerKeyed},
		{"192.0.2.10", peerVerified}, // duplicate of a configured entry
	} {
		addr := PeerAddr{IP: net.ParseIP(spec.ip), Port: 4661}
		g.mu.Lock()
		g.peers[addr.String()] = &PeerServer{Addr: addr, State: spec.state}
		g.mu.Unlock()
	}

	got := rt.advertisableServers()
	t.Logf("input: 2 configured, 1 verified peer, 1 keyed peer, 1 verified duplicate")
	t.Logf("output: %d entries %v", len(got), got)

	seen := map[string]int{}
	for _, sv := range got {
		seen[sv.IP]++
	}
	if seen["192.0.2.10"] != 1 {
		t.Errorf("192.0.2.10 appears %d times, want 1 — the duplicate was not collapsed", seen["192.0.2.10"])
	}
	if seen["192.0.2.11"] != 1 {
		t.Error("configured entries must always be advertised")
	}
	if seen["203.0.113.20"] != 1 {
		t.Error("a verified gossip peer must be advertised")
	}
	if seen["203.0.113.21"] != 0 {
		t.Error("an unverified peer must not be advertised to clients")
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}

	// The dashboard's peer count must be the length of this same list. Reporting
	// Storage.ServersCount() there — which is what it did before — showed 2 while clients
	// were being sent 3, and showed 0 on any server whose peers were all gossip-learned.
	if n := rt.AdvertisedServerCount(); n != len(got) {
		t.Errorf("AdvertisedServerCount()=%d, want %d — the count and the wire list have drifted", n, len(got))
	}
	t.Logf("output: AdvertisedServerCount=%d, Storage.ServersCount=%d",
		rt.AdvertisedServerCount(), rt.Storage.ServersCount())
}

// TestAdvertisableServersUnchangedWithoutGossip pins the no-regression property: with
// gossip off the client-facing list is exactly Storage.ServersAll(), as before.
func TestAdvertisableServersUnchangedWithoutGossip(t *testing.T) {
	rt, _ := dispatchRuntime(t, false, nil)
	rt.Storage.AddServer(storage.Server{IP: "192.0.2.10", Port: 4661})
	got := rt.advertisableServers()
	t.Logf("input: gossip off, 1 configured server; output: %v", got)
	if len(got) != 1 || got[0].IP != "192.0.2.10" {
		t.Fatalf("got %v, want just the configured entry", got)
	}
}

// duplicateServerEngine hands back a peer list containing duplicates, which the
// real engines can no longer produce now that AddServer deduplicates. It exists to
// prove advertisableServers does not *depend* on that: the wire list is the last
// thing between storage and the client, so it collapses duplicates itself.
type duplicateServerEngine struct {
	storage.Engine
	servers []storage.Server
}

func (d duplicateServerEngine) ServersAll() []storage.Server { return d.servers }

// TestAdvertisableServersDeduplicatesWithoutGossip covers the path that had no
// deduplication at all: with gossip disabled the function used to return
// Storage.ServersAll() verbatim, so anything duplicated upstream was published twice.
func TestAdvertisableServersDeduplicatesWithoutGossip(t *testing.T) {
	rt, _ := dispatchRuntime(t, false, nil)
	in := []storage.Server{
		{IP: "192.0.2.10", Port: 4661},
		{IP: "192.0.2.10", Port: 4661},
		{IP: "192.0.2.10", Port: 5661},
	}
	rt.Storage = duplicateServerEngine{Engine: rt.Storage, servers: in}

	got := rt.advertisableServers()
	t.Logf("input:  gossip off, storage returns %d entries %v", len(in), in)
	t.Logf("output: %d entries %v", len(got), got)

	if len(got) != 2 {
		t.Fatalf("got %d entries %v, want 2 — the duplicate was not collapsed", len(got), got)
	}
}

// TestAdvertisableServersCollapsesIPv6Spellings is the bug this dedup pass exists
// for. Configured entries were keyed on the raw config string while gossip peers
// were keyed on net.IP.String(), so an operator who wrote an IPv6 literal in any
// form but the canonical one got the same peer listed twice.
func TestAdvertisableServersCollapsesIPv6Spellings(t *testing.T) {
	rt, g := dispatchRuntime(t, true, nil)
	rt.Storage.AddServer(storage.Server{IP: "2001:DB8::1", Port: 4661})

	addr := PeerAddr{IP: net.ParseIP("2001:db8::1"), Port: 4661}
	g.mu.Lock()
	g.peers[addr.String()] = &PeerServer{Addr: addr, State: peerVerified}
	g.mu.Unlock()

	got := rt.advertisableServers()
	t.Logf("input:  configured %q, gossip-verified %q (the same peer)", "2001:DB8::1", "2001:db8::1")
	t.Logf("output: %d entries %v", len(got), got)

	if len(got) != 1 {
		t.Fatalf("got %d entries %v, want 1 — the two spellings did not collapse", len(got), got)
	}
}

// TestGossipSeedsFromServersFiltersJunk covers the shared config/server.met filter.
func TestGossipSeedsFromServersFiltersJunk(t *testing.T) {
	in := []storage.Server{
		{IP: "192.0.2.10", Port: 4661},
		{IP: "not-an-ip", Port: 4661},
		{IP: "192.0.2.11", Port: 0},
		{IP: "", Port: 4661},
		{IP: "2001:db8::1", Port: 4661},
	}
	got := GossipSeedsFromServers(in)
	t.Logf("input: %v", in)
	t.Logf("output: %v", got)
	if len(got) != 2 {
		t.Fatalf("got %d seeds, want 2 (the malformed IP, port 0 and empty entries dropped)", len(got))
	}
}

// udpRecorder is a UDPReplyConn that keeps what the dispatcher wrote, bound (as far as the
// dispatcher can tell) to localPort.
type udpRecorder struct {
	localPort int
	sent      [][]byte
}

func (c *udpRecorder) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) {
	c.sent = append(c.sent, append([]byte(nil), b...))
	return len(b), nil
}

func (c *udpRecorder) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: c.localPort}
}

// requestPeerList sends an obfuscated 0xA4 from `from` and returns the addresses in the
// 0xA1 that comes back, decrypted with the key the requester holds for us.
func requestPeerList(t *testing.T, rt *ServerRuntime, from string) []string {
	t.Helper()
	remote := &net.UDPAddr{IP: net.ParseIP(from), Port: 4675}
	key := deriveUDPKey(LegacyUDPSecret(rt.udp().UDPServerKey), remote.IP)
	req, err := BuildServerListReq2Packet()
	if err != nil {
		t.Fatal(err)
	}
	conn := &udpRecorder{localPort: 5569}
	rt.UDPHandler(true)(NewUDPCrypt(true, key).EncryptAsClient(req.Bytes()), remote, conn)
	if len(conn.sent) != 1 {
		t.Fatalf("request from %s produced %d datagram(s), want 1", from, len(conn.sent))
	}
	plain := NewUDPCrypt(true, key).DecryptFromServer(conn.sent[0])
	if len(plain) < 2 || plain[0] != PrED2K || plain[1] != OpServerListRes {
		t.Fatalf("reply to %s is not a 0xA1: % x", from, plain)
	}
	entries, err := ParseServerListRes(NewBufferFromBytes(plain[2:]))
	if err != nil {
		t.Fatalf("parse the reply to %s: %v", from, err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.String())
	}
	sort.Strings(out)
	return out
}

// TestPeerListOmitsRequester pins that a server asking for our list is not told about
// itself. eserver takes such an entry at face value: it added itself to its own table,
// pinged itself and counted the result among its working servers.
func TestPeerListOmitsRequester(t *testing.T) {
	rt, g := dispatchRuntime(t, true, nil)
	a := PeerAddr{IP: net.ParseIP("203.0.113.20"), Port: 4661}
	b := PeerAddr{IP: net.ParseIP("203.0.113.21"), Port: 4661}
	g.mu.Lock()
	for _, addr := range []PeerAddr{a, b} {
		g.peers[addr.String()] = &PeerServer{Addr: addr, State: peerVerified, ServerKey: 1}
	}
	g.mu.Unlock()
	t.Logf("input: verified peers %v", g.Verified())

	for _, tc := range []struct {
		from string
		want []string
	}{
		{"203.0.113.20", []string{b.String()}},
		{"203.0.113.21", []string{a.String()}},
		// Not in the table at all: nothing to leave out.
		{"203.0.113.22", []string{a.String(), b.String()}},
	} {
		got := requestPeerList(t, rt, tc.from)
		t.Logf("input: obfuscated 0xA4 from %s", tc.from)
		t.Logf("output: list names %v", got)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("list for %s = %v, want %v", tc.from, got, tc.want)
		}
	}
}

// TestSharedSocketRepliesUsePingChallenge covers gossip sharing the tcp+12 socket. A
// Lugdunum peer decrypts whatever leaves that port with the challenge of its last
// crypt-ping, so that is the key its name reply has to carry; everyone else, and every
// layout with a gossip socket of its own, keeps the derived ServerKey.
func TestSharedSocketRepliesUsePingChallenge(t *testing.T) {
	const challenge = 0x0BADF00D
	for _, tc := range []struct {
		name          string
		udpPortObf    uint16
		knownPeer     bool
		ping          bool
		wantChallenge bool
	}{
		{"shared socket, peer that pinged", 5567, true, true, true},
		{"shared socket, peer that never pinged", 5567, true, false, false},
		{"shared socket, not a peer", 5567, false, true, false},
		{"own gossip socket at tcp+14", 5569, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, g := dispatchRuntime(t, true, func(c *GossipConfig) { c.UDPPortObf = tc.udpPortObf })
			remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.30"), Port: 40000}
			derived := deriveUDPKey(LegacyUDPSecret(rt.udp().UDPServerKey), remote.IP)
			handle := rt.UDPHandler(true)
			conn := &udpRecorder{localPort: 5567}

			if tc.ping {
				// Before the peer is in the table, as when its ping beats its registration.
				raw := []byte{0x0D, 0xF0, 0xAD, 0x0B}
				handle(raw, remote, conn)
				if len(conn.sent) != 1 {
					t.Fatalf("crypt-ping produced %d datagram(s), want 1", len(conn.sent))
				}
				pong := NewUDPCrypt(true, challenge).DecryptFromServer(conn.sent[0])
				if len(pong) < 2 || pong[1] != OpGlobServStatRes {
					t.Fatalf("crypt-ping reply does not decrypt with the challenge: % x", pong)
				}
				conn.sent = nil
			}
			if tc.knownPeer {
				addr := PeerAddr{IP: remote.IP, Port: 4661}
				g.mu.Lock()
				g.peers[addr.String()] = &PeerServer{Addr: addr, State: peerSeen}
				g.mu.Unlock()
			}

			probe, err := MakeUDPPacket(PrED2K, []PacketItem{
				{Type: TypeUint8, Value: OpServerDescReq},
				{Type: TypeUint32, Value: uint32(0x7c7d7e7f)},
			})
			if err != nil {
				t.Fatal(err)
			}
			handle(NewUDPCrypt(true, derived).EncryptAsClient(probe.Bytes()), remote, conn)
			if len(conn.sent) != 1 {
				t.Fatalf("0xA2 produced %d datagram(s), want 1", len(conn.sent))
			}
			isDesc := func(key uint32) bool {
				plain := NewUDPCrypt(true, key).DecryptFromServer(conn.sent[0])
				return len(plain) >= 2 && plain[0] == PrED2K && plain[1] == OpServerDescRes
			}
			byChallenge, byDerived := isDesc(challenge), isDesc(derived)
			t.Logf("input: portUDPOBF=%d knownPeer=%v crypt-ping(0x%08x)=%v, then an obfuscated 0xA2",
				tc.udpPortObf, tc.knownPeer, uint32(challenge), tc.ping)
			t.Logf("output: 0xA3 decrypts with the ping challenge=%v, with the derived ServerKey=%v",
				byChallenge, byDerived)
			if byChallenge != tc.wantChallenge || byDerived == tc.wantChallenge {
				t.Errorf("reply keyed on challenge=%v derived=%v, want challenge=%v",
					byChallenge, byDerived, tc.wantChallenge)
			}
		})
	}
}

// TestInboundPingChallengesAreCapped pins that the challenge map cannot be grown by a
// crypt-ping flood: it is writable by any sender.
func TestInboundPingChallengesAreCapped(t *testing.T) {
	_, g := dispatchRuntime(t, true, func(c *GossipConfig) { c.UDPPortObf = 5567 })
	const senders = maxInboundChallenges + 500
	for i := range senders {
		g.NoteInboundPingChallenge(net.IPv4(10, 1, byte(i>>8), byte(i)), uint32(i+1))
	}
	g.mu.RLock()
	held := len(g.inboundChallenges)
	g.mu.RUnlock()
	t.Logf("input: crypt-pings from %d distinct addresses", senders)
	t.Logf("output: %d challenge(s) held, cap %d", held, maxInboundChallenges)
	if held != maxInboundChallenges {
		t.Errorf("held %d challenges, want exactly the cap %d", held, maxInboundChallenges)
	}
}
