package ed2k

import (
	"net"
	"strings"
	"testing"
	"time"
)

// testGossip builds a handler with a routable identity, so the self-rejection rule has
// something concrete to reject and LAN addresses are refused by default.
func testGossip(t *testing.T, mutate func(*GossipConfig)) *GossipHandler {
	t.Helper()
	cfg := GossipConfig{
		SelfIPv4:    net.ParseIP("198.51.100.1"),
		SelfPort:    4661,
		Name:        "test-server",
		Desc:        "test",
		MaxServers:  4096,
		MaxFailures: 5,
		PublishIPv6: true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return NewGossipHandler(cfg, nil)
}

// keyPeer drives a peer up to peerKeyed, which is the precondition for its peer lists
// to be trusted. Mirrors what phases 1-2 do on the wire.
func keyPeer(t *testing.T, g *GossipHandler, ip string, port uint16) PeerAddr {
	t.Helper()
	addr := PeerAddr{IP: net.ParseIP(ip), Port: port}
	g.mu.Lock()
	g.peers[addr.String()] = &PeerServer{Addr: addr, State: peerSeen}
	g.mu.Unlock()
	g.SetOurChallenge(addr, 0xAABBCCDD)
	g.NoteStatRes(addr.IP, StatResFields{
		Challenge: 0xAABBCCDD, Extended: true,
		ServerKey: 0x12345678, UDPPortObf: port + 14, TCPPortObf: port,
	}, true)
	return addr
}

func peerState_(t *testing.T, g *GossipHandler, addr PeerAddr) peerState {
	t.Helper()
	p, ok := g.PeerByIP(addr.IP)
	if !ok {
		t.Fatalf("peer %s not in the table", addr)
	}
	return p.State
}

// TestMergeRejectsUnobfuscatedList pins the first of the two gates that make gossip
// trustworthy. eserver logs "ignore non obfuscated OP_SERVER_LIST_RES" and drops the
// frame; without this, anyone able to send a UDP packet could inject peers.
func TestMergeRejectsUnobfuscatedList(t *testing.T) {
	g := testGossip(t, nil)
	peer := keyPeer(t, g, "203.0.113.5", 4661)
	entries := []PeerAddr{{IP: net.ParseIP("192.0.2.50"), Port: 4661}}

	admitted := g.MergePeerList(peer.IP, entries, false)
	stats := g.Stats()
	t.Logf("input: 1 entry from a keyed peer, obfuscated=false")
	t.Logf("output: admitted=%d known=%d rejectedPlaintext=%d", admitted, stats.Known, stats.RejectedPlaintext)
	if admitted != 0 {
		t.Fatal("a plaintext peer list must be refused outright")
	}
	if stats.RejectedPlaintext != 1 {
		t.Errorf("RejectedPlaintext = %d, want 1", stats.RejectedPlaintext)
	}
}

// TestMergeRejectsListFromUnknownSender pins the second gate: eserver's "received a
// servlist from unknown server". A sender only qualifies once it has answered our
// bootstrap ping, which requires holding a ServerKey we issued.
func TestMergeRejectsListFromUnknownSender(t *testing.T) {
	g := testGossip(t, nil)
	entries := []PeerAddr{{IP: net.ParseIP("192.0.2.50"), Port: 4661}}

	admitted := g.MergePeerList(net.ParseIP("203.0.113.99"), entries, true)
	stats := g.Stats()
	t.Logf("input: 1 entry from an unhandshaken sender, obfuscated=true")
	t.Logf("output: admitted=%d known=%d rejectedUnsolicited=%d",
		admitted, stats.Known, stats.RejectedUnsolicited)
	if admitted != 0 {
		t.Fatal("a list from a sender we never handshook with must be dropped")
	}
	if stats.RejectedUnsolicited != 1 {
		t.Errorf("RejectedUnsolicited = %d, want 1", stats.RejectedUnsolicited)
	}
}

// TestMergeRejectsSeenButUnkeyedSender is the discriminating case for the gate above:
// peerSeen is not enough, because anyone can reach peerSeen just by appearing in some
// other peer's list.
func TestMergeRejectsSeenButUnkeyedSender(t *testing.T) {
	g := testGossip(t, nil)
	sender := PeerAddr{IP: net.ParseIP("203.0.113.5"), Port: 4661}
	g.mu.Lock()
	g.peers[sender.String()] = &PeerServer{Addr: sender, State: peerSeen}
	g.mu.Unlock()

	admitted := g.MergePeerList(sender.IP, []PeerAddr{{IP: net.ParseIP("192.0.2.50"), Port: 4661}}, true)
	t.Logf("input: sender at state=seen (never answered a ping)")
	t.Logf("output: admitted=%d rejectedUnsolicited=%d", admitted, g.Stats().RejectedUnsolicited)
	if admitted != 0 {
		t.Fatal("a peerSeen sender must not be trusted with a peer list")
	}
}

// TestMergeAdmitsFromKeyedSender is the positive path, so the rejection tests above
// cannot pass by rejecting everything.
func TestMergeAdmitsFromKeyedSender(t *testing.T) {
	g := testGossip(t, nil)
	peer := keyPeer(t, g, "203.0.113.5", 4661)
	entries := []PeerAddr{
		{IP: net.ParseIP("192.0.2.50"), Port: 4661},
		{IP: net.ParseIP("192.0.2.51"), Port: 5555},
	}
	admitted := g.MergePeerList(peer.IP, entries, true)
	t.Logf("input: 2 routable entries from a keyed peer")
	t.Logf("output: admitted=%d known=%d", admitted, g.Stats().Known)
	if admitted != 2 {
		t.Fatalf("admitted %d, want 2", admitted)
	}
	// A harvested entry starts unproven: it must not be advertised until it completes
	// its own handshake.
	if v := g.Verified(); len(v) != 0 {
		t.Fatalf("harvested entries must not be verified on arrival, got %v", v)
	}
	// The referer is recorded, which is how a run of bogus entries is traced back.
	for _, p := range g.Snapshot() {
		if p.Addr.IP.String() == "192.0.2.50" && !p.RefererIP.Equal(peer.IP) {
			t.Errorf("referer = %v, want %v", p.RefererIP, peer.IP)
		}
	}
}

// TestMergeRejectionReasons walks every address-level rejection the policy applies.
func TestMergeRejectionReasons(t *testing.T) {
	cases := []struct {
		name string
		addr PeerAddr
	}{
		{"loopback", PeerAddr{IP: net.ParseIP("127.0.0.1"), Port: 4661}},
		{"private class A", PeerAddr{IP: net.ParseIP("10.0.0.1"), Port: 4661}},
		{"private class B", PeerAddr{IP: net.ParseIP("172.16.0.1"), Port: 4661}},
		{"private class C", PeerAddr{IP: net.ParseIP("192.168.1.1"), Port: 4661}},
		{"link local", PeerAddr{IP: net.ParseIP("169.254.1.1"), Port: 4661}},
		{"unspecified", PeerAddr{IP: net.ParseIP("0.0.0.0"), Port: 4661}},
		{"zero first octet", PeerAddr{IP: net.ParseIP("0.1.2.3"), Port: 4661}},
		{"multicast", PeerAddr{IP: net.ParseIP("224.0.0.1"), Port: 4661}},
		{"reserved", PeerAddr{IP: net.ParseIP("240.0.0.1"), Port: 4661}},
		{"broadcast", PeerAddr{IP: net.ParseIP("255.255.255.255"), Port: 4661}},
		{"port zero", PeerAddr{IP: net.ParseIP("192.0.2.60"), Port: 0}},
		{"nil ip", PeerAddr{IP: nil, Port: 4661}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := testGossip(t, nil)
			peer := keyPeer(t, g, "203.0.113.5", 4661)
			before := g.Stats().Known
			admitted := g.MergePeerList(peer.IP, []PeerAddr{c.addr}, true)
			after := g.Stats()
			t.Logf("input: %v; output: admitted=%d known %d->%d rejectedBad=%d",
				c.addr, admitted, before, after.Known, after.RejectedBad)
			if admitted != 0 {
				t.Fatalf("%s must be refused", c.name)
			}
			if after.RejectedBad == 0 {
				t.Errorf("expected RejectedBad to count this rejection")
			}
		})
	}
}

// TestMergeRejectsSelf covers the rule that stops the phantom self-entries the
// reference implementation kept rediscovering: peers echo back whatever address they
// observed, and re-ingesting it recreates a fake clone of us.
func TestMergeRejectsSelf(t *testing.T) {
	g := testGossip(t, nil)
	g.AddLocalIP(net.ParseIP("203.0.113.77")) // a bind address distinct from the advertised one
	peer := keyPeer(t, g, "203.0.113.5", 4661)

	cases := []struct {
		name string
		addr PeerAddr
	}{
		// Advertised identity, on our own port and on another.
		{"advertised ip and port", PeerAddr{IP: net.ParseIP("198.51.100.1"), Port: 4661}},
		{"advertised ip other port", PeerAddr{IP: net.ParseIP("198.51.100.1"), Port: 36258}},
		// A local bind address the peer observed instead of the advertised one.
		{"local bind address", PeerAddr{IP: net.ParseIP("203.0.113.77"), Port: 4661}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			admitted := g.MergePeerList(peer.IP, []PeerAddr{c.addr}, true)
			t.Logf("input: %v; output: admitted=%d rejectedSelf=%d",
				c.addr, admitted, g.Stats().RejectedSelf)
			if admitted != 0 {
				t.Fatalf("%v is us and must be refused", c.addr)
			}
		})
	}
}

// TestMergeRejectsRecentClient covers the mldonkey case: a client that registered
// itself with real seeds, disconnected from us, and comes back inside someone's list. A
// client is not a server, and admitting one publishes an address that answers nothing.
func TestMergeRejectsRecentClient(t *testing.T) {
	g := testGossip(t, nil)
	peer := keyPeer(t, g, "203.0.113.5", 4661)
	clientIP := net.ParseIP("192.0.2.80")
	g.NoteClient(clientIP)

	admitted := g.MergePeerList(peer.IP, []PeerAddr{{IP: clientIP, Port: 4661}}, true)
	t.Logf("input: an address that is a connected client; output: admitted=%d rejectedPeer=%d",
		admitted, g.Stats().RejectedPeer)
	if admitted != 0 {
		t.Fatal("a connected client's address must not be admitted as a server")
	}

	// Outside the window it becomes admissible again.
	g.mu.Lock()
	g.clientIPs[clientIP.String()] = time.Now().Add(-recentClientWindow - time.Minute)
	g.mu.Unlock()
	admitted = g.MergePeerList(peer.IP, []PeerAddr{{IP: clientIP, Port: 4661}}, true)
	t.Logf("after the %s window elapses: admitted=%d", recentClientWindow, admitted)
	if admitted != 1 {
		t.Fatal("once the window elapses the address should be admissible")
	}
}

// TestMergeHonoursMaxServers pins the DoS guard. Without a cap a hostile peer grows the
// table without bound by echoing fabricated entries.
func TestMergeHonoursMaxServers(t *testing.T) {
	g := testGossip(t, func(c *GossipConfig) { c.MaxServers = 3 })
	peer := keyPeer(t, g, "203.0.113.5", 4661) // occupies 1 of 3
	entries := []PeerAddr{
		{IP: net.ParseIP("192.0.2.1"), Port: 4661},
		{IP: net.ParseIP("192.0.2.2"), Port: 4661},
		{IP: net.ParseIP("192.0.2.3"), Port: 4661},
		{IP: net.ParseIP("192.0.2.4"), Port: 4661},
	}
	admitted := g.MergePeerList(peer.IP, entries, true)
	stats := g.Stats()
	t.Logf("input: maxServers=3, 1 already known, 4 offered")
	t.Logf("output: admitted=%d known=%d rejectedFull=%d", admitted, stats.Known, stats.RejectedFull)
	if stats.Known != 3 {
		t.Fatalf("table holds %d, want the cap of 3", stats.Known)
	}
	if admitted != 2 || stats.RejectedFull != 2 {
		t.Errorf("admitted=%d rejectedFull=%d, want 2 and 2", admitted, stats.RejectedFull)
	}
	_ = peer
}

// TestAllowPrivatePeersOpensLANAddresses covers the escape hatch, which is what makes
// the loopback interop test against the Lugdunum container possible at all.
func TestAllowPrivatePeersOpensLANAddresses(t *testing.T) {
	g := testGossip(t, func(c *GossipConfig) {
		c.AllowPrivatePeers = true
		c.SelfIPv4 = net.ParseIP("192.0.2.200") // not the loopback under test
	})
	peer := keyPeer(t, g, "203.0.113.5", 4661)
	entries := []PeerAddr{
		{IP: net.ParseIP("127.0.0.1"), Port: 4661},
		{IP: net.ParseIP("10.1.2.3"), Port: 4661},
	}
	admitted := g.MergePeerList(peer.IP, entries, true)
	t.Logf("input: allowPrivatePeers=true, offering 127.0.0.1 and 10.1.2.3")
	t.Logf("output: admitted=%d known=%d", admitted, g.Stats().Known)
	if admitted != 2 {
		t.Fatalf("admitted %d, want 2 — allowPrivatePeers must open LAN addresses", admitted)
	}
	// The unconditional rejections still apply even with the hatch open.
	if n := g.MergePeerList(peer.IP, []PeerAddr{{IP: net.ParseIP("224.0.0.1"), Port: 4661}}, true); n != 0 {
		t.Error("multicast must stay refused regardless of allowPrivatePeers")
	}
}

// TestStateMachineProgression walks a peer through all four phases in order and checks
// it is only advertised at the end.
func TestStateMachineProgression(t *testing.T) {
	g := testGossip(t, nil)
	addr := PeerAddr{IP: net.ParseIP("203.0.113.20"), Port: 4661}
	g.mu.Lock()
	g.peers[addr.String()] = &PeerServer{Addr: addr, State: peerSeen}
	g.mu.Unlock()
	t.Logf("phase 0: state=%s verified=%d", peerState_(t, g, addr), len(g.Verified()))

	g.SetOurChallenge(addr, 0xDEADBEEF)
	g.NoteStatRes(addr.IP, StatResFields{
		Challenge: 0xDEADBEEF, Extended: true,
		ServerKey: 0xCAFEBABE, UDPPortObf: 4675, TCPPortObf: 4661,
	}, true)
	t.Logf("phase 2 (obf ping answered): state=%s verified=%d", peerState_(t, g, addr), len(g.Verified()))
	if got := peerState_(t, g, addr); got != peerKeyed {
		t.Fatalf("state = %s, want keyed", got)
	}

	// The name:desc reply is the admission bar (advertisableState), so the peer becomes
	// advertisable here rather than waiting for a list exchange. Requiring the list would be
	// unsatisfiable for a peer with an empty table — confirmed against eserver 17.14, which
	// answers our obfuscated 0xA2 with its identity and sends no list at all.
	if !g.NoteDescription(addr.IP, "peer-name", "peer description") {
		t.Fatal("a valid name:desc reply must be accepted")
	}
	t.Logf("phase 4 (name:desc): state=%s advertisable=%d", peerState_(t, g, addr), len(g.Verified()))
	if got := peerState_(t, g, addr); got != peerDescribed {
		t.Fatalf("state = %s, want described", got)
	}
	v := g.Verified()
	if len(v) != 1 || v[0].String() != "203.0.113.20:4661" {
		t.Fatalf("a described peer must be advertisable, got %v", v)
	}

	// A list exchange is strictly better evidence and moves the peer to the top state, but
	// changes nothing about whether it is advertised.
	g.NoteVerified(addr.IP)
	t.Logf("phase 3 (list exchange): state=%s advertisable=%d", peerState_(t, g, addr), len(g.Verified()))
	if got := peerState_(t, g, addr); got != peerVerified {
		t.Fatalf("state = %s, want verified", got)
	}
	if v := g.Verified(); len(v) != 1 {
		t.Fatalf("Verified() = %v, want exactly the one peer", v)
	}
	// And the peer's learned facts survived into the persisted form.
	entries := g.VerifiedEntries()
	if len(entries) != 1 || entries[0].Name != "peer-name" || entries[0].Description != "peer description" {
		t.Fatalf("VerifiedEntries() = %v", entries)
	}
}

// TestPromoteNeverRegresses matters because the phases complete out of order in
// practice — a description reply can arrive after the list reply — and a late earlier
// phase must not undo progress.
func TestPromoteNeverRegresses(t *testing.T) {
	g := testGossip(t, nil)
	addr := keyPeer(t, g, "203.0.113.30", 4661)
	g.NoteVerified(addr.IP)
	if got := peerState_(t, g, addr); got != peerVerified {
		t.Fatalf("state = %s, want verified", got)
	}
	// A late stat reply would otherwise demote this peer back to keyed.
	g.NoteStatRes(addr.IP, StatResFields{
		Challenge: 0xAABBCCDD, Extended: true, ServerKey: 0x99, UDPPortObf: 4675,
	}, true)
	got := peerState_(t, g, addr)
	t.Logf("input: a late stat reply after verification; output: state=%s", got)
	if got != peerVerified {
		t.Fatalf("state regressed to %s", got)
	}
}

// TestNoteStatResRejectsBadChallenge covers eserver's "sent a bad challenge %x instead
// of %x". Adopting a ServerKey from an unmatched reply would make every later obfuscated
// frame undecryptable at the far end.
func TestNoteStatResRejectsBadChallenge(t *testing.T) {
	g := testGossip(t, nil)
	addr := PeerAddr{IP: net.ParseIP("203.0.113.40"), Port: 4661}
	g.mu.Lock()
	g.peers[addr.String()] = &PeerServer{Addr: addr, State: peerSeen}
	g.mu.Unlock()
	g.SetOurChallenge(addr, 0x11111111)

	g.NoteStatRes(addr.IP, StatResFields{
		Challenge: 0x22222222, Extended: true, ServerKey: 0xBAD,
	}, false)
	p, _ := g.PeerByIP(addr.IP)
	t.Logf("input: reply echoing 0x22222222 where we sent 0x11111111 (challengeMatches=false)")
	t.Logf("output: state=%s ServerKey=0x%08x", p.State, p.ServerKey)
	if p.State != peerSeen {
		t.Errorf("state = %s, want seen: a mismatched reply must not promote", p.State)
	}
	if p.ServerKey != 0 {
		t.Errorf("ServerKey = 0x%08x, want 0: a mismatched reply must not be trusted", p.ServerKey)
	}
}

// TestNoteStatResShortFormDoesNotKey covers the measured Lugdunum behaviour: a plain
// 0x96 gets a 32-byte reply with no ServerKey. That is normal, so the peer must stay
// unkeyed and be retried on the obfuscated channel rather than being treated as broken.
func TestNoteStatResShortFormDoesNotKey(t *testing.T) {
	g := testGossip(t, nil)
	addr := PeerAddr{IP: net.ParseIP("203.0.113.50"), Port: 4661}
	g.mu.Lock()
	g.peers[addr.String()] = &PeerServer{Addr: addr, State: peerSeen}
	g.mu.Unlock()
	g.SetOurChallenge(addr, 0x55AA0001)

	g.NoteStatRes(addr.IP, StatResFields{
		Challenge: 0x55AA0001, Users: 100, Files: 2000, Extended: false,
	}, true)
	p, _ := g.PeerByIP(addr.IP)
	t.Logf("input: short-form 0x97 (no ServerKey), challenge matches")
	t.Logf("output: state=%s users=%d files=%d ServerKey=0x%08x", p.State, p.Users, p.Files, p.ServerKey)
	if p.State != peerSeen {
		t.Errorf("state = %s, want seen: no ServerKey means not yet keyed", p.State)
	}
	// The counts it did report are still worth keeping.
	if p.Users != 100 || p.Files != 2000 {
		t.Errorf("counts = %d/%d, want 100/2000", p.Users, p.Files)
	}
	if p.Failures != 0 {
		t.Error("a short reply is a successful contact, not a failure")
	}
}

// TestNoteDescriptionScreensNameAndDesc covers eserver's "(bad name)"/"(bad desc)"
// rejections. These strings reach logs, the admin page and other servers' lists, so an
// unbounded or control-laden value from an unauthenticated source is not storable.
func TestNoteDescriptionScreensNameAndDesc(t *testing.T) {
	cases := []struct {
		label string
		name  string
		desc  string
		want  bool
	}{
		{"valid", "eserver", "a description", true},
		{"empty description is fine", "eserver", "", true},
		{"empty name refused", "", "d", false},
		{"name too long", strings.Repeat("a", 256), "d", false},
		{"name at the limit", strings.Repeat("a", 255), "d", true},
		{"desc too long", "n", strings.Repeat("b", 513), false},
		{"desc at the limit", "n", strings.Repeat("b", 512), true},
		{"newline in name", "bad\nname", "d", false},
		{"tab in name", "bad\tname", "d", false},
		{"nul in desc", "n", "bad\x00desc", false},
		{"del in desc", "n", "bad\x7fdesc", false},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			g := testGossip(t, nil)
			addr := keyPeer(t, g, "203.0.113.60", 4661)
			ok := g.NoteDescription(addr.IP, c.name, c.desc)
			got := peerState_(t, g, addr)
			t.Logf("input: name=%q desc=%q", truncate(c.name), truncate(c.desc))
			t.Logf("output: accepted=%v state=%s", ok, got)
			if ok != c.want {
				t.Fatalf("accepted = %v, want %v", ok, c.want)
			}
			if c.want && got != peerDescribed {
				t.Errorf("state = %s, want described", got)
			}
			if !c.want && got != peerKeyed {
				t.Errorf("state = %s, want keyed (a bad reply must not promote)", got)
			}
		})
	}
}

// TestNoteRegistrationUsesObservedSourceIP pins that a sender cannot register a third
// party: the announced address is ignored in favour of the observed source. Only the
// port is taken from the payload, since we cannot observe the peer's listening port.
func TestNoteRegistrationUsesObservedSourceIP(t *testing.T) {
	g := testGossip(t, nil)
	observed := net.ParseIP("203.0.113.70")
	g.NoteRegistration(observed, 4661, true)

	snap := g.Snapshot()
	t.Logf("input: 0xA0 from %s announcing port 4661, obfuscated", observed)
	t.Logf("output: %d peer(s) %v", len(snap), snap)
	if len(snap) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(snap))
	}
	if !snap[0].Addr.IP.Equal(observed) || snap[0].Addr.Port != 4661 {
		t.Fatalf("peer = %s, want %s:4661", snap[0].Addr, observed)
	}
	if snap[0].State != peerVerified {
		t.Errorf("state = %s, want verified: an obfuscated 0xA0 proves it holds our ServerKey", snap[0].State)
	}
}

// TestNoteRegistrationPlaintextDoesNotVerify is the gate on 0xA0: a plaintext
// registration is a hint worth probing, never a promotion. eserver logs
// "ignore non obfuscated OP_SERVER_LIST_REQ" for exactly this.
func TestNoteRegistrationPlaintextDoesNotVerify(t *testing.T) {
	g := testGossip(t, nil)
	from := net.ParseIP("203.0.113.71")
	g.NoteRegistration(from, 4661, false)

	p, ok := g.PeerByIP(from)
	stats := g.Stats()
	t.Logf("input: 0xA0 from %s, obfuscated=false", from)
	t.Logf("output: known=%v state=%s verified=%d rejectedPlaintext=%d",
		ok, p.State, len(g.Verified()), stats.RejectedPlaintext)
	if !ok {
		t.Fatal("a plaintext 0xA0 should still be recorded as a hint so the loop probes it")
	}
	if p.State != peerSeen {
		t.Fatalf("state = %s, want seen: plaintext cannot promote", p.State)
	}
	if len(g.Verified()) != 0 {
		t.Fatal("a plaintext registration must not make a peer advertisable")
	}
	if stats.RejectedPlaintext != 1 {
		t.Errorf("RejectedPlaintext = %d, want 1", stats.RejectedPlaintext)
	}
}

// TestNoteRegistrationRejectsSelfAnnouncement covers a peer echoing our own address
// back at us as a registration.
func TestNoteRegistrationRejectsSelfAnnouncement(t *testing.T) {
	g := testGossip(t, nil)
	g.NoteRegistration(net.ParseIP("198.51.100.1"), 4661, true)
	t.Logf("input: 0xA0 apparently from our own advertised IP")
	t.Logf("output: known=%d rejectedSelf=%d", g.Stats().Known, g.Stats().RejectedSelf)
	if g.Stats().Known != 0 {
		t.Fatal("we must never enter ourselves in the peer table")
	}
}

// TestParkingAndRevival covers maxFailures. A parked peer is retained rather than
// deleted so an inbound frame can revive it — a server down for an afternoon should not
// have to be rediscovered from scratch.
func TestParkingAndRevival(t *testing.T) {
	g := testGossip(t, func(c *GossipConfig) { c.MaxFailures = 3 })
	addr := keyPeer(t, g, "203.0.113.80", 4661)

	for i := 1; i <= 3; i++ {
		g.NoteRoundFailure(addr)
		p, _ := g.PeerByIP(addr.IP)
		t.Logf("failure %d: failures=%d parked=%v contactable=%d",
			i, p.Failures, p.Parked(3), len(g.Contactable()))
	}
	if n := len(g.Contactable()); n != 0 {
		t.Fatalf("a parked peer must drop out of the contact list, got %d contactable", n)
	}
	if g.Stats().Known != 1 {
		t.Fatal("a parked peer must be retained, not deleted")
	}

	// An inbound frame revives it.
	g.NoteVerified(addr.IP)
	p, _ := g.PeerByIP(addr.IP)
	t.Logf("after an inbound frame: failures=%d parked=%v contactable=%d",
		p.Failures, p.Parked(3), len(g.Contactable()))
	if p.Failures != 0 || len(g.Contactable()) != 1 {
		t.Fatal("an inbound frame must clear the failure count and revive the peer")
	}
}

// TestVerifiedIsOrderedByFreshness matters because both OP_SERVERLIST and 0xA1 are
// capped at 255: when the table is larger, the freshest entries are the ones worth
// carrying.
func TestVerifiedIsOrderedByFreshness(t *testing.T) {
	g := testGossip(t, nil)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		addr := keyPeer(t, g, ip, 4661)
		g.NoteVerified(addr.IP)
		time.Sleep(2 * time.Millisecond) // distinct LastVerified stamps
	}
	got := g.Verified()
	t.Logf("input: 3 peers verified in ascending order; output: %v", got)
	if len(got) != 3 {
		t.Fatalf("expected 3 verified, got %d", len(got))
	}
	if got[0].IP.String() != "203.0.113.3" {
		t.Fatalf("first entry = %s, want the most recently verified (203.0.113.3)", got[0].IP)
	}
}

// TestNilHandlerIsInert lets every call site skip a nil check when gossip is disabled.
func TestNilHandlerIsInert(t *testing.T) {
	var g *GossipHandler
	g.AddLocalIP(net.ParseIP("1.2.3.4"))
	g.NoteClient(net.ParseIP("1.2.3.4"))
	g.NoteRegistration(net.ParseIP("1.2.3.4"), 4661, true)
	g.NoteStatRes(net.ParseIP("1.2.3.4"), StatResFields{}, true)
	g.NoteVerified(net.ParseIP("1.2.3.4"))
	g.NoteRoundFailure(PeerAddr{IP: net.ParseIP("1.2.3.4"), Port: 4661})
	g.SetOurChallenge(PeerAddr{IP: net.ParseIP("1.2.3.4"), Port: 4661}, 1)
	_, ok := g.PeerByIP(net.ParseIP("1.2.3.4"))
	t.Logf("nil handler: verified=%v entries=%v contactable=%v snapshot=%v peerFound=%v desc=%v merged=%d stats=%+v",
		g.Verified(), g.VerifiedEntries(), g.Contactable(), g.Snapshot(), ok,
		g.NoteDescription(net.ParseIP("1.2.3.4"), "n", "d"),
		g.MergePeerList(net.ParseIP("1.2.3.4"), []PeerAddr{{IP: net.ParseIP("5.6.7.8"), Port: 1}}, true),
		g.Stats())
}

// TestSeedsStartUnverified pins that a configured seed earns its place like any other
// peer. A seed we cannot handshake with is not a peer worth advertising to clients.
func TestSeedsStartUnverified(t *testing.T) {
	seeds := []PeerAddr{{IP: net.ParseIP("203.0.113.5"), Port: 4661}}
	g := NewGossipHandler(GossipConfig{MaxServers: 10, MaxFailures: 5}, seeds)
	t.Logf("input: 1 configured seed")
	t.Logf("output: known=%d verified=%d contactable=%d",
		g.Stats().Known, len(g.Verified()), len(g.Contactable()))
	if g.Stats().Known != 1 {
		t.Fatal("the seed should be in the table")
	}
	if len(g.Verified()) != 0 {
		t.Fatal("a seed must not be advertised before it completes a handshake")
	}
	if len(g.Contactable()) != 1 {
		t.Fatal("the seed must be contacted on the first round")
	}
}

func truncate(s string) string {
	if len(s) <= 32 {
		return s
	}
	return s[:32] + "...(" + string(rune('0'+len(s)/100%10)) + string(rune('0'+len(s)/10%10)) + string(rune('0'+len(s)%10)) + " bytes)"
}
