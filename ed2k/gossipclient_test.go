package ed2k

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// captureWriter records frames instead of sending them, so a round can be driven with
// no sockets bound.
type captureWriter struct {
	mu    sync.Mutex
	sent  []capturedFrame
	label string
}

type capturedFrame struct {
	dst  *net.UDPAddr
	data []byte
}

func (c *captureWriter) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, capturedFrame{
		dst:  &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port},
		data: append([]byte(nil), b...),
	})
	return len(b), nil
}

func (c *captureWriter) frames() []capturedFrame {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]capturedFrame(nil), c.sent...)
}

// decodeObf unwraps a frame with the given ServerKey and returns the inner plaintext.
// Uses the same UDPCrypt a peer would, which is the point: if the loop's envelope were
// wrong, this would fail to produce a PR_ED2K frame.
func decodeObf(t *testing.T, key uint32, data []byte) []byte {
	t.Helper()
	// Decrypt() expects the client->server direction, which is what writeObf produces.
	plain := NewUDPCrypt(true, key).Decrypt(data)
	if len(plain) == 0 || plain[0] != PrED2K {
		t.Fatalf("frame did not decrypt to an eD2K packet: % x", plain)
	}
	return plain
}

// opcodesOf lists the eD2K opcodes among captured plaintext frames.
func opcodesOf(frames []capturedFrame) []uint8 {
	out := make([]uint8, 0, len(frames))
	for _, f := range frames {
		if len(f.data) >= 2 && f.data[0] == PrED2K {
			out = append(out, f.data[1])
		}
	}
	return out
}

func testClientCfg(main, gossip *captureWriter) GossipClientConfig {
	return GossipClientConfig{
		Main: main, Gossip: gossip,
		MainPort: 5559, GossipPort: 5569,
		Interval: time.Hour, // rounds are driven explicitly
	}
}

// TestRoundPhase1UsesMainSocketAndCorrectPorts pins that the plaintext bootstrap leaves
// from the main UDP listener and targets the peer's P+4, and that it carries both the
// 0xA0 registration and the 0x96 probe.
func TestRoundPhase1UsesMainSocketAndCorrectPorts(t *testing.T) {
	main, gossip := &captureWriter{label: "main"}, &captureWriter{label: "gossip"}
	g := NewGossipHandler(GossipConfig{
		SelfIPv4: net.ParseIP("198.51.100.1"), SelfPort: 5555,
		MaxServers: 10, MaxFailures: 5, UDPPortObf: 5569, TCPPortObf: 5555,
	}, []PeerAddr{{IP: net.ParseIP("203.0.113.5"), Port: 4661}})

	g.RunRound(testClientCfg(main, gossip))

	mf := main.frames()
	t.Logf("input: one unkeyed peer at 203.0.113.5:4661")
	for _, f := range mf {
		t.Logf("output: main socket -> %s  % x", f.dst, f.data)
	}
	ops := opcodesOf(mf)
	t.Logf("output: main opcodes %#x", ops)

	if len(mf) != 2 {
		t.Fatalf("expected 2 plaintext frames (0xA0 and 0x96), got %d", len(mf))
	}
	for _, f := range mf {
		if f.dst.Port != 4661+peerMainUDPOffset {
			t.Errorf("phase 1 sent to port %d, want the peer's eD2K port + 4 = %d",
				f.dst.Port, 4661+peerMainUDPOffset)
		}
		if !f.dst.IP.Equal(net.ParseIP("203.0.113.5")) {
			t.Errorf("phase 1 sent to %v", f.dst.IP)
		}
	}
	if len(ops) != 2 || ops[0] != OpServerListReq || ops[1] != OpGlobServStatReq {
		t.Fatalf("phase 1 opcodes = %#x, want [a0 96]", ops)
	}
}

// TestPhase1ChallengeFollowsEMuleConvention pins uChallenge = 0x55AA0000 +
// GetRandomUInt16 (srchybrid/ServerList.cpp:306). The marker does not select the
// extended reply — measured against eserver it does not — but it is what real clients
// send, so matching it keeps us indistinguishable from one on the plain channel.
func TestPhase1ChallengeFollowsEMuleConvention(t *testing.T) {
	main, gossip := &captureWriter{}, &captureWriter{}
	g := NewGossipHandler(GossipConfig{
		SelfIPv4: net.ParseIP("198.51.100.1"), SelfPort: 5555, MaxServers: 10, MaxFailures: 5,
	}, []PeerAddr{{IP: net.ParseIP("203.0.113.5"), Port: 4661}})
	g.RunRound(testClientCfg(main, gossip))

	for _, f := range main.frames() {
		if len(f.data) >= 6 && f.data[1] == OpGlobServStatReq {
			challenge, err := NewBufferFromBytes(f.data[2:]).GetUInt32LE()
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("output: 0x96 challenge = 0x%08x", challenge)
			if challenge&0xFFFF0000 != 0x55AA0000 {
				t.Fatalf("challenge 0x%08x lacks the 0x55AA marker", challenge)
			}
			return
		}
	}
	t.Fatal("no 0x96 frame captured")
}

// TestPhase2SendsRawUnencryptedPingToPlus12 pins the three properties of the bootstrap
// ping that matter: it goes out on the gossip socket, to the peer's +12 (the port eMule
// hardwires and a peer therefore cannot move), and it is NOT encrypted — we hold no key
// for this peer yet, which is the entire reason the phase exists.
func TestPhase2SendsRawUnencryptedPingToPlus12(t *testing.T) {
	main, gossip := &captureWriter{}, &captureWriter{}
	g := NewGossipHandler(GossipConfig{
		SelfIPv4: net.ParseIP("198.51.100.1"), SelfPort: 5555, MaxServers: 10, MaxFailures: 5,
	}, []PeerAddr{{IP: net.ParseIP("203.0.113.5"), Port: 4661}})
	g.RunRound(testClientCfg(main, gossip))

	gf := gossip.frames()
	t.Logf("input: one unkeyed peer; output: %d frame(s) on the gossip socket", len(gf))
	if len(gf) != 1 {
		t.Fatalf("expected exactly the bootstrap ping, got %d frames", len(gf))
	}
	f := gf[0]
	t.Logf("output: gossip socket -> %s  %d bytes  % x", f.dst, len(f.data), f.data)

	if f.dst.Port != 4661+peerObfPingOffset {
		t.Errorf("bootstrap ping sent to port %d, want the peer's eD2K port + 12 = %d",
			f.dst.Port, 4661+peerObfPingOffset)
	}
	if len(f.data) < 4 || len(f.data) > 4+obfPingMaxPad {
		t.Errorf("ping length %d outside 4..%d", len(f.data), 4+obfPingMaxPad)
	}
	if IsProtocol(f.data[0]) {
		t.Errorf("first byte 0x%02x is a protocol constant: the peer would read this as a plaintext frame", f.data[0])
	}
	// The challenge must have been recorded, or the reply cannot be decrypted.
	p, ok := g.PeerByIP(net.ParseIP("203.0.113.5"))
	if !ok {
		t.Fatal("peer vanished")
	}
	wantChallenge := uint32FromV4(f.data[:4])
	t.Logf("output: recorded OurChallenge=0x%08x, wire challenge=0x%08x", p.OurChallenge, wantChallenge)
	if p.OurChallenge != wantChallenge {
		t.Fatalf("recorded challenge 0x%08x does not match the wire 0x%08x — the reply would be undecryptable",
			p.OurChallenge, wantChallenge)
	}
}

// TestPhase3And4AreObfuscatedAndUseAdvertisedPort is the core of the gossip contract:
// once keyed, every frame is wrapped with the peer's ServerKey and sent to the port the
// peer advertised, not the +14 default.
func TestPhase3And4AreObfuscatedAndUseAdvertisedPort(t *testing.T) {
	main, gossip := &captureWriter{}, &captureWriter{}
	g := NewGossipHandler(GossipConfig{
		SelfIPv4: net.ParseIP("198.51.100.1"), SelfPort: 5555,
		MaxServers: 10, MaxFailures: 5, UDPPortObf: 5569, TCPPortObf: 5555,
	}, []PeerAddr{{IP: net.ParseIP("203.0.113.5"), Port: 4661}})

	const key = 0xCAFEBABE
	const advertised = 9999 // deliberately not 4661+14
	addr := PeerAddr{IP: net.ParseIP("203.0.113.5"), Port: 4661}
	g.SetOurChallenge(addr, 0xAABBCCDD)
	g.NoteStatRes(addr.IP, StatResFields{
		Challenge: 0xAABBCCDD, Extended: true,
		ServerKey: key, UDPPortObf: advertised, TCPPortObf: 4661,
	}, true)

	g.RunRound(testClientCfg(main, gossip))

	t.Logf("input: keyed peer, ServerKey=0x%08x, advertised portUDPOBF=%d", uint32(key), advertised)
	if len(main.frames()) != 0 {
		t.Errorf("a keyed peer needs no plaintext phase 1, got %d frames", len(main.frames()))
	}

	var obfOps []uint8
	pingSeen := false
	for _, f := range gossip.frames() {
		if f.dst.Port == 4661+peerObfPingOffset {
			pingSeen = true
			t.Logf("output: -> %s  bootstrap ping (%d bytes)", f.dst, len(f.data))
			continue
		}
		if f.dst.Port != advertised {
			t.Errorf("obfuscated frame sent to port %d, want the advertised %d", f.dst.Port, advertised)
		}
		if f.data[0] == PrED2K {
			t.Fatalf("frame to %s is plaintext (starts 0xE3): gossip must be obfuscated", f.dst)
		}
		plain := decodeObf(t, key, f.data)
		obfOps = append(obfOps, plain[1])
		t.Logf("output: -> %s  obfuscated %d bytes -> inner opcode 0x%02x", f.dst, len(f.data), plain[1])
	}
	if !pingSeen {
		t.Error("the bootstrap ping should still be re-sent each round to keep the ServerKey fresh")
	}
	// 0xA0 re-register, 0xA4 list request, 0xA2 name:desc. No 0xA7 (peer advertised no
	// IPv6 flag) and no 0x97 echo (it never probed us).
	want := map[uint8]bool{OpServerListReq: false, OpServerListReq2: false, OpServerDescReq: false}
	for _, op := range obfOps {
		if _, ok := want[op]; !ok {
			t.Errorf("unexpected obfuscated opcode 0x%02x", op)
			continue
		}
		want[op] = true
	}
	for op, seen := range want {
		if !seen {
			t.Errorf("missing obfuscated opcode 0x%02x", op)
		}
	}
}

// TestPhase3SkipsIPv6RequestWithoutTheFlag keeps 0xA7 off the wire for a stock eserver,
// which would only log it as an unknown opcode.
func TestPhase3SkipsIPv6RequestWithoutTheFlag(t *testing.T) {
	for _, withFlag := range []bool{false, true} {
		main, gossip := &captureWriter{}, &captureWriter{}
		g := NewGossipHandler(GossipConfig{
			SelfIPv4: net.ParseIP("198.51.100.1"), SelfPort: 5555,
			MaxServers: 10, MaxFailures: 5, PublishIPv6: true,
		}, []PeerAddr{{IP: net.ParseIP("203.0.113.5"), Port: 4661}})

		addr := PeerAddr{IP: net.ParseIP("203.0.113.5"), Port: 4661}
		flags := uint32(0)
		if withFlag {
			flags = FlagIPv6
		}
		g.SetOurChallenge(addr, 1)
		g.NoteStatRes(addr.IP, StatResFields{
			Challenge: 1, Extended: true, ServerKey: 0x11, UDPPortObf: 4675, UDPFlags: flags,
		}, true)
		g.RunRound(testClientCfg(main, gossip))

		found := false
		for _, f := range gossip.frames() {
			if f.dst.Port == 4661+peerObfPingOffset {
				continue
			}
			if plain := NewUDPCrypt(true, 0x11).Decrypt(f.data); len(plain) >= 2 && plain[1] == OpServerListReqIPv6 {
				found = true
			}
		}
		t.Logf("peer advertised FlagIPv6=%v -> 0xA7 sent=%v", withFlag, found)
		if found != withFlag {
			t.Errorf("FlagIPv6=%v: 0xA7 sent=%v, want %v", withFlag, found, withFlag)
		}
	}
}

// TestPhase3SendsNoUnsolicitedStatRes pins a correction from live interop: a gossip round
// must never volunteer an OP_GLOBSERVSTATRES.
//
// It used to send one whenever the peer had registered with us, echoing the challenge from
// that 0xA0. eserver keeps a *separate* per-peer ping challenge, so it rejected every one
// ("server %s:%d sent a bad challenge %x instead of %x") and — the part that actually hurt —
// the rejection reset its ping bookkeeping for us, leaving us permanently outside its
// "working servers" list and therefore out of its server.met.
//
// A 0x97 is only ever correct as a direct reply, because only the reply knows which
// challenge was asked. The inbound handler already sends those.
func TestPhase3SendsNoUnsolicitedStatRes(t *testing.T) {
	main, gossip := &captureWriter{}, &captureWriter{}
	g := NewGossipHandler(GossipConfig{
		SelfIPv4: net.ParseIP("198.51.100.1"), SelfPort: 5555,
		MaxServers: 10, MaxFailures: 5, UDPPortObf: 5567, TCPPortObf: 5555,
	}, []PeerAddr{{IP: net.ParseIP("203.0.113.5"), Port: 4661}})

	addr := PeerAddr{IP: net.ParseIP("203.0.113.5"), Port: 4661}
	g.SetOurChallenge(addr, 1)
	g.NoteStatRes(addr.IP, StatResFields{Challenge: 1, Extended: true, ServerKey: 0x22, UDPPortObf: 4675}, true)
	// The peer has registered with us and we hold its key — the exact state that used to
	// trigger an echo.
	g.NoteRegistration(addr.IP, 4661, true)

	g.RunRound(testClientCfg(main, gossip))

	sent := make([]string, 0, 4)
	for _, f := range gossip.frames() {
		if f.dst.Port == 4661+peerObfPingOffset {
			continue // the raw, unencrypted bootstrap ping
		}
		plain := NewUDPCrypt(true, 0x22).Decrypt(f.data)
		if len(plain) < 2 {
			continue
		}
		sent = append(sent, fmt.Sprintf("0x%02x", plain[1]))
		if plain[1] == OpGlobServStatRes {
			t.Errorf("a gossip round sent an unsolicited 0x97 to %s; only a direct reply may carry one", f.dst)
		}
	}
	t.Logf("input: peer keyed and registered; output: obfuscated opcodes sent = %v", sent)
	if len(sent) == 0 {
		t.Fatal("no obfuscated frames at all: the round did not run")
	}
}

// TestGossipDestPortFallsBackToPlus14 covers the case where a peer has advertised
// nothing yet: eserver's portUDPOBF default. Once it advertises, that value wins — the
// port is a donkey.ini parameter, so assuming +14 forever would miss a peer that moved
// it.
func TestGossipDestPortFallsBackToPlus14(t *testing.T) {
	cases := []struct {
		advertised uint16
		want       uint16
	}{
		{0, 4661 + peerGossipOffset},
		{4675, 4675},
		{9999, 9999},
	}
	for _, c := range cases {
		p := PeerServer{Addr: PeerAddr{IP: net.ParseIP("1.2.3.4"), Port: 4661}, UDPPortObf: c.advertised}
		got := gossipDestPort(p)
		t.Logf("advertised portUDPOBF=%d -> destination %d", c.advertised, got)
		if got != c.want {
			t.Errorf("advertised %d: got %d, want %d", c.advertised, got, c.want)
		}
	}
}

// TestRoundSkipsParkedPeers guards the failure budget: a dead peer must stop consuming
// a round's worth of datagrams once it has failed maxFailures times.
func TestRoundSkipsParkedPeers(t *testing.T) {
	main, gossip := &captureWriter{}, &captureWriter{}
	g := NewGossipHandler(GossipConfig{
		SelfIPv4: net.ParseIP("198.51.100.1"), SelfPort: 5555, MaxServers: 10, MaxFailures: 2,
	}, []PeerAddr{{IP: net.ParseIP("203.0.113.5"), Port: 4661}})
	cfg := testClientCfg(main, gossip)

	for round := 1; round <= 4; round++ {
		before := len(main.frames()) + len(gossip.frames())
		g.RunRound(cfg)
		after := len(main.frames()) + len(gossip.frames())
		p, _ := g.PeerByIP(net.ParseIP("203.0.113.5"))
		t.Logf("round %d: frames sent=%d failures=%d parked=%v", round, after-before, p.Failures, p.Parked(2))
	}
	// Rounds 1 and 2 send; the peer parks after 2 failures and rounds 3 and 4 are silent.
	total := len(main.frames()) + len(gossip.frames())
	t.Logf("output: %d frames total across 4 rounds", total)
	if total != 6 {
		t.Fatalf("sent %d frames, want 6 (3 per round for 2 rounds, then parked)", total)
	}
}

// TestRoundIncrementsFailuresClearedByInbound pins the accounting: a round always
// counts a failure, and any inbound frame clears it. Without the clear, a healthy peer
// would park after maxFailures rounds no matter how well it was answering.
func TestRoundIncrementsFailuresClearedByInbound(t *testing.T) {
	main, gossip := &captureWriter{}, &captureWriter{}
	g := NewGossipHandler(GossipConfig{
		SelfIPv4: net.ParseIP("198.51.100.1"), SelfPort: 5555, MaxServers: 10, MaxFailures: 3,
	}, []PeerAddr{{IP: net.ParseIP("203.0.113.5"), Port: 4661}})
	cfg := testClientCfg(main, gossip)
	ip := net.ParseIP("203.0.113.5")

	for range 5 {
		g.RunRound(cfg)
		g.NoteVerified(ip) // the peer answered
	}
	p, _ := g.PeerByIP(ip)
	t.Logf("input: 5 rounds, each answered; output: failures=%d parked=%v state=%s",
		p.Failures, p.Parked(3), p.State)
	if p.Failures != 0 {
		t.Fatalf("failures = %d, want 0: an answering peer must never accumulate", p.Failures)
	}
	if len(g.Contactable()) != 1 {
		t.Fatal("an answering peer must stay contactable")
	}
}

// TestStartGossipClientRunsImmediatelyAndStops covers the scheduler: a server that just
// booted has an empty table and no reason to wait a full interval before filling it, and
// stop must be idempotent because main.go registers it with defer alongside others.
func TestStartGossipClientRunsImmediatelyAndStops(t *testing.T) {
	main, gossip := &captureWriter{}, &captureWriter{}
	g := NewGossipHandler(GossipConfig{
		SelfIPv4: net.ParseIP("198.51.100.1"), SelfPort: 5555, MaxServers: 10, MaxFailures: 5,
	}, []PeerAddr{{IP: net.ParseIP("203.0.113.5"), Port: 4661}})

	stop := g.StartGossipClient(testClientCfg(main, gossip))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(main.frames()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	sent := len(main.frames())
	t.Logf("output: %d frame(s) on the main socket without waiting for the interval", sent)
	if sent == 0 {
		t.Fatal("the first round must run immediately, not after one interval")
	}
	stop()
	stop() // must not panic
	t.Logf("output: stop() is idempotent")
}

// TestNilHandlerClientIsInert lets main.go call these unconditionally when gossip is off.
func TestNilHandlerClientIsInert(t *testing.T) {
	var g *GossipHandler
	stop := g.StartGossipClient(GossipClientConfig{})
	g.RunRound(GossipClientConfig{})
	stop()
	t.Logf("nil handler: StartGossipClient and RunRound are no-ops, config=%+v", g.Config())
}

// TestRoundWithoutSelfIPv4SkipsRegistration covers a server with no routable IPv4: there
// is nothing truthful to put in 0xA0's address field, so registration is skipped rather
// than announcing 0.0.0.0. The obfuscated ping still goes out, so the peer can still
// learn of us.
func TestRoundWithoutSelfIPv4SkipsRegistration(t *testing.T) {
	main, gossip := &captureWriter{}, &captureWriter{}
	g := NewGossipHandler(GossipConfig{
		SelfPort: 5555, MaxServers: 10, MaxFailures: 5, // no SelfIPv4
	}, []PeerAddr{{IP: net.ParseIP("203.0.113.5"), Port: 4661}})
	g.RunRound(testClientCfg(main, gossip))

	t.Logf("input: no SelfIPv4 configured")
	t.Logf("output: main frames=%d gossip frames=%d", len(main.frames()), len(gossip.frames()))
	if len(main.frames()) != 0 {
		t.Errorf("phase 1 must be skipped without a routable IPv4, got %#x", opcodesOf(main.frames()))
	}
	if len(gossip.frames()) != 1 {
		t.Error("the bootstrap ping must still be sent so the peer can learn of us")
	}
}
