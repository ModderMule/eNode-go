package ed2k

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"enode/storage"
)

// captureConn is a mockConn whose Write records the framed bytes the server sends
// so a test can inspect the opcode it emitted. mockConn.Write discards, which is
// why the callback-family test needs its own conn.
type captureConn struct {
	mockConn
	mu  sync.Mutex
	buf []byte
}

func (c *captureConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, b...)
	return len(b), nil
}

// written returns a copy of everything written so far.
func (c *captureConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

// opcode returns the eD2K opcode of the first framed packet written, or 0 if none.
// Framing is <protocol:1><size:4><opcode:1>…, so the opcode is byte 5.
func (c *captureConn) opcode() byte {
	b := c.written()
	if len(b) < 6 {
		return 0
	}
	return b[5]
}

// payload returns the payload of the first framed packet written, or nil if none.
func (c *captureConn) payload() []byte {
	b := c.written()
	if len(b) < 6 {
		return nil
	}
	return b[6:]
}

func TestBuildCallbackRequestedIPv6PacketWire(t *testing.T) {
	ipv6 := net.ParseIP("2001:db8::1234").To16()
	hash := bytes.Repeat([]byte{0xab}, 16)
	for _, tc := range []struct {
		name    string
		crypt   byte
		hash    []byte
		wantLen int
	}{
		{"without trailer", 0x03, nil, 18},
		{"with trailer", 0x0b, hash, 35},
	} {
		pkt, err := BuildCallbackRequestedIPv6Packet(ipv6, 4662, tc.crypt, tc.hash)
		if err != nil {
			t.Fatalf("%s: build failed: %v", tc.name, err)
		}
		b := pkt.Bytes()
		t.Logf("input: %s ipv6=%s port=4662 crypt=%#x, output: % x", tc.name, net.IP(ipv6), tc.crypt, b)
		if b[0] != PrED2K || b[5] != OpCallbackReqdIPv6 {
			t.Fatalf("protocol/opcode = %#x/%#x", b[0], b[5])
		}
		payload := b[6:]
		if len(payload) != tc.wantLen {
			t.Fatalf("payload is %d bytes, want %d", len(payload), tc.wantLen)
		}
		if !bytes.Equal(payload[:16], ipv6) || payload[16] != 0x36 || payload[17] != 0x12 {
			t.Fatalf("ipv6/port = % x", payload[:18])
		}
		if tc.wantLen == 35 && (payload[18] != tc.crypt&0x07 || !bytes.Equal(payload[19:], hash)) {
			t.Fatalf("trailer = % x", payload[18:])
		}
	}
}

func TestBuildIPv6CallbackFailPacketWire(t *testing.T) {
	pkt, err := BuildIPv6CallbackFailPacket(0x00123456, IPv6CallbackRefusedTargetNotOptedIn)
	if err != nil {
		t.Fatal(err)
	}
	b := pkt.Bytes()
	t.Logf("input: target=0x123456 reason=6, output: % x", b)
	want := []byte{PrED2K, 6, 0, 0, 0, OpCallbackFailed, 0x56, 0x34, 0x12, 0x00, 6}
	if !bytes.Equal(b, want) {
		t.Fatalf("packet = % x, want % x", b, want)
	}
}

// ipv6CallbackRig is a server with the IPv6 callback offered, a LowID requester
// whose IPv6 passed the dial-back, and an opted-in LowID target.
type ipv6CallbackRig struct {
	rt                  *ServerRuntime
	requester, target   *tcpClient
	reqConn, targetConn *captureConn
	targetID            uint32
}

func newIPv6CallbackRig(t *testing.T) *ipv6CallbackRig {
	t.Helper()
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address:          "127.0.0.1",
		Hash:             bytes.Repeat([]byte{0x01}, 16),
		Port:             4661,
		AllowLowIDs:      true,
		IPv6:             true,
		PublishV6Sources: true,
		ProbeIPv6:        true,
		IPv6Callback:     true,
	}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	r := &ipv6CallbackRig{rt: rt, reqConn: &captureConn{}, targetConn: &captureConn{}}

	r.target = newTCPClient(rt, r.targetConn, false)
	r.target.infoMu.Lock()
	r.target.logged = true
	r.target.ipv6Capable = true
	r.target.v6CallbackOptIn = true
	r.target.info.LowID = true
	r.target.info.Hash = bytes.Repeat([]byte{0x22}, 16)
	r.target.info.IPv6 = net.ParseIP("2001:db8::99").To16()
	r.target.info.Port = 6000
	r.target.infoMu.Unlock()
	id, ok := rt.LowIDs.Add(r.target)
	if !ok {
		t.Fatal("failed to register target in LowIDs")
	}
	r.targetID = id

	r.requester = newTCPClient(rt, r.reqConn, false)
	r.requester.infoMu.Lock()
	r.requester.logged = true
	r.requester.ipv6Capable = true
	r.requester.info.LowID = true
	r.requester.info.IPv4 = 0x0102030a
	r.requester.info.Hash = bytes.Repeat([]byte{0x11}, 16)
	r.requester.info.IPv6 = net.ParseIP("2001:db8::1234").To16()
	r.requester.info.IPv6Reachable = true
	r.requester.v6Probed = true
	r.requester.info.Port = 5000
	r.requester.infoMu.Unlock()
	return r
}

func (r *ipv6CallbackRig) request(id uint32) {
	req := NewBuffer(4)
	_ = req.PutUInt32LE(id)
	req.Pos(0)
	r.requester.handleIPv6CallbackRequest(req)
}

// TestIPv6CallbackForwarded: a verified LowID requester and an opted-in target get
// the target a 0x26 with the requester's IPv6 and login port, and the requester
// nothing.
func TestIPv6CallbackForwarded(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		reqCrypt, targetCrypt byte
		wantLen               int
	}{
		{"plain", 0, 0, 18},
		{"only requester obfuscates", 0x03, 0, 18},
		{"both obfuscate", 0x03, 0x01, 35},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newIPv6CallbackRig(t)
			r.requester.info.CryptOptions = tc.reqCrypt
			r.target.info.CryptOptions = tc.targetCrypt
			r.request(r.targetID)
			got := r.targetConn.payload()
			t.Logf("input: target=%d reqCrypt=%#x targetCrypt=%#x, output: target opcode=%#x payload=% x requester=% x",
				r.targetID, tc.reqCrypt, tc.targetCrypt, r.targetConn.opcode(), got, r.reqConn.written())
			if r.targetConn.opcode() != OpCallbackReqdIPv6 || len(got) != tc.wantLen {
				t.Fatalf("target got opcode %#x with %d bytes, want 0x26 with %d", r.targetConn.opcode(), len(got), tc.wantLen)
			}
			if !bytes.Equal(got[:16], r.requester.info.IPv6) || binary.LittleEndian.Uint16(got[16:18]) != 5000 {
				t.Fatalf("ipv6/port = % x", got[:18])
			}
			if tc.wantLen == 35 && (got[18] != tc.reqCrypt || !bytes.Equal(got[19:], r.requester.info.Hash)) {
				t.Fatalf("trailer = % x", got[18:])
			}
			if len(r.reqConn.written()) != 0 {
				t.Fatalf("requester got % x, want nothing", r.reqConn.written())
			}
			if n := r.rt.BlockStats().IPv6CallbackForwarded; n != 1 {
				t.Fatalf("forwarded counter = %d", n)
			}
		})
	}
}

// TestIPv6CallbackRefusals walks every refusal in ed2k-server's order: each case
// breaks one condition and expects that reason in the 5-byte 0x36, and no 0x26.
func TestIPv6CallbackRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(r *ipv6CallbackRig) uint32
		want   uint8
	}{
		{"callback off", func(r *ipv6CallbackRig) uint32 {
			cfg := *r.rt.tcp()
			cfg.IPv6Callback = false
			r.rt.tcpCfg.Store(&cfg)
			return r.targetID
		}, IPv6CallbackRefusedNotOffered},
		{"probing off", func(r *ipv6CallbackRig) uint32 {
			cfg := *r.rt.tcp()
			cfg.ProbeIPv6 = false
			r.rt.tcpCfg.Store(&cfg)
			return r.targetID
		}, IPv6CallbackRefusedNotOffered},
		{"requester not v6-capable", func(r *ipv6CallbackRig) uint32 {
			r.requester.ipv6Capable = false
			return r.targetID
		}, IPv6CallbackRefusedNotOffered},
		{"requester highid", func(r *ipv6CallbackRig) uint32 {
			r.requester.info.LowID = false
			return r.targetID
		}, IPv6CallbackRefusedRequesterHighID},
		{"requester dial-back failed", func(r *ipv6CallbackRig) uint32 {
			r.requester.info.IPv6Reachable = false
			return r.targetID
		}, IPv6CallbackRefusedRequesterNotVerified},
		{"requester trusted, not dialled", func(r *ipv6CallbackRig) uint32 {
			r.requester.v6Probed = false
			return r.targetID
		}, IPv6CallbackRefusedRequesterNotVerified},
		{"requester dial-back running", func(r *ipv6CallbackRig) uint32 {
			r.requester.v6Probing = true
			return r.targetID
		}, IPv6CallbackRefusedRequesterNotVerified},
		{"requester has no ipv6", func(r *ipv6CallbackRig) uint32 {
			r.requester.info.IPv6 = nil
			return r.targetID
		}, IPv6CallbackRefusedRequesterNotVerified},
		{"target unknown", func(r *ipv6CallbackRig) uint32 {
			return r.targetID + 1
		}, IPv6CallbackRefusedTargetGone},
		{"target still logging in", func(r *ipv6CallbackRig) uint32 {
			r.target.logged = false
			return r.targetID
		}, IPv6CallbackRefusedTargetGone},
		{"target is the requester", func(r *ipv6CallbackRig) uint32 {
			r.target.info.Hash = r.requester.info.Hash
			return r.targetID
		}, IPv6CallbackRefusedSelfTarget},
		{"target did not opt in", func(r *ipv6CallbackRig) uint32 {
			r.target.v6CallbackOptIn = false
			return r.targetID
		}, IPv6CallbackRefusedTargetNotOptedIn},
		{"target withdrew its ipv6", func(r *ipv6CallbackRig) uint32 {
			r.target.ipv6Capable = false
			return r.targetID
		}, IPv6CallbackRefusedTargetNotOptedIn},
		{"target socket gone", func(r *ipv6CallbackRig) uint32 {
			r.target.conn = &failingConn{}
			return r.targetID
		}, IPv6CallbackRefusedTargetUnreachable},
		{"allowance used up", func(r *ipv6CallbackRig) uint32 {
			r.requester.relayAt = uint16(time.Since(r.requester.connectedAt) / time.Second)
			r.requester.relaySpent = relayBurst
			return r.targetID
		}, IPv6CallbackRefusedRateLimited},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newIPv6CallbackRig(t)
			id := tc.break_(r)
			r.request(id)
			got := r.reqConn.payload()
			t.Logf("input: %s target=%d, output: requester opcode=%#x payload=% x target=% x",
				tc.name, id, r.reqConn.opcode(), got, r.targetConn.written())
			if r.reqConn.opcode() != OpCallbackFailed || len(got) != 5 {
				t.Fatalf("requester got opcode %#x with %d bytes, want 5-byte 0x36", r.reqConn.opcode(), len(got))
			}
			if binary.LittleEndian.Uint32(got[:4]) != id || got[4] != tc.want {
				t.Fatalf("refusal = % x, want target %d reason %d", got, id, tc.want)
			}
			if r.targetConn.opcode() == OpCallbackReqdIPv6 {
				t.Fatal("target got a 0x26")
			}
			if n := r.rt.BlockStats().IPv6CallbackRefused[tc.want]; n != 1 {
				t.Fatalf("refusal counter[%d] = %d", tc.want, n)
			}
		})
	}
}

// TestIPv6CallbackRequestShortPayloadIgnored: under 4 bytes there is no target to
// name in a refusal, so the request is dropped, as by ed2k-server.
func TestIPv6CallbackRequestShortPayloadIgnored(t *testing.T) {
	r := newIPv6CallbackRig(t)
	r.requester.handleIPv6CallbackRequest(NewBufferFromBytes([]byte{1, 2, 3}))
	t.Logf("input: 3-byte payload, output: requester=% x target=% x", r.reqConn.written(), r.targetConn.written())
	if len(r.reqConn.written())+len(r.targetConn.written()) != 0 {
		t.Fatal("a short request was answered")
	}
}

func TestIPv6CallbackOptIn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		offered bool
		before  bool
		payload []byte
		want    bool
	}{
		{"empty opts in", true, false, nil, true},
		{"bit 0 opts in", true, false, []byte{0x01}, true},
		{"other bits ignored", true, false, []byte{0xff}, true},
		{"bit 0 clear opts out", true, true, []byte{0x00}, false},
		{"not offered is ignored", false, false, nil, false},
		{"not offered keeps state", false, true, []byte{0x00}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newIPv6CallbackRig(t)
			r.target.ipv6Capable = tc.offered
			r.target.v6CallbackOptIn = tc.before
			r.target.handleIPv6CallbackOptIn(NewBufferFromBytes(tc.payload))
			t.Logf("input: offered=%t before=%t payload=% x, output: optIn=%t", tc.offered, tc.before, tc.payload, r.target.v6CallbackOptIn)
			if r.target.v6CallbackOptIn != tc.want {
				t.Fatalf("optIn = %t, want %t", r.target.v6CallbackOptIn, tc.want)
			}
			if len(r.targetConn.written()) != 0 {
				t.Fatal("opt-in was answered")
			}
		})
	}
}

// TestIPv6UpdateWithdrawalClearsCallbackOptIn: 16 zero bytes in OP_IPV6_UPDATE take
// the opt-in with the address; a new address keeps it.
func TestIPv6UpdateWithdrawalClearsCallbackOptIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr []byte
		want bool
	}{
		{"withdraw", make([]byte, 16), false},
		{"new address", net.ParseIP("2001:db8::77").To16(), true},
	} {
		r := newIPv6CallbackRig(t)
		cfg := *r.rt.tcp()
		cfg.ProbeIPv6 = false // no dial-back goroutine in this test
		r.rt.tcpCfg.Store(&cfg)
		r.target.handleIPv6Update(NewBufferFromBytes(tc.addr))
		t.Logf("input: %s % x, output: optIn=%t capable=%t", tc.name, tc.addr, r.target.v6CallbackOptIn, r.target.ipv6Capable)
		if r.target.v6CallbackOptIn != tc.want {
			t.Fatalf("%s: optIn = %t, want %t", tc.name, r.target.v6CallbackOptIn, tc.want)
		}
	}
}

// TestServerIdentIPv6CallbackTag: TagIPv6Callback (0xaa) = 0x01 goes to a v6-capable
// session while the callback, publication and probing are on, and nowhere else.
func TestServerIdentIPv6CallbackTag(t *testing.T) {
	for _, tc := range []struct {
		name            string
		callback, probe bool
		capable         bool
		want            bool
	}{
		{"offered", true, true, true, true},
		{"callback off", false, true, true, false},
		{"probing off", true, false, true, false},
		{"client not v6-capable", true, true, false, false},
	} {
		r := newIPv6CallbackRig(t)
		cfg := *r.rt.tcp()
		cfg.IPv6Callback, cfg.ProbeIPv6 = tc.callback, tc.probe
		r.rt.tcpCfg.Store(&cfg)
		r.target.ipv6Capable = tc.capable
		packet := r.target.buildServerIdent(nil)
		if packet == nil {
			t.Fatalf("%s: no OP_SERVERIDENT", tc.name)
		}
		_, payload := tcpFoundSourcesPayload(t, packet)
		got := bytes.Contains(payload, []byte{TypeUint8, 0x01, 0x00, TagIPv6Callback, IPv6CallbackBit})
		t.Logf("input: %s, output: 0xaa=0x01 present=%t", tc.name, got)
		if got != tc.want {
			t.Fatalf("%s: 0xaa=0x01 present=%t, want %t", tc.name, got, tc.want)
		}
	}
}

// TestCallbackRequestFromLowIDNeverSendsIPv6 is the eMuleAI regression: a LowID
// requester with a verified IPv6 sends the classic 0x1C. The target must not get a
// 0x26 it cannot parse; the requester gets the empty 0x36 and may ask with 0x64.
func TestCallbackRequestFromLowIDNeverSendsIPv6(t *testing.T) {
	for _, tc := range []struct {
		name         string
		lowID        bool
		ipv4         uint32
		wantTarget   byte
		wantFailSize int
	}{
		{"highid uses classic callback", false, 0x0102030a, OpCallbackReqd, -1},
		{"lowid over ipv4 fails", true, 0x0102030a, 0, 0},
		{"v6-only fails", true, 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newIPv6CallbackRig(t)
			r.requester.info.LowID, r.requester.info.IPv4 = tc.lowID, tc.ipv4
			req := NewBuffer(4)
			_ = req.PutUInt32LE(r.targetID)
			req.Pos(0)
			r.requester.handleCallbackRequest(req)
			t.Logf("input: lowID=%t ipv4=%#x, output: target opcode=%#x requester=% x",
				tc.lowID, tc.ipv4, r.targetConn.opcode(), r.reqConn.written())
			if r.targetConn.opcode() != tc.wantTarget {
				t.Fatalf("target opcode = %#x, want %#x", r.targetConn.opcode(), tc.wantTarget)
			}
			if tc.wantFailSize >= 0 && (r.reqConn.opcode() != OpCallbackFailed || len(r.reqConn.payload()) != tc.wantFailSize) {
				t.Fatalf("requester got % x, want an empty 0x36", r.reqConn.written())
			}
		})
	}
}

// TestRelayAllowanceSharedByBothCallbacks: the burst is shared by 0x1C and 0x64, and
// an over-budget 0x1C gets the empty 0x36.
func TestRelayAllowanceSharedByBothCallbacks(t *testing.T) {
	r := newIPv6CallbackRig(t)
	for i := 0; i < relayBurst-1; i++ {
		if !r.requester.relayAllow() {
			t.Fatalf("request %d refused inside the burst", i)
		}
	}
	r.request(r.targetID) // the last token
	if r.targetConn.opcode() != OpCallbackReqdIPv6 {
		t.Fatalf("last in-burst 0x64 not forwarded: target opcode %#x", r.targetConn.opcode())
	}
	req := NewBuffer(4)
	_ = req.PutUInt32LE(r.targetID)
	req.Pos(0)
	r.requester.handleCallbackRequest(req)
	t.Logf("input: %d requests in one second, output: requester=% x", relayBurst+1, r.reqConn.written())
	if r.reqConn.opcode() != OpCallbackFailed || len(r.reqConn.payload()) != 0 {
		t.Fatalf("over-budget 0x1C answered % x, want an empty 0x36", r.reqConn.written())
	}
}

// failingConn is a mockConn whose writes fail, a target whose socket is gone.
type failingConn struct{ mockConn }

func (*failingConn) Write([]byte) (int, error) { return 0, net.ErrClosed }

// TestIPv6CallbackOptInSurvivesHandoff: the client opts in once per session, so a
// session moved to a successor process stays a target without asking again.
func TestIPv6CallbackOptInSurvivesHandoff(t *testing.T) {
	for _, optIn := range []bool{true, false} {
		r := newIPv6CallbackRig(t)
		r.target.v6CallbackOptIn = optIn
		st := r.target.exportState()
		next := newTCPClient(r.rt, &captureConn{}, false)
		next.applyState(st)
		t.Logf("input: optIn=%t, output: state=%t successor=%t", optIn, st.IPv6CallbackOptIn, next.v6CallbackOptIn)
		if next.v6CallbackOptIn != optIn || next.ipv6CallbackOptedIn() != optIn {
			t.Fatalf("successor optIn = %t, want %t", next.v6CallbackOptIn, optIn)
		}
	}
}

// TestRelayAllowanceRefills: a spent allowance comes back at relayPerSecond.
func TestRelayAllowanceRefills(t *testing.T) {
	r := newIPv6CallbackRig(t)
	c := r.requester
	c.connectedAt = time.Now().Add(-10 * time.Second)
	c.relayAt, c.relaySpent = 7, relayBurst // spent 3 seconds ago
	got := 0
	for c.relayAllow() {
		got++
	}
	t.Logf("input: burst spent 3s ago at %d/s, output: %d allowed", relayPerSecond, got)
	if got != 3*relayPerSecond {
		t.Fatalf("allowed %d after 3s, want %d", got, 3*relayPerSecond)
	}
}
