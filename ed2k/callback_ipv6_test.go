package ed2k

import (
	"bytes"
	"net"
	"sync"
	"testing"

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

func TestBuildCallbackRequestedIPv6PacketWire(t *testing.T) {
	ipv6 := net.ParseIP("2001:db8::1234").To16()
	port := uint16(4662)
	t.Logf("input: ipv6=%s port=%d", net.IP(ipv6).String(), port)

	pkt, err := BuildCallbackRequestedIPv6Packet(ipv6, port)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	b := pkt.Bytes()
	t.Logf("output: % x", b)

	if b[0] != PrED2K {
		t.Fatalf("protocol = 0x%02x, want 0x%02x", b[0], PrED2K)
	}
	if b[5] != OpCallbackReqdIPv6 {
		t.Fatalf("opcode = 0x%02x, want 0x%02x", b[5], OpCallbackReqdIPv6)
	}
	if got := b[6:22]; !bytes.Equal(got, ipv6) {
		t.Fatalf("ipv6 bytes = % x, want % x", got, ipv6)
	}
	// port is little-endian: 4662 = 0x1236 -> 0x36 0x12.
	if b[22] != 0x36 || b[23] != 0x12 {
		t.Fatalf("port bytes = %02x %02x, want 36 12", b[22], b[23])
	}
	if len(b) != 24 {
		t.Fatalf("packet length = %d, want 24 (no crypt trailer)", len(b))
	}
}

// TestHandleCallbackRequestFamilySelection checks the per-family decision: classic
// IPv4 for a HighID requester, the IPv6 callback when the requester's IPv4 is
// LowID/unavailable but it has a reachable public IPv6 and the target is v6-capable,
// and OP_CALLBACKFAILED otherwise.
func TestHandleCallbackRequestFamilySelection(t *testing.T) {
	ipv6 := net.ParseIP("2001:db8::1234").To16()

	cases := []struct {
		name            string
		selfIPv4        uint32
		selfLowID       bool
		selfIPv6        []byte
		selfV6Reachable bool
		targetV6Capable bool
		targetIPv6      []byte
		targetNotLogged bool
		wantOnTarget    byte // opcode the target should receive (0 = none)
		wantOnRequester byte // opcode the requester should receive (0 = none)
	}{
		{
			name:         "highid ipv4 uses classic callback",
			selfIPv4:     0x0102030a,
			selfLowID:    false,
			wantOnTarget: OpCallbackReqd,
		},
		{
			name:            "v6-only requester uses ipv6 callback",
			selfIPv4:        0,
			selfLowID:       true,
			selfIPv6:        ipv6,
			selfV6Reachable: true,
			targetV6Capable: true,
			targetIPv6:      net.ParseIP("2001:db8::99").To16(),
			wantOnTarget:    OpCallbackReqdIPv6,
		},
		{
			name:            "lowid-over-ipv4 requester uses ipv6 callback",
			selfIPv4:        0x0102030a,
			selfLowID:       true,
			selfIPv6:        ipv6,
			selfV6Reachable: true,
			targetV6Capable: true,
			targetIPv6:      net.ParseIP("2001:db8::99").To16(),
			wantOnTarget:    OpCallbackReqdIPv6,
		},
		{
			name:            "v6-only requester but target not v6-capable fails",
			selfIPv4:        0,
			selfLowID:       true,
			selfIPv6:        ipv6,
			selfV6Reachable: true,
			targetV6Capable: false,
			wantOnRequester: OpCallbackFailed,
		},
		{
			name:            "v6-capable target with no ipv6 of its own fails",
			selfIPv4:        0,
			selfLowID:       true,
			selfIPv6:        ipv6,
			selfV6Reachable: true,
			targetV6Capable: true,
			wantOnRequester: OpCallbackFailed,
		},
		{
			name:            "target still logging in fails",
			selfIPv4:        0x0102030a,
			selfLowID:       false,
			targetNotLogged: true,
			wantOnRequester: OpCallbackFailed,
		},
		{
			name:            "v6-only requester with no reachable ipv6 fails",
			selfIPv4:        0,
			selfLowID:       true,
			selfIPv6:        ipv6,
			selfV6Reachable: false,
			targetV6Capable: true,
			wantOnRequester: OpCallbackFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := NewServerRuntime(TCPRuntimeConfig{
				Address:          "127.0.0.1",
				Port:             4661,
				AllowLowIDs:      true,
				IPv6:             true,
				PublishV6Sources: true,
			}, UDPRuntimeConfig{}, storage.NewMemoryEngine())

			// Target B: the firewalled callback target, registered in the LowIDs table.
			targetConn := &captureConn{}
			target := newTCPClient(rt, targetConn, false)
			target.infoMu.Lock()
			target.ipv6Capable = tc.targetV6Capable
			target.info.IPv6 = tc.targetIPv6
			target.logged = !tc.targetNotLogged
			target.info.Port = 6000
			target.infoMu.Unlock()
			targetID, ok := rt.LowIDs.Add(target)
			if !ok {
				t.Fatal("failed to register target in LowIDs")
			}

			// Requester A: overwrite the reachability fields the decision reads.
			reqConn := &captureConn{}
			requester := newTCPClient(rt, reqConn, false)
			requester.infoMu.Lock()
			requester.info.IPv4 = tc.selfIPv4
			requester.info.LowID = tc.selfLowID
			requester.info.IPv6 = tc.selfIPv6
			requester.info.IPv6Reachable = tc.selfV6Reachable
			requester.info.Port = 5000
			requester.infoMu.Unlock()

			t.Logf("input: requester ipv4=%d lowID=%t ipv6=%v v6reachable=%t targetV6Capable=%t targetIPv6=%v targetLogged=%t targetID=%d",
				tc.selfIPv4, tc.selfLowID, tc.selfIPv6 != nil, tc.selfV6Reachable, tc.targetV6Capable, tc.targetIPv6 != nil, !tc.targetNotLogged, targetID)

			req := NewBuffer(4)
			_ = req.PutUInt32LE(targetID)
			req.Pos(0)
			requester.handleCallbackRequest(req)

			gotTarget := targetConn.opcode()
			gotRequester := reqConn.opcode()
			t.Logf("output: target opcode=0x%02x requester opcode=0x%02x", gotTarget, gotRequester)

			if gotTarget != tc.wantOnTarget {
				t.Fatalf("target opcode = 0x%02x, want 0x%02x", gotTarget, tc.wantOnTarget)
			}
			if gotRequester != tc.wantOnRequester {
				t.Fatalf("requester opcode = 0x%02x, want 0x%02x", gotRequester, tc.wantOnRequester)
			}
		})
	}
}
