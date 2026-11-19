package ed2k

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enode/storage"
)

// ipv6UpdateRig is an IPv6-publishing runtime whose IPv6 dial-back answers reachable
// while open is set and blocks while gate holds it.
type ipv6UpdateRig struct {
	rt     *ServerRuntime
	engine *storage.MemoryEngine
	open   atomic.Bool
	probes atomic.Int32
	gate   sync.RWMutex
}

func newIPv6UpdateRig(t *testing.T, probe bool) *ipv6UpdateRig {
	t.Helper()
	r := &ipv6UpdateRig{engine: storage.NewMemoryEngine()}
	r.rt = NewServerRuntime(TCPRuntimeConfig{
		Address:           "127.0.0.1",
		Port:              4661,
		Hash:              []byte("1111111111111111"),
		AllowLowIDs:       true,
		ConnectionTimeout: 50 * time.Millisecond,
		IPv6:              true,
		PublishV6Sources:  true,
		ProbeIPv6:         probe,
	}, UDPRuntimeConfig{}, r.engine)
	r.rt.firewallProbe = func(*tcpClient) bool { return true }
	r.rt.ipv6Probe = func(*tcpClient) bool {
		r.gate.RLock()
		defer r.gate.RUnlock()
		r.probes.Add(1)
		return r.open.Load()
	}
	return r
}

// login logs a LowID session in over IPv4 with no IPv6 login tag, as aMule does
// before it knows the server probes.
func (r *ipv6UpdateRig) login(t *testing.T) (*tcpClient, *reflectConn) {
	t.Helper()
	c, conn := newReflectClient(t, r.rt, "203.0.113.5")
	c.handlePacket(loginPacket(t, bytes.Repeat([]byte{0x63}, 16), 0, 4662))
	if !c.isLogged() {
		t.Fatalf("login failed: %s", c.getCloseReason())
	}
	return c, conn
}

// update sends OP_IPV6_UPDATE and waits for any dial-back it started.
func ipv6Update(t *testing.T, c *tcpClient, addr net.IP) {
	t.Helper()
	b := make([]byte, 16)
	if addr != nil {
		copy(b, addr.To16())
	}
	c.handleED2K(OpIPv6Update, NewBufferFromBytes(b))
	waitFor(t, "the ipv6 dial-back to finish", func() bool {
		c.infoMu.RLock()
		defer c.infoMu.RUnlock()
		return !c.v6Probing
	})
	// runIPv6Probe clears v6Probing and writes the verdict under one hold of writeMu.
	c.writeMu.Lock()
	c.writeMu.Unlock() //nolint:staticcheck // waits out the verdict's write
}

// identStatuses lists the ipv6status of every OP_SERVERIDENT in raw, 0 where the tag
// is absent.
func identStatuses(t *testing.T, raw []byte) []uint8 {
	t.Helper()
	var out []uint8
	for off := 0; off+6 <= len(raw); {
		size := int(binary.LittleEndian.Uint32(raw[off+1 : off+5]))
		if size < 1 || off+5+size > len(raw) {
			t.Fatalf("malformed frame at %d", off)
		}
		if raw[off] == PrED2K && raw[off+5] == OpServerIdent {
			tags := parseServerIdentTags(t, NewBufferFromBytes(raw[off:off+5+size]))
			var st uint8
			switch v := tags["ipv6status"].(type) {
			case uint8:
				st = v
			case uint32:
				st = uint8(v)
			case uint64:
				st = uint8(v)
			}
			out = append(out, st)
		}
		off += 5 + size
	}
	return out
}

func (r *ipv6UpdateRig) sources(t *testing.T) []storage.Source {
	t.Helper()
	return r.engine.GetSources(offerHash(0), 1024)
}

var (
	updateAddrA = net.ParseIP("2001:db8:1::a")
	updateAddrB = net.ParseIP("2001:db8:2::b")
)

func TestBuildTCPFlagsIPv6UpdateAndProbe(t *testing.T) {
	cases := []struct {
		cfg  TCPServerConfig
		want uint32
	}{
		{TCPServerConfig{DualStack: true, IPv6Update: true, IPv6Probe: true}, FlagIPv6 | FlagIPv6Update | FlagIPv6Probe},
		{TCPServerConfig{DualStack: true, IPv6Update: true}, FlagIPv6 | FlagIPv6Update},
		{TCPServerConfig{DualStack: true}, FlagIPv6},
		{TCPServerConfig{IPv6Update: true, IPv6Probe: true}, 0},
	}
	for _, tc := range cases {
		got := BuildTCPFlags(tc.cfg) & (FlagIPv6 | FlagIPv6Update | FlagIPv6Probe)
		t.Logf("input: %+v; output: ipv6 bits=0x%x", tc.cfg, got)
		if got != tc.want {
			t.Fatalf("ipv6 bits = 0x%x, want 0x%x", got, tc.want)
		}
	}
	if FlagIPv6Update != 0x8000 || FlagIPv6Probe != 0x400000 || OpIPv6Update != 0x63 {
		t.Fatal("ed2k-server's values moved")
	}
}

// The aMule flow: login without an address, then OP_IPV6_UPDATE. The address is
// dialled back, published only when it answers, and the verdict comes in a fresh
// OP_SERVERIDENT.
func TestIPv6UpdateProbesAndPublishes(t *testing.T) {
	r := newIPv6UpdateRig(t, true)
	r.open.Store(true)
	c, conn := r.login(t)
	offerFiles(t, c, 0, 1)
	before := identStatuses(t, conn.written())

	ipv6Update(t, c, updateAddrA)
	info := c.snapshotInfo()
	src := r.sources(t)
	after := identStatuses(t, conn.written())
	t.Logf("input: OP_IPV6_UPDATE %s, dial-back reachable; output: ipv6=%s reachable=%t probes=%d idents %v -> %v sources=%+v",
		updateAddrA, net.IP(info.IPv6), info.IPv6Reachable, r.probes.Load(), before, after, src)
	if !bytes.Equal(info.IPv6, updateAddrA.To16()) || !info.IPv6Reachable || r.probes.Load() != 1 {
		t.Fatalf("session ipv6=%s reachable=%t probes=%d", net.IP(info.IPv6), info.IPv6Reachable, r.probes.Load())
	}
	if !c.isV6Capable() {
		t.Fatal("an update makes the client v6-capable")
	}
	if len(after) != len(before)+1 || after[len(after)-1] != 0x07 {
		t.Fatalf("idents %v -> %v, want one more with 0x07", before, after)
	}
	if len(src) != 1 || !sourceHasReachableIPv6(src[0]) || !bytes.Equal(src[0].IPv6, updateAddrA.To16()) {
		t.Fatalf("sources = %+v, want the file published with %s", src, updateAddrA)
	}
}

// A failed dial-back is reported as 0x05; a repeat of that address dials again (the
// router may have opened a pinhole), a repeat after a pass does not.
func TestIPv6UpdateRepeatRedialsOnlyAfterFailure(t *testing.T) {
	r := newIPv6UpdateRig(t, true)
	c, conn := r.login(t)
	offerFiles(t, c, 0, 1)

	ipv6Update(t, c, updateAddrA)
	first := identStatuses(t, conn.written())
	if got := first[len(first)-1]; got != 0x05 || r.probes.Load() != 1 {
		t.Fatalf("closed port: status 0x%02x probes %d, want 0x05 and 1", got, r.probes.Load())
	}
	if src := r.sources(t); len(src) != 1 || sourceHasReachableIPv6(src[0]) {
		t.Fatalf("an unreachable address was published: %+v", src)
	}

	r.open.Store(true)
	ipv6Update(t, c, updateAddrA)
	second := identStatuses(t, conn.written())
	if got := second[len(second)-1]; got != 0x07 || r.probes.Load() != 2 {
		t.Fatalf("repeat after a failure: status 0x%02x probes %d, want 0x07 and 2", got, r.probes.Load())
	}

	ipv6Update(t, c, updateAddrA)
	third := identStatuses(t, conn.written())
	t.Logf("output: idents %v / %v / %v probes=%d sources=%+v", first, second, third, r.probes.Load(), r.sources(t))
	if len(third) != len(second) || r.probes.Load() != 2 {
		t.Fatalf("repeat after a pass dialled or answered: idents %d -> %d probes %d", len(second), len(third), r.probes.Load())
	}
	if src := r.sources(t); len(src) != 1 || !sourceHasReachableIPv6(src[0]) {
		t.Fatalf("sources = %+v, want the address published", src)
	}
}

// A repeat while the dial-back runs starts nothing, and the status reads 0x01 (held).
func TestIPv6UpdateRepeatWhileProbingIgnored(t *testing.T) {
	r := newIPv6UpdateRig(t, true)
	c, _ := r.login(t)
	r.gate.Lock()
	payload := append([]byte(nil), updateAddrA.To16()...)
	c.handleED2K(OpIPv6Update, NewBufferFromBytes(payload))
	c.handleED2K(OpIPv6Update, NewBufferFromBytes(append([]byte(nil), payload...)))
	c.infoMu.RLock()
	held, dials := c.ipv6StatusLocked(), c.v6Dials
	c.infoMu.RUnlock()
	r.gate.Unlock()
	waitFor(t, "the dial-back", func() bool {
		c.infoMu.RLock()
		defer c.infoMu.RUnlock()
		return !c.v6Probing
	})
	t.Logf("input: the same address twice during one dial-back; output: status=0x%02x dials=%d probes=%d", held, dials, r.probes.Load())
	if held != IPv6StatusHave || dials != 1 || r.probes.Load() != 1 {
		t.Fatalf("status 0x%02x dials %d probes %d, want 0x01, 1, 1", held, dials, r.probes.Load())
	}
}

// At most maxIPv6Dials dials a session; past the cap a new address is held, not
// published.
func TestIPv6UpdateDialCap(t *testing.T) {
	r := newIPv6UpdateRig(t, true)
	c, conn := r.login(t)
	// Distinct addresses, so each is a change.
	for i := 0; i < maxIPv6Dials+2; i++ {
		a := net.ParseIP("2001:db8:9::1").To16()
		a[15] = byte(i + 1)
		ipv6Update(t, c, a)
	}
	c.infoMu.RLock()
	dials, status, reachable := c.v6Dials, c.ipv6StatusLocked(), c.info.IPv6Reachable
	c.infoMu.RUnlock()
	t.Logf("input: %d distinct addresses; output: dials=%d probes=%d status=0x%02x idents=%v",
		maxIPv6Dials+2, dials, r.probes.Load(), status, identStatuses(t, conn.written()))
	if dials != maxIPv6Dials || int(r.probes.Load()) != maxIPv6Dials {
		t.Fatalf("dials %d probes %d, want %d", dials, r.probes.Load(), maxIPv6Dials)
	}
	if status != IPv6StatusHave || reachable {
		t.Fatalf("past the cap: status 0x%02x reachable %t, want held and unpublished", status, reachable)
	}
}

// The login's own dial-back counts toward the cap.
func TestIPv6UpdateLoginDialCounts(t *testing.T) {
	r := newIPv6UpdateRig(t, true)
	c, _ := newReflectClient(t, r.rt, "203.0.113.5")
	c.handlePacket(loginPacketIPv6(t, bytes.Repeat([]byte{0x64}, 16), 4662, updateAddrA))
	c.infoMu.RLock()
	dials, probed := c.v6Dials, c.v6Probed
	c.infoMu.RUnlock()
	t.Logf("input: login with CT_MOD_IP_V6 %s; output: dials=%d probed=%t", updateAddrA, dials, probed)
	if dials != 1 || !probed {
		t.Fatalf("dials %d probed %t, want 1 and true", dials, probed)
	}
}

// Zeros withdraw the address and the capability; the sources lose the address.
func TestIPv6UpdateWithdraw(t *testing.T) {
	r := newIPv6UpdateRig(t, true)
	r.open.Store(true)
	c, _ := r.login(t)
	offerFiles(t, c, 0, 1)
	ipv6Update(t, c, updateAddrA)
	ipv6Update(t, c, nil)
	info := c.snapshotInfo()
	src := r.sources(t)
	t.Logf("input: publish %s, then zeros; output: ipv6=%v reachable=%t capable=%t sources=%+v",
		updateAddrA, info.IPv6, info.IPv6Reachable, c.isV6Capable(), src)
	if info.IPv6 != nil || info.IPv6Reachable || c.isV6Capable() {
		t.Fatal("withdraw left the address or the capability")
	}
	if len(src) != 1 || len(src[0].IPv6) != 0 || src[0].IPv6Reachable {
		t.Fatalf("sources = %+v, want no IPv6", src)
	}
}

// A new address replaces the old one in the sources, unpublished until it answers.
func TestIPv6UpdateNewAddressReplacesOld(t *testing.T) {
	r := newIPv6UpdateRig(t, true)
	r.open.Store(true)
	c, _ := r.login(t)
	offerFiles(t, c, 0, 1)
	ipv6Update(t, c, updateAddrA)
	r.open.Store(false)
	ipv6Update(t, c, updateAddrB)
	src := r.sources(t)
	t.Logf("input: %s reachable, then %s unreachable; output: sources=%+v", updateAddrA, updateAddrB, src)
	if len(src) != 1 || !bytes.Equal(src[0].IPv6, updateAddrB.To16()) || src[0].IPv6Reachable {
		t.Fatalf("sources = %+v, want %s unpublished", src, updateAddrB)
	}
}

// Probing off: the address is published on trust and the status is 0x03 at once.
func TestIPv6UpdateTrustedWithoutProbe(t *testing.T) {
	r := newIPv6UpdateRig(t, false)
	c, conn := r.login(t)
	ipv6Update(t, c, updateAddrA)
	st := identStatuses(t, conn.written())
	t.Logf("input: OP_IPV6_UPDATE, probing off; output: idents=%v probes=%d", st, r.probes.Load())
	if r.probes.Load() != 0 || st[len(st)-1] != 0x03 {
		t.Fatalf("probes %d idents %v, want none and a last 0x03", r.probes.Load(), st)
	}
}

// Ignored: a session that arrived over IPv6, a non-public address published, wrong
// sizes, and a server not publishing IPv6 sources.
func TestIPv6UpdateIgnored(t *testing.T) {
	r := newIPv6UpdateRig(t, true)
	r.open.Store(true)
	v6, _ := newReflectClient(t, r.rt, "2001:db8:7::7")
	v6.handlePacket(loginPacket(t, bytes.Repeat([]byte{0x65}, 16), 0, 4662))
	before := v6.snapshotInfo().IPv6
	ipv6Update(t, v6, updateAddrA)
	t.Logf("input: update on an ipv6 session; output: ipv6 %s -> %s", net.IP(before), net.IP(v6.snapshotInfo().IPv6))
	if !bytes.Equal(v6.snapshotInfo().IPv6, before) {
		t.Fatal("an ipv6 session took the update")
	}

	c, _ := r.login(t)
	ipv6Update(t, c, net.ParseIP("fd00::1"))
	t.Logf("input: unique-local address; output: ipv6=%v capable=%t", c.snapshotInfo().IPv6, c.isV6Capable())
	if c.snapshotInfo().IPv6 != nil || !c.isV6Capable() || r.probes.Load() != 1 {
		t.Fatalf("a non-public address must make the client capable, not be published or dialled (probes %d)", r.probes.Load())
	}
	c.handleED2K(OpIPv6Update, NewBufferFromBytes(make([]byte, 15)))

	off := NewServerRuntime(TCPRuntimeConfig{Port: 4661, Hash: []byte("1111111111111111"), AllowLowIDs: true, IPv6: true},
		UDPRuntimeConfig{}, storage.NewMemoryEngine())
	off.firewallProbe = func(*tcpClient) bool { return true }
	o, _ := newReflectClient(t, off, "203.0.113.6")
	o.handlePacket(loginPacket(t, bytes.Repeat([]byte{0x66}, 16), 0, 4662))
	ipv6Update(t, o, updateAddrA)
	if o.snapshotInfo().IPv6 != nil {
		t.Fatal("a server not publishing IPv6 sources took the update")
	}
}

// The dial count and verdict move to a successor process.
func TestIPv6UpdateStateSurvivesHandoff(t *testing.T) {
	r := newIPv6UpdateRig(t, true)
	c, _ := r.login(t)
	ipv6Update(t, c, updateAddrA)
	st := c.exportState()
	n := newTCPClient(r.rt, &mockConn{remote: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 50000}}, false)
	n.applyState(st)
	n.infoMu.RLock()
	dials, status := n.v6Dials, n.ipv6StatusLocked()
	n.infoMu.RUnlock()
	t.Logf("input: one failed dial-back, handed over; output: dials=%d status=0x%02x", dials, status)
	if dials != 1 || status != 0x05 {
		t.Fatalf("dials %d status 0x%02x, want 1 and 0x05", dials, status)
	}
}

// A verdict for an address the session has since left is dropped: it says nothing
// about the new one.
func TestIPv6UpdateStaleVerdictDropped(t *testing.T) {
	r := newIPv6UpdateRig(t, true)
	r.open.Store(true)
	c, conn := r.login(t)
	r.gate.Lock()
	c.handleED2K(OpIPv6Update, NewBufferFromBytes(append([]byte(nil), updateAddrA.To16()...)))
	c.handleED2K(OpIPv6Update, NewBufferFromBytes(make([]byte, 16)))
	r.gate.Unlock()
	waitFor(t, "both dial-backs", func() bool { return r.probes.Load() == 1 })
	c.writeMu.Lock()
	c.writeMu.Unlock() //nolint:staticcheck // waits out a verdict's write
	info := c.snapshotInfo()
	t.Logf("input: %s, withdrawn during its dial-back; output: ipv6=%v reachable=%t idents=%v",
		updateAddrA, info.IPv6, info.IPv6Reachable, identStatuses(t, conn.written()))
	if info.IPv6 != nil || info.IPv6Reachable {
		t.Fatal("a stale verdict was applied")
	}
}
