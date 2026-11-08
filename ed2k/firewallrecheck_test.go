package ed2k

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"

	"enode/storage"
)

// recheckRig is a runtime whose IPv4 dial-back answers reachable while open is set.
type recheckRig struct {
	rt     *ServerRuntime
	engine *storage.MemoryEngine
	open   atomic.Bool
	probes atomic.Int32
}

func newRecheckRig(t *testing.T, recheck bool, interval time.Duration) *recheckRig {
	t.Helper()
	r := &recheckRig{engine: storage.NewMemoryEngine()}
	r.rt = NewServerRuntime(TCPRuntimeConfig{
		Address:                 "127.0.0.1",
		Port:                    4661,
		Hash:                    []byte("1111111111111111"),
		AllowLowIDs:             true,
		ConnectionTimeout:       50 * time.Millisecond,
		FirewallRecheck:         recheck,
		FirewallRecheckInterval: interval,
	}, UDPRuntimeConfig{}, r.engine)
	r.rt.firewallProbe = func(*tcpClient) bool {
		r.probes.Add(1)
		return !r.open.Load()
	}
	return r
}

// login logs a session in from 203.0.113.5:port; reachable decides HighID or LowID.
func (r *recheckRig) login(t *testing.T, hash byte, port uint16, reachable bool) (*tcpClient, *reflectConn) {
	t.Helper()
	r.open.Store(reachable)
	c, conn := newReflectClient(t, r.rt, "203.0.113.5")
	c.handlePacket(loginPacket(t, bytes.Repeat([]byte{hash}, 16), 0, port))
	if !c.isLogged() {
		t.Fatalf("login failed: %s", c.getCloseReason())
	}
	return c, conn
}

// idChanges lists the clientIDs of every OP_IDCHANGE in raw.
func idChanges(t *testing.T, raw []byte) []uint32 {
	t.Helper()
	var ids []uint32
	for off := 0; off+6 <= len(raw); {
		size := int(binary.LittleEndian.Uint32(raw[off+1 : off+5]))
		if size < 1 || off+5+size > len(raw) {
			t.Fatalf("malformed frame at %d", off)
		}
		if raw[off] == PrED2K && raw[off+5] == OpIDChange {
			ids = append(ids, binary.LittleEndian.Uint32(raw[off+6:off+10]))
		}
		off += 5 + size
	}
	return ids
}

func recheckPayload(port uint16) *Buffer {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, port)
	return NewBufferFromBytes(b)
}

// recheck sends OpRecheckFirewall and waits for its probe to finish.
func recheck(t *testing.T, c *tcpClient, payload *Buffer) {
	t.Helper()
	c.handleED2K(OpRecheckFirewall, payload)
	waitFor(t, "the recheck to finish", func() bool {
		c.infoMu.RLock()
		defer c.infoMu.RUnlock()
		return !c.recheckBusy
	})
}

func TestFirewallRecheckPromotesLowID(t *testing.T) {
	r := newRecheckRig(t, true, 0)
	c, conn := r.login(t, 0x51, 4662, false)
	offerFiles(t, c, 0, 1)
	lowID := c.snapshotInfo().ID
	if HasHighID(lowID) || r.rt.LowIDs.Count() != 1 {
		t.Fatalf("login gave id=%#x LowIDs=%d, want one LowID", lowID, r.rt.LowIDs.Count())
	}
	r.rt.natCallback.rememberKeepalive(lowID, natCallbackRecent{at: time.Now(), owner: c})

	r.open.Store(true)
	before := len(conn.written())
	recheck(t, c, NewBuffer(0))
	ids := idChanges(t, conn.written()[before:])
	info := c.snapshotInfo()
	sources := r.engine.GetSources(offerHash(0), 1024)
	t.Logf("input: LowID %#x, port now reachable; output: IDCHANGE %#x, info id=%#x lowID=%t, LowIDs=%d, sources=%v",
		lowID, ids, info.ID, info.LowID, r.rt.LowIDs.Count(), sources)
	if len(ids) != 1 || ids[0] != info.IPv4 {
		t.Fatalf("IDCHANGE ids %#x, want one with the HighID %#x", ids, info.IPv4)
	}
	if info.LowID || info.ID != info.IPv4 || c.hasLowID {
		t.Fatalf("session still LowID: %+v", info)
	}
	if _, ok := r.rt.LowIDs.Get(lowID); ok || r.rt.LowIDs.Count() != 0 {
		t.Fatalf("LowID %#x still registered", lowID)
	}
	if _, ok := r.rt.natCallback.keepaliveFor(lowID, time.Now()); ok {
		t.Fatal("NAT keepalive state of the old LowID kept")
	}
	if len(sources) != 1 || sources[0].ID != info.IPv4 || sources[0].Port != 4662 {
		t.Fatalf("sources %+v, want the HighID %#x:4662", sources, info.IPv4)
	}

	// Same address and port again draws the same LowID seed: the old LowID is free,
	// and releasing the promoted session must not free it under the new holder.
	other, _ := r.login(t, 0x52, 4662, false)
	otherID := other.snapshotInfo().ID
	c.releaseSession()
	if got, ok := r.rt.LowIDs.Get(otherID); !ok || got != other {
		t.Fatalf("releasing the promoted session freed LowID %#x of another session", otherID)
	}
	if r.rt.LowIDs.Count() != 1 || r.engine.ClientsCount() != 1 || len(r.engine.GetSources(offerHash(0), 1024)) != 0 {
		t.Fatalf("after release: LowIDs=%d clients=%d sources=%d, want 1/1/0",
			r.rt.LowIDs.Count(), r.engine.ClientsCount(), len(r.engine.GetSources(offerHash(0), 1024)))
	}
	t.Logf("output: re-issued LowID %#x (old %#x) survives the promoted session's release", otherID, lowID)
}

func TestFirewallRecheckStaysLowID(t *testing.T) {
	r := newRecheckRig(t, true, 0)
	c, conn := r.login(t, 0x53, 4662, false)
	lowID := c.snapshotInfo().ID
	before := len(conn.written())
	recheck(t, c, recheckPayload(0))
	ids := idChanges(t, conn.written()[before:])
	t.Logf("input: LowID %#x, still firewalled; output: IDCHANGE %#x probes=%d", lowID, ids, r.probes.Load())
	if len(ids) != 1 || ids[0] != lowID {
		t.Fatalf("IDCHANGE ids %#x, want the same LowID %#x", ids, lowID)
	}
	if got, ok := r.rt.LowIDs.Get(lowID); !ok || got != c || !c.snapshotInfo().LowID {
		t.Fatal("LowID lost though the port is still firewalled")
	}
	if r.probes.Load() != 2 {
		t.Fatalf("probes = %d, want login + recheck", r.probes.Load())
	}
}

func TestFirewallRecheckPortChange(t *testing.T) {
	cases := []struct {
		name          string
		highID        bool
		reachable     bool
		wantPort      uint16
		wantPromotion bool
	}{
		{"LowID, new port firewalled: port taken", false, false, 5000, false},
		{"LowID, new port reachable: promoted", false, true, 5000, true},
		{"HighID, new port reachable: moved", true, true, 5000, false},
		{"HighID, new port silent: kept", true, false, 4662, false},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRecheckRig(t, true, 0)
			c, conn := r.login(t, byte(0x60+i), 4662, tc.highID)
			offerFiles(t, c, 0, 1)
			oldID := c.snapshotInfo().ID
			r.open.Store(tc.reachable)
			before := len(conn.written())
			recheck(t, c, recheckPayload(5000))
			info := c.snapshotInfo()
			ids := idChanges(t, conn.written()[before:])
			sources := r.engine.GetSources(offerHash(0), 1024)
			t.Logf("input: id=%#x port 4662 → 5000 reachable=%t; output: id=%#x port=%d IDCHANGE=%#x sources=%v",
				oldID, tc.reachable, info.ID, info.Port, ids, sources)
			if info.Port != tc.wantPort {
				t.Fatalf("port = %d, want %d", info.Port, tc.wantPort)
			}
			wantID := oldID
			if tc.wantPromotion {
				wantID = info.IPv4
			}
			if info.ID != wantID || len(ids) != 1 || ids[0] != wantID {
				t.Fatalf("id=%#x IDCHANGE=%#x, want %#x", info.ID, ids, wantID)
			}
			if len(sources) != 1 || sources[0].ID != wantID || sources[0].Port != tc.wantPort {
				t.Fatalf("sources %+v, want %#x:%d", sources, wantID, tc.wantPort)
			}
		})
	}
}

// A HighID asking for its own port is answered without a dial-back.
func TestFirewallRecheckHighIDSamePortNoProbe(t *testing.T) {
	r := newRecheckRig(t, true, 0)
	c, conn := r.login(t, 0x54, 4662, true)
	before := len(conn.written())
	recheck(t, c, NewBuffer(0))
	ids := idChanges(t, conn.written()[before:])
	if len(ids) != 1 || ids[0] != c.snapshotInfo().IPv4 || r.probes.Load() != 1 {
		t.Fatalf("IDCHANGE %#x probes=%d, want the HighID and no new probe", ids, r.probes.Load())
	}
}

func TestFirewallRecheckThrottled(t *testing.T) {
	r := newRecheckRig(t, true, time.Hour)
	c, conn := r.login(t, 0x55, 4662, false)
	before := len(conn.written())
	recheck(t, c, NewBuffer(0))
	c.handleED2K(OpRecheckFirewall, NewBuffer(0)) // throttled: answered synchronously with nothing
	time.Sleep(20 * time.Millisecond)
	ids := idChanges(t, conn.written()[before:])
	t.Logf("input: two rechecks within 1h; output: IDCHANGE=%#x probes=%d", ids, r.probes.Load())
	if len(ids) != 1 || r.probes.Load() != 2 {
		t.Fatalf("IDCHANGE=%#x probes=%d, want one answer and one recheck probe", ids, r.probes.Load())
	}
}

func TestFirewallRecheckInFlightIgnored(t *testing.T) {
	r := newRecheckRig(t, true, time.Hour)
	c, conn := r.login(t, 0x56, 4662, false)
	hold := make(chan struct{})
	var probes atomic.Int32
	// Swapped while no probe runs; the recheck goroutine starts after.
	r.rt.firewallProbe = func(*tcpClient) bool { probes.Add(1); <-hold; return true }
	before := len(conn.written())
	c.handleED2K(OpRecheckFirewall, NewBuffer(0))
	waitFor(t, "the probe to start", func() bool { return probes.Load() == 1 })
	c.lastRecheck = 0 // past the throttle: only the in-flight guard is left
	c.handleED2K(OpRecheckFirewall, NewBuffer(0))
	close(hold)
	waitFor(t, "the recheck to finish", func() bool {
		c.infoMu.RLock()
		defer c.infoMu.RUnlock()
		return !c.recheckBusy
	})
	ids := idChanges(t, conn.written()[before:])
	t.Logf("input: second recheck while the first probes; output: probes=%d IDCHANGE=%#x", probes.Load(), ids)
	if probes.Load() != 1 || len(ids) != 1 {
		t.Fatalf("probes=%d IDCHANGE=%#x, want one of each", probes.Load(), ids)
	}
}

func TestFirewallRecheckIgnoredPayloadsAndOff(t *testing.T) {
	r := newRecheckRig(t, true, 0)
	c, conn := r.login(t, 0x57, 4662, false)
	before := len(conn.written())
	c.handleED2K(OpRecheckFirewall, NewBufferFromBytes([]byte{1, 2, 3}))
	off := newRecheckRig(t, false, 0)
	c2, conn2 := off.login(t, 0x58, 4662, false)
	before2 := len(conn2.written())
	c2.handleED2K(OpRecheckFirewall, NewBuffer(0))
	time.Sleep(20 * time.Millisecond)
	t.Logf("output: bad length → %d bytes, %d probes; off → %d bytes, %d probes",
		len(conn.written())-before, r.probes.Load(), len(conn2.written())-before2, off.probes.Load())
	if len(conn.written()) != before || r.probes.Load() != 1 {
		t.Fatal("a 3-byte payload was acted on")
	}
	if len(conn2.written()) != before2 || off.probes.Load() != 1 {
		t.Fatal("recheck answered with tcp.firewallRecheck off")
	}
	if !c.isLogged() || !c2.isLogged() {
		t.Fatal("an ignored recheck dropped the session")
	}
}

func TestFirewallRecheckBeforeLoginDrops(t *testing.T) {
	r := newRecheckRig(t, true, 0)
	conn := &recordingConn{}
	c := newTCPClient(r.rt, conn, false)
	c.handleED2K(OpRecheckFirewall, NewBuffer(0))
	t.Logf("output: closed=%d reason=%s probes=%d", conn.closed, c.getCloseReason(), r.probes.Load())
	if conn.closed == 0 || c.getCloseReason() != "not-logged-in" || r.probes.Load() != 0 {
		t.Fatalf("pre-login recheck: closed=%d reason=%s probes=%d", conn.closed, c.getCloseReason(), r.probes.Load())
	}
}

func TestBuildTCPFlagsFirewallRecheck(t *testing.T) {
	on := BuildTCPFlags(TCPServerConfig{FirewallRecheck: true})
	off := BuildTCPFlags(TCPServerConfig{})
	t.Logf("output: on=0x%x off=0x%x", on, off)
	if on&FlagFirewallRecheck == 0 || off&FlagFirewallRecheck != 0 || on&^FlagFirewallRecheck != off {
		t.Fatalf("flags on=0x%x off=0x%x", on, off)
	}
	if FlagFirewallRecheck == 0x400000 {
		t.Fatal("0x400000 is ed2k-server's IPV6_PROBE")
	}
}

// A promoted session moves to a successor process as the HighID it now is.
func TestFirewallRecheckThenHandoff(t *testing.T) {
	var openA atomic.Bool
	rtA, engineA, addr := handoffRuntimeProbe(t, func(*tcpClient) bool { return !openA.Load() })
	rtB, engineB, _ := handoffRuntime(t)

	c := dialWireClient(t, addr, true)
	lowID := c.login(bytes.Repeat([]byte{0xd4}, 16), 4662)
	file := offerHash(9)
	c.write(c.frame(offerOne(file, "promoted.avi", 9000)))
	waitFor(t, "the offer to be stored", func() bool { return len(engineA.GetSources(file, 9000)) == 1 })

	openA.Store(true)
	c.write(c.frame([]PacketItem{{Type: TypeUint8, Value: OpRecheckFirewall}, {Type: TypeUint16, Value: uint16(0)}}))
	highID := binary.LittleEndian.Uint32(c.expect(OpIDChange))
	if HasHighID(lowID) || !HasHighID(highID) || rtA.LowIDs.Count() != 0 {
		t.Fatalf("lowID=%#x → %#x, A LowIDs=%d; want a promotion", lowID, highID, rtA.LowIDs.Count())
	}

	moved := handOver(t, rtA, engineA, rtB, engineB)
	c.write(c.frame(getSourcesItems(file, 9000)))
	payload := c.expect(OpFoundSources)
	id := binary.LittleEndian.Uint32(payload[17:21])
	port := binary.LittleEndian.Uint16(payload[21:23])
	t.Logf("input: LowID %#x promoted to %#x then handed over; output: moved=%d B LowIDs=%d source %#x:%d",
		lowID, highID, moved, rtB.LowIDs.Count(), id, port)
	if moved != 1 || rtB.LowIDs.Count() != 0 || payload[16] != 1 || id != highID || port != 4662 {
		t.Fatalf("after handover: moved=%d LowIDs=%d count=%d source %#x:%d, want 1/0/1 %#x:4662",
			moved, rtB.LowIDs.Count(), payload[16], id, port, highID)
	}
	_ = c.conn.Close()
	waitFor(t, "B to release the session", func() bool { return engineB.ClientsCount() == 0 })
}
