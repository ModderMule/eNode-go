package ed2k

import (
	"encoding/binary"
	"net"
	"runtime"
	"testing"
	"time"
)

func natIndexHash(i int) []byte {
	h := make([]byte, 16)
	binary.BigEndian.PutUint32(h, uint32(i))
	h[15] = 0x77
	return h
}

func TestNatIndexRebinding(t *testing.T) {
	h := NewNATTraversalHandler(time.Minute)
	hash := natIndexHash(1)
	oldEP := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4672}
	newEP := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 50001}
	h.processPacket(encodeNATPacket(OpNatRegister, hash), oldEP, 2004)
	h.processPacket(encodeNATPacket(OpNatRegister, hash), newEP, 2004)
	_, oldHit := h.touchByAddr(oldEP, 0)
	got, newHit := h.touchByAddr(newEP, 0)
	t.Logf("input: register %s then %s, output: keepalive old=%t new=%t (hash %x), index size %d", oldEP, newEP, oldHit, newHit, got[:4], len(h.byAddr))
	if oldHit || !newHit || len(h.byAddr) != 1 {
		t.Fatalf("after rebinding: old=%t new=%t index=%d, want false/true/1", oldHit, newHit, len(h.byAddr))
	}
}

func TestNatIndexExpiry(t *testing.T) {
	h := NewNATTraversalHandler(50 * time.Millisecond)
	ep := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4672}
	h.processPacket(encodeNATPacket(OpNatRegister, natIndexHash(1)), ep, 2004)
	time.Sleep(80 * time.Millisecond)
	h.cleanup()
	_, hit := h.touchByAddr(ep, 0)
	t.Logf("input: register, wait past TTL, sweep; output: entries=%d index=%d keepalive=%t", h.entryCount(), len(h.byAddr), hit)
	if h.entryCount() != 0 || len(h.byAddr) != 0 || hit {
		t.Fatal("expired candidate still indexed")
	}
}

// One endpoint is one socket: a second hash registering it takes it over.
func TestNatIndexEndpointTakenOver(t *testing.T) {
	h := NewNATTraversalHandler(time.Minute)
	ep := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4672}
	h.processPacket(encodeNATPacket(OpNatRegister, natIndexHash(1)), ep, 2004)
	h.processPacket(encodeNATPacket(OpNatRegister, natIndexHash(2)), ep, 2004)
	got, hit := h.touchByAddr(ep, 0)
	t.Logf("input: hash 1 then hash 2 from %s, output: keepalive -> %x, entries=%d", ep, got[:4], h.entryCount())
	if !hit || got != [16]byte(natIndexHash(2)) || h.entryCount() != 1 || h.candidateCount([16]byte(natIndexHash(1))) != 0 {
		t.Fatal("endpoint not owned by the newer registration")
	}
}

// A keepalive from the v4-mapped spelling of an IPv4 (dual-stack socket) matches.
func TestNatIndexMappedIPv4(t *testing.T) {
	h := NewNATTraversalHandler(time.Minute)
	h.processPacket(encodeNATPacket(OpNatRegister, natIndexHash(1)), &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1).To4(), Port: 4672}, 2004)
	mapped := &net.UDPAddr{IP: net.ParseIP("::ffff:198.51.100.1"), Port: 4672}
	outs := h.processPacket([]byte{0x00}, mapped, 2004)
	t.Logf("input: 1-byte keepalive from %s, output: %v", mapped, outOpcodes(outs))
	if len(outs) != 1 {
		t.Fatal("mapped keepalive did not match")
	}
}

// TestNatIndexCost measures the registry at 100,000 IPv4 entries: bytes per entry
// (index included) and the time of one keepalive. Before the index an entry took
// 171 B and a missed keepalive 3.8 ms, a scan of the whole registry.
func TestNatIndexCost(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates 100k entries")
	}
	const n = 100_000
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	h := NewNATTraversalHandler(time.Hour)
	for i := 0; i < n; i++ {
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
		h.upsert([16]byte(natIndexHash(i)), &net.UDPAddr{IP: ip, Port: 4672}, 0, 0)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	perEntry := float64(after.HeapAlloc-before.HeapAlloc) / n

	miss := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}
	hit := &net.UDPAddr{IP: net.IPv4(10, 0, 0x30, 0x39), Port: 4672}
	const rounds = 10_000
	start := time.Now()
	for i := 0; i < rounds; i++ {
		h.touchByAddr(miss, 0)
		h.touchByAddr(hit, 0)
	}
	per := time.Since(start) / (2 * rounds)
	t.Logf("input: %d IPv4 entries, output: %.0f B per entry incl. index, %v per keepalive", n, perEntry, per)
	if perEntry > 171 {
		t.Fatalf("%.0f B per entry, more than the 171 B before the index", perEntry)
	}
	if per > 50*time.Microsecond {
		t.Fatalf("keepalive takes %v, want O(1)", per)
	}
	runtime.KeepAlive(h)
}
