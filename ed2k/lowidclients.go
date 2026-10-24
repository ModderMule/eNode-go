package ed2k

import (
	"encoding/binary"
	"hash/fnv"
	"net"
	"sync"
)

type LowIDClients struct {
	mu    sync.Mutex
	min   uint32
	max   uint32
	count uint32
	// oddCount is how many of count are odd. Kept so a parity-bound Add can tell
	// that its half of the range is full without scanning it.
	oddCount    uint32
	allowLowIDs bool
	clients     map[uint32]any
}

// LowID parity requests for AddByAddress. Lugdunum eserver and ed2k-server give an
// odd LowID to a client that set SrvCapNatTraversal (login bit 0x1000) and an even
// one to everyone else; clients skip the NAT callback for an even target
// (docs/lugdunum-nat-callback.local.md). LowIDAnyParity keeps the old behaviour for
// a server that does not offer the callback.
const (
	LowIDAnyParity  = -1
	LowIDEvenParity = 0
	LowIDOddParity  = 1
)

// lowIDCeiling is the top of the LowID space. The ed2k ID that flags a client as
// firewalled must stay below 0x1000000 (24 bits), so 0xffffff is the hard max.
const lowIDCeiling uint32 = 0xffffff

// NewLowIDClients builds the allocator over the [min,max] range configured by
// tcp.minLowID / tcp.maxLowID. The clamping lives here, not at the call site, so
// an omitted config (0/0) can never produce a degenerate one-element range:
//
//   - min == 0            → 1   (0 is reserved: it is what "not a LowID" looks like)
//   - max == 0 or > ceil  → 0xffffff
//   - min > max           → the full 1..0xffffff range (a misconfiguration, not fatal)
func NewLowIDClients(allowLowIDs bool, min, max uint32) *LowIDClients {
	if min == 0 {
		min = 1
	}
	if max == 0 || max > lowIDCeiling {
		max = lowIDCeiling
	}
	if min > max {
		min, max = 1, lowIDCeiling
	}
	return &LowIDClients{
		min:         min,
		max:         max,
		allowLowIDs: allowLowIDs,
		clients:     map[uint32]any{},
	}
}

func (l *LowIDClients) rangeSizeLocked() uint32 {
	return l.max - l.min + 1
}

func (l *LowIDClients) addByKeyLocked(key []byte, client any, parity int) (uint32, bool) {
	if !l.allowLowIDs {
		return 0, false
	}
	first, span := l.paritySpanLocked(parity)
	if span == 0 || l.usedLocked(parity) >= span {
		return 0, false
	}
	step := uint32(1)
	if parity != LowIDAnyParity {
		step = 2
	}
	for nonce := uint32(0); nonce < span; nonce++ {
		id := first + step*(hashLowIDSeed(key, nonce)%span)
		if _, ok := l.clients[id]; ok {
			continue
		}
		l.putLocked(id, client)
		return id, true
	}
	return 0, false
}

func (l *LowIDClients) Count() uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

func (l *LowIDClients) Add(client any) (uint32, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Backward-compatible fallback for generic callers/tests.
	return l.addByKeyLocked([]byte("lowid-default-seed"), client, LowIDAnyParity)
}

func (l *LowIDClients) AddByEndpoint(ipv4 uint32, port uint16, client any) (uint32, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := endpointKey(ipv4, port)
	return l.addByKeyLocked(key[:], client, LowIDAnyParity)
}

// AddByAddress seeds the LowID from the client's full connecting address. For an
// IPv6 peer it keys on the 16 address bytes so v6-only clients (all of whom have
// ipv4 == 0) do not collide on a single seed; for an IPv4 or absent address it
// reuses the exact [ipv4 LE][port] key AddByEndpoint uses, leaving v4 LowID
// assignment unchanged.
//
// parity is LowIDAnyParity, LowIDEvenParity or LowIDOddParity. A bound parity
// only uses its half of the range, so that half can fill up while the other
// still has room; that reports false like a full range.
func (l *LowIDClients) AddByAddress(ip net.IP, ipv4 uint32, port uint16, client any, parity int) (uint32, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := IPv6Bytes(ip); ok {
		key := make([]byte, 0, 18)
		key = append(key, b[:]...)
		var pb [2]byte
		binary.LittleEndian.PutUint16(pb[:], port)
		key = append(key, pb[:]...)
		return l.addByKeyLocked(key, client, parity)
	}
	key := endpointKey(ipv4, port)
	return l.addByKeyLocked(key[:], client, parity)
}

// endpointKey builds the [ipv4 LE][port LE] seed shared by the IPv4 LowID paths.
func endpointKey(ipv4 uint32, port uint16) [6]byte {
	var key [6]byte
	binary.LittleEndian.PutUint32(key[0:4], ipv4)
	binary.LittleEndian.PutUint16(key[4:6], port)
	return key
}

func (l *LowIDClients) Get(id uint32) (any, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.clients[id]
	return v, ok
}

// Restore registers client under a LowID it already holds: a session handed over
// from a predecessor process keeps the ID its client was told. It reports false
// when the ID is taken. The configured range is not enforced, since the ID was
// valid when it was issued.
func (l *LowIDClients) Restore(id uint32, client any) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if id == 0 || id > lowIDCeiling {
		return false
	}
	if _, ok := l.clients[id]; ok {
		return false
	}
	l.putLocked(id, client)
	return true
}

func (l *LowIDClients) Remove(id uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.clients[id]; ok {
		delete(l.clients, id)
		l.count--
		if id&1 == 1 {
			l.oddCount--
		}
	}
}

func (l *LowIDClients) putLocked(id uint32, client any) {
	l.clients[id] = client
	l.count++
	if id&1 == 1 {
		l.oddCount++
	}
}

// paritySpanLocked returns the lowest ID of the requested parity in [min,max]
// and how many such IDs there are. For LowIDAnyParity it is the whole range.
func (l *LowIDClients) paritySpanLocked(parity int) (first, span uint32) {
	if parity == LowIDAnyParity {
		return l.min, l.rangeSizeLocked()
	}
	first = l.min
	if int(first&1) != parity {
		first++
	}
	if first > l.max {
		return first, 0
	}
	return first, (l.max-first)/2 + 1
}

// usedLocked counts the IDs in use that the parity's half of the range competes
// for. IDs restored from a handoff may lie outside [min,max]; they are counted too,
// which only makes the early "full" answer slightly conservative.
func (l *LowIDClients) usedLocked(parity int) uint32 {
	switch parity {
	case LowIDOddParity:
		return l.oddCount
	case LowIDEvenParity:
		return l.count - l.oddCount
	default:
		return l.count
	}
}

func hashLowIDSeed(key []byte, nonce uint32) uint32 {
	h := fnv.New32a()
	_, _ = h.Write(key)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], nonce)
	_, _ = h.Write(b[:])
	return h.Sum32() & 0x00ffffff
}
