package ed2k

import (
	"encoding/binary"
	"hash/fnv"
	"net"
	"sync"
)

type LowIDClients struct {
	mu          sync.Mutex
	min         uint32
	max         uint32
	count       uint32
	allowLowIDs bool
	clients     map[uint32]any
}

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

func (l *LowIDClients) addByKeyLocked(key []byte, client any) (uint32, bool) {
	if !l.allowLowIDs {
		return 0, false
	}
	if l.count >= l.rangeSizeLocked() {
		return 0, false
	}
	for nonce := uint32(0); nonce < l.rangeSizeLocked(); nonce++ {
		id := l.hashToLowIDLocked(key, nonce)
		if _, ok := l.clients[id]; ok {
			continue
		}
		l.clients[id] = client
		l.count++
		return id, true
	}
	return 0, false
}

func (l *LowIDClients) hashToLowIDLocked(key []byte, nonce uint32) uint32 {
	h := fnv.New32a()
	_, _ = h.Write(key)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], nonce)
	_, _ = h.Write(b[:])
	raw := h.Sum32() & 0x00ffffff
	span := l.rangeSizeLocked()
	return l.min + (raw % span)
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
	return l.addByKeyLocked([]byte("lowid-default-seed"), client)
}

func (l *LowIDClients) AddByEndpoint(ipv4 uint32, port uint16, client any) (uint32, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := endpointKey(ipv4, port)
	return l.addByKeyLocked(key[:], client)
}

// AddByAddress seeds the LowID from the client's full connecting address. For an
// IPv6 peer it keys on the 16 address bytes so v6-only clients (all of whom have
// ipv4 == 0) do not collide on a single seed; for an IPv4 or absent address it
// reuses the exact [ipv4 LE][port] key AddByEndpoint uses, leaving v4 LowID
// assignment unchanged.
func (l *LowIDClients) AddByAddress(ip net.IP, ipv4 uint32, port uint16, client any) (uint32, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := IPv6Bytes(ip); ok {
		key := make([]byte, 0, 18)
		key = append(key, b[:]...)
		var pb [2]byte
		binary.LittleEndian.PutUint16(pb[:], port)
		key = append(key, pb[:]...)
		return l.addByKeyLocked(key, client)
	}
	key := endpointKey(ipv4, port)
	return l.addByKeyLocked(key[:], client)
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
	l.clients[id] = client
	l.count++
	return true
}

func (l *LowIDClients) Remove(id uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.clients[id]; ok {
		delete(l.clients, id)
		l.count--
	}
}
