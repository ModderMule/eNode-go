package contentfilter

import (
	"net"
	"sync"
	"time"
)

// banList is the publisher sanction: user hashes and addresses refused at login until
// their ban runs out. In memory only — a restart forgives everyone, which is the
// cheaper mistake than a ban file that outlives the list entry that caused it.
type banList struct {
	mu      sync.Mutex
	entries map[string]time.Time // key -> expiry
	now     func() time.Time
}

func newBanList() *banList {
	return &banList{entries: make(map[string]time.Time), now: time.Now}
}

func (b *banList) add(userHash []byte, ip net.IP, d time.Duration) {
	until := b.now().Add(d)
	b.mu.Lock()
	defer b.mu.Unlock()
	if k := hashKey(userHash); k != "" {
		b.entries[k] = until
	}
	if k := ipKey(ip); k != "" {
		b.entries[k] = until
	}
}

func (b *banList) banned(userHash []byte, ip net.IP) bool {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, k := range [2]string{hashKey(userHash), ipKey(ip)} {
		if k == "" {
			continue
		}
		// An expired entry is treated as absent here and removed by sweep.
		if until, ok := b.entries[k]; ok && now.Before(until) {
			return true
		}
	}
	return false
}

// sweep drops expired entries and returns how many remain.
func (b *banList) sweep() int {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, until := range b.entries {
		if !now.Before(until) {
			delete(b.entries, k)
		}
	}
	return len(b.entries)
}

func hashKey(userHash []byte) string {
	if len(userHash) != HashSize {
		return ""
	}
	return "h" + string(userHash)
}

// ipKey bans an IPv4 address exactly and an IPv6 address by its /64: a v6 host picks
// its own low 64 bits, so banning one address would ban nothing.
func ipKey(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return "4" + string(v4)
	}
	if v6 := ip.To16(); v6 != nil {
		return "6" + string(v6[:8])
	}
	return ""
}
