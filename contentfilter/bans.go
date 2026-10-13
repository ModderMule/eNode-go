package contentfilter

import (
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// BanEntry is one active ban for the admin surface. Key is what Unban takes:
// "hash:<32 hex digits>", "ip:<IPv4 address>" or "ip:<IPv6 /64 prefix>".
type BanEntry struct {
	Key   string
	Until time.Time
}

// ErrBanKey is returned for a ban key that names neither a user hash nor an address.
var ErrBanKey = errors.New("ban key must be hash:<32 hex digits> or ip:<address>")

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

// list returns the bans still running, soonest to expire first.
func (b *banList) list() []BanEntry {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]BanEntry, 0, len(b.entries))
	for k, until := range b.entries {
		if now.Before(until) {
			out = append(out, BanEntry{Key: displayKey(k), Until: until})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Until.Equal(out[j].Until) {
			return out[i].Until.Before(out[j].Until)
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// remove lifts one ban and reports whether it existed.
func (b *banList) remove(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.entries[key]; !ok {
		return false
	}
	delete(b.entries, key)
	return true
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

// displayKey renders an internal ban key the way BanEntry.Key documents it.
func displayKey(k string) string {
	switch {
	case strings.HasPrefix(k, "h"):
		return "hash:" + hex.EncodeToString([]byte(k[1:]))
	case strings.HasPrefix(k, "4"):
		return "ip:" + net.IP(k[1:]).String()
	case strings.HasPrefix(k, "6"):
		prefix := make(net.IP, net.IPv6len)
		copy(prefix, k[1:])
		return "ip:" + prefix.String() + "/64"
	}
	return k
}

// parseBanKey turns a BanEntry.Key back into the user hash or address it names.
func parseBanKey(key string) (userHash []byte, ip net.IP, err error) {
	kind, value, ok := strings.Cut(strings.TrimSpace(key), ":")
	if !ok {
		return nil, nil, ErrBanKey
	}
	switch kind {
	case "hash":
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != HashSize {
			return nil, nil, ErrBanKey
		}
		return raw, nil, nil
	case "ip":
		ip := net.ParseIP(strings.TrimSuffix(value, "/64"))
		if ip == nil {
			return nil, nil, ErrBanKey
		}
		return nil, ip, nil
	}
	return nil, nil, ErrBanKey
}
