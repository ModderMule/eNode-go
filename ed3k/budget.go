package ed3k

import (
	"net/netip"
	"sync"
	"time"

	"enode/ed3k/ident"
	"enode/ed3k/transport"
	quic "enode/internal/ed3k/iquic"
)

// banTime is how long a node ID over its connection rate is banned (§4.6).
const banTime = 24 * time.Hour

// budget keeps the connection limits of §4.6: new connections per node ID (a
// ban beyond) and per host group (refused, never banned) per minute, and open
// connections per host group, per site and in all. Private addresses in a named
// network are exempt from the address rows.
type budget struct {
	cfg   Budget
	named bool

	mu      sync.Mutex
	open    int
	host    map[netip.Prefix]int
	site    map[netip.Prefix]int
	newHost map[netip.Prefix][]time.Time
	newNode map[ident.NodeID][]time.Time
	banned  map[ident.NodeID]time.Time
}

func newBudget(cfg Budget, named bool) *budget {
	return &budget{cfg: cfg, named: named, host: map[netip.Prefix]int{}, site: map[netip.Prefix]int{},
		newHost: map[netip.Prefix][]time.Time{}, newNode: map[ident.NodeID][]time.Time{}, banned: map[ident.NodeID]time.Time{}}
}

// admit counts a completed handshake and reports whether to close it, with the
// close code.
func (b *budget) admit(id ident.NodeID, a netip.Addr, now time.Time) (quic.ApplicationErrorCode, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if until, ok := b.banned[id]; ok {
		if now.Before(until) {
			return transport.CodeDenied, true
		}
		delete(b.banned, id)
	}
	b.newNode[id] = recent(append(b.newNode[id], now), now)
	if len(b.newNode[id]) > b.cfg.NewPerNodeIDMin {
		b.banned[id] = now.Add(banTime)
		return transport.CodeDenied, true
	}
	exempt := b.named && ident.Private(a)
	host, site := ident.HostKey(a, b.named), ident.SiteKey(a)
	if !exempt {
		b.newHost[host] = recent(append(b.newHost[host], now), now)
		if len(b.newHost[host]) > b.cfg.NewPerHostMin {
			return transport.CodeBusy, true
		}
		if b.host[host] >= b.cfg.PerHost || b.site[site] >= b.cfg.PerSite {
			return transport.CodeBusy, true
		}
	}
	if b.open >= b.cfg.MaxConns {
		return transport.CodeBusy, true
	}
	b.open++
	b.host[host]++
	b.site[site]++
	return 0, false
}

// leave counts a closed connection.
func (b *budget) leave(a netip.Addr) {
	b.mu.Lock()
	defer b.mu.Unlock()
	host, site := ident.HostKey(a, b.named), ident.SiteKey(a)
	b.open--
	if b.host[host]--; b.host[host] <= 0 {
		delete(b.host, host)
	}
	if b.site[site]--; b.site[site] <= 0 {
		delete(b.site, site)
	}
}

// sweep drops counts older than a minute and bans that ended.
func (b *budget) sweep(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, ts := range b.newHost {
		if ts = recent(ts, now); len(ts) == 0 {
			delete(b.newHost, k)
		} else {
			b.newHost[k] = ts
		}
	}
	for k, ts := range b.newNode {
		if ts = recent(ts, now); len(ts) == 0 {
			delete(b.newNode, k)
		} else {
			b.newNode[k] = ts
		}
	}
	for k, until := range b.banned {
		if !now.Before(until) {
			delete(b.banned, k)
		}
	}
}

// recent keeps the times of the last minute.
func recent(ts []time.Time, now time.Time) []time.Time {
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= time.Minute {
		i++
	}
	return ts[i:]
}
