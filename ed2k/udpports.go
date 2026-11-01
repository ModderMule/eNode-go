package ed2k

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// This file tracks where a client's *server-UDP* listener lives.
//
// The ed2k server-UDP protocol is asymmetric in a way the TCP login makes
// invisible: a client never tells us its server-UDP port. The original client
// binds that listener to an ephemeral port (srchybrid/Preferences.cpp "ServerUDPPort"
// defaults to -1 → srchybrid/UDPSocket.cpp Create() binds 0) and every reply we
// ever send to it — global search results, found sources — goes back to the
// SOURCE PORT of the client's own datagrams. So the only place this server ever
// sees that port is the remote address of a client-protocol UDP frame, and it
// was discarded there. ClientView.Port (the port claimed in OP_LOGINREQUEST,
// server_runtime.go c.info.Port = req.Port) is the client's TCP listen port, a
// different socket entirely; targeting it sends datagrams into the void.
//
// The table below keeps the last-seen UDP source port per address so the admin
// client list can show it (ClientRow.udpPort) and operators can point UDP probes
// at the socket that actually parses server-UDP frames.
//
// It is an opt-in diagnostic (udp.trackClientPorts, off by default and absent
// from the shipped configs). Off, ServerRuntime.udpPorts is nil: no table is
// allocated and the UDP hot path pays one atomic load. Turning it off on a
// reload drops the table, so its memory is returned.
//
// Coverage is partial by design of the client, not of this table: eMule never
// sends OP_GLOBGETSOURCES to the server it is connected to
// (srchybrid/DownloadQueue.cpp skips pConnectedServer), so a logged-in client
// usually shows up here only through its periodic OP_GLOBSERVSTATREQ ping
// (srchybrid/ServerList.cpp ServerStats) or a global search.

// clientUDPPortTTL is how long an observed UDP source port stays answerable.
// A client that has not sent us a UDP frame within this window may have bound a
// new socket (reconnect, or NAT re-mapping), so its old port must not be handed
// out as if still live.
const clientUDPPortTTL = 30 * time.Minute

// clientUDPPortMaxEntries bounds the table against a flood of unique source
// addresses (UDP sources are trivially spoofed). At ~40 bytes an entry the
// table tops out near 1 MiB. When it is full of fresh entries, new addresses
// are dropped; addresses already present keep updating.
const clientUDPPortMaxEntries = 16384

// clientUDPPortRefresh is how stale an unchanged entry may get before a repeat
// datagram rewrites its timestamp. It keeps the write lock off the hot path for
// a chatty sender, at the price of an age that can read up to this much high.
const clientUDPPortRefresh = 10 * time.Second

// clientUDPPortSweepInterval is how often expired entries are swept. Sweeping
// is O(n) under the write lock, so it runs at most this often — never once per
// datagram, even while the table is full.
const clientUDPPortSweepInterval = 5 * time.Minute

// udpPortEpoch anchors udpPortEntry.seen to the monotonic clock, so a wall
// clock step neither expires every entry nor keeps them alive forever.
var udpPortEpoch = time.Now()

// udpPortTable is the observation table, allocated only while tracking is on.
type udpPortTable struct {
	mu sync.RWMutex
	m  map[netip.Addr]udpPortEntry
	// lastSweep is when sweepLocked last ran, in udpPortEpoch nanoseconds.
	lastSweep int64
}

// udpPortEntry is one observed UDP source port for an address. seen is in
// udpPortEpoch nanoseconds rather than a time.Time, which would triple its size.
type udpPortEntry struct {
	seen int64
	port uint16
}

// NoteClientUDPPort records the UDP source port of remote, called from the UDP
// handler once a datagram has passed the protocol check. Only well-formed
// eD2K-protocol frames reach this, so junk and crypt-ping probes do not poison
// the table. The observation is advisory: gossip peers and scanners land here
// too, but the only reader is the admin lookup keyed on a client's TCP address.
// A no-op while tracking is off.
func (s *ServerRuntime) NoteClientUDPPort(remote *net.UDPAddr) {
	t := s.udpPorts.Load()
	if t == nil || remote == nil || remote.Port <= 0 || remote.Port > 0xFFFF {
		return
	}
	addr, ok := udpPortKey(remote.IP)
	if !ok {
		return
	}
	t.note(addr, uint16(remote.Port), int64(time.Since(udpPortEpoch)))
}

// ClientUDPPort returns the UDP source port last observed from ip and when it
// was seen, within clientUDPPortTTL. ok is false when tracking is off, the
// address never sent us a client-protocol UDP frame, or its entry has aged out.
func (s *ServerRuntime) ClientUDPPort(ip net.IP) (port uint16, seen time.Time, ok bool) {
	t := s.udpPorts.Load()
	if t == nil {
		return 0, time.Time{}, false
	}
	addr, valid := udpPortKey(ip)
	if !valid {
		return 0, time.Time{}, false
	}
	t.mu.RLock()
	entry, found := t.m[addr]
	t.mu.RUnlock()
	// Expired entries are left for the sweep rather than deleted here, so a
	// read never takes the write lock.
	if !found || int64(time.Since(udpPortEpoch))-entry.seen > int64(clientUDPPortTTL) {
		return 0, time.Time{}, false
	}
	return entry.port, udpPortEpoch.Add(time.Duration(entry.seen)), true
}

// setUDPPortTracking allocates or drops the table to match on. Called at
// construction and on every config apply; an unchanged setting keeps the
// existing table and its observations.
func (s *ServerRuntime) setUDPPortTracking(on bool) {
	if !on {
		s.udpPorts.Store(nil)
		return
	}
	if s.udpPorts.Load() == nil {
		s.udpPorts.CompareAndSwap(nil, &udpPortTable{m: make(map[netip.Addr]udpPortEntry)})
	}
}

// note records port for addr at now (udpPortEpoch nanoseconds).
func (t *udpPortTable) note(addr netip.Addr, port uint16, now int64) {
	// Fast path: a repeat from the same socket only needs the read lock.
	t.mu.RLock()
	e, found := t.m[addr]
	t.mu.RUnlock()
	if found && e.port == port && now-e.seen < int64(clientUDPPortRefresh) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if now-t.lastSweep >= int64(clientUDPPortSweepInterval) {
		t.sweepLocked(now)
	}
	if _, exists := t.m[addr]; !exists && len(t.m) >= clientUDPPortMaxEntries {
		return // full of fresh entries; keep the table bounded
	}
	t.m[addr] = udpPortEntry{seen: now, port: port}
}

// sweepLocked drops entries older than the TTL. Caller holds mu for writing.
func (t *udpPortTable) sweepLocked(now int64) {
	t.lastSweep = now
	for k, e := range t.m {
		if now-e.seen > int64(clientUDPPortTTL) {
			delete(t.m, k)
		}
	}
}

// udpPortKey keys the table: an IPv4-mapped IPv6 address shares the key of its
// IPv4 form, so a dual-stack client is one entry, matching how the bot detector
// and rate limiter bucket addresses. netip.Addr is comparable and needs no
// allocation, unlike the string form.
func udpPortKey(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}
