package ed2k

import (
	"math"
	"time"

	"enode/logging"
)

// The network names the meta searcher answers NetworkUsers for: meta.NetworkKad and
// meta.NetworkTorrent, repeated here because this package does not import meta.
const (
	metaNetworkKad     = "kad"
	metaNetworkTorrent = "torrent"
)

// autoSearchMaxUsers is the user count eMule's Automatic search type stops trusting
// a server at: it searches the server rather than Kad only below it
// (srchybrid/SearchResultsWnd.cpp, src/core/search/SearchParams.cpp).
const autoSearchMaxUsers = 2000000

// usersCeilingWarnEvery is how often the warning about passing autoSearchMaxUsers
// is repeated while it holds; the count is read on every status reply.
const usersCeilingWarnEvery = time.Hour

// StatsBoost holds fixed offsets added to the user, LowID-user and file counts that
// both status packets advertise: TCP OP_SERVERSTATUS and UDP OP_GLOBSERVSTATRES.
// Applying them in one place keeps the two channels in agreement, which the old
// UDP-only +2000/+1000 did not. Configured by the local-only statsBoost section;
// see config.StatsBoostConfig and docs/stats-boost.local.md.
//
// KadUsers and TorrentUsers add something that is not fixed: the number of users the
// Kad network and the BitTorrent DHT are estimated to have, as the catalogue daemon
// of each last reported it. Off, or with no such daemon, they add nothing.
type StatsBoost struct {
	Users      int
	LowIDUsers int
	Files      int

	KadUsers     bool
	TorrentUsers bool
}

// SetStatsBoost sets the advertised-count offsets. Safe to call with the listeners live.
func (s *ServerRuntime) SetStatsBoost(b StatsBoost) {
	s.boost.Store(&b)
}

// PublicStatus is what this server tells anyone who asks: the figures of
// OP_SERVERSTATUS and OP_GLOBSERVSTATRES, read the same way. It never carries the
// real counts when a statsBoost is set.
type PublicStatus struct {
	Name        string
	Description string
	Users       int
	LowIDUsers  int
	Files       int
	// Servers is how many peer servers a client is sent in OP_SERVERLIST.
	Servers       int
	MaxUsers      uint32
	SoftFileLimit uint32
	HardFileLimit uint32
}

// PublicStatus returns the advertised figures, from the same cached reading and the
// same offsets as buildStatRes, so an HTTP status route cannot disagree with the wire.
func (s *ServerRuntime) PublicStatus() PublicStatus {
	clients, files := s.counters.Counts()
	cfg := s.udp()
	return PublicStatus{
		Name:          cfg.Name,
		Description:   cfg.Description,
		Users:         s.advertisedUsers(clients),
		LowIDUsers:    s.advertisedLowIDs(int(s.LowIDs.Count())),
		Files:         s.advertisedFiles(files),
		Servers:       s.AdvertisedServerCount(),
		MaxUsers:      cfg.MaxConnections,
		SoftFileLimit: cfg.SoftFiles,
		HardFileLimit: cfg.HardFiles,
	}
}

// statsBoost returns the current offsets, zero when none were set.
func (s *ServerRuntime) statsBoost() StatsBoost {
	if b := s.boost.Load(); b != nil {
		return *b
	}
	return StatsBoost{}
}

// advertisedUsers adds the statsBoost users offset to the online-client count, and
// the estimated users of the networks statsBoost counts in.
func (s *ServerRuntime) advertisedUsers(clients int) int {
	boost := s.statsBoost()
	total := addClampedUint32(clients, boost.Users)
	if s.meta == nil || !(boost.KadUsers || boost.TorrentUsers) {
		return total
	}
	if boost.KadUsers {
		total = addClampedUint32(total, s.meta.NetworkUsers(metaNetworkKad))
	}
	if boost.TorrentUsers {
		total = addClampedUint32(total, s.meta.NetworkUsers(metaNetworkTorrent))
	}
	if total > autoSearchMaxUsers {
		s.warnUsersOverCeiling(total)
	}
	return total
}

// advertisedLowIDs adds the statsBoost LowID offset to the LowID-client count.
func (s *ServerRuntime) advertisedLowIDs(lowIDs int) int {
	return addClampedUint32(lowIDs, s.statsBoost().LowIDUsers)
}

// warnUsersOverCeiling says, at most once per usersCeilingWarnEvery, that the network
// estimates pushed the advertised users past what eMule's Automatic search accepts.
func (s *ServerRuntime) warnUsersOverCeiling(total int) {
	now := time.Now().UnixNano()
	last := s.usersCeilingWarned.Load()
	if last != 0 && now-last < int64(usersCeilingWarnEvery) {
		return
	}
	if !s.usersCeilingWarned.CompareAndSwap(last, now) {
		return
	}
	logging.Warnf("statsBoost: advertising %d users with the network estimates, more than the %d below which eMule's automatic search uses a server",
		total, autoSearchMaxUsers)
}

// addClampedUint32 sums two non-negative counts into the uint32 range the status
// packets carry, so a large offset saturates instead of wrapping to a small number.
func addClampedUint32(count, offset int) int {
	total := uint64(max(count, 0)) + uint64(max(offset, 0))
	return int(min(total, math.MaxUint32))
}
