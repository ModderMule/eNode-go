package ed2k

import "math"

// StatsBoost holds fixed offsets added to the user, LowID-user and file counts that
// both status packets advertise: TCP OP_SERVERSTATUS and UDP OP_GLOBSERVSTATRES.
// Applying them in one place keeps the two channels in agreement, which the old
// UDP-only +2000/+1000 did not. Configured by the local-only statsBoost section;
// see config.StatsBoostConfig and docs/stats-boost.local.md.
type StatsBoost struct {
	Users      int
	LowIDUsers int
	Files      int
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

// advertisedUsers adds the statsBoost users offset to the online-client count.
func (s *ServerRuntime) advertisedUsers(clients int) int {
	return addClampedUint32(clients, s.statsBoost().Users)
}

// advertisedLowIDs adds the statsBoost LowID offset to the LowID-client count.
func (s *ServerRuntime) advertisedLowIDs(lowIDs int) int {
	return addClampedUint32(lowIDs, s.statsBoost().LowIDUsers)
}

// addClampedUint32 sums two non-negative counts into the uint32 range the status
// packets carry, so a large offset saturates instead of wrapping to a small number.
func addClampedUint32(count, offset int) int {
	total := uint64(max(count, 0)) + uint64(max(offset, 0))
	return int(min(total, math.MaxUint32))
}
