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
