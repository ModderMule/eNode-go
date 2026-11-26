package ed2k

import (
	"time"
)

// statusSlices is how many slices one ServerStatusInterval is cut into. Each live
// session belongs to one slice (tcpClient.statusSlot), so a tick touches about
// 1/statusSlices of them and the OP_SERVERSTATUS writes spread over the interval
// instead of bunching up.
const statusSlices = 60

// minStatusStep keeps a very short interval (tests use 1 ms) from turning the loop
// into a busy wait.
const minStatusStep = time.Millisecond

// The status loop sends every logged-in session its periodic OP_SERVERSTATUS and
// drops the "More" rows that have expired, for all sessions at once.
//
// It replaces a goroutine with its own time.Ticker per session. That goroutine cost
// each idle connection a second stack plus a ticker, timer, channel and closure:
// about 3.3 KiB of the 24 KiB an idle session cost (see
// docs/memory-footprint.local.md §2.5). The Rust ed2k-server does the same with one
// keepalive task (src/server/keepalive.rs).
//
// The loop runs while there are live sessions. trackSession starts it with the first
// one, and it ends at the first tick that finds none left, so a ServerRuntime with
// no connections holds no goroutine.

// statusSlotLocked gives a new session its slice and starts the loop if it is not
// running. Callers hold liveMu.
func (s *ServerRuntime) statusSlotLocked(c *tcpClient) {
	c.statusSlot = uint8(s.statusNextSlot % statusSlices)
	s.statusNextSlot++
	if !s.statusLoopOn {
		s.statusLoopOn = true
		go s.runStatusLoop()
	}
}

// runStatusLoop visits one slice of the live sessions per tick, so each session is
// visited once per ServerStatusInterval.
func (s *ServerRuntime) runStatusLoop() {
	var batch []*tcpClient
	timer := time.NewTimer(s.statusStep())
	defer timer.Stop()
	for slot := uint8(0); ; slot = (slot + 1) % statusSlices {
		<-timer.C
		var ok bool
		batch, ok = s.statusBatch(batch[:0], slot)
		if !ok {
			return
		}
		s.statusTick(batch, time.Now())
		clear(batch)
		// Read every tick: a config reload may change the interval.
		timer.Reset(s.statusStep())
	}
}

// statusTick serves one slice: every session drops its expired "More" rows, and the
// logged-in ones get an OP_SERVERSTATUS.
func (s *ServerRuntime) statusTick(batch []*tcpClient, now time.Time) {
	// Not while a handover is parking the sessions: a write now would move the RC4
	// keystream past the state being handed over.
	parking := s.parking.Load() != nil
	for _, c := range batch {
		c.dropExpiredResults(now)
		if !parking && c.isLogged() {
			// On its own goroutine: the write may block for up to writeTimeout on a
			// client that does not read, and must not hold up the rest of the slice.
			// The goroutine lives only as long as the write.
			go c.sendServerStatus()
		}
	}
}

// statusStep is the time between two ticks.
func (s *ServerRuntime) statusStep() time.Duration {
	interval := s.tcp().ServerStatusInterval
	if interval <= 0 {
		interval = defaultServerStatusInterval
	}
	return max(interval/statusSlices, minStatusStep)
}

// statusBatch appends the live sessions of slot to batch. ok is false when no
// session is left; the loop is then marked stopped, under the same lock
// trackSession takes, so the next session starts a new one.
func (s *ServerRuntime) statusBatch(batch []*tcpClient, slot uint8) ([]*tcpClient, bool) {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	if len(s.live) == 0 {
		s.statusLoopOn = false
		return batch, false
	}
	for c := range s.live {
		if c.statusSlot == slot {
			batch = append(batch, c)
		}
	}
	return batch, true
}
