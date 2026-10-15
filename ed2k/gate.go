package ed2k

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// Gate holds the accept loop of a TCP listener, or the read loop of a UDP socket,
// while it is closed. A process taking over from a predecessor binds its sockets
// closed and opens them once the predecessor has let go; a process handing over
// closes its TCP gate so no connection is accepted that would then have to be
// handed over too. A nil *Gate is always open.
//
// Closing interrupts a loop blocked in Accept or Read by setting a deadline in the
// past; the loop sees the timeout, finds the gate closed and waits.
type Gate struct {
	mu      sync.Mutex
	open    bool
	opened  chan struct{}
	targets []func(time.Time) error
}

// NewGate returns a gate that starts open or closed.
func NewGate(open bool) *Gate {
	g := &Gate{open: open, opened: make(chan struct{})}
	if open {
		close(g.opened)
	}
	return g
}

// Open lets the loops run.
func (g *Gate) Open() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.open {
		return
	}
	g.open = true
	// Deadlines first, then the wake-up: a loop woken before its deadline is
	// cleared would time out once and come straight back, which is harmless, but
	// there is no reason to make it.
	for _, set := range g.targets {
		_ = set(time.Time{})
	}
	close(g.opened)
}

// Close holds the loops at their next Accept or Read.
func (g *Gate) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.open {
		return
	}
	g.open = false
	g.opened = make(chan struct{})
	for _, set := range g.targets {
		_ = set(gatePast)
	}
}

// IsOpen reports whether the gate is open.
func (g *Gate) IsOpen() bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.open
}

// wait blocks while the gate is closed.
func (g *Gate) wait() {
	if g == nil {
		return
	}
	g.mu.Lock()
	ch := g.opened
	g.mu.Unlock()
	<-ch
}

// attach registers how to interrupt a loop: SetDeadline for a listener,
// SetReadDeadline for a UDP socket, whose writes must keep working.
func (g *Gate) attach(set func(time.Time) error) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.targets = append(g.targets, set)
	if !g.open {
		_ = set(gatePast)
	}
}

// interrupted reports whether a loop's error is the gate's own deadline rather than
// the socket closing: only a gate ever sets one on these sockets.
func (g *Gate) interrupted(err error) bool {
	if g == nil {
		return false
	}
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// gatePast is a deadline that has always passed.
var gatePast = time.Unix(1, 0)
