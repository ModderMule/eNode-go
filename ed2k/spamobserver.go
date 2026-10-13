package ed2k

import (
	"net"

	"enode/storage"
)

// SpamObserver scores the files clients offer and what their shares look like. It
// observes: nothing is refused because of it. Declared here rather than imported for
// the reason ContentFilter is.
//
// ObserveOffer is called from connection goroutines at once, so implementations must
// be safe for concurrent use.
type SpamObserver interface {
	// ObserveOffer is given the files of one OP_OFFERFILES that the content filter
	// let through. session is what the previous call for this connection returned,
	// nil on the first; the observer keeps its per-session state in it, so that state
	// goes away with the connection.
	ObserveOffer(session any, userHash []byte, ip net.IP, files []storage.File) any
}

// SetSpamObserver attaches the spam detector. Like SetContentFilter it is called
// before any listener binds; nil disables it.
func (s *ServerRuntime) SetSpamObserver(o SpamObserver) {
	s.Spam = o
}
