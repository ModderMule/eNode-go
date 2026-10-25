package ed2k

import (
	"net"
	"time"

	"enode/logging"
)

// PR_NAT TCP wake-up (docs/pr-nat-rendezvous-spec.md, "Waking a local target").
//
// A client that announces SrvCapNatWake at login keeps no standing PR_NAT registration.
// When a SYNC2 names it and it has no live candidate, the server sends it OP_NAT_WAKE
// over its eD2K session; it answers with one REGISTER per requested family, and that
// REGISTER completes the pairing. The server holds state only while such an attempt is
// in flight, so an idle client costs nothing.

// SetSessionWake registers the hook that sends OP_NAT_WAKE to a session logged in here.
// Mirrors SetSessionTouch: the runtime supplies it, and without it nobody is woken.
func (h *NATTraversalHandler) SetSessionWake(fn func(hash [16]byte, families byte) bool) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessionWake = fn
}

// BuildNatWakePacket builds TCP OP_NAT_WAKE: <families 1>, NatWakeIPv4 | NatWakeIPv6.
func BuildNatWakePacket(families byte) (*Buffer, error) {
	return MakePacket(PrED2K, []PacketItem{
		{Type: TypeUint8, Value: OpNatWake},
		{Type: TypeUint8, Value: families},
	})
}

// natWakeEnabled reports whether this server wakes PR_NAT targets. The advertised TCP
// flag is the switch, as for the Lugdunum callback.
func (s *ServerRuntime) natWakeEnabled() bool {
	return s.tcp().Flags&FlagNatWake != 0
}

// wakeNatSession is the SetSessionWake hook: it sends OP_NAT_WAKE to the session
// logged in under hash, when that session announced SrvCapNatWake.
func (s *ServerRuntime) wakeNatSession(hash [16]byte, families byte) bool {
	if s.parking.Load() != nil {
		return false
	}
	c := s.sessionByHash(hash[:])
	if c == nil {
		return false
	}
	c.infoMu.RLock()
	ok := c.logged && c.natWakeCapable
	c.infoMu.RUnlock()
	if !ok {
		return false
	}
	packet, err := BuildNatWakePacket(families)
	if err != nil {
		return false
	}
	return c.writePacket(packet) == nil
}

// wakeTarget asks the woken-target path to handle a SYNC2 whose target has no candidate
// the requester can pair with. It reports true when the SYNC2 now waits on a wake: the
// answer then comes from completeWake or expireWake, not from the caller.
func (h *NATTraversalHandler) wakeTarget(src natClientEntry, dstHash [16]byte, connAck [4]byte, remote *net.UDPAddr, conn UDPReplyConn) bool {
	h.mu.RLock()
	wake := h.sessionWake
	lookup := h.sessionAddrs
	member := h.isLocalMember
	v6Enabled := h.ipv6Enabled
	h.mu.RUnlock()
	if wake == nil || src.hash == dstHash {
		return false
	}
	// The requester must have registered: the SYNC2 does that unless registerAllowed
	// refused it, and then there is nothing to pair it on.
	var families byte
	if src.v4 != nil {
		families |= NatWakeIPv4
	}
	if src.v6 != nil && v6Enabled {
		families |= NatWakeIPv6
	}
	// Ask for IPv6 only from a target whose session has one we know of; it cannot
	// register over a family it does not have, and the wait would only time out.
	if lookup != nil {
		if _, v6, local := lookup(dstHash); local && v6 == nil {
			families &^= NatWakeIPv6
		}
	}
	if families == 0 {
		return false
	}
	// Both peers must be logged in here. The target is (it has a session to wake);
	// the requester is checked here. No predicate only on a standalone handler.
	if member != nil && !member(src.hash) {
		return false
	}
	waiter := natWakeWaiter{hash: src.hash, connAck: connAck, remote: cloneUDPAddr(remote), conn: conn}

	h.mu.Lock()
	if p, ok := h.pending[dstHash]; ok {
		// Already woken: a repeated SYNC2, or a second requester, joins the wait. Only
		// families not asked for yet need another wake.
		joined := p.addWaiter(waiter)
		extra := families &^ p.families
		p.families |= families
		h.mu.Unlock()
		if !joined {
			return false
		}
		if extra != 0 {
			wake(dstHash, extra)
		}
		return true
	}
	if len(h.pending) >= natWakeMaxPending {
		h.mu.Unlock()
		return false
	}
	h.mu.Unlock()

	// The TCP write runs outside the NAT lock, as touchSession does.
	if !wake(dstHash, families) {
		return false
	}
	logging.Debugf("[module=nat] dir=send, opcode=OP_NAT_WAKE(0x%02x), target=%x, families=0x%02x, requester=%x",
		OpNatWake, dstHash[:], families, src.hash[:])

	h.mu.Lock()
	defer h.mu.Unlock()
	if p, ok := h.pending[dstHash]; ok {
		// Another SYNC2 woke the same target meanwhile.
		p.families |= families
		return p.addWaiter(waiter)
	}
	p := &natWakePending{families: families, waiters: []natWakeWaiter{waiter}}
	p.timer = time.AfterFunc(natWakeTimeout, func() { h.expireWake(dstHash, p) })
	h.pending[dstHash] = p
	return true
}

// completeWake pairs the SYNC2s waiting on hash, now that it registered from remote.
// It returns nothing when no wake for hash is pending or remote's family was not asked
// for (the target may register its other family first).
//
// IPv6 is preferred, as for any pairing, but the target's two REGISTERs race: when IPv6
// was asked for and the IPv4 one arrives first, the wait is cut to natWakeIPv6Grace and
// expireWake pairs on whatever arrived by then.
func (h *NATTraversalHandler) completeWake(hash [16]byte, remote *net.UDPAddr) []natOutbound {
	family := NatWakeIPv4
	if remoteIsIPv6(remote) {
		family = NatWakeIPv6
	}
	h.mu.Lock()
	p, ok := h.pending[hash]
	if !ok || p.families&family == 0 {
		h.mu.Unlock()
		return nil
	}
	if family == NatWakeIPv4 && p.families&NatWakeIPv6 != 0 {
		if !p.graced {
			p.graced = true
			p.timer.Reset(natWakeIPv6Grace)
		}
		h.mu.Unlock()
		return nil
	}
	delete(h.pending, hash)
	p.timer.Stop()
	h.mu.Unlock()
	return h.wakeOutbound(hash, p)
}

// expireWake ends the wait on hash: after natWakeIPv6Grace when only the target's IPv4
// arrived, else after natWakeTimeout. Each waiting requester is paired on what the target
// registered, or gets OP_NAT_FAILED 0x01.
func (h *NATTraversalHandler) expireWake(hash [16]byte, p *natWakePending) {
	h.mu.Lock()
	if h.pending[hash] != p {
		h.mu.Unlock()
		return
	}
	delete(h.pending, hash)
	h.mu.Unlock()
	// No datagram to answer: requesters get theirs through via, the SYNC to the target
	// leaves from the target's socket (a requester's when unknown).
	var fallback UDPReplyConn
	if len(p.waiters) > 0 {
		fallback = p.waiters[0].conn
	}
	h.send(nil, fallback, nil, h.wakeOutbound(hash, p))
}

// wakeOutbound builds the answers to the requesters of a finished wait: the SYNC pair on
// a family both have, or OP_NAT_FAILED 0x01 when the target registered none they share.
// Answers to a requester leave through the socket its SYNC2 came in on (via).
func (h *NATTraversalHandler) wakeOutbound(hash [16]byte, p *natWakePending) []natOutbound {
	v6Enabled := h.isIPv6Enabled()
	dst, dstOK := h.get(hash)
	var out []natOutbound
	for _, w := range p.waiters {
		src, ok := h.get(w.hash)
		var pair []natOutbound
		if ok && dstOK {
			pair = pairOutbound(src, dst, w.connAck[:], v6Enabled)
		}
		if pair == nil {
			f := h.natFailed(w.remote, hash, natFailReasonNotRegistered)
			f.via = w.conn
			out = append(out, f)
			continue
		}
		pair[0].via = w.conn // pair[0] goes to the requester
		out = append(out, pair...)
	}
	return out
}

// pendingWakes reports how many targets are waiting on a wake. Used by tests.
func (h *NATTraversalHandler) pendingWakes() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.pending)
}

// addWaiter adds a requester to the wait, or refreshes it when the same requester
// repeats its SYNC2. It reports false when the wait is full.
func (p *natWakePending) addWaiter(w natWakeWaiter) bool {
	for i := range p.waiters {
		if p.waiters[i].hash == w.hash {
			p.waiters[i] = w
			return true
		}
	}
	if len(p.waiters) >= natWakeMaxWaiters {
		return false
	}
	p.waiters = append(p.waiters, w)
	return true
}
