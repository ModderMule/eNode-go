package ed2k

import (
	"time"

	"enode/logging"
)

// defaultFirewallRecheckInterval is the least time between two OpRecheckFirewall of
// one session when TCPRuntimeConfig leaves it zero (config tcp.firewallRecheckInterval).
const defaultFirewallRecheckInterval = 120 * time.Second

func (s *ServerRuntime) firewallRecheckInterval() time.Duration {
	if d := s.tcp().FirewallRecheckInterval; d > 0 {
		return d
	}
	return defaultFirewallRecheckInterval
}

// handleRecheckFirewall answers OpRecheckFirewall: <tcpPort uint16 LE>, or empty / 0
// for the current port. The port is dial-tested off this goroutine; the answer is a
// fresh OP_IDCHANGE (promoteSession). Throttled or in flight: no answer.
func (c *tcpClient) handleRecheckFirewall(data *Buffer) {
	if !c.server.tcp().FirewallRecheck {
		logging.Debugf("tcp firewall recheck ignored remote=%s: off", c.remoteHost)
		return
	}
	var port uint16
	switch data.Remaining() {
	case 0:
	case 2:
		port, _ = data.GetUInt16LE()
	default:
		logging.Debugf("tcp firewall recheck ignored remote=%s: payload %d bytes", c.remoteHost, data.Remaining())
		return
	}
	now := uint32(time.Since(c.connectedAt)/time.Second) + 1
	if c.lastRecheck != 0 && time.Duration(now-c.lastRecheck)*time.Second < c.server.firewallRecheckInterval() {
		logging.Debugf("tcp firewall recheck ignored remote=%s: throttled, last %ds ago", c.remoteHost, now-c.lastRecheck)
		return
	}
	c.infoMu.Lock()
	busy := c.recheckBusy
	c.recheckBusy = true
	c.infoMu.Unlock()
	if busy {
		logging.Debugf("tcp firewall recheck ignored remote=%s: one in flight", c.remoteHost)
		return
	}
	c.lastRecheck = now
	go c.runFirewallRecheck(port)
}

// runFirewallRecheck decides like the login does (HasHighID, then the dial-back)
// and applies the outcome. A HighID is never demoted: its port only moves to one
// that answered.
func (c *tcpClient) runFirewallRecheck(port uint16) {
	defer func() {
		c.infoMu.Lock()
		c.recheckBusy = false
		c.infoMu.Unlock()
	}()
	info := c.snapshotInfo()
	if port == 0 {
		port = info.Port
	}
	c.infoMu.RLock()
	lowID := c.hasLowID
	c.infoMu.RUnlock()
	reachable := false
	switch {
	case !lowID && port == info.Port:
		reachable = true // nothing to test
	case HasHighID(info.IPv4):
		reachable = !c.server.isFirewalledAt(c, port)
	}
	logging.Debugf("tcp firewall recheck remote=%s lowID=%t port=%d->%d reachable=%t",
		c.remoteHost, lowID, info.Port, port, reachable)
	if !lowID && !reachable {
		port = info.Port
	}
	c.promoteSession(port, lowID && reachable)
}

// promoteSession moves the session to port and, with promote, from its LowID to its
// HighID, then sends OP_IDCHANGE with the resulting ID.
//
// Lock order writeMu → storeMu → infoMu → LowIDs. writeMu first: a handover parks
// sessions holding it, so nothing changes between exportState and the move; a session
// handed off is left alone. storeMu orders this against releaseSession, which reads
// the ID to free under it.
func (c *tcpClient) promoteSession(port uint16, promote bool) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.handedOff.Load() {
		return
	}
	c.storeMu.Lock()
	if c.released {
		c.storeMu.Unlock()
		return
	}
	c.infoMu.Lock()
	old := c.info
	c.info.Port = port
	promoted := promote && c.hasLowID
	if promoted {
		c.server.LowIDs.Remove(old.ID)
		c.hasLowID = false
		c.info.LowID = false
		c.info.ID = c.info.IPv4
	}
	info := c.info
	c.infoMu.Unlock()
	if info.ID != old.ID || info.Port != old.Port {
		if err := c.server.Storage.UpdateClient(old.ID, old.Port, info); err != nil {
			logging.Warnf("storage update client remote=%s storeID=%d failed: %v", c.remoteHost, info.StoreID, err)
		}
	}
	c.storeMu.Unlock()
	if promoted {
		c.server.natCallback.forgetLowID(old.ID, c)
		logging.Infof("firewall recheck promoted remote=%s lowID=%d -> highID=%d port=%d",
			c.remoteHost, old.ID, info.ID, info.Port)
	} else if info.Port != old.Port {
		logging.Infof("firewall recheck moved port remote=%s id=%d lowID=%t port=%d->%d",
			c.remoteHost, info.ID, info.LowID, old.Port, info.Port)
	}
	if packet := c.buildIDChange(info.ID); packet != nil {
		_ = c.writeRawLocked(packet.Bytes())
	}
}
