package ed2k

import (
	"bytes"
	"net"

	"enode/logging"
)

// maxIPv6Dials caps the IPv6 dial-backs of one session, the login's included. Each
// goes where the client points it, so without a cap a client could aim the server at
// any number of addresses. Same cap as ed2k-server (README, IPv6).
const maxIPv6Dials = 4

// handleIPv6Update answers OpIPv6Update (0x63): <ipv6 16>, the client's new public
// IPv6, or zeros to withdraw it. No reply. Rules, after ed2k-server (README, IPv6;
// issues #34, #43, #60):
//
//   - A session that arrived over IPv6 keeps its observed address; the update is
//     ignored.
//   - Zeros withdraw the address and the client's IPv6 capability. Any other
//     address makes the client able to receive IPv6 sources; only a public one is
//     published.
//   - A new public address is dialled back before it is published (probing on), or
//     published on trust (probing off). The verdict comes in a fresh OP_SERVERIDENT.
//   - The same address again starts nothing while its dial-back runs or after one
//     passed. After one failed, it is dialled again (a router may have opened a
//     pinhole since). Never more than maxIPv6Dials dials a session.
func (c *tcpClient) handleIPv6Update(data *Buffer) {
	if !c.server.publishV6Sources() {
		logging.Debugf("tcp ipv6 update ignored remote=%s: ipv6.publishSources off", c.remoteHost())
		return
	}
	if data.Remaining() != 16 {
		logging.Debugf("tcp ipv6 update ignored remote=%s: payload %d bytes", c.remoteHost(), data.Remaining())
		return
	}
	addr := append([]byte(nil), data.Bytes()[data.Pos():data.Pos()+16]...)
	if c.connectedV6 {
		logging.Debugf("tcp ipv6 update ignored remote=%s: session is ipv6, keeps %s", c.remoteHost(), c.peerIP)
		return
	}
	withdraw := bytes.Equal(addr, make([]byte, 16))
	public := !withdraw && IsPublicIPv6(net.IP(addr))
	if !public {
		addr = nil
	}
	probe := c.server.tcp().ProbeIPv6

	c.storeMu.Lock()
	if c.released {
		c.storeMu.Unlock()
		return
	}
	c.infoMu.Lock()
	c.ipv6Capable = !withdraw
	if withdraw {
		// No IPv6 to dial a requester from: the opt-in goes with it, as in
		// ed2k-server. The client opts in again after announcing a new address.
		c.v6CallbackOptIn = false
	}
	same := bytes.Equal(addr, c.info.IPv6)
	var dial, changed, capped bool
	switch {
	case same && addr == nil:
		// Nothing published before or after.
	case same:
		// A repeat: only a failed dial-back is worth another.
		if probe && !c.v6Probing && !(c.v6Probed && c.info.IPv6Reachable) {
			dial, capped = c.v6Dials < maxIPv6Dials, c.v6Dials >= maxIPv6Dials
		}
	default:
		changed = true
		c.info.IPv6 = addr
		c.info.IPv6Reachable = addr != nil && !probe
		c.v6Probing, c.v6Probed = false, false
		if addr != nil && probe {
			dial, capped = c.v6Dials < maxIPv6Dials, c.v6Dials >= maxIPv6Dials
		}
	}
	if dial {
		c.v6Dials++
		c.v6Probing = true
	}
	info := c.info
	c.infoMu.Unlock()
	if changed {
		if err := c.server.Storage.UpdateClientIPv6(info); err != nil {
			logging.Warnf("storage update client ipv6 remote=%s storeID=%d failed: %v", c.remoteHost(), info.StoreID, err)
		}
	}
	c.storeMu.Unlock()

	logging.Infof("tcp ipv6 update remote=%s ipv6=%s withdraw=%t public=%t changed=%t dial=%t capped=%t",
		c.remoteHost(), net.IP(addr), withdraw, public, changed, dial, capped)
	switch {
	case dial:
		go c.runIPv6Probe(addr)
	case changed && addr != nil && !probe:
		// Published on trust: the verdict (0x03) is known now.
		c.sendServerIdent(nil)
	}
}

// runIPv6Probe dials addr back and applies the verdict, unless the session's
// address is no longer addr or the session is gone. The verdict is always about the
// address it is applied to, however the updates interleave.
func (c *tcpClient) runIPv6Probe(addr []byte) {
	reachable := c.server.isIPv6ReachableAt(c, addr)

	// Lock order writeMu → storeMu → infoMu, as promoteSession: writeMu keeps a
	// handover from exporting the session between the verdict and its packet.
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.storeMu.Lock()
	c.infoMu.Lock()
	if !c.v6Probing || !bytes.Equal(c.info.IPv6, addr) {
		c.infoMu.Unlock()
		c.storeMu.Unlock()
		return
	}
	c.v6Probing = false
	if c.released || c.handedOff.Load() {
		c.infoMu.Unlock()
		c.storeMu.Unlock()
		return
	}
	c.v6Probed = true
	changed := c.info.IPv6Reachable != reachable
	c.info.IPv6Reachable = reachable
	info := c.info
	c.infoMu.Unlock()
	if changed {
		if err := c.server.Storage.UpdateClientIPv6(info); err != nil {
			logging.Warnf("storage update client ipv6 remote=%s storeID=%d failed: %v", c.remoteHost(), info.StoreID, err)
		}
	}
	c.storeMu.Unlock()
	logging.Infof("tcp ipv6 update verdict remote=%s ipv6=%s reachable=%t", c.remoteHost(), net.IP(info.IPv6), reachable)
	_ = c.writePacketLocked(c.buildServerIdent(nil))
}

// ipv6StatusLocked is the TagIPv6Status bitfield for the session's IPv6: 0 without
// one, 0x01 (held) while its dial-back runs or when none could run, then 0x07 or 0x05
// after a dial-back, 0x03 when published on trust. The caller holds infoMu.
func (c *tcpClient) ipv6StatusLocked() uint8 {
	if len(c.info.IPv6) != 16 {
		return 0
	}
	status := IPv6StatusHave
	if c.v6Probing {
		return status
	}
	if c.info.IPv6Reachable {
		status |= IPv6StatusReachable
	}
	if c.v6Probed {
		status |= IPv6StatusProbed
	}
	return status
}
