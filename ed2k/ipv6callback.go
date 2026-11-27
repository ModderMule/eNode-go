package ed2k

import (
	"bytes"
	"net"
	"time"

	"enode/logging"
)

// The IPv6 callback (ModderMule/eNode-go#2, andrey23127/ed2k-server#62) lets a LowID
// requester whose IPv6 passed the dial-back reach a LowID target over IPv6: the
// requester sends OpIPv6CallbackRequest naming the target, and the server sends the
// target OpCallbackReqdIPv6 with the requester's verified IPv6. Rules, values and
// refusal order are ed2k-server's (src/server/callback.rs), so a client sees one
// protocol on both servers:
//
//   - Offered (TagIPv6Callback in OP_SERVERIDENT) only to a v6-capable session while
//     ipv6.callback, ipv6.publishSources and ipv6.probeReachability are on.
//   - A target is named only after it sent OpIPv6CallbackOptIn on this session;
//     CT_MOD_IP_V6 alone does not prove it can handle 0x26.
//   - Only an address the server dialled back as that client is handed out, so a
//     client cannot aim a crowd of targets at a host of its choice.
//   - Every refusal is the 5-byte OP_CALLBACK_FAIL <target LowID><reason>, so the
//     requester goes on to the hole punch at once.

// relayPerSecond and relayBurst are the per-session allowance for requests that make
// the server push a frame to another client: OP_CALLBACKREQUEST and
// OpIPv6CallbackRequest. ed2k-server's admission.session_relay_* defaults; a LowID
// population makes callbacks common, hence the large burst.
const (
	relayPerSecond = 10
	relayBurst     = 200
)

// handleIPv6CallbackOptIn answers OpIPv6CallbackOptIn: empty, or one feature byte
// whose IPv6CallbackBit opts in when set and out when clear. Ignored unless this
// session was offered the callback. No reply.
func (c *tcpClient) handleIPv6CallbackOptIn(data *Buffer) {
	if !c.ipv6CallbackOffered() {
		logging.Debugf("tcp ipv6 callback opt-in ignored remote=%s: not offered", c.remoteHost())
		return
	}
	features := IPv6CallbackBit
	if data.Remaining() > 0 {
		features, _ = data.GetUInt8()
	}
	optIn := features&IPv6CallbackBit != 0
	c.infoMu.Lock()
	c.v6CallbackOptIn = optIn
	c.infoMu.Unlock()
	logging.Debugf("tcp ipv6 callback opt-in remote=%s features=0x%02x optIn=%t", c.remoteHost(), features, optIn)
}

// handleIPv6CallbackRequest answers OpIPv6CallbackRequest: <target LowID:4 LE>. A
// payload shorter than that is ignored, as ed2k-server does.
func (c *tcpClient) handleIPv6CallbackRequest(data *Buffer) {
	targetID, err := data.GetUInt32LE()
	if err != nil {
		logging.Debugf("tcp ipv6 callback request ignored remote=%s: payload %d bytes", c.remoteHost(), data.Remaining())
		return
	}
	// The allowance comes first, as in ed2k-server: an over-budget request costs
	// no lookup.
	if !c.relayAllow() {
		c.refuseIPv6Callback(targetID, IPv6CallbackRefusedRateLimited)
		return
	}
	target, reason := c.planIPv6Callback(targetID)
	if reason != 0 {
		c.refuseIPv6Callback(targetID, reason)
		return
	}
	self, targetInfo := c.snapshotInfo(), target.snapshotInfo()
	var hash []byte
	// The trailer only between two obfuscating clients (ed2k-server callback_crypt):
	// a target that cannot obfuscate has no use for the hash.
	if self.CryptOptions&targetInfo.CryptOptions&0x01 != 0 {
		hash = self.Hash
	}
	packet, err := BuildCallbackRequestedIPv6Packet(self.IPv6, self.Port, self.CryptOptions, hash)
	if err == nil {
		err = target.writePacket(packet)
	}
	if err != nil {
		c.refuseIPv6Callback(targetID, IPv6CallbackRefusedTargetUnreachable)
		return
	}
	c.server.blocks.ipv6CallbackForwarded.Add(1)
	c.debugPayloadf("tcp ipv6 callback forwarded remote=%s target=%d ipv6=%s port=%d crypt=%t",
		c.remoteHost(), targetID, net.IP(self.IPv6), self.Port, hash != nil)
}

// ipv6CallbackOffered reports whether this session is offered the IPv6 callback, i.e.
// whether its OP_SERVERIDENT carries TagIPv6Callback. ed2k-server's
// ipv6_callback_offered, without its IPv6-route check: eNode-go has none, so on a
// host that cannot reach IPv6 the dial-backs fail and a request is refused as
// unverified (3) rather than not offered (1).
func (c *tcpClient) ipv6CallbackOffered() bool {
	cfg := c.server.tcp()
	return cfg.IPv6Callback && cfg.PublishV6Sources && cfg.ProbeIPv6 && c.isV6Capable()
}

// ipv6CallbackFeatures is the TagIPv6Callback byte for this session's OP_SERVERIDENT,
// zero to omit the tag.
func (c *tcpClient) ipv6CallbackFeatures() uint8 {
	if c.ipv6CallbackOffered() {
		return IPv6CallbackBit
	}
	return 0
}

// planIPv6Callback picks the target of an OpIPv6CallbackRequest, or the reason not
// to forward it, checking in ed2k-server's order (plan_ipv6_callback).
func (c *tcpClient) planIPv6Callback(targetID uint32) (*tcpClient, uint8) {
	if !c.ipv6CallbackOffered() {
		return nil, IPv6CallbackRefusedNotOffered
	}
	c.infoMu.RLock()
	highID := !c.info.LowID
	// Verified is ST_IPV6_STATUS 0x07: a dial-back of the current address passed.
	// runIPv6Probe applies a verdict only to the address it dialled, so the
	// verdict here is about the address that will be handed out.
	verified := c.ipv6StatusLocked() == IPv6StatusHave|IPv6StatusReachable|IPv6StatusProbed
	selfHash := c.info.Hash
	c.infoMu.RUnlock()
	if highID {
		return nil, IPv6CallbackRefusedRequesterHighID
	}
	if !verified {
		return nil, IPv6CallbackRefusedRequesterNotVerified
	}
	v, ok := c.server.LowIDs.Get(targetID)
	target, isClient := v.(*tcpClient)
	if !ok || !isClient || !target.isLogged() {
		return nil, IPv6CallbackRefusedTargetGone
	}
	if target == c || bytes.Equal(target.snapshotInfo().Hash, selfHash) {
		return nil, IPv6CallbackRefusedSelfTarget
	}
	if !target.ipv6CallbackOptedIn() {
		return nil, IPv6CallbackRefusedTargetNotOptedIn
	}
	return target, 0
}

// ipv6CallbackOptedIn reports whether this session may be named as an
// OpCallbackReqdIPv6 target: it is v6-capable and sent OpIPv6CallbackOptIn. Read
// from the requester's goroutine, hence infoMu.
func (c *tcpClient) ipv6CallbackOptedIn() bool {
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	return c.ipv6Capable && c.v6CallbackOptIn
}

// refuseIPv6Callback counts a refusal and sends the requester the 5-byte
// OP_CALLBACK_FAIL.
func (c *tcpClient) refuseIPv6Callback(targetID uint32, reason uint8) {
	if int(reason) < len(c.server.blocks.ipv6CallbackRefused) {
		c.server.blocks.ipv6CallbackRefused[reason].Add(1)
	}
	c.debugPayloadf("tcp ipv6 callback refused remote=%s target=%d reason=%d", c.remoteHost(), targetID, reason)
	packet, err := BuildIPv6CallbackFailPacket(targetID, reason)
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

// relayAllow takes one request from the session's relay allowance (relayPerSecond,
// up to relayBurst), shared by OP_CALLBACKREQUEST and OpIPv6CallbackRequest as in
// ed2k-server. Both arrive on this connection's goroutine, so the bucket needs no
// lock. It is kept as the amount spent, so a zero session — new, or handed over from
// another process — has the full burst, as ed2k-server starts a new session's. The
// clock is whole seconds since connectedAt in 16 bits: a session idle for a multiple
// of ~18 hours may find a spent allowance refilled a few seconds late, nothing worse.
func (c *tcpClient) relayAllow() bool {
	now := uint16(time.Since(c.connectedAt) / time.Second)
	if c.relaySpent > 0 {
		refill := uint32(now-c.relayAt) * relayPerSecond
		if refill >= uint32(c.relaySpent) {
			c.relaySpent = 0
		} else {
			c.relaySpent -= uint8(refill)
		}
	}
	c.relayAt = now
	if c.relaySpent >= relayBurst {
		return false
	}
	c.relaySpent++
	return true
}
