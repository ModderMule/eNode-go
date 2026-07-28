package ed2k

import (
	"bytes"
	"encoding/binary"
	"testing"

	"enode/storage"
)

// payloadOfOpcode walks a captured stream of framed packets and returns the
// payload of the first one carrying the wanted opcode. A login writes several
// packets back to back — server messages, status, OP_IDCHANGE, OP_SERVERIDENT —
// so the single-packet tcpFoundSourcesPayload cannot be reused here. Framing is
// the same: protocol(1) + size(4 LE) + opcode(1) + payload.
func payloadOfOpcode(t *testing.T, raw []byte, opcode byte) []byte {
	t.Helper()
	for off := 0; off+6 <= len(raw); {
		size := int(binary.LittleEndian.Uint32(raw[off+1 : off+5]))
		if size < 1 || off+5+size > len(raw) {
			t.Fatalf("malformed frame at offset %d: size=%d, %d bytes remain", off, size, len(raw)-off-5)
		}
		if raw[off] == PrED2K && raw[off+5] == opcode {
			return raw[off+6 : off+5+size]
		}
		off += 5 + size
	}
	t.Fatalf("no packet with opcode 0x%02x in the %d bytes written", opcode, len(raw))
	return nil
}

// loginWithProbe runs one login from remote, with the IPv4 dial-back stubbed to
// report reachable/firewalled, and returns the session, the bytes it wrote and
// how many times the dial-back was consulted.
func loginWithProbe(t *testing.T, remote string, reachable bool) (*tcpClient, []byte, int) {
	t.Helper()
	rt := newLoginTestRuntime(storage.NewMemoryEngine())
	probes := 0
	// The real probe dials the peer, so the HighID branch is unreachable in a test
	// otherwise: no .0 address can be made dialable portably. Stubbing it is what
	// lets the .0 case be tested with the probe *succeeding*, which is the only
	// state in which the bug this guards against was visible.
	rt.firewallProbe = func(*tcpClient) bool {
		probes++
		return !reachable
	}
	client, conn := newReflectClient(t, rt, remote)
	client.handlePacket(loginPacket(t, bytes.Repeat([]byte{0x5a}, 16), 0, 4662))
	return client, conn.written(), probes
}

// TestLoginForcesLowIDForUnrepresentableIPv4 pins the rule the reference client
// depends on: an ed2k HighID *is* the packed IPv4 (first octet in the low byte),
// so an address ending in .0 packs to a value <= 0x00ffffff, which every client
// reads back as a LowID. eMule dropped its own .0 handling on the grounds that
// "the servers just give *.*.*.0 users a lowID" (srchybrid/otherfunctions.h:448).
//
// Handing such a client its packed IPv4 as a HighID splits the two sides: the
// server publishes it as directly reachable and never registers it in the LowID
// pool, while the client and every peer that receives it as a source treat it as
// a LowID and send a callback the server cannot route — leaving the source
// reachable by nobody.
func TestLoginForcesLowIDForUnrepresentableIPv4(t *testing.T) {
	cases := []struct {
		name       string
		remote     string
		reachable  bool // what the stubbed IPv4 dial-back reports
		wantLowID  bool
		wantProbes int
	}{
		{
			name:       "ordinary reachable address keeps its HighID",
			remote:     "203.0.113.5",
			reachable:  true,
			wantLowID:  false,
			wantProbes: 1,
		},
		{
			name:       "ordinary firewalled address gets a LowID",
			remote:     "203.0.113.5",
			reachable:  false,
			wantLowID:  true,
			wantProbes: 1,
		},
		{
			// The regression guard: reachable, so nothing but the address itself
			// can force the LowID.
			name:       "reachable .0 address cannot be a HighID",
			remote:     "203.0.113.0",
			reachable:  true,
			wantLowID:  true,
			wantProbes: 0,
		},
		{
			name:       "firewalled .0 address gets a LowID without a dial-back",
			remote:     "203.0.113.0",
			reachable:  false,
			wantLowID:  true,
			wantProbes: 0,
		},
		{
			name:       "v6-only session has no IPv4 to pack at all",
			remote:     "2001:db8::1",
			reachable:  true,
			wantLowID:  true,
			wantProbes: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, _, probes := loginWithProbe(t, tc.remote, tc.reachable)
			info := client.snapshotInfo()
			t.Logf("input: peer=%s packedIPv4=0x%08x dialBackSaysReachable=%t",
				tc.remote, info.IPv4, tc.reachable)
			t.Logf("output: logged=%t assignedID=0x%08x lowID=%t dialBackCalls=%d",
				client.isLogged(), info.ID, info.LowID, probes)

			if !client.isLogged() {
				t.Fatalf("login was rejected: %q", client.getCloseReason())
			}
			if info.LowID != tc.wantLowID {
				t.Fatalf("lowID = %t, want %t", info.LowID, tc.wantLowID)
			}
			if probes != tc.wantProbes {
				t.Fatalf("IPv4 dial-back called %d time(s), want %d", probes, tc.wantProbes)
			}

			// The invariant that ties the server's view to the client's: an ID the
			// server calls a HighID must be one the client reads as a HighID too.
			if !info.LowID && !HasHighID(info.ID) {
				t.Fatalf("assigned HighID 0x%08x is in the LowID range — the client will disagree", info.ID)
			}

			if tc.wantLowID {
				if _, ok := client.server.LowIDs.Get(info.ID); !ok {
					t.Fatalf("LowID 0x%08x was not registered in the pool, so no callback for it can be routed", info.ID)
				}
				return
			}
			if info.ID != info.IPv4 {
				t.Fatalf("HighID = 0x%08x, want the packed IPv4 0x%08x", info.ID, info.IPv4)
			}
		})
	}
}

// TestLoginIDChangeMatchesTheIDDecision checks the packet the .0 client actually
// receives. eMule zeroes a reported IP that looks like a LowID and ASSERTs on it,
// then asserts the reported IP equals the ID unless the ID is a LowID
// (srchybrid/ServerSocket.cpp:308-314) — both hold only because the ID decision
// and the reflected address now use the same predicate.
func TestLoginIDChangeMatchesTheIDDecision(t *testing.T) {
	client, written, probes := loginWithProbe(t, "203.0.113.0", true)
	info := client.snapshotInfo()
	payload := payloadOfOpcode(t, written, OpIDChange)
	t.Logf("input: peer=203.0.113.0 packedIPv4=0x%08x dialBackSaysReachable=true dialBackCalls=%d",
		info.IPv4, probes)
	t.Logf("output: OP_IDCHANGE payload=% x", payload)

	if len(payload) != 16 {
		t.Fatalf("payload = %d bytes, want 16", len(payload))
	}
	if got := binary.LittleEndian.Uint32(payload[0:4]); got != info.ID {
		t.Fatalf("clientID = 0x%08x, want the assigned LowID 0x%08x", got, info.ID)
	}
	if got := binary.LittleEndian.Uint32(payload[12:16]); got != 0 {
		t.Fatalf("observed IPv4 = 0x%08x, want 0 — eMule ASSERTs on a reported IP in the LowID range", got)
	}
	t.Logf("output: clientID=0x%08x observedIPv4=0 (no encoding exists for a .0 address here)", info.ID)
}
