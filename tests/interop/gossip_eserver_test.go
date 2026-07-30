package interop

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"enode/ed2k"
)

// Paths inside the containers.
const (
	enodeServerMet   = "/rig/data/server.met"
	eserverServerMet = "/eserver/server.met"
)

// eserverRejections are eserver's own log strings for a refused peer. Each one names a
// specific decision in docs/server-gossip.md that would have failed, so the test reports
// which rather than just "the handshake did not complete":
//
//	portUDPobf      the port we gossip FROM must equal the portUDPOBF we ADVERTISE
//	bad name:desc   our 0xa3 reply failed its name or description sanity check
//	bad challenge   we echoed the wrong challenge back in 0x97
//	unknown server  we sent a list or a desc reply before completing the handshake
//	non obfuscated  we sent a gossip opcode in the clear
//	Deny server     an ipfilter refused us before any of the above
var eserverRejections = []string{
	"continue because portUDPobf",
	"bad name:desc",
	"sent a bad challenge",
	"from unknown server",
	"ignore non obfuscated",
	"Deny server",
}

// TestGossipWithLugdunumEserver is the case the host-based rig could not reach: with both
// servers on one Docker network, eserver can route back to us, so its half of the
// handshake runs and it can admit us to its own peer table.
//
// Both directions are asserted, and from both sides' own records — our peer table and
// server.met, its peer table and server.met — because the two are independent. Ours can
// fill in from a reply we merely decoded; only its records prove it accepted us.
func TestGossipWithLugdunumEserver(t *testing.T) {
	pool := requireInterop(t)
	network := newNetwork(t, pool, false)

	// eserver first, so eNode can be handed a seed address. It starts with no seed of its
	// own: everything it learns about us must come from our registration or from `ask`.
	eserver := startEserver(t, pool, network, eserverOptions{})
	enode := startEnode(t, pool, network, enodeOptions{Name: "enode", SeedIP: eserver.ip, SeedPort: eserverTCPPort})

	// --- direction 1: we verify eserver -------------------------------------------------
	//
	// Reaching "verified" requires all four phases to have completed: the plain bootstrap
	// on P+4, the unencrypted obf-ping on P+12 whose reply carries eserver's ServerKey,
	// the obfuscated registration on its advertised portUDPOBF, and the name:desc probe
	// whose well-formed 0xa3 reply is the admission bar.
	stats := waitForStats(t, enode, 2*time.Minute, "a verified peer", func(s liveStats) bool {
		return s.GossipVerified >= 1
	})
	if stats.Servers < 1 {
		t.Errorf("gossip verified a peer but Servers=%d: the peer is not being advertised to clients", stats.Servers)
	}

	// Persistence runs on its own timer, so this polls rather than reading once: the peer
	// reaches "verified" well before the first write tick.
	ourMet := waitForServerMet(t, enode, enodeServerMet, eserver.ip, eserverTCPPort, 45*time.Second)
	if !containsEntry(ourMet, eserver.ip, eserverTCPPort) {
		t.Errorf("eNode's server.met does not contain %s:%d — persistence did not record the verified peer (got %s)",
			eserver.ip, eserverTCPPort, describeEntries(ourMet))
	}

	// --- direction 2: eserver admits us -------------------------------------------------
	//
	// Our registration should already have prompted eserver to probe back. `ask` forces a
	// round immediately rather than waiting on its own cadence, so a failure here is a
	// protocol failure and not a timing one.
	eserver.console(fmt.Sprintf("ask %s:%d", enode.ip, enodeTCPPort))

	adding := fmt.Sprintf("Adding server %s:%d", enode.ip, enodeTCPPort)
	if !waitFor(t, 90*time.Second, adding, func() bool { return strings.Contains(eserver.logs(), adding) }) {
		t.Errorf("eserver never logged %q — it did not admit us to its peer table", adding)
	}

	logs := eserver.logs()

	// The phase-by-phase trace of eserver probing US. Advisory rather than fatal: these are
	// verbose-mode lines and a future donkey.ini or version could stop emitting one without
	// the protocol having changed. The hard assertions are "Adding server" above and the
	// server.met below.
	for _, phase := range []struct{ what, marker string }{
		{"phase 2 obf-ping sent to us", "Send an OBF ping"},
		// "receive cinfo from %s" prints the peer address with no port, so the bare address
		// is what attributes the line to us.
		{"phase 2 our 0x97 reply parsed", "receive cinfo from " + enode.ip},
		{"phase 4 name:desc probe answered", "servdescreply(" + enode.ip},
	} {
		if strings.Contains(logs, phase.marker) {
			t.Logf("output: eserver %s — found %q", phase.what, phase.marker)
		} else {
			t.Logf("output: NOTE eserver log has no %q (%s); not fatal, the peer-table checks are authoritative",
				phase.marker, phase.what)
		}
	}

	// Its in-memory table, read through the console — the authoritative record of whether
	// eserver accepted us, and the thing that was impossible to reach from the host.
	//
	// Polled rather than sampled once: the console, the UDP workers and our own gossip
	// rounds all run on separate clocks, so the row fills in over several seconds. Matched
	// on the "IP:port {" form rather than the bare address, so it is not confused with the
	// "Adding server <ip>:<port>" line that also names us.
	//
	// Required markers — present on every run, each proving a different phase completed.
	wanted := []struct{ what, marker string }{
		{"our advertised portUDPOBF, from the 0x97 we answered its ping with", fmt.Sprintf("{U%d}", enodeUDPObfPort)},
		{"our advertised portTCPOBF, from the same reply", fmt.Sprintf("{T%d}", enodeTCPObfPort)},
		{"a ServerKey, which only the obf-ping phase can produce", "{K"},
	}
	// Reported, not required. Our name reaches eserver — it appears in the row as
	// `dynip=… version=… enode`, which can only have come from the tags in our 0xa3 — but
	// whether it is still there when the row is sampled is a coin flip: it turns up on
	// roughly one run in three, and every round logs `Updating server … name= desc=` with
	// both fields empty. That is eserver's own bookkeeping, part of the same unreliability
	// as the `working` flag in docs/interop-docker-tests.md §5, so it is logged rather than
	// asserted. Phase 4 itself is covered by the `servdescreply(` check above.
	const nameMarker = "enode"
	// The richest row observed is kept rather than the latest, because eserver takes the
	// name back out again on later rounds. `ask` is issued once, before this loop and never
	// inside it, for the same reason: re-asking drives more of those updates and destroys
	// the evidence.
	var row string
	sawName := false
	best := -1
	waitFor(t, 45*time.Second, "a complete `vs` table row for us", func() bool {
		eserver.console("vs")
		current := lineContaining(eserver.logs(), fmt.Sprintf("%s:%d {", enode.ip, enodeTCPPort))
		if current == "" {
			return false
		}
		found := 0
		for _, w := range wanted {
			if strings.Contains(current, w.marker) {
				found++
			}
		}
		if found > best {
			best, row = found, current
		}
		sawName = sawName || strings.Contains(current, nameMarker)
		return found == len(wanted) && sawName
	})

	if row == "" {
		t.Errorf("eserver `vs` has no table row for %s:%d at all", enode.ip, enodeTCPPort)
	} else {
		t.Logf("output: eserver `vs` row: %s", strings.TrimSpace(row))
		for _, w := range wanted {
			if !strings.Contains(row, w.marker) {
				t.Errorf("eserver `vs` row lacks %s (%q)", w.what, w.marker)
			}
		}
		if sawName {
			t.Logf("output: eserver also showed our name %q, so the tags in our 0xa3 were parsed", nameMarker)
		} else {
			t.Logf("output: eserver never showed our name in the row this run — see the note above; " +
				"phase 4 is covered by the servdescreply( check")
		}
	}

	// eserver's server.met, forced with saveServers rather than waited for — autoservlist
	// writes on a fixed ~225s tick.
	//
	// Reported, not asserted, and the distinction is deliberate. The manual says the file
	// holds "only working known servers", and `working` is an internal flag of a
	// closed-source binary that we have not been able to make it set for us: measured over
	// four minutes, its ping counters for our row freeze after an initial burst and do not
	// move again, with or without a client and a published file on our side. Its live table
	// above is the authoritative evidence that it admitted us; making the run fail on a
	// heuristic we cannot drive would be asserting something we do not understand.
	//
	// Read through our own ReadServerMet, so eserver's own entry in it still validates our
	// parser against the 2007 writer.
	eserver.console("saveServers")
	theirMet := eserver.serverMet(eserverServerMet)
	t.Logf("output: eserver %s -> %s", eserverServerMet, describeEntries(theirMet))
	if containsEntry(theirMet, enode.ip, enodeTCPPort) {
		t.Logf("output: eserver now persists us in its own server.met — the `working` flag it withholds has flipped; this assertion can be made fatal")
	} else {
		t.Logf("output: KNOWN GAP — eserver has us in its live table but not in server.met; it never marks us `working`. See docs/interop-docker-tests.md")
	}

	// --- what a client sees --------------------------------------------------------------
	//
	// The only assertion that covers the actual point of gossip: a peer learned over the
	// wire has to reach real clients through OP_SERVERLIST.
	list := fetchServerList(t, enode.hostIP(), enode.hostPort("5555/tcp"))
	t.Logf("output: OP_SERVERLIST from eNode -> %s", list)
	if !list.has(eserver.ip, eserverTCPPort) {
		t.Errorf("OP_SERVERLIST does not advertise the gossiped peer %s:%d", eserver.ip, eserverTCPPort)
	}

	assertNoRejections(t, eserver, "eserver")
}

// assertNoRejections fails on any of eserver's refusal messages. Absence is meaningful:
// each string corresponds to one decision that has to be right for the handshake to work,
// so a hit points straight at which one is wrong.
func assertNoRejections(t *testing.T, n *node, label string) {
	t.Helper()
	logs := n.logs()
	for _, bad := range eserverRejections {
		if strings.Contains(logs, bad) {
			t.Errorf("%s log contains the refusal %q: %s", label, bad, strings.TrimSpace(lineContaining(logs, bad)))
		}
	}
	t.Logf("output: %s log carries none of the %d refusal messages", label, len(eserverRejections))
}

// waitForServerMet polls until a server.met inside a container holds ip:port, returning
// whatever it last read so a failure can report the actual contents.
func waitForServerMet(t *testing.T, n *node, path, ip string, port uint16, timeout time.Duration) []ed2k.ServerMetEntry {
	t.Helper()
	var entries []ed2k.ServerMetEntry
	waitFor(t, timeout, fmt.Sprintf("%s to contain %s:%d", path, ip, port), func() bool {
		entries = n.serverMet(path)
		return containsEntry(entries, ip, port)
	})
	t.Logf("output: %s %s -> %s", n.label, path, describeEntries(entries))
	return entries
}

// lineContaining returns the first line holding needle, for error messages that should
// quote the evidence rather than just assert on it.
func lineContaining(haystack, needle string) string {
	for _, line := range strings.Split(haystack, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}
