package interop

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"enode/ed2k"
)

// TestGossipBetweenTwoENodes covers what no run against eserver can: our own inbound
// serving side, and the 0xA7/0xA8 IPv6 extension.
//
// eserver 17.14 predates IPv6 entirely, so those two opcodes have never had a counterpart
// to talk to. This is also the only place both halves of the protocol are ours, which
// means a symmetric bug — encoding and decoding a field the same wrong way — would show up
// here as success and against eserver as failure; run both, not one.
func TestGossipBetweenTwoENodes(t *testing.T) {
	pool := requireInterop(t)
	network := newNetwork(t, pool, true) // dual-stack, for 0xA7/0xA8

	// A starts with no seed at all: it must learn B purely from B's inbound registration.
	nodeA := startEnode(t, pool, network, enodeOptions{Name: "enode-a"})
	nodeB := startEnode(t, pool, network, enodeOptions{
		Name: "enode-b", SeedIP: nodeA.ip, SeedPort: enodeTCPPort,
	})
	t.Logf("input: A=%s (v6 %s) unseeded, B=%s (v6 %s) seeded from A",
		nodeA.ip, orNone(nodeA.ip6), nodeB.ip, orNone(nodeB.ip6))

	if nodeA.ip6 == "" || nodeB.ip6 == "" {
		t.Fatalf("dual-stack network produced no IPv6 addresses (A=%q B=%q): the 0xA7/0xA8 case cannot run",
			nodeA.ip6, nodeB.ip6)
	}

	// B verifies A from the seed; A verifies B from B's registration plus its own probe of
	// the sender. The second direction is the interesting one — it is the path a real peer
	// takes when it finds us without being told.
	waitForStats(t, nodeB, 90*time.Second, "a verified peer (from its seed)", func(s liveStats) bool {
		return s.GossipVerified >= 1
	})
	waitForStats(t, nodeA, 90*time.Second, "a verified peer (learned from an inbound registration)",
		func(s liveStats) bool { return s.GossipVerified >= 1 })

	waitForServerMet(t, nodeA, enodeServerMet, nodeB.ip, enodeTCPPort, 45*time.Second)
	waitForServerMet(t, nodeB, enodeServerMet, nodeA.ip, enodeTCPPort, 45*time.Second)

	// The IPv6 extension. Asserted from both ends of one exchange: the request side logs
	// that it answered a 0xA7, the response side that it consumed a 0xA8.
	assertLogEventually(t, nodeA, 60*time.Second,
		"answering an IPv6 peer list request (0xA7)",
		"no peer ever asked A for its IPv6 list: the 0xA7 extension is not being sent")
	assertLogEventually(t, nodeB, 60*time.Second,
		"received an IPv6 peer list (0xA8)",
		"B never consumed a 0xA8 reply: the IPv6 extension completes in one direction only")

	// Restarting B proves the reload path: with gossip.persist on, a restarted server picks
	// its seeds out of data/server.met rather than starting from the configured list.
	t.Logf("input: restarting %s to exercise the server.met reload path", nodeB.label)
	nodeB.restart(t)
	assertLogEventually(t, nodeB, 60*time.Second, "seed(s) from data/server.met",
		"after a restart B did not seed from its persisted server.met")
	waitForStats(t, nodeB, 90*time.Second, "a verified peer after restart", func(s liveStats) bool {
		return s.GossipVerified >= 1
	})
}

// TestGossipPropagatesThroughEserver is the mesh property: a server learns a peer it was
// never told about, from a third party.
//
// enode-b registers with eserver; enode-a is seeded with eserver *only* and must end up
// knowing b. This was a skip until we started advertising a Lugdunum-compatible
// ST_VERSION: eserver builds every peer list — for clients and for servers alike — from
// one function that skips peers it has not flagged `working` (fcn.00430010), and the sole
// writer of that flag is the version gate in its 0xa3 handler. With no qualifying entry it
// sends no datagram at all, so the old run saw silence rather than an empty list.
//
// Both halves therefore have to hold for this to pass: eserver must flag B `working`, and
// it must then serve B to A. The first is checked directly below so a failure says which.
func TestGossipPropagatesThroughEserver(t *testing.T) {
	pool := requireInterop(t)
	network := newNetwork(t, pool, false)

	eserver := startEserver(t, pool, network, eserverOptions{})

	// B first, and given time to complete its handshake, so eserver has something to serve
	// by the time A asks.
	nodeB := startEnode(t, pool, network, enodeOptions{
		Name: "enode-b", SeedIP: eserver.ip, SeedPort: eserverTCPPort,
	})
	waitForStats(t, nodeB, 90*time.Second, "a verified eserver", func(s liveStats) bool {
		return s.GossipVerified >= 1
	})
	eserver.console(fmt.Sprintf("ask %s:%d", nodeB.ip, enodeTCPPort))
	waitFor(t, 60*time.Second, "eserver to hold B in its table", func() bool {
		eserver.console("vs")
		return lineContaining(eserver.logs(), fmt.Sprintf("%s:%d {", nodeB.ip, enodeTCPPort)) != ""
	})

	// Holding B is necessary but not sufficient: a peer eserver has not flagged `working`
	// is in its table, pinged forever, and invisible to its peer-list builder. Its
	// server.met has the same gate, so it is the one artifact that separates "eserver never
	// accepted B" from "eserver accepted B but did not pass it on" — and without this check
	// the failure below could mean either.
	var theirMet []ed2k.ServerMetEntry
	if !waitFor(t, 60*time.Second, "eserver's server.met to contain B", func() bool {
		eserver.console("saveServers " + eserverServerMetName)
		theirMet = eserver.serverMet(eserverServerMet)
		return containsEntry(theirMet, nodeB.ip, enodeTCPPort)
	}) {
		t.Fatalf("eserver holds B in its table but never wrote it to %s (%s): B is not flagged `working`, "+
			"so eserver's peer-list builder skips it and A cannot possibly learn it. The ST_VERSION tag in "+
			"B's 0xa3 must parse as >= 17.7 — see ed2k.GossipVersionStr",
			eserverServerMet, describeEntries(theirMet))
	}
	t.Logf("output: eserver %s -> %s (B is `working`)", eserverServerMet, describeEntries(theirMet))

	// A knows only eserver. Anything it learns about B came through eserver's peer list.
	nodeA := startEnode(t, pool, network, enodeOptions{
		Name: "enode-a", SeedIP: eserver.ip, SeedPort: eserverTCPPort,
	})
	t.Logf("input: A=%s seeded with eserver=%s only; B=%s already registered with eserver",
		nodeA.ip, eserver.ip, nodeB.ip)

	learned := waitFor(t, 2*time.Minute, "A to learn B through eserver", func() bool {
		entries := nodeA.serverMet(enodeServerMet)
		return containsEntry(entries, nodeB.ip, enodeTCPPort)
	})
	stats, _ := nodeA.stats()
	t.Logf("output: A %s, server.met -> %s", stats, describeEntries(nodeA.serverMet(enodeServerMet)))

	if learned {
		return
	}

	// It did not propagate. Which of two very different things happened is decided here
	// rather than left to the reader: eserver declining to name its peers is its behaviour to
	// have, but us discarding peers it did name would be a defect on this side.
	//
	// Asking is ours to get right, so not asking is always our failure.
	if !strings.Contains(nodeA.logs(), "sent phase3 0xA4") {
		t.Fatalf("A never sent a 0xA4 list request, so nothing was ever asked for")
	}

	// "dir=recv" as well as the opcode: A also *sends* 0xA1 whenever eserver asks it for a
	// list, and matching on the opcode alone counts our own answers as replies to ourselves.
	// A 0xA1 payload is <count:1> then 6 bytes per entry, so payloadLen=1 is an empty list.
	replies := allLinesMatching(nodeA.logs(), "dir=recv", "opcode=0xa1")
	for _, line := range replies {
		if !strings.Contains(line, "payloadLen=1") {
			t.Errorf("eserver sent a non-empty peer list and A still did not learn %s:%d — the entries "+
				"were dropped by our merge policy, which is a defect here: %s",
				nodeB.ip, enodeTCPPort, strings.TrimSpace(line))
			return
		}
	}

	// Every 0xA1 we received was empty, and B is `working` — checked above — so eserver had
	// something to say and did not say it. That is a change in the reference server's
	// behaviour, or in the request we send it, and either way it is a real failure now.
	t.Fatalf("A never learned B through eserver: it sent 0xA4 list requests and got %d non-empty "+
		"replies, while eserver's table and server.met both hold %s and %s.\n\n"+
		"eserver serves both OP_SERVERLIST and OP_SERVER_LIST_RES from one builder that skips "+
		"peers it has not flagged `working`, and B clears that gate, so an empty list means the "+
		"request itself was refused rather than the peer being withheld. Check the refusal strings "+
		"in the trace below — `ignore non obfuscated OP_SERVER_LIST_REQ` and `from unknown server` "+
		"are the two that produce exactly this.\nSee docs/interop-docker-tests.md.\n\n"+
		"eserver gossip lines:\n%s",
		len(replies), nodeA.ip, nodeB.ip, gossipLines(eserver.logs()))
}

// allLinesMatching returns every line holding all of the needles.
func allLinesMatching(haystack string, needles ...string) []string {
	var out []string
	for _, line := range strings.Split(haystack, "\n") {
		matched := true
		for _, n := range needles {
			if !strings.Contains(line, n) {
				matched = false
				break
			}
		}
		if matched {
			out = append(out, line)
		}
	}
	return out
}

// TestAccessFilterDropsEserverBeforeParsing covers the ipfilter layer end to end, on a live
// socket rather than a unit-test stub: a blocked address must be refused before any wire
// parsing, so nothing it sends can advance any state.
func TestAccessFilterDropsEserverBeforeParsing(t *testing.T) {
	pool := requireInterop(t)
	network := newNetwork(t, pool, false)

	eserver := startEserver(t, pool, network, eserverOptions{})

	// Level 0 with the default minLevel of 100, so the range blocks. eNode still seeds from
	// eserver, so our outbound frames go out normally and eserver answers — every one of
	// those replies has to die at the first statement of the UDP handler.
	filter := fmt.Sprintf("%s - %s , 000 , interop: block the reference server", eserver.ip, eserver.ip)
	enode := startEnode(t, pool, network, enodeOptions{
		Name: "enode", SeedIP: eserver.ip, SeedPort: eserverTCPPort, IPFilter: filter,
	})
	t.Logf("input: ipfilter.dat line %q", filter)

	// Long enough for several gossip rounds at the 10s interval, so "nothing verified" means
	// the filter held rather than the handshake being slow.
	time.Sleep(35 * time.Second)

	stats, err := enode.stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	t.Logf("output: %s", stats)

	if stats.FilterBlockedIP == 0 {
		t.Errorf("filterBlockedIP is 0: eserver's replies were never dropped, so the filter is not on the datagram path")
	}
	if stats.GossipVerified != 0 {
		t.Errorf("gossipVerified=%d with the peer's address blocked: a filtered peer must never reach a verified state",
			stats.GossipVerified)
	}
	if _, ok := enode.readFile(enodeServerMet); ok {
		t.Errorf("%s was written even though no peer could be verified", enodeServerMet)
	}

	// And the far side. eserver *does* still list us — our own outbound registration reaches
	// it, and outbound traffic is not filtered, since we chose to initiate it. What it must
	// never get is a *reply*: every probe it sends us is dropped at the first statement of
	// the UDP handler, so the two lines it logs on parsing an answer cannot appear.
	logs := eserver.logs()
	for _, reply := range []struct{ what, marker string }{
		{"our 0x97 stat reply", "receive cinfo from " + enode.ip},
		{"our 0xa3 name:desc reply", "servdescreply(" + enode.ip},
	} {
		if strings.Contains(logs, reply.marker) {
			t.Errorf("eserver parsed %s (%q) even though its address is filtered: its probe was answered",
				reply.what, reply.marker)
		}
	}
	t.Logf("output: eserver received no reply of any kind from us, as required")
}

// assertLogEventually polls a container's log for a marker, failing with the supplied
// explanation. Polled rather than read once because the logs are produced by background
// rounds on their own timers.
func assertLogEventually(t *testing.T, n *node, timeout time.Duration, marker, explain string) {
	t.Helper()
	if waitFor(t, timeout, marker, func() bool { return strings.Contains(n.logs(), marker) }) {
		t.Logf("output: %s logged %q", n.label, marker)
		return
	}
	t.Errorf("%s: %s (never logged %q)", n.label, explain, marker)
}

// gossipLines extracts the reference server's gossip trace for a failure message.
func gossipLines(logs string) string {
	var out []string
	for _, line := range strings.Split(logs, "\n") {
		for _, n := range []string{"server", "ping", "cinfo", "servgot", "Adding", "Updating"} {
			if strings.Contains(line, n) && !strings.HasPrefix(strings.TrimSpace(line), "scan_line") {
				out = append(out, strings.TrimSpace(line))
				break
			}
		}
	}
	return strings.Join(out, "\n")
}
