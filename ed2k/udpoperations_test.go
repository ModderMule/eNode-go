package ed2k

import (
	"fmt"
	"strings"
	"testing"

	"enode/storage"
)

func TestBuildGlobPackets(t *testing.T) {
	hash := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	p, err := BuildGlobFoundSourcesPacket(hash, []storage.Source{{ID: 1, Port: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Bytes()[0] != PrED2K || p.Bytes()[1] != OpGlobFoundSources {
		t.Fatalf("bad packet header")
	}

	packets, err := BuildGlobSearchResPackets([]storage.File{{
		Hash: hash, Name: "x", Size: 1, Type: "Pro", Sources: 1, Completed: 1, SourceID: 1, SourcePort: 2,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 || packets[0].Bytes()[1] != OpGlobSearchRes {
		t.Fatalf("bad glob search res packet")
	}
}

func TestBuildGlobServStatAndDesc(t *testing.T) {
	cfg := UDPConfig{
		Name: "n", Description: "d", DynIP: "dyn", UDPFlags: 1, UDPPortObf: 2, TCPPortObf: 3, UDPServerKey: 4, MaxConnections: 5,
	}
	p, err := BuildGlobServStatResPacket(7, cfg, 10, 20, 30)
	if err != nil {
		t.Fatal(err)
	}
	if p.Bytes()[1] != OpGlobServStatRes {
		t.Fatalf("bad opcode")
	}
	d, err := BuildServerDescResPacket(7, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if d.Bytes()[1] != OpServerDescRes {
		t.Fatalf("bad opcode")
	}
}

// TestServerDescResVersion pins the ST_VERSION (0x91) tag of our OP_SERVER_DESC_RES,
// because a Lugdunum eserver silently refuses to flag us `working` if it parses below
// 17.7 — and a non-working peer is absent from its server.met and from both of its
// peer-list replies, so the whole network behind it stops seeing us. There is no log
// line for the refusal on either side; this test is the only cheap warning.
//
// The gate is the compare at 0x0042f68a in eserver 17.14, reached from the sscanf at
// 0x0042f685, with the minimum minor hard-coded to 7 at 0x00430a72. See
// docs/eserver-working-flag-disassembly.local.md.
func TestServerDescResVersion(t *testing.T) {
	t.Logf("input: GossipVersionStr = %q (compat %q, %s %s)",
		GossipVersionStr, GossipCompatVersion, ENodeName, ENodeVersionStr)

	packet, err := BuildServerDescResPacket(0x11223344, UDPConfig{Name: "n", Description: "d", DynIP: "dyn"})
	if err != nil {
		t.Fatalf("build OP_SERVER_DESC_RES: %v", err)
	}

	// [proto][opcode][challenge:4][tags]
	b := NewBufferFromBytes(packet.Bytes()[2:])
	if _, err := b.GetUInt32LE(); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	tags, err := b.GetTags()
	if err != nil {
		t.Fatalf("read tags: %v", err)
	}

	want := tagName(TagVersion2)
	var value any
	found := false
	for _, tag := range tags {
		t.Logf("output: tag %s = %#v", tag.Name, tag.Value)
		if tag.Name == want {
			value, found = tag.Value, true
		}
	}
	if !found {
		t.Fatalf("no ST_VERSION (0x91) tag in the reply: eserver treats a missing version tag exactly "+
			"like a version below its bar (0x0042f64f), so we would never become `working`. tags=%v", tags)
	}

	// String rather than uint32. Both forms reach the same sscanf in eserver, but the
	// string is what lets eMule display our real identity beside the compat claim.
	advertised, ok := value.(string)
	if !ok {
		t.Fatalf("ST_VERSION is %T, want a string tag: %#v", value, value)
	}

	// eserver's own parse, verbatim: sscanf(version, "%d.%d", &major, &minor). Anything
	// after the minor is ignored by it, which is the whole point of the string form.
	var major, minor int
	if _, err := fmt.Sscanf(advertised, "%d.%d", &major, &minor); err != nil {
		t.Fatalf("ST_VERSION %q does not parse as %%d.%%d, which is how eserver reads it: %v", advertised, err)
	}
	t.Logf("output: advertised %q -> major=%d minor=%d", advertised, major, minor)

	if !(major > 17 || (major == 17 && minor >= 7)) {
		t.Errorf("ST_VERSION %q parses as %d.%d, below eserver's 17.7 bar: it would hold us in memory, "+
			"ping us forever and never name us to a client or a peer", advertised, major, minor)
	}

	// The derivation, not the literal. If GossipVersionStr is ever flattened into a
	// hard-coded string, scripts/publish-release.sh stops bumping it and every release
	// afterwards tells the network the version it shipped the day it was flattened.
	if suffix := " (" + ENodeName + " " + ENodeVersionStr + ")"; !strings.HasSuffix(advertised, suffix) {
		t.Errorf("ST_VERSION %q does not end with %q: it is no longer derived from ENodeVersionStr, "+
			"so a release bump will not reach the wire", advertised, suffix)
	}
}
