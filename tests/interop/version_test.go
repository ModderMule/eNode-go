package interop

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"enode/ed2k"
)

// serverVersionPrefix is the 14-character literal both eMule trees look for at the start of
// an OP_SERVERMESSAGE before treating the rest of the line as a version
// (srchybrid/ServerSocket.cpp:176-183, src/core/server/ServerConnect.cpp:1150-1156).
const serverVersionPrefix = "server version"

// TestVersionSurfaces pins the four places ST_VERSION (0x91) can reach a client. We say two
// different things across them on purpose — the compatibility claim eserver's `working`
// gate parses over UDP, our own identity over TCP — and neither string is free to move:
//
//	OP_SERVERIDENT 0x41         no version tag at all
//	UDP 0xa3, challenge form    ed2k.GossipVersionStr, "17.14 (eNode-go v0.1.0)"
//	UDP 0xa3, legacy form       no tags, so no version either
//	TCP OP_SERVERMESSAGE 0x38   "server version v0.1.0 (eNode-go)"
//
// The load-bearing assertion is the last one, and it is a guard rather than a description.
// The tempting harmonisation — putting the compatibility claim in the login line too — is a
// regression: srchybrid tries _stscanf("%u.%u") on the text after the prefix and, when that
// *succeeds*, reformats the whole value to a bare "17.14" (ServerSocket.cpp:180-181),
// dropping our name and leaving us indistinguishable from a real eserver. Our leading "v"
// is what makes the scanf fail and the name survive. See §3.5a of
// docs/ed2k-server-rust-comparison.local.md.
//
// Unlike every other case in this package this one needs no reference binary — one eNode
// container, no eserver — so it runs on a fresh clone with nothing but Docker.
func TestVersionSurfaces(t *testing.T) {
	pool := requireInterop(t)
	network := newNetwork(t, pool, false)
	enode := startEnode(t, pool, network, enodeOptions{Name: "enode"})

	// --- surface 1: the TCP login line ---------------------------------------------------
	frames := fetchLoginFrames(t, enode.hostIP(), enode.hostPort("5555/tcp"))

	wantLine := fmt.Sprintf("%s %s (%s)", serverVersionPrefix, ed2k.ENodeVersionStr, ed2k.ENodeName)
	var versionLine string
	for _, m := range frames.Messages {
		if strings.HasPrefix(m, serverVersionPrefix) {
			versionLine = m
			break
		}
	}
	switch {
	case versionLine == "":
		t.Errorf("no OP_SERVERMESSAGE begins with %q; a client that connects would show no version at all (got %q)",
			serverVersionPrefix, frames.Messages)
	case versionLine != wantLine:
		t.Errorf("login line is %q, want %q (built from ed2k.ENodeVersionStr and ed2k.ENodeName)",
			versionLine, wantLine)
	default:
		t.Logf("output: surface 1, TCP OP_SERVERMESSAGE -> %q", versionLine)
	}

	// The guard. Checked independently of the equality above, so it still fires if someone
	// changes the expected string here to match a changed server.
	if versionLine != "" {
		rest := strings.TrimSpace(strings.TrimPrefix(versionLine, serverVersionPrefix))
		if scanfTwoUints(rest) {
			t.Errorf("the login line's version part %q parses as _stscanf(\"%%u.%%u\"), so srchybrid "+
				"reformats it to a bare \"%%u.%%02u\" (ServerSocket.cpp:180-181) and our identity is "+
				"discarded — the client then shows a plain eserver version. Keep a non-numeric lead, "+
				"e.g. %q, or move the identity to the front", rest, ed2k.ENodeVersionStr)
		} else {
			t.Logf("output: surface 1 guard, %q does not parse as \"%%u.%%u\", so both trees display it verbatim", rest)
		}
	}

	// --- surface 2: OP_SERVERIDENT carries no version tag ---------------------------------
	//
	// hash(16) + ip(4) + port(2) then the tag block. eMule ignores a version tag here (§3.5
	// of the comparison doc), which is why we do not send one; asserting its absence keeps
	// the doc's table honest if the builder ever grows one.
	if len(frames.Ident) < 22 {
		t.Fatalf("OP_SERVERIDENT payload is %d bytes, too short for hash+ip+port", len(frames.Ident))
	}
	identTags := decodeTagBlock(t, "OP_SERVERIDENT", frames.Ident[22:])
	if v, ok := stringTag(identTags, ed2k.TagVersion2); ok {
		t.Errorf("OP_SERVERIDENT now carries ST_VERSION %q; it did not before, and eMule ignores it there, "+
			"so this is a claim nothing reads", v)
	} else {
		t.Logf("output: surface 2, OP_SERVERIDENT has no ST_VERSION among its %d tag(s)", len(identTags))
	}

	// --- surface 3: the challenge-form 0xa3 -----------------------------------------------
	//
	// The request is OP_SERVER_DESC_REQ (0xa2); 0xa3 is the reply. A payload of 6 bytes or
	// more takes the challenge branch (ed2k/server_runtime.go:369-373).
	udpAddr := net.JoinHostPort(enode.hostIP(), enode.hostPort("5559/udp"))
	const challenge uint32 = 0x0BADC0DE
	req := []byte{ed2k.PrED2K, ed2k.OpServerDescReq}
	req = binary.LittleEndian.AppendUint32(req, challenge)
	body := expectDescRes(t, "challenge-form 0xa3", probeServerDesc(t, udpAddr, req, "challenge-form OP_SERVER_DESC_REQ"))

	if len(body) < 4 {
		t.Fatalf("challenge-form reply is %d bytes after the opcode, too short for the echoed challenge", len(body))
	}
	if got := binary.LittleEndian.Uint32(body[:4]); got != challenge {
		t.Errorf("challenge-form reply echoes 0x%08x, want 0x%08x", got, challenge)
	}
	descTags := decodeTagBlock(t, "challenge-form 0xa3", body[4:])
	version, ok := stringTag(descTags, ed2k.TagVersion2)
	switch {
	case !ok:
		t.Errorf("the challenge-form 0xa3 carries no ST_VERSION tag. eserver's `working` gate is the sole "+
			"reader of it and admits a peer only at 17.7 or above, so without it we are invisible to its "+
			"clients and to its peers (got %d tag(s))", len(descTags))
	case version != ed2k.GossipVersionStr:
		t.Errorf("ST_VERSION is %q, want ed2k.GossipVersionStr %q", version, ed2k.GossipVersionStr)
	default:
		t.Logf("output: surface 3, challenge-form 0xa3 ST_VERSION -> %q", version)
	}
	if name, ok := stringTag(descTags, ed2k.TagName); ok {
		t.Logf("output: the same reply names us %q", name)
	}

	// --- surface 4: the legacy 0xa3 has no version at all ----------------------------------
	//
	// Under 6 bytes the dispatcher answers with the pre-tag format: name and description,
	// nothing else. A client that asks this way learns no version from us, which is a
	// documented gap rather than a defect — the old request has no room for a challenge and
	// the old reply has no room for tags.
	legacy := expectDescRes(t, "legacy 0xa3",
		probeServerDesc(t, udpAddr, []byte{ed2k.PrED2K, ed2k.OpServerDescReq}, "legacy OP_SERVER_DESC_REQ"))

	name, rest := takeString(t, "legacy 0xa3 name", legacy)
	desc, rest := takeString(t, "legacy 0xa3 description", rest)
	if len(rest) != 0 {
		t.Errorf("legacy 0xa3 has %d byte(s) after name and description (% x); the old format carries no "+
			"tag block, so anything here is unreadable to the clients that ask this way", len(rest), rest)
	}
	t.Logf("output: surface 4, legacy 0xa3 -> name=%q desc=%q, no tags and therefore no version", name, desc)
}

// ---------------------------------------------------------------------------
// private helpers
// ---------------------------------------------------------------------------

// wireTag is one decoded eD2K tag. Hand-rolled for the reason at the top of client_test.go:
// decoding with the encoder under test would let a framing mistake cancel itself out.
type wireTag struct {
	Type uint8
	Code uint8
	Str  string
}

// decodeTagBlock reads <count:4 LE> followed by count tags, each
// <type:1><namelen:2 LE = 1><code:1><value> (ed2k/buffer.go:294-311,359-368).
func decodeTagBlock(t *testing.T, label string, b []byte) []wireTag {
	t.Helper()
	if len(b) < 4 {
		t.Fatalf("%s: %d bytes is too short for a tag count", label, len(b))
	}
	count := int(binary.LittleEndian.Uint32(b[:4]))
	off := 4
	tags := make([]wireTag, 0, count)
	for i := 0; i < count; i++ {
		if off+4 > len(b) {
			t.Fatalf("%s: truncated in the header of tag %d of %d", label, i, count)
		}
		tag := wireTag{Type: b[off], Code: b[off+3]}
		if nameLen := binary.LittleEndian.Uint16(b[off+1 : off+3]); nameLen != 1 {
			t.Fatalf("%s: tag %d declares a %d-byte name, but the server emits single-byte tag codes only",
				label, i, nameLen)
		}
		off += 4

		width := 0
		switch tag.Type {
		case ed2k.TypeString:
			var s string
			s, width = readString(t, label, b, off)
			tag.Str = s
		case ed2k.TypeHash:
			width = 16
		case ed2k.TypeUint32:
			width = 4
		case ed2k.TypeUint16:
			width = 2
		case ed2k.TypeUint8:
			width = 1
		default:
			t.Fatalf("%s: tag %d has unknown type 0x%02x, so the rest of the block cannot be skipped",
				label, i, tag.Type)
		}
		if off+width > len(b) {
			t.Fatalf("%s: tag %d of %d runs %d byte(s) past the end", label, i, count, off+width-len(b))
		}
		off += width
		tags = append(tags, tag)
	}
	if off != len(b) {
		t.Logf("note: %s has %d trailing byte(s) after its %d tag(s)", label, len(b)-off, count)
	}
	return tags
}

// stringTag returns the value of the first string tag with the given code.
func stringTag(tags []wireTag, code uint8) (string, bool) {
	for _, tag := range tags {
		if tag.Code == code && tag.Type == ed2k.TypeString {
			return tag.Str, true
		}
	}
	return "", false
}

// readString decodes <len:2 LE><bytes> at off, returning the text and the bytes consumed.
func readString(t *testing.T, label string, b []byte, off int) (string, int) {
	t.Helper()
	if off+2 > len(b) {
		t.Fatalf("%s: no room for a string length at offset %d of %d", label, off, len(b))
	}
	n := int(binary.LittleEndian.Uint16(b[off : off+2]))
	if off+2+n > len(b) {
		t.Fatalf("%s: string at offset %d declares %d bytes but only %d remain", label, off, n, len(b)-off-2)
	}
	return string(b[off+2 : off+2+n]), 2 + n
}

// takeString decodes a leading <len:2 LE><bytes> and returns the remainder, for the tagless
// legacy reply where the fields are positional.
func takeString(t *testing.T, label string, b []byte) (string, []byte) {
	t.Helper()
	s, width := readString(t, label, b, 0)
	return s, b[width:]
}

// expectDescRes checks the protocol byte and opcode of a desc reply and returns everything
// after them.
func expectDescRes(t *testing.T, what string, reply []byte) []byte {
	t.Helper()
	if len(reply) < 2 {
		t.Fatalf("%s: reply is %d byte(s), too short for a protocol byte and an opcode", what, len(reply))
	}
	if reply[0] != ed2k.PrED2K {
		t.Fatalf("%s: reply starts with 0x%02x, not PR_ED2K — the probe was answered obfuscated, which a "+
			"plain request should never be", what, reply[0])
	}
	if reply[1] != ed2k.OpServerDescRes {
		t.Fatalf("%s: reply carries opcode 0x%02x, want OP_SERVER_DESC_RES 0x%02x", what, reply[1], ed2k.OpServerDescRes)
	}
	return reply[2:]
}

// probeServerDesc sends one datagram to the published UDP port and returns the reply.
//
// Three attempts because this is the only probe in the package that depends on UDP
// traversing a Docker port mapping rather than a container-to-container hop; a lost
// datagram is a rig symptom, not a protocol one, and the failure says so.
func probeServerDesc(t *testing.T, addr string, payload []byte, what string) []byte {
	t.Helper()
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		conn, err := net.Dial("udp", addr)
		if err != nil {
			t.Fatalf("dial udp %s: %v", addr, err)
		}
		t.Logf("input: %s -> %s (% x)", what, addr, payload)
		if _, err := conn.Write(payload); err != nil {
			lastErr = err
			_ = conn.Close()
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		_ = conn.Close()
		if err != nil {
			lastErr = err
			t.Logf("output: attempt %d of 3 saw no datagram come back: %v", attempt, err)
			continue
		}
		t.Logf("output: %s <- %d bytes (% x)", what, n, buf[:n])
		return buf[:n]
	}
	t.Fatalf("%s: nothing came back from %s in 3 attempts (last error: %v). No datagram arrived at all, so "+
		"check that 5559/udp is published and that UDP survives the Docker port mapping before suspecting "+
		"the request payload", what, addr, lastErr)
	return nil
}

// scanfTwoUints reports whether C's _stscanf(s, "%u.%u", …) would return 2 — the condition
// under which srchybrid discards everything but the two numbers (ServerSocket.cpp:180-181).
// Digits, a dot, digits, with %u's leading-whitespace skip; a sign would also be accepted by
// C but we would never emit one.
func scanfTwoUints(s string) bool {
	digits := func(in string, from int) int {
		i := from
		for i < len(in) && in[i] >= '0' && in[i] <= '9' {
			i++
		}
		return i
	}
	s = strings.TrimLeft(s, " \t\r\n")
	i := digits(s, 0)
	if i == 0 || i >= len(s) || s[i] != '.' {
		return false
	}
	j := i + 1
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	return digits(s, j) > j
}
