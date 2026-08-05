package ed2k

import (
	"encoding/binary"
	"strings"
	"testing"
)

// TestBuildServerMessagePacketEmitsCRLF pins the wire form of a multi-line
// OP_SERVERMESSAGE: one packet, CRLF between lines.
//
// The payload is read back rather than trusting the input, because the point is what a
// client receives. Messages are kept under minZlibPayloadOnSend so MaybeCompressTCPPacket
// leaves the payload readable in place.
func TestBuildServerMessagePacketEmitsCRLF(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare LF, the form the config layer hands us", "one\ntwo\nthree", "one\r\ntwo\r\nthree"},
		{"already CRLF, must not double", "one\r\ntwo", "one\r\ntwo"},
		{"lone CR, classic-Mac style", "one\rtwo", "one\r\ntwo"},
		{"mixed CRLF and LF", "one\r\ntwo\nthree", "one\r\ntwo\r\nthree"},
		{"single line is untouched", "Welcome to eNode!", "Welcome to eNode!"},
		{"empty stays empty", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("input: %q", tc.in)

			packet, err := BuildServerMessagePacket(tc.in)
			if err != nil {
				t.Fatalf("BuildServerMessagePacket(%q): %v", tc.in, err)
			}
			got := decodeServerMessagePayload(t, packet.Bytes())

			t.Logf("output: %q (%d bytes on the wire)", got, len(packet.Bytes()))
			if got != tc.want {
				t.Errorf("wire text is %q, want %q", got, tc.want)
			}
		})
	}
}

// TestServerMessageCRLFSurvivesBothSplitStrategies is the reason CRLF is emitted at all.
//
// eMule splits on a *set* of delimiter characters — the MFC client via
// CString::Tokenize(_T("\r\n")) (srchybrid/ServerSocket.cpp:172), the Qt client by
// folding CR into LF first — so bare LF would already work for both. A third-party
// client that splits on the literal two-character sequence "\r\n" would not: it would
// see one line where we meant several. CRLF is the only encoding both strategies agree
// on, so assert both here.
func TestServerMessageCRLFSurvivesBothSplitStrategies(t *testing.T) {
	const in = "Welcome to eNode!\nAn experimental ed2k server written in Go."
	want := []string{"Welcome to eNode!", "An experimental ed2k server written in Go."}
	t.Logf("input: %q", in)

	packet, err := BuildServerMessagePacket(in)
	if err != nil {
		t.Fatalf("BuildServerMessagePacket: %v", err)
	}
	text := decodeServerMessagePayload(t, packet.Bytes())

	// How eMule reads it: any CR or LF ends a line, runs of them collapse.
	charSet := nonEmptyLines(strings.FieldsFunc(text, func(r rune) bool { return r == '\r' || r == '\n' }))
	// How a naive client reads it: the literal two-character sequence, nothing else.
	literal := nonEmptyLines(strings.Split(text, "\r\n"))

	t.Logf("output: character-set split -> %q", charSet)
	t.Logf("output: literal \"\\r\\n\" split -> %q", literal)

	if !equalLines(charSet, want) {
		t.Errorf("character-set split gave %q, want %q", charSet, want)
	}
	if !equalLines(literal, want) {
		t.Errorf("literal \"\\r\\n\" split gave %q, want %q — a client that splits this way "+
			"would show the whole greeting as one line", literal, want)
	}
}

// decodeServerMessagePayload pulls the text back out of a built packet:
// protocol(1) + size(4) + opcode(1) + length(2 LE) + text.
func decodeServerMessagePayload(t *testing.T, frame []byte) string {
	t.Helper()
	if len(frame) < 8 {
		t.Fatalf("frame is %d bytes, too short for OP_SERVERMESSAGE", len(frame))
	}
	if frame[0] != PrED2K {
		t.Fatalf("protocol byte is 0x%02x, want 0x%02x — the payload was compressed and "+
			"cannot be read in place; shorten the test message", frame[0], PrED2K)
	}
	if frame[5] != OpServerMessage {
		t.Fatalf("opcode is 0x%02x, want OP_SERVERMESSAGE 0x%02x", frame[5], OpServerMessage)
	}
	n := int(binary.LittleEndian.Uint16(frame[6:8]))
	if 8+n > len(frame) {
		t.Fatalf("declared text length %d overruns the %d-byte frame", n, len(frame))
	}
	return string(frame[8 : 8+n])
}

func nonEmptyLines(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func equalLines(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
