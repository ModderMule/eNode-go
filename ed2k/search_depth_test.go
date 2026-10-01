package ed2k

import (
	"errors"
	"strings"
	"testing"

	"enode/storage"
)

// searchLeaf is a minimal well-formed text term: token 0x01, 2-byte length, "a".
var searchLeaf = []byte{0x01, 0x01, 0x00, 'a'}

// nestedAndExpr builds a well-formed tree nested `levels` deep along its left
// spine. A boolean node is `0x00 <op> <left> <right>` and takes *two* children,
// so each level needs its own right-hand leaf — a bare chain of 0x00 tokens
// would simply run out of bytes and fail on bounds rather than on depth.
func nestedAndExpr(levels int) []byte {
	out := make([]byte, 0, levels*6+len(searchLeaf))
	for i := 0; i < levels; i++ {
		out = append(out, 0x00, 0x00)
	}
	out = append(out, searchLeaf...)
	for i := 0; i < levels; i++ {
		out = append(out, searchLeaf...)
	}
	return out
}

// A 2-byte token that recurses twice with no depth counter lets a peer drive
// the parser past Go's 1 GB stack ceiling. That is a runtime throw rather than
// a panic, so it kills the process outright and no recover() could catch it.
// Reachable pre-login, and over UDP with no handshake at all.
func TestParseSearchExprRejectsDeepNesting(t *testing.T) {
	const levels = 100000
	payload := nestedAndExpr(levels)
	t.Logf("input: %d nested boolean levels in %d bytes", levels, len(payload))

	expr, err := ParseSearchExpr(NewBufferFromBytes(payload))
	t.Logf("output: expr=%v err=%v", expr != nil, err)

	if err == nil {
		t.Fatal("a 100000-level expression parsed successfully")
	}
	if !strings.Contains(err.Error(), "nested deeper") {
		t.Fatalf("expected a depth error, got %v", err)
	}
}

// The limit must not clip expressions eMule legitimately builds — it uses the
// same ceiling when generating them, so anything under it has to keep working.
func TestParseSearchExprDepthBoundary(t *testing.T) {
	cases := []struct {
		name      string
		levels    int
		wantError bool
	}{
		{"one below the limit", MaxSearchExprDepth - 1, false},
		{"at the limit", MaxSearchExprDepth, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := nestedAndExpr(tc.levels)
			expr, err := ParseSearchExpr(NewBufferFromBytes(payload))
			t.Logf("input: %d nested levels -> output: expr=%v err=%v", tc.levels, expr != nil, err)

			if tc.wantError {
				if err == nil {
					t.Fatalf("%d levels was accepted, want rejected", tc.levels)
				}
				return
			}
			if err != nil {
				t.Fatalf("%d levels was rejected: %v — this would break real clients", tc.levels, err)
			}
			if expr == nil {
				t.Fatal("no expression returned")
			}
		})
	}
}

// A flat, unnested query is the common case and must be unaffected.
func TestParseSearchExprSimpleQueryUnaffected(t *testing.T) {
	payload := []byte{0x01, 0x04, 0x00, 'f', 'o', 'o', 'd'}
	expr, err := ParseSearchExpr(NewBufferFromBytes(payload))
	if err != nil {
		t.Fatalf("a plain text search was rejected: %v", err)
	}
	t.Logf("input: plain text search -> output: kind=%d text=%q", expr.Kind, expr.Text)
	if expr.Text != "food" {
		t.Fatalf("got text %q, want %q", expr.Text, "food")
	}
}

// balancedOrExpr builds a balanced OR tree of n text leaves. Balanced, so its depth
// stays near log2(n) and only the width limit can reject it.
func balancedOrExpr(n int) []byte {
	if n == 1 {
		return append([]byte(nil), searchLeaf...)
	}
	out := []byte{0x00, 0x01}
	out = append(out, balancedOrExpr(n/2)...)
	return append(out, balancedOrExpr(n-n/2)...)
}

// Depth alone admitted a balanced tree of thousands of leaves in one 64 KB datagram,
// and matching costs leaves x files: one such UDP search held the storage lock for
// seconds. The leaf count is bounded too.
func TestParseSearchExprLeafLimit(t *testing.T) {
	cases := []struct {
		leaves    int
		wantError bool
	}{
		{MaxSearchExprLeaves, false},
		{MaxSearchExprLeaves + 1, true},
		{9000, true},
	}
	for _, tc := range cases {
		payload := balancedOrExpr(tc.leaves)
		t.Logf("input: balanced OR tree, %d leaves, %d bytes", tc.leaves, len(payload))
		expr, err := ParseSearchExpr(NewBufferFromBytes(payload))
		t.Logf("output: expr=%v err=%v", expr != nil, err)
		if tc.wantError && !errors.Is(err, ErrSearchTooManyLeaves) {
			t.Fatalf("%d leaves: want ErrSearchTooManyLeaves, got %v", tc.leaves, err)
		}
		if !tc.wantError && err != nil {
			t.Fatalf("%d leaves: unexpected error %v", tc.leaves, err)
		}
	}
}

// A leaf may name its tag with a string instead of a one-byte id; the parser used to
// read a fixed 3 or 4 bytes, so everything after such a name was misframed. The name
// is consumed whole and the leaf decodes to a type storage prunes.
func TestParseSearchExprStringTagName(t *testing.T) {
	wire := []byte{
		0x00, 0x00, // AND
		0x03, 0x80, 0x00, 0x00, 0x00, 0x03, 0x07, 0x00, 'b', 'i', 't', 'r', 'a', 't', 'e', // bitrate >= 128, named
		0x00, 0x00, // AND
		0x02, 0x03, 0x00, 'm', 'p', '3', 0x01, 0x00, 0xd5, // codec "mp3", one-byte id
		0x01, 0x04, 0x00, 's', 'n', 'o', 'w', // keyword
	}
	expr, err := ParseSearchExpr(NewBufferFromBytes(wire))
	t.Logf("input: % x", wire)
	if err != nil {
		t.Fatal(err)
	}
	named, codec, text := expr.Left, expr.Right.Left, expr.Right.Right
	t.Logf("output: named type=%#x codec type=%#x value=%q text=%q", named.TagType, codec.TagType, codec.ValueString, text.Text)
	if _, _, ok := storage.NumericConstraint(named); ok {
		t.Fatal("a string-named numeric leaf must not decode as a known constraint")
	}
	if codec.TagType != 0x00d50001 || codec.ValueString != "mp3" || text.Text != "snow" {
		t.Fatalf("leaves after the named one were misframed: codec=%#x %q text=%q", codec.TagType, codec.ValueString, text.Text)
	}
}
