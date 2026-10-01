package ed2k

import (
	"encoding/binary"
	"runtime"
	"testing"
)

// MFC's CTag skips a BOOLARRAY (u16 bit count, count/8+1 bytes) and reads STR1-16
// under a long-form name too. Rejecting either aborted the whole tag list, and the
// packet carrying it with it.
func TestGetTagsSkipsBoolArrayAndReadsLongFormStrN(t *testing.T) {
	wire := []byte{
		3, 0, 0, 0, // three tags
		TypeBoolArray, 1, 0, 0x77, 12, 0, 0xff, 0x0f, // long name 0x77, 12 bits = 2 bytes
		0x13, 1, 0, 0x01, 'a', 'b', 'c', // STR3, long name 0x01 (name)
		TypeUint8 | 0x80, 0x11, 7, // short UINT8, code 0x11 (version)
	}
	b := NewBufferFromBytes(wire)
	tags, err := b.GetTags()
	t.Logf("input: % x, output: tags=%+v err=%v", wire, tags, err)
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 3 || tags[1].Value != "abc" || tags[1].Type != TypeString || tags[2].Value != uint64(7) {
		t.Fatalf("unexpected tags %+v", tags)
	}
	if b.Remaining() != 0 {
		t.Fatalf("%d bytes left unread", b.Remaining())
	}
}

// A declared tag count reserves at most maxTagPrealloc entries: a 2 MB login could
// otherwise make the server allocate ~32 MB of NamedTag before the first tag fails.
func TestGetTagsDoesNotPreallocateDeclaredCount(t *testing.T) {
	const count = 100_000
	wire := make([]byte, 4+2*count)
	binary.LittleEndian.PutUint32(wire, count)
	for i := 4; i < len(wire); i += 2 {
		wire[i] = 0xff // unknown short tag type, fails at once
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _ = NewBufferFromBytes(wire).GetTags()
	runtime.ReadMemStats(&after)
	bytesPer := float64(after.TotalAlloc - before.TotalAlloc)
	t.Logf("input: tag count %d, first tag invalid; output: %.0f bytes allocated", count, bytesPer)
	if bytesPer > 64*1024 {
		t.Fatalf("allocated %.0f bytes for a list that failed at its first tag", bytesPer)
	}
}
