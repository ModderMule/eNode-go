package ed2k

import (
	"bytes"
	"errors"
	"testing"
)

func TestBufferReadWritePrimitives(t *testing.T) {
	b := NewBuffer(64)
	if err := b.PutUInt8(0x7a); err != nil {
		t.Fatal(err)
	}
	if err := b.PutUInt16LE(0x1337); err != nil {
		t.Fatal(err)
	}
	if err := b.PutUInt32LE(0xdeadbeef); err != nil {
		t.Fatal(err)
	}
	if err := b.PutString("abc"); err != nil {
		t.Fatal(err)
	}
	hash := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if err := b.PutHash(hash); err != nil {
		t.Fatal(err)
	}

	b.Pos(0)
	u8, err := b.GetUInt8()
	if err != nil {
		t.Fatal(err)
	}
	if u8 != 0x7a {
		t.Fatalf("u8 mismatch: got 0x%x", u8)
	}

	u16, err := b.GetUInt16LE()
	if err != nil {
		t.Fatal(err)
	}
	if u16 != 0x1337 {
		t.Fatalf("u16 mismatch: got 0x%x", u16)
	}

	u32, err := b.GetUInt32LE()
	if err != nil {
		t.Fatal(err)
	}
	if u32 != 0xdeadbeef {
		t.Fatalf("u32 mismatch: got 0x%x", u32)
	}

	s, err := b.GetString()
	if err != nil {
		t.Fatal(err)
	}
	if s != "abc" {
		t.Fatalf("string mismatch: got %q", s)
	}

	gotHash := b.Get(16)
	if !bytes.Equal(gotHash, hash) {
		t.Fatalf("hash mismatch: got %v", gotHash)
	}
}

func TestTagsRoundTrip(t *testing.T) {
	tags := []Tag{
		{Type: TypeString, Code: TagName, Data: "file.iso"},
		{Type: TypeUint32, Code: TagSize, Data: uint32(1234)},
		{Type: TypeUint16, Code: TagPort, Data: uint16(4662)},
		{Type: TypeUint8, Code: TagFlags, Data: uint8(1)},
	}
	l, err := TagsLength(tags)
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuffer(l)
	if err := b.PutTags(tags); err != nil {
		t.Fatal(err)
	}

	b.Pos(0)
	parsed, err := b.GetTags()
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 4 {
		t.Fatalf("parsed tags count mismatch: got %d", len(parsed))
	}
	if parsed[0].Name != "name" || parsed[0].Value.(string) != "file.iso" {
		t.Fatalf("name tag mismatch: %#v", parsed[0])
	}
	// Every integer width decodes to uint64 regardless of the wire type.
	if parsed[1].Name != "size" || parsed[1].Value.(uint64) != 1234 {
		t.Fatalf("size tag mismatch: %#v", parsed[1])
	}
	if parsed[2].Name != "port2" || parsed[2].Value.(uint64) != 4662 {
		t.Fatalf("port tag mismatch: %#v", parsed[2])
	}
	if parsed[3].Name != "flags" || parsed[3].Value.(uint64) != 1 {
		t.Fatalf("flags tag mismatch: %#v", parsed[3])
	}
	t.Logf("parsed tags: %s=%q %s=%d %s=%d %s=%d",
		parsed[0].Name, parsed[0].Value, parsed[1].Name, parsed[1].Value,
		parsed[2].Name, parsed[2].Value, parsed[3].Name, parsed[3].Value)
}

func TestGetFileList(t *testing.T) {
	fileTags := []Tag{
		{Type: TypeString, Code: TagName, Data: "movie.mkv"},
		{Type: TypeUint32, Code: TagSize, Data: uint32(1)},
		{Type: TypeUint32, Code: TagSizeHi, Data: uint32(1)},
	}
	tagLen, err := TagsLength(fileTags)
	if err != nil {
		t.Fatal(err)
	}

	total := 4 + 16 + 4 + 2 + tagLen
	b := NewBuffer(total)
	if err := b.PutUInt32LE(1); err != nil {
		t.Fatal(err)
	}
	hash := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	if err := b.PutHash(hash); err != nil {
		t.Fatal(err)
	}
	if err := b.PutUInt32LE(ValPartialID); err != nil {
		t.Fatal(err)
	}
	if err := b.PutUInt16LE(ValPartialPort); err != nil {
		t.Fatal(err)
	}
	if err := b.PutTags(fileTags); err != nil {
		t.Fatal(err)
	}

	b.Pos(0)
	files, err := b.GetFileList()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("files count mismatch: got %d", len(files))
	}
	f := files[0]
	if f.Complete {
		t.Fatalf("expected partial file")
	}
	if f.tagMap()["name"].(string) != "movie.mkv" {
		t.Fatalf("name mismatch: %#v", f.tagMap()["name"])
	}
	if f.Size != 0x100000001 {
		t.Fatalf("size mismatch: got %d", f.Size)
	}
}

func TestGetTagErrorContainsContext(t *testing.T) {
	// malformed long tag: type=TypeUint32, name-len=1, code, but the declared
	// uint32 value is truncated (only 2 bytes present). The parse must fail with
	// context at the read-value stage.
	in := []byte{TypeUint32, 0x01, 0x00, TagSize, 0x11, 0x22}
	b := NewBufferFromBytes(in)
	_, err := b.GetTag()
	if err == nil {
		t.Fatal("expected error")
	}
	var tagErr *TagDecodeError
	if !errors.As(err, &tagErr) {
		t.Fatalf("expected TagDecodeError, got %T (%v)", err, err)
	}
	if tagErr.Stage != "read-value" {
		t.Fatalf("unexpected stage: %s", tagErr.Stage)
	}
	t.Logf("input: %x -> error stage=%s: %v", in, tagErr.Stage, err)
}

// TestGetTagStringNamedTagConsumed pins the fix for the login-drop bug: a tag
// whose name length is not 1 (a textual name) must be consumed and returned
// rather than aborting the whole list. eMule permits string-named tags, and
// aborting on one previously dropped otherwise-valid login/offer packets.
func TestGetTagStringNamedTagConsumed(t *testing.T) {
	// type=TypeUint32, name-len=2, name="xy", value=0x44332211 (LE).
	in := []byte{TypeUint32, 0x02, 0x00, 'x', 'y', 0x11, 0x22, 0x33, 0x44}
	b := NewBufferFromBytes(in)
	tag, err := b.GetTag()
	if err != nil {
		t.Fatalf("string-named tag should parse, got: %v", err)
	}
	if tag.Name != "xy" {
		t.Fatalf("name mismatch: got %q want %q", tag.Name, "xy")
	}
	v, ok := tag.Value.(uint64)
	if !ok || v != 0x44332211 {
		t.Fatalf("value mismatch: got %T %v", tag.Value, tag.Value)
	}
	if b.Remaining() != 0 {
		t.Fatalf("tag not fully consumed: %d bytes left", b.Remaining())
	}
	t.Logf("input: %x -> name=%q value=0x%x", in, tag.Name, v)
}

// TestGetTagHashValue verifies the previously-missing hash tag type (0x01)
// decodes to 16 bytes — the type CT_MOD_IP_V6 (0xae) rides on.
func TestGetTagHashValue(t *testing.T) {
	ipv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	in := append([]byte{TypeHash, 0x01, 0x00, TagModIPv6}, ipv6...)
	b := NewBufferFromBytes(in)
	tag, err := b.GetTag()
	if err != nil {
		t.Fatalf("hash tag should parse, got: %v", err)
	}
	if tag.Name != "ipv6" {
		t.Fatalf("name mismatch: %q", tag.Name)
	}
	got, ok := tag.Value.([]byte)
	if !ok || !bytes.Equal(got, ipv6) {
		t.Fatalf("value mismatch: got %T %x", tag.Value, tag.Value)
	}
	t.Logf("input: %x -> name=%s value=%x", in, tag.Name, got)
}

func TestGetTagShortFormatUint16(t *testing.T) {
	// 0x88 => short format + TypeUint16, next byte is code.
	b := NewBufferFromBytes([]byte{
		0x88, TagPort, 0x36, 0x12,
	})
	tag, err := b.GetTag()
	if err != nil {
		t.Fatal(err)
	}
	if tag.Name != "port2" {
		t.Fatalf("name mismatch: %s", tag.Name)
	}
	v, ok := tag.Value.(uint64)
	if !ok {
		t.Fatalf("value type mismatch: %T", tag.Value)
	}
	if v != 0x1236 {
		t.Fatalf("value mismatch: %d", v)
	}
	t.Logf("input: %x -> output: name=%s value=0x%x", []byte{0x88, TagPort, 0x36, 0x12}, tag.Name, v)
}

// encodeFileList builds a one-entry OP_OFFERFILES payload carrying the given tags.
func encodeFileList(t *testing.T, hash []byte, tags []Tag) *Buffer {
	t.Helper()
	tagLen, err := TagsLength(tags)
	if err != nil {
		t.Fatalf("TagsLength: %v", err)
	}
	b := NewBuffer(4 + 16 + 4 + 2 + tagLen)
	if err := b.PutUInt32LE(1); err != nil {
		t.Fatal(err)
	}
	if err := b.PutHash(hash); err != nil {
		t.Fatal(err)
	}
	if err := b.PutUInt32LE(ValCompleteID); err != nil {
		t.Fatal(err)
	}
	if err := b.PutUInt16LE(ValCompletePort); err != nil {
		t.Fatal(err)
	}
	if err := b.PutTags(tags); err != nil {
		t.Fatal(err)
	}
	b.Pos(0)
	return b
}

// TestGetFileListNarrowedSizeTag covers eMule's magnitude-based narrowing of
// FT_FILESIZE. Before normalization the UINT8 and UINT16 cases decoded to a
// non-uint32 dynamic type, the assertion in GetFileList failed, and the file was
// indexed with Size = 0 — so it was published but never returned any sources.
func TestGetFileListNarrowedSizeTag(t *testing.T) {
	hash := []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	cases := []struct {
		name string
		typ  uint8
		data any
		want uint64
	}{
		{"uint8 (file < 256 B)", TypeUint8, uint8(200), 200},
		{"uint16 (file < 64 KiB)", TypeUint16, uint16(60000), 60000},
		{"uint32", TypeUint32, uint32(5_000_000), 5_000_000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tags := []Tag{
				{Type: TypeString, Code: TagName, Data: "shared.bin"},
				{Type: tc.typ, Code: TagSize, Data: tc.data},
			}
			t.Logf("input: FT_FILESIZE wire type 0x%02x value %v", tc.typ, tc.data)

			files, err := encodeFileList(t, hash, tags).GetFileList()
			if err != nil {
				t.Fatalf("GetFileList: %v", err)
			}
			if len(files) != 1 {
				t.Fatalf("files count mismatch: got %d", len(files))
			}
			t.Logf("output: Size=%d SizeLo=%d", files[0].Size, files[0].SizeLo)

			if files[0].Size != tc.want {
				t.Fatalf("Size mismatch: got %d, want %d", files[0].Size, tc.want)
			}
			if files[0].SizeLo != uint32(tc.want) {
				t.Fatalf("SizeLo mismatch: got %d, want %d", files[0].SizeLo, tc.want)
			}
		})
	}
}

// TestGetFileListLargeFileNarrowedSizeHi covers the high dword of a large file.
// eMule narrows FT_FILESIZE_HI too, and for any file under 1 TiB that value is
// small enough to ship as TAGTYPE_UINT8 — so large files lost their high dword
// entirely and were indexed at (size mod 4 GiB).
func TestGetFileListLargeFileNarrowedSizeHi(t *testing.T) {
	const want = uint64(5) << 30 // 5 GiB
	lo := uint32(want & 0xffffffff)
	hi := uint8(want >> 32) // == 1

	hash := []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}
	tags := []Tag{
		{Type: TypeString, Code: TagName, Data: "large.iso"},
		{Type: TypeUint32, Code: TagSize, Data: lo},
		{Type: TypeUint8, Code: TagSizeHi, Data: hi}, // narrowed by magnitude
	}
	t.Logf("input: 5 GiB file, FT_FILESIZE=%d (uint32), FT_FILESIZE_HI=%d (uint8)", lo, hi)

	files, err := encodeFileList(t, hash, tags).GetFileList()
	if err != nil {
		t.Fatalf("GetFileList: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("files count mismatch: got %d", len(files))
	}
	f := files[0]
	t.Logf("output: Size=%d SizeLo=%d SizeHi=%d", f.Size, f.SizeLo, f.SizeHi)

	if f.Size != want {
		t.Fatalf("Size mismatch: got %d, want %d (high dword dropped?)", f.Size, want)
	}
	if f.SizeHi != uint32(hi) {
		t.Fatalf("SizeHi mismatch: got %d, want %d", f.SizeHi, hi)
	}
}

// TestGetTagValueUint64 covers TAGTYPE_UINT64 (0x0b). It was undefined, so an
// incoming 0x0b tag returned ErrUnsupportedTag, which aborted GetTags and in turn
// aborted GetFileList — discarding the entire OFFERFILES batch, not just one tag.
func TestGetTagValueUint64(t *testing.T) {
	const want = uint64(6) << 30 // exceeds uint32

	t.Run("single tag decodes", func(t *testing.T) {
		tags := []Tag{{Type: TypeUint64, Code: TagSize, Data: want}}
		l, err := TagsLength(tags)
		if err != nil {
			t.Fatalf("TagsLength: %v", err)
		}
		b := NewBuffer(l)
		if err := b.PutTags(tags); err != nil {
			t.Fatalf("PutTags: %v", err)
		}
		t.Logf("input: TAGTYPE_UINT64 value %d encoded as %x", want, b.Bytes())

		b.Pos(0)
		parsed, err := b.GetTags()
		if err != nil {
			t.Fatalf("GetTags: %v", err)
		}
		if len(parsed) != 1 {
			t.Fatalf("tag count mismatch: got %d", len(parsed))
		}
		got, ok := parsed[0].Value.(uint64)
		if !ok {
			t.Fatalf("value type mismatch: %T", parsed[0].Value)
		}
		t.Logf("output: %s=%d", parsed[0].Name, got)
		if got != want {
			t.Fatalf("value mismatch: got %d, want %d", got, want)
		}
	})

	t.Run("does not discard the whole batch", func(t *testing.T) {
		hash := []byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4}
		tags := []Tag{
			{Type: TypeString, Code: TagName, Data: "huge.iso"},
			{Type: TypeUint64, Code: TagSize, Data: want},
		}
		t.Logf("input: file list with one TAGTYPE_UINT64 size tag (%d)", want)

		files, err := encodeFileList(t, hash, tags).GetFileList()
		if err != nil {
			t.Fatalf("GetFileList dropped the batch: %v", err)
		}
		if len(files) != 1 {
			t.Fatalf("files count mismatch: got %d", len(files))
		}
		t.Logf("output: files=%d Size=%d", len(files), files[0].Size)
		if files[0].Size != want {
			t.Fatalf("Size mismatch: got %d, want %d", files[0].Size, want)
		}
	})
}

// TestPutGetTagRoundTripAllWidths guards the TagsLength accounting for every
// supported wire type, including the newly added TAGTYPE_UINT64.
func TestPutGetTagRoundTripAllWidths(t *testing.T) {
	tags := []Tag{
		{Type: TypeString, Code: TagName, Data: "round.trip"},
		{Type: TypeUint8, Code: TagType, Data: uint8(0x7f)},
		{Type: TypeUint16, Code: TagPort, Data: uint16(0xbeef)},
		{Type: TypeUint32, Code: TagSize, Data: uint32(0xdeadbeef)},
		{Type: TypeUint64, Code: TagSizeHi, Data: uint64(0x00ddccbbaa998877)},
	}
	want := []any{"round.trip", uint64(0x7f), uint64(0xbeef), uint64(0xdeadbeef), uint64(0x00ddccbbaa998877)}

	l, err := TagsLength(tags)
	if err != nil {
		t.Fatalf("TagsLength: %v", err)
	}
	b := NewBuffer(l)
	if err := b.PutTags(tags); err != nil {
		t.Fatalf("PutTags: %v", err)
	}
	t.Logf("input: %d tags, TagsLength=%d, encoded=%x", len(tags), l, b.Bytes())

	// A wrong TagsLength shows up as leftover or missing bytes.
	if got := len(b.Bytes()); got != l {
		t.Fatalf("encoded length mismatch: got %d, want %d", got, l)
	}

	b.Pos(0)
	parsed, err := b.GetTags()
	if err != nil {
		t.Fatalf("GetTags: %v", err)
	}
	if len(parsed) != len(tags) {
		t.Fatalf("tag count mismatch: got %d, want %d", len(parsed), len(tags))
	}
	for i, p := range parsed {
		t.Logf("output: [%d] %s = %v (%T)", i, p.Name, p.Value, p.Value)
		if p.Value != want[i] {
			t.Fatalf("tag %d (%s) mismatch: got %v (%T), want %v", i, p.Name, p.Value, p.Value, want[i])
		}
	}
}
