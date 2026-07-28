package ed2k

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

var (
	ErrOutOfBounds       = errors.New("buffer: out of bounds")
	ErrInvalidHashLength = errors.New("buffer: hash must be 16 bytes")
	ErrUnsupportedTag    = errors.New("buffer: unsupported tag type")
	ErrUnhandledTag      = errors.New("buffer: unhandled tag")
)

type Tag struct {
	Type uint8
	Code uint8
	Data any
}

type NamedTag struct {
	Name  string
	Value any
}

type FileRecord struct {
	Hash     []byte
	Complete bool
	ID       uint32
	Port     uint16
	Tags     map[string]any
	SizeLo   uint32
	SizeHi   uint32
	Size     uint64
}

type TagDecodeError struct {
	Pos     int
	Stage   string
	TagType uint8
	Code    uint8
	Err     error
}

func (e *TagDecodeError) Error() string {
	if e == nil {
		return "tag decode error"
	}
	if e.Code != 0 {
		return fmt.Sprintf("tag decode failed stage=%s pos=%d type=0x%x code=0x%x: %v",
			e.Stage, e.Pos, e.TagType, e.Code, e.Err)
	}
	return fmt.Sprintf("tag decode failed stage=%s pos=%d type=0x%x: %v",
		e.Stage, e.Pos, e.TagType, e.Err)
}

func (e *TagDecodeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Smallest number of bytes a single element can occupy on the wire. Used by
// checkWireCount to reject a declared count that the remaining bytes could not
// possibly supply.
const (
	// A short-format tag whose type nibble encodes a zero-length string is just
	// the type byte and the code byte — see GetTag, tagType&0x7f == 0x10.
	minTagBytes = 2
	// hash(16) + id(4) + port(2) + tag count(4), with no tags.
	minFileRecordBytes = 26
)

type Buffer struct {
	data    []byte
	pointer int
}

func NewBuffer(size int) *Buffer {
	return &Buffer{data: make([]byte, size)}
}

func NewBufferFromBytes(data []byte) *Buffer {
	return &Buffer{data: data}
}

func (b *Buffer) Bytes() []byte {
	return b.data
}

func (b *Buffer) Pos(pos ...int) int {
	if len(pos) == 0 {
		return b.pointer
	}
	b.pointer = pos[0]
	if b.pointer < 0 {
		b.pointer = 0
	}
	if b.pointer > len(b.data) {
		b.pointer = len(b.data)
	}
	return b.pointer
}

// Remaining reports how many bytes are left to read. Used to sanity-check
// wire-supplied element counts before allocating for them.
func (b *Buffer) Remaining() int {
	if b.pointer >= len(b.data) {
		return 0
	}
	return len(b.data) - b.pointer
}

func (b *Buffer) require(n int) error {
	if b.pointer+n > len(b.data) {
		return ErrOutOfBounds
	}
	return nil
}

func (b *Buffer) GetUInt8() (uint8, error) {
	if err := b.require(1); err != nil {
		return 0, err
	}
	v := b.data[b.pointer]
	b.pointer++
	return v, nil
}

func (b *Buffer) PutUInt8(n uint8) error {
	if err := b.require(1); err != nil {
		return err
	}
	b.data[b.pointer] = n
	b.pointer++
	return nil
}

func (b *Buffer) GetUInt16LE() (uint16, error) {
	if err := b.require(2); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint16(b.data[b.pointer:])
	b.pointer += 2
	return v, nil
}

func (b *Buffer) PutUInt16LE(n uint16) error {
	if err := b.require(2); err != nil {
		return err
	}
	binary.LittleEndian.PutUint16(b.data[b.pointer:], n)
	b.pointer += 2
	return nil
}

func (b *Buffer) GetUInt32LE() (uint32, error) {
	if err := b.require(4); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint32(b.data[b.pointer:])
	b.pointer += 4
	return v, nil
}

func (b *Buffer) PutUInt32LE(n uint32) error {
	if err := b.require(4); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(b.data[b.pointer:], n)
	b.pointer += 4
	return nil
}

func (b *Buffer) GetUInt64LE() (uint64, error) {
	if err := b.require(8); err != nil {
		return 0, err
	}
	lo := binary.LittleEndian.Uint32(b.data[b.pointer:])
	hi := binary.LittleEndian.Uint32(b.data[b.pointer+4:])
	b.pointer += 8
	return uint64(lo) + uint64(hi)*0x100000000, nil
}

func (b *Buffer) PutUInt64LE(n uint64) error {
	if err := b.require(8); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(b.data[b.pointer:], n)
	b.pointer += 8
	return nil
}

func (b *Buffer) GetString(length ...int) (string, error) {
	l := 0
	if len(length) == 0 {
		v, err := b.GetUInt16LE()
		if err != nil {
			return "", err
		}
		l = int(v)
	} else {
		l = length[0]
	}
	// Bounds-check before Get. Get truncates to the bytes remaining, so a declared
	// length past the end would otherwise return a silently truncated string with
	// no error — a filename cut off at a TCP boundary that parses "successfully"
	// corrupted. Every other getter returns ErrOutOfBounds on a short read; match
	// them, so a lying length prefix aborts the parse (as with the M2/M11 hardening).
	if l < 0 || b.Remaining() < l {
		return "", ErrOutOfBounds
	}
	return string(b.Get(l)), nil
}

func (b *Buffer) PutString(s string) error {
	if err := b.PutUInt16LE(uint16(len([]byte(s)))); err != nil {
		return err
	}
	src := []byte(s)
	if err := b.require(len(src)); err != nil {
		return err
	}
	copy(b.data[b.pointer:], src)
	b.pointer += len(src)
	return nil
}

func (b *Buffer) PutBuffer(src []byte) {
	n := copy(b.data[b.pointer:], src)
	b.pointer += n
	if b.pointer > len(b.data) {
		b.pointer = len(b.data)
	}
}

func (b *Buffer) PutHash(hash []byte) error {
	if len(hash) != 16 {
		return ErrInvalidHashLength
	}
	b.PutBuffer(hash)
	return nil
}

func (b *Buffer) Get(length ...int) []byte {
	if len(length) > 0 && length[0] == 0 {
		return nil
	}
	if len(length) == 0 {
		out := b.data[b.pointer:]
		b.pointer = len(b.data)
		return out
	}
	end := b.pointer + length[0]
	if end > len(b.data) {
		end = len(b.data)
	}
	out := b.data[b.pointer:end]
	b.pointer = end
	return out
}

func TagsLength(tags []Tag) (int, error) {
	length := 4
	for _, t := range tags {
		length += 4
		switch t.Type {
		case TypeString:
			v, ok := t.Data.(string)
			if !ok {
				return 0, ErrUnsupportedTag
			}
			length += 2 + len([]byte(v))
		case TypeHash:
			length += 16
		case TypeUint8:
			length += 1
		case TypeUint16:
			length += 2
		case TypeUint32:
			length += 4
		case TypeUint64:
			length += 8
		default:
			return 0, fmt.Errorf("%w: 0x%x", ErrUnsupportedTag, t.Type)
		}
	}
	return length, nil
}

func (b *Buffer) PutTag(tag Tag) error {
	if err := b.PutUInt8(tag.Type); err != nil {
		return err
	}
	if err := b.PutUInt16LE(1); err != nil {
		return err
	}
	if err := b.PutUInt8(tag.Code); err != nil {
		return err
	}

	switch tag.Type {
	case TypeString:
		v, ok := tag.Data.(string)
		if !ok {
			return ErrUnsupportedTag
		}
		return b.PutString(v)
	case TypeHash:
		v, ok := tag.Data.([]byte)
		if !ok {
			return ErrUnsupportedTag
		}
		return b.PutHash(v)
	case TypeUint8:
		switch v := tag.Data.(type) {
		case uint8:
			return b.PutUInt8(v)
		case int:
			return b.PutUInt8(uint8(v))
		default:
			return ErrUnsupportedTag
		}
	case TypeUint16:
		switch v := tag.Data.(type) {
		case uint16:
			return b.PutUInt16LE(v)
		case int:
			return b.PutUInt16LE(uint16(v))
		default:
			return ErrUnsupportedTag
		}
	case TypeUint32:
		switch v := tag.Data.(type) {
		case uint32:
			return b.PutUInt32LE(v)
		case int:
			return b.PutUInt32LE(uint32(v))
		default:
			return ErrUnsupportedTag
		}
	case TypeUint64:
		switch v := tag.Data.(type) {
		case uint64:
			return b.PutUInt64LE(v)
		case int:
			return b.PutUInt64LE(uint64(v))
		default:
			return ErrUnsupportedTag
		}
	default:
		return fmt.Errorf("%w: 0x%x", ErrUnsupportedTag, tag.Type)
	}
}

func (b *Buffer) PutTags(tags []Tag) error {
	if err := b.PutUInt32LE(uint32(len(tags))); err != nil {
		return err
	}
	for _, tag := range tags {
		if err := b.PutTag(tag); err != nil {
			return err
		}
	}
	return nil
}

// GetTagValue decodes a tag payload. All integer widths are normalized to uint64
// so that consumers can type-assert a single type.
//
// eMule narrows every integer tag by magnitude when NEWTAGS is advertised
// (CTag::WriteNewEd2kTag): <=0xff becomes TAGTYPE_UINT8, <=0xffff TAGTYPE_UINT16,
// and so on. Returning the wire width as a distinct Go type meant an exact
// assertion such as Tags["size"].(uint32) silently failed for any file under
// 64 KiB, and for the FT_FILESIZE_HI of any large file (the high dword of a 5 GiB
// file is 1, so it ships as TAGTYPE_UINT8).
func (b *Buffer) GetTagValue(typ uint8) (any, error) {
	switch typ {
	case TypeString:
		return b.GetString()
	case TypeUint8:
		v, err := b.GetUInt8()
		return uint64(v), err
	case TypeUint16:
		v, err := b.GetUInt16LE()
		return uint64(v), err
	case TypeUint32:
		v, err := b.GetUInt32LE()
		return uint64(v), err
	case TypeUint64:
		return b.GetUInt64LE()
	case TypeHash:
		// 16 raw bytes, no length prefix. eMuleAI's CT_MOD_IP_V6 (0xae) and
		// CT_MOD_SVR_IP_V6 (0xaf) ride this type; before it was decoded, a login
		// carrying a public IPv6 aborted the whole tag list and the client never
		// got OP_IDCHANGE.
		if b.Remaining() < 16 {
			return nil, ErrOutOfBounds
		}
		return append([]byte(nil), b.Get(16)...), nil
	case TypeFloat:
		if b.Remaining() < 4 {
			return nil, ErrOutOfBounds
		}
		return math.Float32frombits(binary.LittleEndian.Uint32(b.Get(4))), nil
	case TypeBool:
		v, err := b.GetUInt8()
		if err != nil {
			return nil, err
		}
		return v != 0, nil
	case TypeBlob:
		// uint32 length prefix, then that many bytes.
		n, err := b.GetUInt32LE()
		if err != nil {
			return nil, err
		}
		if b.Remaining() < int(n) {
			return nil, ErrOutOfBounds
		}
		return append([]byte(nil), b.Get(int(n))...), nil
	case TypeBsob:
		// uint8 length prefix, then that many bytes.
		n, err := b.GetUInt8()
		if err != nil {
			return nil, err
		}
		if b.Remaining() < int(n) {
			return nil, ErrOutOfBounds
		}
		return append([]byte(nil), b.Get(int(n))...), nil
	default:
		return nil, fmt.Errorf("%w: 0x%x", ErrUnsupportedTag, typ)
	}
}

func tagName(code uint8) string {
	switch code {
	case TagName:
		return "name"
	case TagSize:
		return "size"
	case TagSizeHi:
		return "sizehi"
	case TagType:
		return "type"
	case TagFormat:
		return "format"
	case TagVersion:
		return "version"
	case TagPort:
		return "port2"
	case TagSources:
		return "sources"
	case TagMuleVersion:
		return "muleversion"
	case TagFlags:
		return "flags"
	case TagRating:
		return "rating"
	case TagMediaArtist:
		return "artist"
	case TagMediaAlbum:
		return "album"
	case TagMediaTitle:
		return "title"
	case TagMediaLength:
		return "length"
	case TagMediaBitrate:
		return "bitrate"
	case TagMediaCodec:
		return "codec"
	case TagSearchTree:
		return "searchtree"
	case TagEmuleUDPPorts:
		return "udpports"
	case TagEmuleOptions1:
		return "options1"
	case TagEmuleOptions2:
		return "options2"
	case TagModIPv6:
		return "ipv6"
	case TagModSvrIPv6:
		return "svripv6"
	case TagNatPort:
		return "natport"
	case TagModYourIP:
		return "yourip"
	case TagIPv6Status:
		return "ipv6status"
	default:
		return fmt.Sprintf("0x%x", code)
	}
}

func (b *Buffer) GetTag() (NamedTag, error) {
	startPos := b.Pos()
	tagType, err := b.GetUInt8()
	if err != nil {
		return NamedTag{}, err
	}
	origTagType := tagType
	shortFormat := false

	var code uint8
	var value any
	// name overrides the code-derived name when a tag carries a textual name
	// (name length != 1) instead of a single-byte code.
	var name string
	haveName := false

	if tagType&0x80 != 0 {
		shortFormat = true
		c, err := b.GetUInt8()
		if err != nil {
			return NamedTag{}, &TagDecodeError{Pos: startPos, Stage: "read-short-code", TagType: origTagType, Err: err}
		}
		code = c
		tagType &= 0x7f
		if tagType >= 0x10 {
			strLen := int(tagType - 0x10)
			tagType = TypeString
			s, err := b.GetString(strLen)
			if err != nil {
				return NamedTag{}, &TagDecodeError{Pos: startPos, Stage: "read-short-string", TagType: origTagType, Code: code, Err: err}
			}
			value = s
		}
	}

	if value == nil {
		if !shortFormat {
			l, err := b.GetUInt16LE()
			if err != nil {
				return NamedTag{}, &TagDecodeError{Pos: startPos, Stage: "read-name-len", TagType: origTagType, Err: err}
			}
			if l == 1 {
				c, err := b.GetUInt8()
				if err != nil {
					return NamedTag{}, &TagDecodeError{Pos: startPos, Stage: "read-name-code", TagType: origTagType, Err: err}
				}
				code = c
			} else {
				// Textual tag name. eMule permits a string name in place of the
				// single-byte code; consume it so the value stays in sync rather
				// than aborting the whole list. We key tags by numeric code, so a
				// string-named tag simply carries its literal name and matches no
				// known code.
				if b.Remaining() < int(l) {
					return NamedTag{}, &TagDecodeError{Pos: startPos, Stage: "read-name-string", TagType: origTagType, Err: ErrOutOfBounds}
				}
				name = string(b.Get(int(l)))
				haveName = true
			}
		}
		v, err := b.GetTagValue(tagType)
		if err != nil {
			return NamedTag{}, &TagDecodeError{Pos: startPos, Stage: "read-value", TagType: origTagType, Code: code, Err: err}
		}
		value = v
	}

	if !haveName {
		name = tagName(code)
	}
	return NamedTag{Name: name, Value: value}, nil
}

func (b *Buffer) GetTags() ([]NamedTag, error) {
	startPos := b.Pos()
	count, err := b.GetUInt32LE()
	if err != nil {
		return nil, err
	}
	if err := checkWireCount(count, b.Remaining(), minTagBytes, "tags"); err != nil {
		return nil, err
	}
	tags := make([]NamedTag, 0, count)
	for i := uint32(0); i < count; i++ {
		tag, err := b.GetTag()
		if err != nil {
			return nil, fmt.Errorf("tags decode failed start=%d idx=%d: %w", startPos, i, err)
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

func (b *Buffer) GetFileList() ([]FileRecord, error) {
	count, err := b.GetUInt32LE()
	if err != nil {
		return nil, err
	}
	if err := checkWireCount(count, b.Remaining(), minFileRecordBytes, "file records"); err != nil {
		return nil, err
	}
	files := make([]FileRecord, 0, count)
	for i := uint32(0); i < count; i++ {
		hash := append([]byte(nil), b.Get(16)...)
		if len(hash) != 16 {
			return nil, ErrOutOfBounds
		}
		id, err := b.GetUInt32LE()
		if err != nil {
			return nil, err
		}
		port, err := b.GetUInt16LE()
		if err != nil {
			return nil, err
		}
		tags, err := b.GetTags()
		if err != nil {
			return nil, fmt.Errorf("filelist decode failed file-idx=%d hash=%x id=%d port=%d: %w", i, hash, id, port, err)
		}
		record := FileRecord{
			Hash:     hash,
			Complete: true,
			ID:       id,
			Port:     port,
			Tags:     make(map[string]any, len(tags)),
		}
		for _, t := range tags {
			record.Tags[t.Name] = t.Value
		}
		if id == ValPartialID && port == ValPartialPort {
			record.Complete = false
		} else if id == ValCompleteID && port == ValCompletePort {
			record.Complete = true
		}
		if v, ok := tagUint64(record.Tags, "size"); ok {
			record.SizeLo = uint32(v)
			record.Size = v
		}
		if v, ok := tagUint64(record.Tags, "sizehi"); ok {
			record.SizeHi = uint32(v)
			record.Size += v * 0x100000000
		}
		files = append(files, record)
	}
	return files, nil
}

// checkWireCount rejects an element count that could not possibly be backed by
// the bytes still in the buffer.
//
// Both GetTags and GetFileList size their slice from a 4-byte wire count, so a
// declared 0xFFFFFFFF reserves ~137 GB of NamedTag or ~275 GB of FileRecord
// from a handful of bytes. Comparing against the smallest legal encoding gives
// a bound that no honest peer can trip.
//
// The count itself is rejected rather than clamped on purpose: clamping the
// loop would silently accept a truncated list, and every record after it would
// then be framed from the wrong offset instead of failing with ErrOutOfBounds.
func checkWireCount(count uint32, remaining, minBytesEach int, what string) error {
	if remaining < 0 {
		remaining = 0
	}
	if uint64(count) > uint64(remaining/minBytesEach) {
		return fmt.Errorf("%w: %s count %d exceeds %d remaining bytes",
			ErrOutOfBounds, what, count, remaining)
	}
	return nil
}

// tagUint64 reads a normalized integer tag. GetTagValue returns every integer
// width as uint64, so a single assertion covers TAGTYPE_UINT8/16/32/64 alike.
func tagUint64(tags map[string]any, key string) (uint64, bool) {
	v, ok := tags[key].(uint64)
	return v, ok
}

// tagUint32 reads an integer tag destined for a uint32 field, saturating rather
// than wrapping if a client sends an implausibly large value.
func tagUint32(tags map[string]any, key string) (uint32, bool) {
	v, ok := tagUint64(tags, key)
	if !ok {
		return 0, false
	}
	if v > math.MaxUint32 {
		return math.MaxUint32, true
	}
	return uint32(v), true
}
