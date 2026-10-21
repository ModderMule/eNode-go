package wire

import (
	"errors"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// The zstd profile of Protocol.md §5.3: magicless frames, no checksum, no
// content size, window ≤ 1 MiB, one frame per body, output ≤ 1 MiB.

// MaxBody is the largest frame body, before and after decompression.
const MaxBody = 1 << 20

// MinCompress is the body size below which a sender does not try compressing.
const MinCompress = 64

// Errors of Decompress. ErrNeedDict maps to Error{UNSUPPORTED}; the others to
// Error{MALFORMED}.
var (
	ErrNotOneFrame = errors.New("ed3k: zstd body is not exactly one frame")
	ErrWindow      = errors.New("ed3k: zstd window above 1 MiB")
	ErrTooLong     = errors.New("ed3k: zstd output above 1 MiB")
	ErrNeedDict    = errors.New("ed3k: zstd dictionary not held")
)

// Decompress inflates a magicless zstd body. This node holds no dictionary
// (Hello.dict = 0), so a frame that names one is ErrNeedDict.
func Decompress(body []byte) ([]byte, error) {
	framed := make([]byte, 0, len(body)+4)
	framed = append(framed, zstdMagic...)
	framed = append(framed, body...)
	var h zstd.Header
	if err := h.Decode(framed); err != nil || h.Skippable {
		return nil, ErrNotOneFrame
	}
	ws := h.WindowSize
	if h.SingleSegment {
		ws = h.FrameContentSize
	}
	if ws > MaxBody {
		return nil, ErrWindow
	}
	if h.HasFCS && h.FrameContentSize > MaxBody {
		return nil, ErrTooLong
	}
	n, err := frameLength(framed, h)
	if err != nil || n != len(framed) {
		return nil, ErrNotOneFrame
	}
	if h.DictionaryID != 0 {
		return nil, ErrNeedDict
	}
	out, err := decoder().DecodeAll(framed, nil)
	if err != nil {
		if errors.Is(err, zstd.ErrDecoderSizeExceeded) || errors.Is(err, zstd.ErrWindowSizeExceeded) {
			return nil, ErrTooLong
		}
		return nil, ErrNotOneFrame
	}
	if len(out) > MaxBody {
		return nil, ErrTooLong
	}
	return out, nil
}

// Compress deflates a body in the §5.3 profile. ok is false when compressing
// does not pay (body under MinCompress bytes, or a result that is not smaller);
// the caller then sends the body as it is.
func Compress(body []byte) (out []byte, ok bool) {
	if len(body) < MinCompress || len(body) > MaxBody {
		return nil, false
	}
	framed := encoder().EncodeAll(body, nil)
	out, err := profileHeader(framed, len(body))
	if err != nil || len(out) >= len(body) {
		return nil, false
	}
	return out, true
}

var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

var (
	encOnce sync.Once
	enc     *zstd.Encoder
	decOnce sync.Once
	dec     *zstd.Decoder
)

func encoder() *zstd.Encoder {
	encOnce.Do(func() {
		enc, _ = zstd.NewWriter(nil,
			zstd.WithEncoderCRC(false),
			zstd.WithSingleSegment(true),
			zstd.WithWindowSize(MaxBody),
			zstd.WithEncoderConcurrency(1),
			zstd.WithEncoderLevel(zstd.SpeedDefault))
	})
	return enc
}

func decoder() *zstd.Decoder {
	decOnce.Do(func() {
		dec, _ = zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(0),
			zstd.WithDecoderMaxMemory(MaxBody),
			zstd.WithDecoderMaxWindow(MaxBody))
	})
	return dec
}

// profileHeader turns the single-segment frame klauspost writes, which always
// carries a content size, into a magicless frame without one: the content-size
// field gives way to a window descriptor covering the body.
func profileHeader(framed []byte, size int) ([]byte, error) {
	if len(framed) < 6 || string(framed[:4]) != string(zstdMagic) {
		return nil, errors.New("ed3k: unexpected zstd output")
	}
	fhd := framed[4]
	if fhd&0x03 != 0 || fhd&0x20 == 0 {
		return nil, errors.New("ed3k: unexpected zstd header")
	}
	fcsLen := [4]int{1, 2, 4, 8}[fhd>>6]
	rest := framed[5+fcsLen:]
	newFHD := fhd &^ 0xe0 // FCS flag 0, Single_Segment 0, checksum bit as it was
	out := make([]byte, 0, 2+len(rest))
	out = append(out, newFHD, windowDescriptor(size))
	return append(out, rest...), nil
}

// windowDescriptor is the smallest zstd window descriptor of at least size bytes
// (and at least the 1 KiB minimum).
func windowDescriptor(size int) byte {
	for e := 0; e < 32; e++ {
		base := 1 << (10 + e)
		for m := 0; m < 8; m++ {
			if base+base/8*m >= size {
				return byte(e<<3 | m)
			}
		}
	}
	return 0xff
}

// frameLength walks the blocks of one zstd frame (with its magic) and returns its
// length in bytes.
func frameLength(b []byte, h zstd.Header) (int, error) {
	fhd := b[4]
	pos := 5
	if fhd&0x20 == 0 {
		pos++ // window descriptor
	}
	pos += [4]int{0, 1, 2, 4}[fhd&0x03]
	fcs := [4]int{0, 2, 4, 8}[fhd>>6]
	if fhd>>6 == 0 && fhd&0x20 != 0 {
		fcs = 1
	}
	pos += fcs
	for {
		if pos+3 > len(b) {
			return 0, ErrNotOneFrame
		}
		bh := uint32(b[pos]) | uint32(b[pos+1])<<8 | uint32(b[pos+2])<<16
		pos += 3
		last := bh&1 == 1
		typ := (bh >> 1) & 3
		bsize := int(bh >> 3)
		switch typ {
		case 0, 2: // raw, compressed
			pos += bsize
		case 1: // RLE
			pos++
		default:
			return 0, ErrNotOneFrame
		}
		if pos > len(b) {
			return 0, ErrNotOneFrame
		}
		if last {
			break
		}
	}
	if h.HasCheckSum {
		pos += 4
	}
	return pos, nil
}
