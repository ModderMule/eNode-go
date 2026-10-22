// Package wire is the ed3k frame layer (Protocol.md §5.1–§5.3): frame headers,
// body limits and compression.
package wire

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

// Frame types of Protocol.md §5.1 that an index node reads or writes.
const (
	TypeHello      = 1
	TypeError      = 2
	TypeKadRequest = 3
	TypeKadAnswer  = 4
	TypePunch      = 11
	TypeRelay      = 12
	TypeReachTest  = 13
)

// ErrHeader is a frame header that does not parse: a varint over 10 bytes, a
// len above 1 MiB, or an exchange that ends inside the header. The connection
// is closed with PROTOCOL. When the stream failed instead (a read deadline, a
// reset), the stream's error is wrapped too, and the caller gives the exchange
// up without closing the connection (§4.1, §5.2).
var ErrHeader = errors.New("ed3k: frame header does not parse")

// ErrEmpty is an exchange that ended before the first byte of a header: a
// failed exchange, not a header that does not parse.
var ErrEmpty = errors.New("ed3k: exchange ends before a frame")

// ErrShort is a body that the exchange ends before; answered Error{MALFORMED}.
// A stream that failed inside the body is wrapped as for ErrHeader.
var ErrShort = errors.New("ed3k: exchange ends inside a frame body")

// Frame is one decoded frame: its type and its body, decompressed.
type Frame struct {
	Type uint64
	Body []byte
}

// ReadFrame reads one frame. ErrHeader closes the connection; ErrShort and the
// errors of Decompress are answered Error{MALFORMED} (ErrNeedDict
// Error{UNSUPPORTED}).
func ReadFrame(r io.ByteReader) (Frame, error) {
	first, err := r.ReadByte()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return Frame{}, ErrEmpty
		}
		return Frame{}, fmt.Errorf("%w: %w", ErrHeader, err)
	}
	tag, err := readVarint(&prefixed{first: first, r: r})
	if err != nil {
		return Frame{}, headerErr(err)
	}
	n, err := readVarint(r)
	if err != nil {
		return Frame{}, headerErr(err)
	}
	if n > MaxBody {
		return Frame{}, ErrHeader
	}
	body := make([]byte, n)
	if rr, ok := r.(io.Reader); ok {
		if _, err := io.ReadFull(rr, body); err != nil {
			return Frame{}, shortErr(err)
		}
	} else {
		for i := range body {
			if body[i], err = r.ReadByte(); err != nil {
				return Frame{}, shortErr(err)
			}
		}
	}
	f := Frame{Type: tag >> 1, Body: body}
	if tag&1 == 1 {
		if f.Body, err = Decompress(body); err != nil {
			return f, err
		}
	}
	return f, nil
}

// NewReader wraps a stream for ReadFrame.
func NewReader(r io.Reader) *bufio.Reader { return bufio.NewReaderSize(r, 4096) }

// AppendFrame encodes msg as a frame of typ, compressed when that pays.
func AppendFrame(dst []byte, typ uint64, msg proto.Message) ([]byte, error) {
	body, err := proto.Marshal(msg)
	if err != nil {
		return dst, err
	}
	if len(body) > MaxBody {
		return dst, errors.New("ed3k: frame body above 1 MiB")
	}
	z := uint64(0)
	if c, ok := Compress(body); ok {
		body, z = c, 1
	}
	dst = binary.AppendUvarint(dst, typ<<1|z)
	dst = binary.AppendUvarint(dst, uint64(len(body)))
	return append(dst, body...), nil
}

// WriteFrame writes one frame to w.
func WriteFrame(w io.Writer, typ uint64, msg proto.Message) error {
	b, err := AppendFrame(nil, typ, msg)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// headerErr is ErrHeader, wrapping the stream's own error when there is one.
func headerErr(err error) error {
	if errors.Is(err, ErrHeader) || errors.Is(err, io.EOF) {
		return ErrHeader
	}
	return fmt.Errorf("%w: %w", ErrHeader, err)
}

// shortErr is ErrShort, wrapping the stream's own error when the stream failed
// rather than ended.
func shortErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrShort
	}
	return fmt.Errorf("%w: %w", ErrShort, err)
}

// prefixed hands out one byte already read, then reads from r.
type prefixed struct {
	first byte
	used  bool
	r     io.ByteReader
}

func (p *prefixed) ReadByte() (byte, error) {
	if !p.used {
		p.used = true
		return p.first, nil
	}
	return p.r.ReadByte()
}

// readVarint reads a protobuf varint of at most 10 bytes; longer-than-needed
// forms are accepted (§5.1).
func readVarint(r io.ByteReader) (uint64, error) {
	var x uint64
	for i := 0; i < 10; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		if i < 9 {
			x |= uint64(b&0x7f) << (7 * i)
		} else {
			if b > 1 {
				return 0, ErrHeader // overflows 64 bits
			}
			x |= uint64(b) << 63
		}
		if b < 0x80 {
			return x, nil
		}
	}
	return 0, ErrHeader
}
