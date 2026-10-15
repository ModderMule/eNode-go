//go:build unix

package handoff

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

// Kind is the type of one frame on the control stream.
type Kind uint8

const (
	// MsgReady: successor → predecessor, booted and ready to take over. Payload: the
	// successor's ProtocolVersion as a big-endian uint32.
	MsgReady Kind = iota + 1
	// MsgBegin: predecessor → successor, the transfer starts. Payload: the number of
	// sessions that will follow, as a big-endian uint32.
	MsgBegin
	// MsgData and MsgDataEnd carry the storage export, an opaque stream in chunks.
	MsgData
	MsgDataEnd
	// MsgSession is one encoded session. Its socket travels on the descriptor lane,
	// in the same order.
	MsgSession
	// MsgImported: successor → predecessor, everything is restored and nothing is
	// served yet.
	MsgImported
	// MsgCommit: predecessor → successor, the predecessor has let go; serve.
	MsgCommit
	// MsgAbort: either side gives up. Payload: the reason as text.
	MsgAbort
)

func (k Kind) String() string {
	switch k {
	case MsgReady:
		return "ready"
	case MsgBegin:
		return "begin"
	case MsgData:
		return "data"
	case MsgDataEnd:
		return "data-end"
	case MsgSession:
		return "session"
	case MsgImported:
		return "imported"
	case MsgCommit:
		return "commit"
	case MsgAbort:
		return "abort"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

const (
	// maxFrame bounds one frame. A session state is a few KiB, more with a pending
	// search page; storage arrives in dataChunk pieces.
	maxFrame = 64 << 20
	// dataChunk is the size of one MsgData frame.
	dataChunk = 1 << 20
	// fdBatch is how many descriptors one message on the descriptor lane carries,
	// under Linux's SCM_MAX_FD of 253.
	fdBatch = 64
)

// ErrAborted is returned when the other side sent MsgAbort.
var ErrAborted = errors.New("handoff aborted by the other process")

// Channel is the link between predecessor and successor: a control stream of
// framed messages, and a separate lane for socket descriptors.
//
// The descriptors get a socket of their own because ancillary data rides on the
// stream's bytes, and a reader that buffers ahead — as every frame reader does —
// could read a descriptor-carrying byte inside a larger read and lose track of
// which descriptors belong to which session. On the lane every message is one byte
// read with a one-byte buffer, so a read can only ever return one message.
type Channel struct {
	ctrl *net.UnixConn
	fds  *net.UnixConn
}

// NewChannel wraps the two ends of a socket pair.
func NewChannel(ctrl, fds *net.UnixConn) *Channel {
	return &Channel{ctrl: ctrl, fds: fds}
}

// Close closes both lanes.
func (c *Channel) Close() error {
	err := c.ctrl.Close()
	if ferr := c.fds.Close(); err == nil {
		err = ferr
	}
	return err
}

// SetDeadline bounds every read and write on both lanes until it is changed.
func (c *Channel) SetDeadline(t time.Time) {
	_ = c.ctrl.SetDeadline(t)
	_ = c.fds.SetDeadline(t)
}

// Send writes one frame.
func (c *Channel) Send(kind Kind, payload []byte) error {
	if len(payload) > maxFrame {
		return fmt.Errorf("handoff %s frame of %d bytes exceeds %d", kind, len(payload), maxFrame)
	}
	frame := make([]byte, 5+len(payload))
	frame[0] = byte(kind)
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	if _, err := c.ctrl.Write(frame); err != nil {
		return fmt.Errorf("handoff send %s: %w", kind, err)
	}
	return nil
}

// SendUint32 sends a frame whose payload is one big-endian uint32.
func (c *Channel) SendUint32(kind Kind, v uint32) error {
	return c.Send(kind, binary.BigEndian.AppendUint32(nil, v))
}

// Recv reads one frame.
func (c *Channel) Recv() (Kind, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.ctrl, hdr[:]); err != nil {
		return 0, nil, fmt.Errorf("handoff receive: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[1:5])
	if n > maxFrame {
		return 0, nil, fmt.Errorf("handoff receive: frame of %d bytes exceeds %d", n, maxFrame)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.ctrl, payload); err != nil {
		return 0, nil, fmt.Errorf("handoff receive %s payload: %w", Kind(hdr[0]), err)
	}
	return Kind(hdr[0]), payload, nil
}

// Expect reads one frame and requires it to be of kind want. MsgAbort from the
// other side is ErrAborted, with its reason.
func (c *Channel) Expect(want Kind) ([]byte, error) {
	kind, payload, err := c.Recv()
	if err != nil {
		return nil, err
	}
	if kind == want {
		return payload, nil
	}
	if kind == MsgAbort {
		return nil, fmt.Errorf("%w: %s", ErrAborted, payload)
	}
	return nil, fmt.Errorf("handoff: expected %s, got %s", want, kind)
}

// ExpectUint32 is Expect for a frame carrying one big-endian uint32.
func (c *Channel) ExpectUint32(want Kind) (uint32, error) {
	payload, err := c.Expect(want)
	if err != nil {
		return 0, err
	}
	if len(payload) != 4 {
		return 0, fmt.Errorf("handoff: %s payload is %d bytes, want 4", want, len(payload))
	}
	return binary.BigEndian.Uint32(payload), nil
}

// DataWriter returns a writer that sends what it is given as MsgData frames. The
// stream is ended with EndData.
func (c *Channel) DataWriter() io.Writer {
	return dataWriter{c}
}

// EndData ends the stream DataWriter started.
func (c *Channel) EndData() error {
	return c.Send(MsgDataEnd, nil)
}

// DataReader returns a reader over the MsgData frames up to MsgDataEnd, after
// which it reports io.EOF.
func (c *Channel) DataReader() io.Reader {
	return &dataReader{c: c}
}

// SendFiles passes the descriptors of files on the descriptor lane, in order. The
// files stay open; the receiver gets duplicates.
func (c *Channel) SendFiles(files []*os.File) error {
	for start := 0; start < len(files); start += fdBatch {
		batch := files[start:min(start+fdBatch, len(files))]
		fds := make([]int, 0, len(batch))
		for _, f := range batch {
			fd, err := rawFD(f)
			if err != nil {
				return fmt.Errorf("handoff send descriptors: %w", err)
			}
			fds = append(fds, fd)
		}
		n, oobn, err := c.fds.WriteMsgUnix([]byte{byte(len(batch))}, syscall.UnixRights(fds...), nil)
		if err != nil {
			return fmt.Errorf("handoff send descriptors: %w", err)
		}
		if n != 1 || oobn == 0 {
			return fmt.Errorf("handoff send descriptors: short write (%d, %d)", n, oobn)
		}
	}
	return nil
}

// RecvFiles receives n descriptors sent by SendFiles.
func (c *Channel) RecvFiles(n int) ([]*os.File, error) {
	out := make([]*os.File, 0, n)
	fail := func(err error) ([]*os.File, error) {
		for _, f := range out {
			_ = f.Close()
		}
		return nil, err
	}
	buf := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(fdBatch*4))
	for len(out) < n {
		_, oobn, flags, _, err := c.fds.ReadMsgUnix(buf, oob)
		if err != nil {
			return fail(fmt.Errorf("handoff receive descriptors: %w", err))
		}
		msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return fail(fmt.Errorf("handoff receive descriptors: %w", err))
		}
		var got []int
		for i := range msgs {
			fds, err := syscall.ParseUnixRights(&msgs[i])
			if err != nil {
				continue
			}
			got = append(got, fds...)
		}
		for _, fd := range got {
			syscall.CloseOnExec(fd)
			out = append(out, os.NewFile(uintptr(fd), "handoff-session"))
		}
		if flags&syscall.MSG_CTRUNC != 0 {
			return fail(errors.New("handoff receive descriptors: control message truncated"))
		}
		if len(got) != int(buf[0]) {
			return fail(fmt.Errorf("handoff receive descriptors: %d arrived, %d announced", len(got), buf[0]))
		}
	}
	return out, nil
}

type dataWriter struct{ c *Channel }

func (w dataWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), dataChunk)]
		if err := w.c.Send(MsgData, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

type dataReader struct {
	c    *Channel
	buf  []byte
	done bool
}

func (r *dataReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.done {
			return 0, io.EOF
		}
		kind, payload, err := r.c.Recv()
		if err != nil {
			return 0, err
		}
		switch kind {
		case MsgData:
			r.buf = payload
		case MsgDataEnd:
			r.done = true
		case MsgAbort:
			return 0, fmt.Errorf("%w: %s", ErrAborted, payload)
		default:
			return 0, fmt.Errorf("handoff: expected data, got %s", kind)
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// rawFD returns f's descriptor without f.Fd(), which would switch the socket to
// blocking mode — and the mode belongs to the socket, not to this duplicate, so the
// live connection this process still serves would block with it.
func rawFD(f *os.File) (int, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	fd := -1
	if err := rc.Control(func(d uintptr) { fd = int(d) }); err != nil {
		return 0, err
	}
	return fd, nil
}
