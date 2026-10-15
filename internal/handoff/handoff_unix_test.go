//go:build unix

package handoff

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// channelPair returns the two ends of a Channel, as Spawn and Init build them.
func channelPair(t *testing.T) (*Channel, *Channel) {
	t.Helper()
	ctrlA, ctrlB := unixPair(t)
	fdsA, fdsB := unixPair(t)
	a, b := NewChannel(ctrlA, fdsA), NewChannel(ctrlB, fdsB)
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	local, remote, err := socketPair("test")
	if err != nil {
		t.Fatal(err)
	}
	// Dup first: unixConnFromFD consumes the descriptor it is given, which remote
	// would otherwise close a second time when it is collected.
	fd, err := syscall.Dup(int(remote.Fd()))
	_ = remote.Close()
	if err != nil {
		t.Fatal(err)
	}
	other, err := unixConnFromFD(fd, "test")
	if err != nil {
		t.Fatal(err)
	}
	return local, other
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close()
		_ = s.Close()
	})
	return c.(*net.TCPConn), s.(*net.TCPConn)
}

// A listener handed in by a predecessor is adopted when the same network and
// address are bound, and keeps accepting on the same port. One nothing binds is
// closed by CloseUnclaimed.
func TestListenAdoptsInheritedSocket(t *testing.T) {
	orig, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := orig.Addr().String()
	f, err := orig.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	_ = orig.Close() // the duplicate keeps the socket bound
	sockets.inherit(socketKey("tcp4", addr), f)

	spare, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	spareFile, _ := spare.(*net.TCPListener).File()
	_ = spare.Close()
	sockets.inherit(socketKey("tcp4", "127.0.0.1:1"), spareFile)

	ln, err := Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("Listen %s: %v", addr, err)
	}
	defer ln.Close()
	t.Logf("input: inherited listener %s, output: adopted %s", addr, ln.Addr())
	if ln.Addr().String() != addr {
		t.Fatalf("adopted %s, want %s", ln.Addr(), addr)
	}
	go func() {
		if c, err := net.Dial("tcp4", addr); err == nil {
			_, _ = c.Write([]byte("hi"))
			_ = c.Close()
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept on adopted listener: %v", err)
	}
	got, _ := io.ReadAll(c)
	_ = c.Close()
	if string(got) != "hi" {
		t.Fatalf("read %q, want hi", got)
	}

	closed := CloseUnclaimed()
	t.Logf("output: closed unclaimed %v", closed)
	if len(closed) != 1 || closed[0] != socketKey("tcp4", "127.0.0.1:1") {
		t.Fatalf("CloseUnclaimed = %v, want the spare socket only", closed)
	}
}

// Frames, the chunked data stream and descriptors all cross the channel intact,
// and a passed socket is the same connection on the other side.
func TestChannelCarriesFramesDataAndSockets(t *testing.T) {
	a, b := channelPair(t)

	payload := bytes.Repeat([]byte("0123456789"), dataChunk/5) // two chunks
	clients := make([]*net.TCPConn, 0, fdBatch+3)
	files := make([]*os.File, 0, fdBatch+3)
	for range fdBatch + 3 {
		c, s := tcpPair(t)
		f, err := s.File()
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		files = append(files, f)
	}

	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		if err := a.SendUint32(MsgBegin, 7); err != nil {
			errs <- err
			return
		}
		if _, err := a.DataWriter().Write(payload); err != nil {
			errs <- err
			return
		}
		if err := a.EndData(); err != nil {
			errs <- err
			return
		}
		if err := a.Send(MsgSession, []byte("state")); err != nil {
			errs <- err
			return
		}
		errs <- a.SendFiles(files)
	}()

	n, err := b.ExpectUint32(MsgBegin)
	if err != nil || n != 7 {
		t.Fatalf("begin = %d, %v", n, err)
	}
	got, err := io.ReadAll(b.DataReader())
	if err != nil {
		t.Fatal(err)
	}
	st, err := b.Expect(MsgSession)
	if err != nil {
		t.Fatal(err)
	}
	received, err := b.RecvFiles(len(files))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	t.Logf("input: %d data bytes, session %q, %d sockets; output: %d bytes, %q, %d sockets",
		len(payload), "state", len(files), len(got), st, len(received))
	if !bytes.Equal(got, payload) || string(st) != "state" || len(received) != len(files) {
		t.Fatal("channel content differs")
	}
	for i, f := range received {
		conn, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatalf("socket %d: %v", i, err)
		}
		msg := []byte{byte(i)}
		if _, err := conn.Write(msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1)
		_ = clients[i].SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(clients[i], buf); err != nil || buf[0] != byte(i) {
			t.Fatalf("socket %d is not connection %d: %v %v", i, i, buf, err)
		}
		_ = conn.Close()
	}
	for _, f := range files {
		_ = f.Close()
	}
}

// Passing a socket must not switch it to blocking mode, which would break the
// deadlines of the connection the predecessor still serves until it commits.
func TestSendFilesKeepsSocketNonBlocking(t *testing.T) {
	a, b := channelPair(t)
	_, s := tcpPair(t)
	f, err := s.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	go func() { _ = a.SendFiles([]*os.File{f}) }()
	got, err := b.RecvFiles(1)
	if err != nil {
		t.Fatal(err)
	}
	_ = got[0].Close()
	_ = s.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	start := time.Now()
	_, err = s.Read(make([]byte, 1))
	t.Logf("output: read on the original after passing it returned %v after %s", err, time.Since(start).Round(time.Millisecond))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read = %v, want a deadline error: the socket went blocking", err)
	}
}

// fakeExporter and fakeImporter record what the protocol asks of each side.
type fakeExporter struct {
	mu       sync.Mutex
	calls    []string
	storage  []byte
	states   [][]byte
	files    []*os.File
	failSent bool
}

func (e *fakeExporter) note(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, s)
}

func (e *fakeExporter) Quiesce() error { e.note("quiesce"); return nil }
func (e *fakeExporter) Sessions() ([][]byte, []*os.File, error) {
	e.note("sessions")
	return e.states, e.files, nil
}
func (e *fakeExporter) ExportStorage(w io.Writer) error {
	e.note("export")
	_, err := w.Write(e.storage)
	return err
}
func (e *fakeExporter) Resume()  { e.note("resume") }
func (e *fakeExporter) Release() { e.note("release") }

type fakeImporter struct {
	calls     []string
	storage   []byte
	states    [][]byte
	files     []*os.File
	importErr error
}

func (i *fakeImporter) ImportStorage(r io.Reader) error {
	i.calls = append(i.calls, "import")
	// Reads only part of the stream, as a decoder that stops at its last value
	// may: Takeover must skip the rest before reading the sessions.
	buf := make([]byte, 3)
	n, _ := io.ReadFull(r, buf)
	i.storage = buf[:n]
	return i.importErr
}
func (i *fakeImporter) Restore(states [][]byte, files []*os.File) error {
	i.calls = append(i.calls, "restore")
	i.states, i.files = states, files
	return nil
}
func (i *fakeImporter) Start() { i.calls = append(i.calls, "start") }
func (i *fakeImporter) Abort() { i.calls = append(i.calls, "abort") }

var testTimeouts = Timeouts{Ready: 5 * time.Second, Transfer: 5 * time.Second}

func TestHandoverAndTakeoverComplete(t *testing.T) {
	parent, child := channelPair(t)
	_, s := tcpPair(t)
	f, err := s.File()
	if err != nil {
		t.Fatal(err)
	}
	exp := &fakeExporter{
		storage: []byte("storage-state"),
		states:  [][]byte{[]byte("session-1")},
		files:   []*os.File{f},
	}
	imp := &fakeImporter{}
	done := make(chan error, 1)
	go func() { done <- Takeover(child, imp, testTimeouts) }()

	err = Handover(&Successor{Channel: parent, exited: make(chan struct{})}, exp, testTimeouts)
	childErr := <-done
	t.Logf("input: storage %q, 1 session; output: parent=%v child=%v parentCalls=%v childCalls=%v",
		exp.storage, err, childErr, exp.calls, imp.calls)
	if err != nil || childErr != nil {
		t.Fatalf("handover: parent=%v child=%v", err, childErr)
	}
	if strings.Join(exp.calls, ",") != "quiesce,sessions,export,release" {
		t.Fatalf("parent calls %v", exp.calls)
	}
	if strings.Join(imp.calls, ",") != "import,restore,start" {
		t.Fatalf("child calls %v", imp.calls)
	}
	if string(imp.storage) != "sto" || len(imp.states) != 1 || string(imp.states[0]) != "session-1" || len(imp.files) != 1 {
		t.Fatalf("child received storage=%q states=%q files=%d", imp.storage, imp.states, len(imp.files))
	}
	_ = imp.files[0].Close()
}

// A successor that fails to import tells the predecessor, which goes back to
// serving; the successor never starts anything.
func TestHandoverResumesWhenSuccessorFails(t *testing.T) {
	parent, child := channelPair(t)
	exp := &fakeExporter{storage: []byte("x")}
	imp := &fakeImporter{importErr: errors.New("wrong engine")}
	done := make(chan error, 1)
	go func() { done <- Takeover(child, imp, testTimeouts) }()

	err := Handover(&Successor{Channel: parent, exited: make(chan struct{})}, exp, testTimeouts)
	childErr := <-done
	t.Logf("output: parent=%v child=%v parentCalls=%v childCalls=%v", err, childErr, exp.calls, imp.calls)
	if err == nil || childErr == nil {
		t.Fatal("a failed import must fail both sides")
	}
	if strings.Join(exp.calls, ",") != "quiesce,sessions,export,resume" {
		t.Fatalf("parent calls %v, want it resumed and never released", exp.calls)
	}
	for _, c := range imp.calls {
		if c == "start" {
			t.Fatal("the successor started serving after a failed import")
		}
	}
}

// A successor speaking another protocol version is refused before anything is
// parked.
func TestHandoverRefusesOtherProtocolVersion(t *testing.T) {
	parent, child := channelPair(t)
	exp := &fakeExporter{}
	go func() { _ = child.SendUint32(MsgReady, ProtocolVersion+1) }()
	err := Handover(&Successor{Channel: parent, exited: make(chan struct{})}, exp, testTimeouts)
	t.Logf("output: %v calls=%v", err, exp.calls)
	if err == nil || len(exp.calls) != 0 {
		t.Fatalf("err=%v calls=%v, want a refusal before quiesce", err, exp.calls)
	}
}

// A successor whose predecessor vanishes before committing must not serve: the
// predecessor may have resumed on the very same sockets.
func TestTakeoverWithoutCommitAborts(t *testing.T) {
	parent, child := channelPair(t)
	imp := &fakeImporter{}
	done := make(chan error, 1)
	go func() { done <- Takeover(child, imp, testTimeouts) }()
	if _, err := parent.ExpectUint32(MsgReady); err != nil {
		t.Fatal(err)
	}
	_ = parent.SendUint32(MsgBegin, 0)
	_ = parent.EndData()
	_ = parent.SendFiles(nil)
	if _, err := parent.Expect(MsgImported); err != nil {
		t.Fatal(err)
	}
	_ = parent.Close()
	err := <-done
	t.Logf("output: %v calls=%v", err, imp.calls)
	if err == nil || imp.calls[len(imp.calls)-1] != "abort" {
		t.Fatalf("err=%v calls=%v, want an abort", err, imp.calls)
	}
}

// Init adopts the descriptors named in the environment.
func TestInitAdoptsEnvironment(t *testing.T) {
	ctrl, ctrlRemote, err := socketPair("ctrl")
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	fds, fdsRemote, err := socketPair("fds")
	if err != nil {
		t.Fatal(err)
	}
	defer fds.Close()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lf, _ := ln.(*net.TCPListener).File()
	_ = ln.Close()
	ctrlFD, _ := syscall.Dup(int(ctrlRemote.Fd()))
	fdsFD, _ := syscall.Dup(int(fdsRemote.Fd()))
	lnFD, _ := syscall.Dup(int(lf.Fd()))
	_ = ctrlRemote.Close()
	_ = fdsRemote.Close()
	_ = lf.Close()
	key := socketKey("tcp4", ln.Addr().String())
	t.Setenv(envKey, `{"control":`+strconv.Itoa(ctrlFD)+`,"fds":`+strconv.Itoa(fdsFD)+`,"listeners":{"`+key+`":`+strconv.Itoa(lnFD)+`}}`)
	defer func() {
		childMu.Lock()
		childChannel = nil
		childMu.Unlock()
	}()

	if err := Init(); err != nil {
		t.Fatal(err)
	}
	_, stillSet := os.LookupEnv(envKey)
	t.Logf("output: Inherited=%t envStillSet=%t", Inherited(), stillSet)
	if !Inherited() || ParentChannel() == nil || stillSet {
		t.Fatal("Init did not adopt the handover environment")
	}
	adopted, err := Listen("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = adopted.Close()
	_ = ParentChannel().Close()
}
