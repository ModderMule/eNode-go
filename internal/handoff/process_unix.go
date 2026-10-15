//go:build unix

package handoff

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// envKey carries the successor's half of the handover: which inherited descriptor
// is the control lane, which the descriptor lane, and which listener is which.
const envKey = "ENODE_HANDOFF"

// childSpec is envKey's JSON value.
type childSpec struct {
	Control   int            `json:"control"`
	FDs       int            `json:"fds"`
	Listeners map[string]int `json:"listeners"`
}

var (
	childMu      sync.Mutex
	childChannel *Channel
)

// Init adopts what a predecessor passed in, if this process was started by a
// handover. Call it once, first thing in main: the inherited sockets must be in the
// registry before anything binds.
func Init() error {
	raw, ok := os.LookupEnv(envKey)
	if !ok {
		return nil
	}
	// Unset at once: a process this one starts later must not believe it was
	// started by a handover.
	_ = os.Unsetenv(envKey)
	var spec childSpec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		return fmt.Errorf("handoff: bad %s: %w", envKey, err)
	}
	ctrl, err := unixConnFromFD(spec.Control, "handoff-control")
	if err != nil {
		return fmt.Errorf("handoff: control lane: %w", err)
	}
	fds, err := unixConnFromFD(spec.FDs, "handoff-fds")
	if err != nil {
		_ = ctrl.Close()
		return fmt.Errorf("handoff: descriptor lane: %w", err)
	}
	for key, fd := range spec.Listeners {
		syscall.CloseOnExec(fd)
		sockets.inherit(key, os.NewFile(uintptr(fd), key))
	}
	childMu.Lock()
	childChannel = NewChannel(ctrl, fds)
	childMu.Unlock()
	return nil
}

// Inherited reports whether this process was started by a handover, so it must
// take over from its predecessor rather than start from nothing.
func Inherited() bool {
	childMu.Lock()
	defer childMu.Unlock()
	return childChannel != nil
}

// Supported reports whether this platform can hand over.
func Supported() bool { return true }

// ParentChannel returns the link to the predecessor, or nil when there is none.
func ParentChannel() *Channel {
	childMu.Lock()
	defer childMu.Unlock()
	return childChannel
}

// Successor is a process started to take over from this one.
type Successor struct {
	*Channel
	cmd    *exec.Cmd
	exited chan struct{}
	err    error
}

// SpawnConfig is how to start a successor.
type SpawnConfig struct {
	// Path is the executable — normally the path this process was started from,
	// where an update has put the new binary.
	Path string
	Args []string
	Env  []string
	Dir  string
	// Stdout and Stderr default to the null device.
	Stdout, Stderr *os.File
}

// Spawn starts a successor, handing it every registered socket and the two ends of
// the link. The successor runs in a session of its own, so it outlives this process
// and the terminal this one may have been started from.
func Spawn(cfg SpawnConfig) (*Successor, error) {
	ctrlLocal, ctrlRemote, err := socketPair("handoff-control")
	if err != nil {
		return nil, err
	}
	fdsLocal, fdsRemote, err := socketPair("handoff-fds")
	if err != nil {
		_ = ctrlLocal.Close()
		_ = ctrlRemote.Close()
		return nil, err
	}
	keys, files := sockets.files()
	closeAll := func() {
		_ = ctrlRemote.Close()
		_ = fdsRemote.Close()
		for _, f := range files {
			_ = f.Close()
		}
	}

	// ExtraFiles[i] is descriptor 3+i in the child.
	spec := childSpec{Control: 3, FDs: 4, Listeners: make(map[string]int, len(keys))}
	extra := []*os.File{ctrlRemote, fdsRemote}
	for i, k := range keys {
		spec.Listeners[k] = 5 + i
		extra = append(extra, files[i])
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		closeAll()
		_ = ctrlLocal.Close()
		_ = fdsLocal.Close()
		return nil, err
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		closeAll()
		_ = ctrlLocal.Close()
		_ = fdsLocal.Close()
		return nil, err
	}
	defer devNull.Close()

	cmd := exec.Command(cfg.Path, cfg.Args...)
	cmd.Env = append(append([]string(nil), cfg.Env...), envKey+"="+string(raw))
	cmd.Dir = cfg.Dir
	cmd.ExtraFiles = extra
	cmd.Stdin = devNull
	cmd.Stdout, cmd.Stderr = devNull, devNull
	if cfg.Stdout != nil {
		cmd.Stdout = cfg.Stdout
	}
	if cfg.Stderr != nil {
		cmd.Stderr = cfg.Stderr
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = cmd.Start()
	// os/exec takes each ExtraFile's descriptor through File.Fd, which puts the
	// socket into blocking mode — and the mode is shared with the copy this process
	// still serves on, whose deadlines then stop working. Put it back either way.
	restoreNonblock()
	closeAll()
	if err != nil {
		_ = ctrlLocal.Close()
		_ = fdsLocal.Close()
		return nil, fmt.Errorf("handoff: start %s: %w", cfg.Path, err)
	}

	s := &Successor{
		Channel: NewChannel(ctrlLocal, fdsLocal),
		cmd:     cmd,
		exited:  make(chan struct{}),
	}
	go func() {
		s.err = cmd.Wait()
		close(s.exited)
	}()
	return s, nil
}

// Pid is the successor's process id.
func (s *Successor) Pid() int {
	if s.cmd == nil {
		return 0
	}
	return s.cmd.Process.Pid
}

// Kill stops a successor that is not to take over, and waits for it to be gone, so
// it can never touch a socket the caller goes back to serving. A Successor without
// a process — a test's — only has its link closed.
func (s *Successor) Kill() {
	if s.cmd != nil {
		_ = s.cmd.Process.Kill()
		select {
		case <-s.exited:
		case <-time.After(10 * time.Second):
		}
	}
	_ = s.Close()
}

// Exited is closed once the successor has exited.
func (s *Successor) Exited() <-chan struct{} { return s.exited }

// socketPair returns a connected local end and a remote end to pass to a child.
func socketPair(name string) (*net.UnixConn, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("handoff: socketpair: %w", err)
	}
	syscall.CloseOnExec(fds[0])
	syscall.CloseOnExec(fds[1])
	local, err := unixConnFromFD(fds[0], name)
	if err != nil {
		_ = syscall.Close(fds[1])
		return nil, nil, err
	}
	return local, os.NewFile(uintptr(fds[1]), name), nil
}

// unixConnFromFD adopts descriptor fd as a *net.UnixConn, consuming it.
func unixConnFromFD(fd int, name string) (*net.UnixConn, error) {
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		return nil, fmt.Errorf("descriptor %d is not open", fd)
	}
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		return nil, errors.New("not a unix socket")
	}
	return uc, nil
}

// restoreNonblock puts every registered socket back into non-blocking mode.
func restoreNonblock() {
	for _, s := range sockets.liveSockets() {
		sc, ok := s.(syscall.Conn)
		if !ok {
			continue
		}
		rc, err := sc.SyscallConn()
		if err != nil {
			continue
		}
		_ = rc.Control(func(fd uintptr) { _ = syscall.SetNonblock(int(fd), true) })
	}
}
