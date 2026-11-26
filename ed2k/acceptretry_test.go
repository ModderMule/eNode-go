package ed2k

import (
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// scriptedListener returns its errors in order, then one connection, then
// net.ErrClosed.
type scriptedListener struct {
	mu    sync.Mutex
	errs  []error
	conn  net.Conn
	calls int
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		return nil, err
	}
	if l.conn != nil {
		c := l.conn
		l.conn = nil
		return c, nil
	}
	return nil, &net.OpError{Op: "accept", Net: "tcp", Err: net.ErrClosed}
}
func (l *scriptedListener) Close() error { return nil }
func (l *scriptedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4661}
}

// TestAcceptRetriesTemporaryErrors pins that running out of file descriptors pauses
// the accept loop instead of ending it, and that a closed listener still ends it.
func TestAcceptRetriesTemporaryErrors(t *testing.T) {
	emfile := &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	ln := &scriptedListener{errs: []error{emfile, emfile}, conn: &mockConn{}}
	handled := make(chan net.Conn, 1)
	done := make(chan struct{})
	start := time.Now()
	go func() {
		acceptTCP(ln, TCPServerConfig{}, func(c net.Conn) { handled <- c })
		close(done)
	}()
	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("no connection accepted after two EMFILE errors")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept loop did not end on a closed listener")
	}
	t.Logf("input: accept errors EMFILE, EMFILE, then a conn, then closed; output: %d Accept calls in %s",
		ln.calls, time.Since(start).Round(time.Millisecond))
	if ln.calls != 4 {
		t.Fatalf("Accept called %d times, want 4", ln.calls)
	}
}

// TestAcceptTemporaryClassifies pins which Accept errors are retried.
func TestAcceptTemporaryClassifies(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"EMFILE", &net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.EMFILE)}, true},
		{"ENFILE", &net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.ENFILE)}, true},
		{"closed listener", &net.OpError{Op: "accept", Err: net.ErrClosed}, false},
		{"plain error", errors.New("boom"), false},
	}
	for _, tc := range cases {
		got := acceptTemporary(tc.err)
		t.Logf("input: %s (%v), output: retry=%t", tc.name, tc.err, got)
		if got != tc.want {
			t.Errorf("%s: retry=%t, want %t", tc.name, got, tc.want)
		}
	}
	var d time.Duration
	var steps []time.Duration
	for range 10 {
		d = nextAcceptDelay(d)
		steps = append(steps, d)
	}
	t.Logf("input: 10 retries, output: delays %v", steps)
	if steps[0] != 5*time.Millisecond || steps[9] != time.Second {
		t.Fatalf("delays %v, want 5ms rising to a 1s cap", steps)
	}
}
