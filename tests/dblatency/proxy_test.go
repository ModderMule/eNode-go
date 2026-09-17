// Package dblatency measures what the SQL and MongoDB storage engines cost over a
// network link. A TCP proxy sits between an engine and a real database container,
// parses the client→server wire protocol to count the requests that wait for a reply
// (round-trips), and can hold every chunk in each direction for half a configured RTT
// to model a database in another rack or datacenter.
//
// The round-trip counts are exact and independent of the host. The wall-clock figures
// depend on the machine and on Docker, and are there to show the shape, not to be
// compared across runs. Findings are written up in docs/remote-database.local.md.
//
// Gated on ENODE_INTEGRATION=1, matching the rest of the suite; skipped without Docker.
package dblatency

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// frameParser classifies the client→server byte stream of one wire protocol.
type frameParser interface {
	// parse consumes as many complete frames from the front of buf as it can, calling
	// emit once per frame, and returns how many bytes those frames used.
	parse(buf []byte, emit func(label string, roundTrip bool)) int
}

// rttProxy forwards TCP connections to backend, counting frames with parser.
type rttProxy struct {
	ln      net.Listener
	backend string
	parser  frameParser
	// halfRTT is the one-way delay, in nanoseconds, applied to every chunk.
	halfRTT atomic.Int64

	mu         sync.Mutex
	labels     map[string]int
	roundTrips int
	conns      int
}

func startProxy(t *testing.T, backend string, parser frameParser) *rttProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &rttProxy{ln: ln, backend: backend, parser: parser, labels: map[string]int{}}
	t.Cleanup(func() { _ = ln.Close() })
	go p.serve()
	return p
}

func (p *rttProxy) addr() string { return p.ln.Addr().String() }

// setRTT sets the round-trip time the proxy adds, split evenly across both directions.
func (p *rttProxy) setRTT(rtt time.Duration) { p.halfRTT.Store(int64(rtt / 2)) }

func (p *rttProxy) serve() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.conns++
		p.mu.Unlock()
		go p.handle(client)
	}
}

func (p *rttProxy) handle(client net.Conn) {
	defer client.Close()
	server, err := net.Dial("tcp", p.backend)
	if err != nil {
		return
	}
	defer server.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); p.pipe(server, client, true) }()
	go func() { defer wg.Done(); p.pipe(client, server, false) }()
	wg.Wait()
}

// pipe copies src to dst behind a constant delay. Each chunk is released at its
// arrival time plus halfRTT rather than after a sleep per chunk, so a reply split over
// several reads is delayed once — like a real link — instead of once per read.
func (p *rttProxy) pipe(dst, src net.Conn, parse bool) {
	type chunk struct {
		at time.Time
		b  []byte
	}
	queue := make(chan chunk, 4096)
	done := make(chan struct{})
	go func() {
		defer close(done)
		failed := false
		for c := range queue {
			if failed {
				continue // keep draining so the reader never blocks
			}
			if d := time.Until(c.at); d > 0 {
				time.Sleep(d)
			}
			if _, err := dst.Write(c.b); err != nil {
				failed = true
			}
		}
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	var pending []byte
	buf := make([]byte, 64<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			b := append([]byte(nil), buf[:n]...)
			if parse {
				pending = append(pending, b...)
				used := p.parser.parse(pending, p.record)
				pending = append([]byte(nil), pending[used:]...)
			}
			queue <- chunk{at: time.Now().Add(time.Duration(p.halfRTT.Load())), b: b}
		}
		if err != nil {
			break
		}
	}
	close(queue)
	<-done
}

func (p *rttProxy) record(label string, roundTrip bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.labels[label]++
	if roundTrip {
		p.roundTrips++
	}
}

// proxyCounts is a snapshot of everything the proxy has seen.
type proxyCounts struct {
	labels     map[string]int
	roundTrips int
	conns      int
}

func (p *rttProxy) snapshot() proxyCounts {
	p.mu.Lock()
	defer p.mu.Unlock()
	labels := make(map[string]int, len(p.labels))
	for k, v := range p.labels {
		labels[k] = v
	}
	return proxyCounts{labels: labels, roundTrips: p.roundTrips, conns: p.conns}
}

// since returns what happened after before was taken.
func (c proxyCounts) since(before proxyCounts) proxyCounts {
	out := proxyCounts{labels: map[string]int{}, roundTrips: c.roundTrips - before.roundTrips, conns: c.conns - before.conns}
	for k, v := range c.labels {
		if d := v - before.labels[k]; d > 0 {
			out.labels[k] = d
		}
	}
	return out
}

func (c proxyCounts) String() string {
	keys := make([]string, 0, len(c.labels))
	for k := range c.labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, c.labels[k]))
	}
	s := fmt.Sprintf("%3d round-trips  [%s]", c.roundTrips, strings.Join(parts, " "))
	if c.conns > 0 {
		s += fmt.Sprintf("  (+%d new connection)", c.conns)
	}
	return s
}

// mysqlFrames parses MySQL client packets: a 3-byte little-endian length and a
// sequence id, then the payload. A command starts a new sequence, so seq 0 with a
// command byte is one request; handshake and auth packets carry other sequence ids.
type mysqlFrames struct{}

func (mysqlFrames) parse(buf []byte, emit func(string, bool)) int {
	used := 0
	for len(buf)-used >= 4 {
		n := int(buf[used]) | int(buf[used+1])<<8 | int(buf[used+2])<<16
		if len(buf)-used < 4+n {
			break
		}
		if seq := buf[used+3]; seq == 0 && n > 0 {
			switch cmd := buf[used+4]; cmd {
			case 0x03:
				emit("COM_QUERY", true)
			case 0x16:
				emit("COM_STMT_PREPARE", true)
			case 0x17:
				emit("COM_STMT_EXECUTE", true)
			case 0x19:
				emit("COM_STMT_CLOSE", false) // no reply
			case 0x01:
				emit("COM_QUIT", false)
			case 0x0e:
				emit("COM_PING", true)
			default:
				emit(fmt.Sprintf("COM_0x%02x", cmd), true)
			}
		}
		used += 4 + n
	}
	return used
}

// mongoFrames parses MongoDB wire messages: a 16-byte header (length, requestID,
// responseTo, opCode) and a body. An OP_MSG is labelled with its command name, the
// first key of its body section.
//
// The driver's own traffic — handshakes, the heartbeat and RTT monitors, auth, and
// session cleanup — is labelled but not counted: it runs on its own schedule, not per
// engine call. A message flagged moreToCome expects no reply and is not a round-trip.
type mongoFrames struct{}

var mongoDriverCommands = map[string]bool{
	"hello": true, "isMaster": true, "ismaster": true, "ping": true,
	"saslStart": true, "saslContinue": true, "endSessions": true, "buildInfo": true,
}

func (mongoFrames) parse(buf []byte, emit func(string, bool)) int {
	used := 0
	for len(buf)-used >= 16 {
		n := int(binary.LittleEndian.Uint32(buf[used:]))
		if n < 16 || len(buf)-used < n {
			break
		}
		msg := buf[used : used+n]
		switch opCode := binary.LittleEndian.Uint32(msg[12:]); opCode {
		case 2013: // OP_MSG
			name, moreToCome := opMsgCommand(msg[16:])
			emit(name, !moreToCome && !mongoDriverCommands[name])
		case 2004: // OP_QUERY: only the legacy handshake uses it
			emit("OP_QUERY", false)
		default:
			emit(fmt.Sprintf("opCode_%d", opCode), true)
		}
		used += n
	}
	return used
}

// opMsgCommand returns the command name of an OP_MSG body and its moreToCome flag.
func opMsgCommand(body []byte) (string, bool) {
	if len(body) < 5 {
		return "?", false
	}
	flags := binary.LittleEndian.Uint32(body)
	moreToCome := flags&0x2 != 0
	end := len(body)
	if flags&0x1 != 0 { // checksumPresent
		end -= 4
	}
	for pos := 4; pos < end; {
		kind := body[pos]
		pos++
		switch kind {
		case 0: // body: one BSON document whose first element names the command
			if pos+5 > end {
				return "?", moreToCome
			}
			keyStart := pos + 5 // int32 length, element type byte
			keyEnd := keyStart
			for keyEnd < end && body[keyEnd] != 0 {
				keyEnd++
			}
			return string(body[keyStart:keyEnd]), moreToCome
		case 1: // document sequence: int32 size (inclusive), identifier, documents
			if pos+4 > end {
				return "?", moreToCome
			}
			pos += int(binary.LittleEndian.Uint32(body[pos:]))
		default:
			return "?", moreToCome
		}
	}
	return "?", moreToCome
}
