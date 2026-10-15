//go:build unix

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"enode/ed2k"
)

// e2eClient is a plaintext ed2k client on a real socket.
type e2eClient struct {
	t    *testing.T
	conn net.Conn
}

func dialE2E(t *testing.T, addr string) *e2eClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &e2eClient{t: t, conn: conn}
}

func (c *e2eClient) frame(items []ed2k.PacketItem) []byte {
	c.t.Helper()
	wire, err := ed2k.MakePacket(ed2k.PrED2K, items)
	if err != nil {
		c.t.Fatal(err)
	}
	return wire.Bytes()
}

func (c *e2eClient) write(b []byte) {
	c.t.Helper()
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

// expect reads frames until one with opcode arrives and returns its payload.
func (c *e2eClient) expect(opcode uint8) []byte {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	for range 30 {
		hdr := make([]byte, ed2k.PacketHeaderSize)
		if _, err := io.ReadFull(c.conn, hdr); err != nil {
			c.t.Fatalf("waiting for opcode 0x%02x: %v", opcode, err)
		}
		payload := make([]byte, binary.LittleEndian.Uint32(hdr[1:5])-1)
		if _, err := io.ReadFull(c.conn, payload); err != nil {
			c.t.Fatalf("waiting for opcode 0x%02x: %v", opcode, err)
		}
		if hdr[5] == opcode {
			return payload
		}
	}
	c.t.Fatalf("no opcode 0x%02x in 30 frames", opcode)
	return nil
}

func (c *e2eClient) login(hash []byte, port uint16) uint32 {
	c.t.Helper()
	c.write(c.frame([]ed2k.PacketItem{
		{Type: ed2k.TypeUint8, Value: ed2k.OpLoginRequest},
		{Type: ed2k.TypeHash, Value: hash},
		{Type: ed2k.TypeUint32, Value: uint32(0)},
		{Type: ed2k.TypeUint16, Value: port},
		{Type: ed2k.TypeTags, Value: []ed2k.Tag{}},
	}))
	return binary.LittleEndian.Uint32(c.expect(ed2k.OpIDChange))
}

func e2eGetSources(hash []byte, size uint32) []ed2k.PacketItem {
	return []ed2k.PacketItem{
		{Type: ed2k.TypeUint8, Value: ed2k.OpGetSources},
		{Type: ed2k.TypeHash, Value: hash},
		{Type: ed2k.TypeUint32, Value: size},
	}
}

// firstSource reads an OP_FOUNDSOURCES payload: the count and the first source.
func firstSource(payload []byte) (count int, id uint32, port uint16) {
	count = int(payload[16])
	if count == 0 {
		return 0, 0, 0
	}
	return count, binary.LittleEndian.Uint32(payload[17:21]), binary.LittleEndian.Uint16(payload[21:23])
}

func readPID(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	return pid
}

func alive(pid int) bool {
	return pid > 0 && syscall.Kill(pid, 0) == nil
}

// The real thing, end to end: a built enode binary serving a client is sent SIGUSR2
// twice, the second time after its binary was replaced the way update.sh replaces
// it. Each time a new process takes over and the old one exits, and the client
// — never reconnecting — finishes a packet it started before the handover, gets its
// sources from the new process, and a new client finds the file it published.
func TestHandoffKeepsClientConnected(t *testing.T) {
	s := startE2EServer(t, "storage:\n  engine: memory\n")
	s.exerciseHandoffs(2)
	s.requireLog("handed over to pid", "took over ")
	s.stop()
}

// handoff.memory "file": the index goes through a file next to the snapshot file
// instead of the socket, and the file is gone once the handover is done.
func TestHandoffThroughFile(t *testing.T) {
	s := startE2EServer(t, `storage:
  engine: memory
  snapshot:
    enabled: false
    file: "data/storage.gob"
handoff:
  memory: file
`)
	s.exerciseHandoffs(1)
	s.requireLog("index written to", "took over ")
	handoffFile := filepath.Join(s.dir, "data", "storage.gob.handoff")
	if _, err := os.Stat(handoffFile); !os.IsNotExist(err) {
		t.Fatalf("handoff file left behind: %v", err)
	}
	s.stop()
}

// handoff.memory "off": SIGUSR2 is refused, the reason lands in the status file
// update.sh reads, and the server carries on serving the same sessions.
func TestHandoffRefusedWhenOff(t *testing.T) {
	s := startE2EServer(t, "storage:\n  engine: memory\nhandoff:\n  memory: off\n")
	pid := s.cmd.Process.Pid
	status := handoffStatusPath(s.pidFile)
	if err := syscall.Kill(pid, syscall.SIGUSR2); err != nil {
		t.Fatal(err)
	}
	s.waitUntil("the refusal in the status file", 30*time.Second, func() bool {
		raw, err := os.ReadFile(status)
		return err == nil && len(raw) > 0
	})
	raw, _ := os.ReadFile(status)
	t.Logf("input: SIGUSR2 with handoff.memory off; output: status %q, pid file %d", strings.TrimSpace(string(raw)), readPID(s.pidFile))
	if !strings.Contains(string(raw), `handoff.memory is "off"`) {
		t.Fatalf("status file says %q", raw)
	}
	if !alive(pid) || readPID(s.pidFile) != pid {
		t.Fatal("the server stopped serving after a refused handover")
	}
	s.client.write(s.ask)
	if n, gotID, _ := firstSource(s.client.expect(ed2k.OpFoundSources)); n != 1 || gotID != s.clientID {
		t.Fatalf("after the refusal: %d sources, first %d; want the client %d", n, gotID, s.clientID)
	}
	s.stop()
}

// The mysql engine against the project's MariaDB container
// (scripts/docker-mariadb.sh, port 13306 or ENODE_TEST_MYSQL_PORT). Only the
// offered counts cross; the successor must keep the rows online instead of resetting
// them at Init, or the handed-over client would vanish from every source list.
func TestHandoffMySQL(t *testing.T) {
	if os.Getenv("ENODE_INTEGRATION") != "1" {
		t.Skip("set ENODE_INTEGRATION=1 and start scripts/docker-mariadb.sh")
	}
	port := os.Getenv("ENODE_TEST_MYSQL_PORT")
	if port == "" {
		port = "13306"
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 2*time.Second); err != nil {
		t.Skipf("no MariaDB on 127.0.0.1:%s (scripts/docker-mariadb.sh): %v", port, err)
	} else {
		_ = c.Close()
	}
	schema, err := filepath.Abs(filepath.Join("..", "..", "misc", "enode.sql"))
	if err != nil {
		t.Fatal(err)
	}
	s := startE2EServer(t, fmt.Sprintf(`storage:
  engine: mysql
  mysql:
    host: 127.0.0.1
    port: %s
    user: enode
    pass: password
    database: enode
    schemaFile: %q
`, port, schema))
	s.exerciseHandoffs(2)
	s.requireLog("handed over to pid", "took over ")
	s.stop()
}

// TestHandoffMongoDB is TestHandoffKeepsClientConnected on the mongodb engine,
// against the database of scripts/docker-mongodb.sh.
func TestHandoffMongoDB(t *testing.T) {
	if os.Getenv("ENODE_INTEGRATION") != "1" {
		t.Skip("set ENODE_INTEGRATION=1 and start scripts/docker-mongodb.sh")
	}
	port := os.Getenv("ENODE_TEST_MONGODB_PORT")
	if port == "" {
		port = "37017"
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 2*time.Second); err != nil {
		t.Skipf("no MongoDB on 127.0.0.1:%s (scripts/docker-mongodb.sh): %v", port, err)
	} else {
		_ = c.Close()
	}
	s := startE2EServer(t, fmt.Sprintf(`storage:
  engine: mongodb
  mongodb:
    host: 127.0.0.1
    port: %s
    database: enode
`, port))
	s.exerciseHandoffs(2)
	s.requireLog("handed over to pid", "took over ")
	s.stop()
}

// e2eServer is a built enode binary serving one logged-in client that published
// one file.
type e2eServer struct {
	t       *testing.T
	dir     string
	bin     string
	pidFile string
	logFile string
	addr    string
	cmd     *exec.Cmd
	exited  chan struct{}

	client     *e2eClient
	clientID   uint32
	clientPort uint16
	file       []byte
	ask        []byte
}

// startE2EServer builds the binary, starts it with storageYAML appended to a
// minimal config, and logs a client in that publishes one file. Hashes are random:
// a database engine keeps rows from earlier runs.
func startE2EServer(t *testing.T, storageYAML string) *e2eServer {
	t.Helper()
	if testing.Short() {
		t.Skip("builds and runs the server binary")
	}
	dir := t.TempDir()
	s := &e2eServer{t: t, dir: dir, bin: filepath.Join(dir, "enode"),
		pidFile: filepath.Join(dir, "enode.pid"), logFile: filepath.Join(dir, "enode.log")}
	build := exec.Command("go", "build", "-o", s.bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	tcpPort, udpPort := freePort(t), freePort(t)
	configPath := filepath.Join(dir, "enode.config.yaml")
	config := fmt.Sprintf(`
name: "handoff test"
address: "127.0.0.1"
dynIp: "127.0.0.1"
supportCrypt: false
logLevel: "info"
logFile: %q
pidFile: %q
tcp:
  port: %d
  portObfuscated: %d
  allowLowIDs: true
udp:
  port: %d
  portObfuscated: %d
  serverKey: 305419896
natTraversal:
  enabled: false
gossip:
  enabled: false
ipv6:
  enabled: false
admin:
  bindIP: "127.0.0.1"
  port: %d
  checkUpdates: false
`, s.logFile, s.pidFile, tcpPort, tcpPort+1, udpPort, udpPort+1, freePort(t)) + storageYAML
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			s.dumpLog()
		}
	})

	s.cmd = exec.Command(s.bin, "-config", configPath)
	s.cmd.Dir = dir
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s.exited = make(chan struct{})
	go func() { _ = s.cmd.Wait(); close(s.exited) }()
	t.Cleanup(func() {
		for _, pid := range []int{readPID(s.pidFile), s.cmd.Process.Pid} {
			if alive(pid) {
				_ = syscall.Kill(pid, syscall.SIGTERM)
			}
		}
	})
	s.waitUntil("the server to write its pid file", 60*time.Second, func() bool { return readPID(s.pidFile) == s.cmd.Process.Pid })

	s.addr = fmt.Sprintf("127.0.0.1:%d", tcpPort)
	s.client = dialE2E(t, s.addr)
	// A closed port: the dial-back is refused at once, so the client is a LowID.
	s.clientPort = freePort(t)
	s.clientID = s.client.login(randomHash(t), s.clientPort)
	s.file = randomHash(t)
	offer := []ed2k.PacketItem{
		{Type: ed2k.TypeUint8, Value: ed2k.OpOfferFiles},
		{Type: ed2k.TypeUint32, Value: uint32(1)},
	}
	ed2k.AddFile(&offer, ed2k.SharedFile{Name: "survives restarts.mkv", Size: 123456, Hash: s.file,
		SourceID: ed2k.ValCompleteID, SourcePort: ed2k.ValCompletePort, Completed: 1, Sources: 1})
	s.client.write(s.client.frame(offer))
	s.ask = s.client.frame(e2eGetSources(s.file, 123456))
	// A database engine stores the offer after the read loop has moved on, so the
	// first answer may come before it.
	s.waitUntil("the offer to be stored", 10*time.Second, func() bool {
		s.client.write(s.ask)
		n, gotID, _ := firstSource(s.client.expect(ed2k.OpFoundSources))
		return n == 1 && gotID == s.clientID
	})
	t.Logf("input: client id=%d port=%d published %x on pid %d", s.clientID, s.clientPort, s.file, s.cmd.Process.Pid)
	return s
}

// exerciseHandoffs hands the server over rounds times; from the second round on,
// its binary is replaced first, the way update.sh replaces it. Each round the
// client sends half a request before the handover and the rest after it, and must
// be answered on the same socket; then a new client must find the file.
func (s *e2eServer) exerciseHandoffs(rounds int) {
	t := s.t
	t.Helper()
	prev := s.cmd.Process.Pid
	for round := 1; round <= rounds; round++ {
		if round > 1 {
			raw, err := os.ReadFile(s.bin)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(s.bin); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(s.bin, raw, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		s.client.write(s.ask[:4])
		start := time.Now()
		if err := syscall.Kill(prev, syscall.SIGUSR2); err != nil {
			t.Fatal(err)
		}
		s.waitUntil(fmt.Sprintf("pid %d to exit after handing over", prev), 60*time.Second, func() bool {
			if prev == s.cmd.Process.Pid {
				select {
				case <-s.exited:
					return true
				default:
					return false
				}
			}
			return !alive(prev)
		})
		next := readPID(s.pidFile)
		s.waitUntil("the successor to write the pid file", 10*time.Second, func() bool {
			next = readPID(s.pidFile)
			return next != prev && alive(next)
		})
		s.client.write(s.ask[4:])
		n, gotID, gotPort := firstSource(s.client.expect(ed2k.OpFoundSources))
		t.Logf("round %d: pid %d → %d in %s; same socket answered: %d source(s), first %d:%d",
			round, prev, next, time.Since(start).Round(time.Millisecond), n, gotID, gotPort)
		if n != 1 || gotID != s.clientID || gotPort != s.clientPort {
			t.Fatalf("round %d: %d sources, first %d:%d; want the client %d:%d", round, n, gotID, gotPort, s.clientID, s.clientPort)
		}

		other := dialE2E(t, s.addr)
		other.login(randomHash(t), freePort(t))
		other.write(other.frame(e2eGetSources(s.file, 123456)))
		if n, gotID, _ := firstSource(other.expect(ed2k.OpFoundSources)); n != 1 || gotID != s.clientID {
			t.Fatalf("round %d: a new client sees %d sources, first %d; want the handed-over client", round, n, gotID)
		}
		_ = other.conn.Close()
		prev = next
	}
	for _, line := range strings.Split(s.log(), "\n") {
		if strings.Contains(line, "handoff:") || strings.Contains(line, "handed over") {
			t.Logf("log: %s", line)
		}
	}
}

// stop ends whichever process serves now and checks it cleaned up.
func (s *e2eServer) stop() {
	t := s.t
	t.Helper()
	pid := readPID(s.pidFile)
	_ = syscall.Kill(pid, syscall.SIGTERM)
	s.waitUntil("the last server to stop", 30*time.Second, func() bool { return !alive(pid) })
	if _, err := os.Stat(s.pidFile); !os.IsNotExist(err) {
		t.Fatalf("pid file left behind after a clean stop: %v", err)
	}
}

func (s *e2eServer) requireLog(want ...string) {
	s.t.Helper()
	raw := s.log()
	for _, w := range want {
		if !strings.Contains(raw, w) {
			s.t.Fatalf("log lacks %q", w)
		}
	}
}

func (s *e2eServer) waitUntil(what string, d time.Duration, cond func() bool) {
	s.t.Helper()
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	s.t.Fatalf("timed out waiting for %s", what)
}

func (s *e2eServer) log() string {
	raw, _ := os.ReadFile(s.logFile)
	return string(raw)
}

func (s *e2eServer) dumpLog() {
	s.t.Logf("server log:\n%s", s.log())
}

func randomHash(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
