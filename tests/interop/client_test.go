package interop

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"enode/ed2k"
)

// A minimal eD2K client, deliberately hand-rolled rather than built from the server's own
// packet helpers.
//
// The point of the OP_SERVERLIST assertion is to see what a *client* receives, so encoding
// the request and decoding the reply with the same code under test would make the check
// circular: a byte-order or framing mistake would cancel out. These bytes are laid down
// from the wire format as documented in docs/server-client-communication.md and pinned by
// ed2k/serverlist_ipv6_test.go — a v4 entry is a.b.c.d then a little-endian port, and the
// trailing v6 block is count(1) then 16 network-order bytes and a little-endian port.
//
// It is also the only place in the suite where a login crosses a real network hop rather
// than an in-process mockConn.
type serverListReply struct {
	V4 []serverEntry
	V6 []serverEntry
}

type serverEntry struct {
	IP   net.IP
	Port uint16
}

func (e serverEntry) String() string { return fmt.Sprintf("%s:%d", e.IP, e.Port) }

// fetchServerList logs in over TCP and returns the peers the server advertises.
func fetchServerList(t *testing.T, hostIP, hostPort string) serverListReply {
	t.Helper()

	addr := net.JoinHostPort(hostIP, hostPort)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))

	// hash(16) + clientID(4 LE) + port(2 LE) + tagcount(4 LE). No tags: none are
	// mandatory, and leaving them out keeps this client from depending on our own tag
	// encoder. The hash is arbitrary but must be stable and unique per connection.
	login := make([]byte, 0, 26)
	for i := 0; i < 16; i++ {
		login = append(login, byte(0xA0+i))
	}
	login = binary.LittleEndian.AppendUint32(login, 0)    // clientID: 0, let the server assign
	login = binary.LittleEndian.AppendUint16(login, 4662) // the client's own TCP port
	login = binary.LittleEndian.AppendUint32(login, 0)    // zero tags
	if err := writeFrame(conn, ed2k.OpLoginRequest, login); err != nil {
		t.Fatalf("write OP_LOGINREQUEST: %v", err)
	}
	t.Logf("input: OP_LOGINREQUEST to %s (%d payload bytes)", addr, len(login))

	// The login path dials back to probe for a firewall, which cannot succeed for a
	// client on the Docker host, so this session lands as a LowID after that attempt
	// times out. Harmless here: OP_SERVERLIST does not depend on the ID.
	if err := writeFrame(conn, ed2k.OpGetServerList, nil); err != nil {
		t.Fatalf("write OP_GETSERVERLIST: %v", err)
	}
	t.Logf("input: OP_GETSERVERLIST to %s", addr)

	// The server volunteers several frames on login (ID change, messages, status), so read
	// until OP_SERVERLIST turns up rather than assuming a position.
	seen := make([]string, 0, 8)
	for {
		opcode, payload, err := readFrame(conn)
		if err != nil {
			t.Fatalf("no OP_SERVERLIST before %v (frames seen: %v)", err, seen)
		}
		seen = append(seen, fmt.Sprintf("0x%02x/%dB", opcode, len(payload)))
		if opcode != ed2k.OpServerList {
			continue
		}
		t.Logf("output: frames %v", seen)
		return decodeServerList(t, payload)
	}
}

// writeFrame emits <protocol:1><size:4 LE><opcode:1><payload>, where size counts the
// opcode.
func writeFrame(conn net.Conn, opcode uint8, payload []byte) error {
	frame := make([]byte, 0, 6+len(payload))
	frame = append(frame, ed2k.PrED2K)
	frame = binary.LittleEndian.AppendUint32(frame, uint32(len(payload)+1))
	frame = append(frame, opcode)
	frame = append(frame, payload...)
	_, err := conn.Write(frame)
	return err
}

func readFrame(conn net.Conn) (uint8, []byte, error) {
	var head [6]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return 0, nil, err
	}
	if head[0] != ed2k.PrED2K {
		return 0, nil, fmt.Errorf("unexpected protocol byte 0x%02x (obfuscation was not requested)", head[0])
	}
	size := binary.LittleEndian.Uint32(head[1:5])
	if size == 0 || size > 1<<20 {
		return 0, nil, fmt.Errorf("implausible frame size %d", size)
	}
	payload := make([]byte, size-1) // size includes the opcode, already consumed
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	return head[5], payload, nil
}

func decodeServerList(t *testing.T, payload []byte) serverListReply {
	t.Helper()
	var out serverListReply
	if len(payload) < 1 {
		t.Fatalf("OP_SERVERLIST payload is empty")
	}
	n := int(payload[0])
	off := 1
	for i := 0; i < n; i++ {
		if off+6 > len(payload) {
			t.Fatalf("OP_SERVERLIST truncated in v4 entry %d of %d (payload %d bytes)", i, n, len(payload))
		}
		out.V4 = append(out.V4, serverEntry{
			IP:   net.IPv4(payload[off], payload[off+1], payload[off+2], payload[off+3]),
			Port: binary.LittleEndian.Uint16(payload[off+4 : off+6]),
		})
		off += 6
	}

	// The v6 block is optional: it is emitted only when the server has v6 peers to
	// publish, so its absence is not an error.
	if off >= len(payload) {
		return out
	}
	n6 := int(payload[off])
	off++
	for i := 0; i < n6; i++ {
		if off+18 > len(payload) {
			t.Fatalf("OP_SERVERLIST truncated in v6 entry %d of %d", i, n6)
		}
		ip := make(net.IP, 16)
		copy(ip, payload[off:off+16])
		out.V6 = append(out.V6, serverEntry{IP: ip, Port: binary.LittleEndian.Uint16(payload[off+16 : off+18])})
		off += 18
	}
	return out
}

func (r serverListReply) has(ip string, port uint16) bool {
	want := net.ParseIP(ip)
	for _, e := range append(append([]serverEntry{}, r.V4...), r.V6...) {
		if e.Port == port && e.IP.Equal(want) {
			return true
		}
	}
	return false
}

func (r serverListReply) String() string {
	return fmt.Sprintf("v4=%v v6=%v", r.V4, r.V6)
}

// loginAndPublish holds a session open with one published file, so the server's advertised
// client and file counts are non-zero. Returns a function that closes the session.
func loginAndPublish(t *testing.T, hostIP, hostPort string) func() {
	t.Helper()
	addr := net.JoinHostPort(hostIP, hostPort)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))

	login := make([]byte, 0, 26)
	for i := 0; i < 16; i++ {
		login = append(login, byte(0xB0+i))
	}
	login = binary.LittleEndian.AppendUint32(login, 0)
	login = binary.LittleEndian.AppendUint16(login, 4662)
	login = binary.LittleEndian.AppendUint32(login, 0)
	if err := writeFrame(conn, ed2k.OpLoginRequest, login); err != nil {
		t.Fatalf("write OP_LOGINREQUEST: %v", err)
	}

	// OP_OFFERFILES: <count:4 LE> then per file <hash:16><id:4><port:2><tagcount:4><tags>.
	// One tag, TagFileName, is enough for the file to be indexed and counted.
	offer := binary.LittleEndian.AppendUint32(nil, 1)
	for i := 0; i < 16; i++ {
		offer = append(offer, byte(0xC0+i))
	}
	offer = binary.LittleEndian.AppendUint32(offer, 0) // clientID: complete-source sentinel
	offer = binary.LittleEndian.AppendUint16(offer, 0)
	offer = binary.LittleEndian.AppendUint32(offer, 2) // two tags: name and size
	name := "interop-probe.bin"
	offer = append(offer, 0x02) // string tag
	offer = binary.LittleEndian.AppendUint16(offer, 1)
	offer = append(offer, 0x01) // TagFileName
	offer = binary.LittleEndian.AppendUint16(offer, uint16(len(name)))
	offer = append(offer, name...)
	offer = append(offer, 0x03) // uint32 tag
	offer = binary.LittleEndian.AppendUint16(offer, 1)
	offer = append(offer, 0x02) // TagFileSize
	offer = binary.LittleEndian.AppendUint32(offer, 1024)
	if err := writeFrame(conn, ed2k.OpOfferFiles, offer); err != nil {
		t.Fatalf("write OP_OFFERFILES: %v", err)
	}

	// Drain in the background so the server's writes never block on a full socket buffer.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()
	t.Logf("input: session logged in with 1 published file (%q)", name)
	return func() { _ = conn.Close() }
}
