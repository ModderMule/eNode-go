package ed2k

import (
	"encoding/binary"
	"math"
	"net"
	"testing"
	"time"

	"enode/storage"
)

type mockConn struct {
	closed int
	// remote overrides RemoteAddr; nil means 127.0.0.2:50000, the address every
	// mockConn shares unless a test needs two connections from different hosts.
	remote net.Addr
}

func (m *mockConn) Read(_ []byte) (int, error)  { return 0, net.ErrClosed }
func (m *mockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockConn) Close() error                { m.closed++; return nil }
func (m *mockConn) LocalAddr() net.Addr         { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4661} }
func (m *mockConn) RemoteAddr() net.Addr {
	if m.remote != nil {
		return m.remote
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 50000}
}
func (m *mockConn) SetDeadline(_ time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(_ time.Time) error { return nil }

// The session map and its replaceSession/loginSessionKey helpers are gone. They
// implemented "evict the existing session", which was remotely triggerable with
// a public user hash; duplicate logins are now rejected instead. Coverage for
// the replacement lives in duplicate_login_test.go.

func TestNewServerRuntimeSetsDefaultServerStatusInterval(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	if rt.TCP.ServerStatusInterval != defaultServerStatusInterval {
		t.Fatalf("default interval=%v want=%v", rt.TCP.ServerStatusInterval, defaultServerStatusInterval)
	}

	custom := 2 * time.Minute
	rt2 := NewServerRuntime(TCPRuntimeConfig{ServerStatusInterval: custom}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	if rt2.TCP.ServerStatusInterval != custom {
		t.Fatalf("custom interval=%v want=%v", rt2.TCP.ServerStatusInterval, custom)
	}
}

func TestUDPObfuscatedNATRegisterReplyIsEncrypted(t *testing.T) {
	serverKey := uint32(0x22334455)
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{UDPServerKey: serverKey}, storage.NewMemoryEngine())
	nat := NewNATTraversalHandler(time.Minute)
	rt.SetNATHandler(nat)
	handler := rt.UDPHandler(true)

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen server udp: %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer clientConn.Close()

	var hash [16]byte
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	req := encodeNATPacket(OpNatRegister, hash[:])
	// The client obfuscates with the per-client key derived from its own IP, which
	// is what the obf listener recomputes from the datagram's source IP.
	crypt := NewUDPCrypt(true, deriveUDPKey(serverKey, net.IPv4(127, 0, 0, 1)))
	wire := buildObfuscatedClientUDP(crypt, req, 0x3344)

	remote := clientConn.LocalAddr().(*net.UDPAddr)
	handler(wire, remote, serverConn)

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := clientConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read nat register ack: %v", err)
	}
	gotWire := append([]byte(nil), buf[:n]...)
	if len(gotWire) == 0 {
		t.Fatalf("empty nat register ack")
	}
	if gotWire[0] == PrNat {
		t.Fatalf("nat register ack should be obfuscated on udp-obfuscated listener")
	}

	plain, ok := decryptObfuscatedServerUDP(crypt, gotWire)
	if !ok {
		t.Fatalf("failed to decrypt obfuscated nat register ack")
	}
	opcode, _, ok := decodeNATPacket(plain)
	if !ok {
		t.Fatalf("decrypted ack is not a NAT packet")
	}
	if opcode != OpNatRegister {
		t.Fatalf("opcode=0x%x want=0x%x", opcode, OpNatRegister)
	}
}

func TestUDPPlainNATRegisterReplyIsPlaintext(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{UDPServerKey: 0x22334455}, storage.NewMemoryEngine())
	nat := NewNATTraversalHandler(time.Minute)
	rt.SetNATHandler(nat)
	handler := rt.UDPHandler(false)

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen server udp: %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer clientConn.Close()

	var hash [16]byte
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	req := encodeNATPacket(OpNatRegister, hash[:])
	remote := clientConn.LocalAddr().(*net.UDPAddr)
	handler(req, remote, serverConn)

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := clientConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read nat register ack: %v", err)
	}
	got := append([]byte(nil), buf[:n]...)
	if len(got) == 0 {
		t.Fatalf("empty nat register ack")
	}
	if got[0] != PrNat {
		t.Fatalf("nat register ack should be plaintext on udp listener")
	}

	opcode, _, ok := decodeNATPacket(got)
	if !ok {
		t.Fatalf("ack is not a NAT packet")
	}
	if opcode != OpNatRegister {
		t.Fatalf("opcode=0x%x want=0x%x", opcode, OpNatRegister)
	}
}

func TestNATKeepaliveReplyUsesSameUDPListenerPort(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	nat := NewNATTraversalHandler(time.Minute)
	rt.SetNATHandler(nat)
	handler := rt.UDPHandler(false)

	serverConnA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen server udp A: %v", err)
	}
	defer serverConnA.Close()
	serverConnB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen server udp B: %v", err)
	}
	defer serverConnB.Close()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer clientConn.Close()

	var hash [16]byte
	for i := range hash {
		hash[i] = byte(0xa0 + i)
	}

	readNAT := func(timeout time.Duration) (uint8, *net.UDPAddr) {
		t.Helper()
		_ = clientConn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 2048)
		n, from, err := clientConn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read nat packet: %v", err)
		}
		opcode, _, ok := decodeNATPacket(buf[:n])
		if !ok {
			t.Fatalf("decode nat packet failed")
		}
		return opcode, from
	}

	remote := clientConn.LocalAddr().(*net.UDPAddr)

	handler(encodeNATPacket(OpNatRegister, hash[:]), remote, serverConnA)
	opcode, from := readNAT(2 * time.Second)
	if opcode != OpNatRegister {
		t.Fatalf("register ack opcode=0x%x want=0x%x", opcode, OpNatRegister)
	}
	if from.Port != serverConnA.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("register ack source port=%d want=%d", from.Port, serverConnA.LocalAddr().(*net.UDPAddr).Port)
	}

	handler(encodeNATPacket(OpNatKeepAlive, nil), remote, serverConnA)
	opcode, from = readNAT(2 * time.Second)
	if opcode != OpNatPing {
		t.Fatalf("keepalive ping opcode=0x%x want=0x%x", opcode, OpNatPing)
	}
	if from.Port != serverConnA.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("keepalive ping source port=%d want=%d", from.Port, serverConnA.LocalAddr().(*net.UDPAddr).Port)
	}

	handler(encodeNATPacket(OpNatKeepAlive, nil), remote, serverConnB)
	opcode, from = readNAT(2 * time.Second)
	if opcode != OpNatPing {
		t.Fatalf("keepalive ping opcode on listener B=0x%x want=0x%x", opcode, OpNatPing)
	}
	if from.Port != serverConnB.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("keepalive ping source port on listener B=%d want=%d", from.Port, serverConnB.LocalAddr().(*net.UDPAddr).Port)
	}
}

// TestFileFromRecordNarrowedIntTags covers the metadata tags eMule narrows to
// TAGTYPE_UINT8 because their values are small: source counts, media runtime and
// bitrate (128/192/256 all fit in a byte). Before normalization each exact uint32
// assertion failed and every one of these fields was stored as zero.
func TestFileFromRecordNarrowedIntTags(t *testing.T) {
	record := FileRecord{
		Hash:     []byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
		Size:     4096,
		Complete: true,
		Tags: map[string]any{
			"name":            "song.mp3",
			"sources":         uint64(3),   // wire TAGTYPE_UINT8
			"completesources": uint64(1),   // wire TAGTYPE_UINT8
			"length":          uint64(210), // wire TAGTYPE_UINT8
			"bitrate":         uint64(128), // wire TAGTYPE_UINT8
		},
	}
	info := storage.ClientInfo{ID: 0x0100007f, Port: 4662}
	t.Logf("input: tags=%v", record.Tags)

	file := fileFromRecord(record, info)
	t.Logf("output: Sources=%d Completed=%d Runtime=%d Bitrate=%d Type=%q",
		file.Sources, file.Completed, file.Runtime, file.Bitrate, file.Type)

	for _, c := range []struct {
		field string
		got   uint32
		want  uint32
	}{
		{"Sources", file.Sources, 3},
		{"Completed", file.Completed, 1},
		{"Runtime", file.Runtime, 210},
		{"Bitrate", file.Bitrate, 128},
	} {
		if c.got != c.want {
			t.Errorf("%s mismatch: got %d, want %d", c.field, c.got, c.want)
		}
	}
}

// TestFileFromRecordSaturatesOversizedTag pins the saturation rule in tagUint32
// for values that do not fit a uint32 field, so a hostile or buggy client cannot
// wrap a count around to a small number.
func TestFileFromRecordSaturatesOversizedTag(t *testing.T) {
	record := FileRecord{
		Hash: []byte{6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6},
		Tags: map[string]any{
			"name":    "evil.bin",
			"sources": uint64(1) << 40,
		},
	}
	t.Logf("input: sources=%d (exceeds uint32)", uint64(1)<<40)

	file := fileFromRecord(record, storage.ClientInfo{})
	t.Logf("output: Sources=%d", file.Sources)

	if file.Sources != math.MaxUint32 {
		t.Fatalf("Sources mismatch: got %d, want %d (saturate, not wrap)", file.Sources, uint32(math.MaxUint32))
	}
}

func buildObfuscatedClientUDP(crypt *UDPCrypt, plain []byte, randomKey uint16) []byte {
	enc := NewBuffer(len(plain) + 5)
	_ = enc.PutUInt32LE(MagicValueUDPSyncServer)
	_ = enc.PutUInt8(0)
	enc.PutBuffer(plain)
	cipher := RC4Crypt(enc.Bytes(), len(enc.Bytes()), crypt.rc4Key(MagicValueUDPClientServer, randomKey))
	wire := NewBuffer(3 + len(cipher))
	_ = wire.PutUInt8(0xff)
	_ = wire.PutUInt16LE(randomKey)
	wire.PutBuffer(cipher)
	return wire.Bytes()
}

func decryptObfuscatedServerUDP(crypt *UDPCrypt, wire []byte) ([]byte, bool) {
	if len(wire) < 8 {
		return nil, false
	}
	randomKey := binary.LittleEndian.Uint16(wire[1:3])
	dec := RC4Crypt(wire[3:], len(wire)-3, crypt.rc4Key(MagicValueUDPServerClient, randomKey))
	if len(dec) < 5 {
		return nil, false
	}
	sync := binary.LittleEndian.Uint32(dec[:4])
	if sync != MagicValueUDPSyncServer {
		return nil, false
	}
	padLen := int(dec[4])
	if 5+padLen > len(dec) {
		return nil, false
	}
	return dec[5+padLen:], true
}
