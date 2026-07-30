package ed2k

import (
	"net"
	"testing"
	"time"

	"enode/storage"
)

// A client that speaks plaintext to the obfuscated port must still be served.
//
// Before the protocol sniff in handleBytes, the login payload was fed straight
// into the DH negotiation: negotiate() only checks that at least 97 bytes are
// present, so it "succeeded", derived RC4 keys from login bytes, wrote 96 bytes
// of garbage back, and left the session in CsNegotiating forever. The client was
// never logged in and the socket lingered until disconnectTimeout.
//
// The original routes on the protocol byte first for exactly this reason
// (eNode/ed2k/packet.js:105-129).
func TestPlaintextLoginOnObfuscatedPortIsServed(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address:           "127.0.0.1",
		Port:              4661,
		Hash:              []byte("1111111111111111"),
		AllowLowIDs:       true,
		ConnectionTimeout: 50 * time.Millisecond,
	}, UDPRuntimeConfig{}, storage.NewMemoryEngine())

	// enableCrypt=true is what the obfuscated listener passes; it is the only
	// difference from the plain port.
	client := newTCPClient(rt, &mockConn{}, true)
	if client.crypt == nil {
		t.Fatal("expected a crypt-enabled client")
	}
	if got := client.crypt.State(); got != CsUnknown {
		t.Fatalf("expected initial state CsUnknown, got %d", got)
	}

	// The payload is padded past 97 bytes on purpose. negotiate() reads
	// [marker][96-byte DH A][padlen], so a shorter login would merely fail the
	// bounds check — the damaging case is a realistically-sized login that
	// negotiate() consumes *successfully*, deriving keys from login bytes.
	wire, err := MakePacket(PrED2K, []PacketItem{
		{Type: TypeUint8, Value: OpLoginRequest},
		{Type: TypeHash, Value: []byte("0123456789abcdef")},
		{Type: TypeUint32, Value: uint32(0)},
		{Type: TypeUint16, Value: uint16(4662)},
		{Type: TypeTags, Value: []Tag{
			{Type: TypeString, Code: TagName, Data: "a-client-name-long-enough-to-pass-97-bytes-total"},
			{Type: TypeUint32, Code: TagVersion, Data: uint32(0x3c)},
			{Type: TypeUint32, Code: TagPort, Data: uint32(4662)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	raw := wire.Bytes()
	if len(raw) <= 1+CryptPrimeSize {
		t.Fatalf("payload must exceed %d bytes to reach negotiate()'s success path, got %d",
			1+CryptPrimeSize, len(raw))
	}
	t.Logf("input: %d bytes of plaintext OP_LOGINREQUEST, first byte=0x%x (PR_ED2K)", len(raw), raw[0])

	client.handleBytes(raw)

	t.Logf("output: cryptState=%d logged=%t id=%d storeID=%d",
		client.crypt.State(), client.logged, client.info.ID, client.info.StoreID)

	if client.crypt.State() != CsNone {
		t.Fatalf("plaintext stream must disable obfuscation, state=%d", client.crypt.State())
	}
	if !client.logged {
		t.Fatal("plaintext login on the obfuscated port was not served")
	}
	if client.info.StoreID == 0 {
		t.Fatal("expected a non-zero storeID after login")
	}
}

// TestOneListenerServesBothProtocols is the property that lets obfuscated TCP share the
// plaintext port, as eserver does — its portTCPOBF defaults to the value of `port`, and
// eMule falls back to pServer->GetPort() for the obfuscation port
// (srchybrid/UDPSocket.cpp:394).
//
// main.go now passes cfg.SupportCrypt to the plaintext listener's TCPHandler rather than a
// hardcoded false. That is only safe if one crypt-enabled handler serves both kinds of
// client, which is what this asserts over real sockets: the same handler must log in a
// plaintext client and advance an obfuscated one to negotiation. The two existing tests
// above cover each half through newTCPClient; this one covers them sharing a listener.
func TestOneListenerServesBothProtocols(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address:           "127.0.0.1",
		Port:              4661,
		Hash:              []byte("1111111111111111"),
		AllowLowIDs:       true,
		ConnectionTimeout: 50 * time.Millisecond,
		DisconnectTimeout: 2 * time.Second,
		SupportCrypt:      true,
	}, UDPRuntimeConfig{}, storage.NewMemoryEngine())

	// enableCrypt=true is what main.go now passes for the *plaintext* port.
	handler := rt.TCPHandler(true)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()

	// A plaintext login on the crypt-enabled listener must be served.
	login, err := MakePacket(PrED2K, []PacketItem{
		{Type: TypeUint8, Value: OpLoginRequest},
		{Type: TypeHash, Value: []byte("0123456789abcdef")},
		{Type: TypeUint32, Value: uint32(0)},
		{Type: TypeUint16, Value: uint16(4662)},
		{Type: TypeTags, Value: []Tag{
			{Type: TypeString, Code: TagName, Data: "plaintext-client"},
			{Type: TypeUint32, Code: TagVersion, Data: uint32(0x3c)},
			{Type: TypeUint32, Code: TagPort, Data: uint32(4662)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if _, err := plain.Write(login.Bytes()); err != nil {
		t.Fatal(err)
	}
	_ = plain.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := plain.Read(buf)
	t.Logf("input: plaintext OP_LOGINREQUEST (%d bytes) to a crypt-enabled listener", len(login.Bytes()))
	t.Logf("output: read %d bytes err=%v first bytes=% x", n, err, buf[:min(n, 12)])
	if n == 0 {
		t.Fatalf("plaintext client got no reply on the shared port: %v", err)
	}
	// The server's first frame is a real eD2K packet, not DH garbage.
	if buf[0] != PrED2K && buf[0] != PrZlib {
		t.Fatalf("first reply byte 0x%02x is not a protocol byte: the login was consumed as a DH handshake", buf[0])
	}

	// An obfuscated client on the same listener must still reach negotiation, so this
	// cannot pass by having quietly disabled obfuscation.
	obf, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer obf.Close()
	negIn := make([]byte, 0, 1+CryptPrimeSize+1)
	negIn = append(negIn, 0x7a) // non-protocol marker
	negIn = append(negIn, make([]byte, CryptPrimeSize)...)
	negIn = append(negIn, 0x00)
	negIn[1] = 0x02
	if _, err := obf.Write(negIn); err != nil {
		t.Fatal(err)
	}
	_ = obf.SetReadDeadline(time.Now().Add(3 * time.Second))
	n2, err := obf.Read(buf)
	t.Logf("input: obfuscated DH handshake (%d bytes) to the same listener", len(negIn))
	t.Logf("output: read %d bytes err=%v", n2, err)
	if n2 == 0 {
		t.Fatalf("obfuscated client got no DH answer on the shared port: %v", err)
	}
	if n2 < CryptPrimeSize {
		t.Fatalf("DH answer is %d bytes, want at least the %d-byte prime", n2, CryptPrimeSize)
	}
}

// The obfuscated path itself must keep working: a non-protocol first byte still
// goes to the DH negotiation. Without this, the H4 fix could "pass" by simply
// disabling obfuscation for everyone.
func TestObfuscatedHandshakeStillNegotiates(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address: "127.0.0.1",
		Port:    4661,
	}, UDPRuntimeConfig{}, storage.NewMemoryEngine())

	client := newTCPClient(rt, &mockConn{}, true)

	// [non-protocol marker][96-byte DH A][padlen=0]
	negIn := make([]byte, 0, 1+CryptPrimeSize+1)
	negIn = append(negIn, 0x7a)
	negIn = append(negIn, make([]byte, CryptPrimeSize)...)
	negIn = append(negIn, 0x00)
	negIn[1] = 0x02 // a small non-zero A so the modexp is meaningful

	t.Logf("input: %d bytes, first byte=0x%x (not a protocol byte)", len(negIn), negIn[0])
	client.handleBytes(negIn)
	t.Logf("output: cryptState=%d", client.crypt.State())

	if client.crypt.State() != CsNegotiating {
		t.Fatalf("obfuscated handshake must advance to CsNegotiating, got %d", client.crypt.State())
	}
}

// A malformed obfuscated handshake must close the connection rather than leave
// it wedged in CsNegotiating until disconnectTimeout (3600s by default).
func TestFailedCryptHandshakeClosesConnection(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address: "127.0.0.1",
		Port:    4661,
	}, UDPRuntimeConfig{}, storage.NewMemoryEngine())

	conn := &mockConn{}
	client := newTCPClient(rt, conn, true)

	// Not a protocol byte, and too short to be a DH negotiation.
	short := []byte{0x7a, 0x01, 0x02}
	t.Logf("input: %d bytes, first byte=0x%x", len(short), short[0])
	client.handleBytes(short)
	t.Logf("output: closed=%d reason=%q", conn.closed, client.getCloseReason())

	if conn.closed == 0 {
		t.Fatal("a failed crypt handshake must close the connection")
	}
}
