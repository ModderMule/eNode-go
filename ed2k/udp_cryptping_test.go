package ed2k

import (
	"net"
	"testing"
	"time"

	"enode/storage"
)

// cryptProbe drives the real obfuscated UDP dispatcher (UDPHandler(true)) with a
// raw datagram and returns whatever it writes back, or nil on no reply.
func cryptProbe(t *testing.T, udpCfg UDPRuntimeConfig, request []byte) []byte {
	t.Helper()

	engine := storage.NewMemoryEngine()
	owner := storage.ClientInfo{Hash: []byte("0123456789abcdef"), ID: 0x0100007F, Port: 4662}
	engine.Connect(owner)
	engine.AddFile(storage.File{Hash: []byte("fedcba9876543210"), Size: 1024, Name: "food.bin"}, owner)

	rt := NewServerRuntime(TCPRuntimeConfig{}, udpCfg, engine)
	handler := rt.UDPHandler(true) // obfuscated listener

	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen server udp: %v", err)
	}
	defer server.Close()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer client.Close()

	handler(request, client.LocalAddr().(*net.UDPAddr), server)

	_ = client.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buf := make([]byte, 4096)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	return append([]byte(nil), buf[:n]...)
}

// decryptServerReply reverses UDPCrypt.Encrypt (the server→client direction): it
// keys on baseKey with MAGICVALUE_UDP_SERVERCLIENT (0xA5), exactly as eMule's
// DecryptReceivedServer (srchybrid/EncryptedDatagramSocket.cpp:378-424). Returns
// the plaintext ed2k payload, or nil if the SYNC_SERVER marker does not appear
// (i.e. the reply was not keyed on baseKey).
func decryptServerReply(t *testing.T, reply []byte, baseKey uint32) []byte {
	t.Helper()
	b := NewBufferFromBytes(reply)
	if _, err := b.GetUInt8(); err != nil { // semi-random protocol byte (clear)
		t.Fatalf("reply too short for protocol byte: %v", err)
	}
	randomKey, err := b.GetUInt16LE() // per-packet key part (clear)
	if err != nil {
		t.Fatalf("reply too short for random key: %v", err)
	}
	key := (&UDPCrypt{Status: CsEncrypting, ServerKey: baseKey}).rc4Key(MagicValueUDPServerClient, randomKey)
	ct := b.Get()
	pt := NewBufferFromBytes(RC4Crypt(ct, len(ct), key))
	sync, err := pt.GetUInt32LE()
	if err != nil || sync != MagicValueUDPSyncServer {
		return nil
	}
	padLen, err := pt.GetUInt8()
	if err != nil {
		return nil
	}
	padLen &= 0x0f
	_ = pt.Get(int(padLen))
	return pt.Get()
}

// encryptClientToServer builds a normal obfuscated client→server datagram, keyed
// on baseKey with MAGICVALUE_UDP_CLIENTSERVER (0x6B) — the direction the server's
// Decrypt expects. Mirrors eMule's EncryptSendServer with a fixed random key part
// for determinism.
func encryptClientToServer(payload []byte, baseKey uint32) []byte {
	const randomKey uint16 = 0x1234
	key := (&UDPCrypt{Status: CsEncrypting, ServerKey: baseKey}).rc4Key(MagicValueUDPClientServer, randomKey)
	inner := NewBuffer(len(payload) + 5)
	_ = inner.PutUInt32LE(MagicValueUDPSyncServer)
	_ = inner.PutUInt8(0) // padding length
	inner.PutBuffer(payload)
	ct := RC4Crypt(inner.Bytes(), len(inner.Bytes()), key)
	out := NewBuffer(len(payload) + 8)
	_ = out.PutUInt8(0x01) // semi-random non-protocol marker
	_ = out.PutUInt16LE(randomKey)
	out.PutBuffer(ct)
	return out.Bytes()
}

// A raw crypt-ping (unencrypted 32-bit challenge + padding) to the obfuscated
// listener must be answered with an OP_GLOBSERVSTATRES encrypted keyed on the
// challenge, carrying the real UDP key at +36 — the bootstrap that lets a client
// learn our key without first holding it.
func TestUDPCryptPingRoundTrip(t *testing.T) {
	const (
		challenge uint32 = 0xDEADBEEF // low byte 0xEF: not PR_ED2K (0xe3), not PrNat (0xf1)
		serverKey uint32 = 0x12345678
	)
	cfg := UDPRuntimeConfig{UDPServerKey: serverKey, UDPPortObf: 5567, TCPPortObf: 5565}
	// The reply advertises a per-client key derived from the loopback client IP,
	// not the raw secret. cryptProbe's client binds to 127.0.0.1.
	wantKey := deriveUDPKey(serverKey, net.IPv4(127, 0, 0, 1))

	for _, pad := range []int{0, 7, 15} {
		req := NewBuffer(4 + pad)
		_ = req.PutUInt32LE(challenge)
		for i := 0; i < pad; i++ {
			_ = req.PutUInt8(0xAB)
		}
		reply := cryptProbe(t, cfg, req.Bytes())
		t.Logf("input: raw crypt-ping challenge=0x%08x padding=%d len=%d", challenge, pad, len(req.Bytes()))
		t.Logf("output: reply=%d bytes", len(reply))
		if reply == nil {
			t.Fatalf("padding=%d: no reply to crypt-ping", pad)
		}

		pt := decryptServerReply(t, reply, challenge)
		if pt == nil {
			t.Fatalf("padding=%d: reply not decryptable with baseKey=challenge (wrong key or magic)", pad)
		}
		db := NewBufferFromBytes(pt)
		proto, _ := db.GetUInt8()
		opcode, _ := db.GetUInt8()
		gotChallenge, _ := db.GetUInt32LE()
		_ = db.Get(32) // user,files,maxconn,soft,hard,flags,lowid (7×4) + udpport,tcpport (2×2)
		gotKey, _ := db.GetUInt32LE()
		t.Logf("decrypted: proto=0x%02x opcode=0x%02x challenge=0x%08x udpKey=0x%08x (want 0x%08x, raw secret 0x%08x)", proto, opcode, gotChallenge, gotKey, wantKey, serverKey)

		if proto != PrED2K || opcode != OpGlobServStatRes {
			t.Fatalf("padding=%d: got proto=0x%02x opcode=0x%02x, want 0x%02x/0x%02x", pad, proto, opcode, PrED2K, OpGlobServStatRes)
		}
		if gotChallenge != challenge {
			t.Fatalf("padding=%d: echoed challenge=0x%08x, want 0x%08x", pad, gotChallenge, challenge)
		}
		if gotKey != wantKey {
			t.Fatalf("padding=%d: reply carried udpKey=0x%08x at +36, want per-client 0x%08x", pad, gotKey, wantKey)
		}
		if gotKey == serverKey {
			t.Fatalf("padding=%d: reply advertised the raw secret 0x%08x, not a per-client key", pad, serverKey)
		}
	}
}

// TestUDPStatResReflectsObservedIP covers the 4 trailing bytes at payload offset +40.
//
// Lugdunum already sends this field — measured against eserver 17.14, its extended reply
// is 44 payload bytes and the last four are the address it saw the requester on. eMule
// discards them, logging only "contains %d additional bytes"
// (srchybrid/UDPSocket.cpp:384-388), so the field is additive; a client taught to read it
// gets IPv4 reflection from eserver and from us alike.
//
// The value must come from the socket, never from anything the requester claimed, which
// is why this test drives a real datagram rather than calling the builder.
func TestUDPStatResReflectsObservedIP(t *testing.T) {
	const challenge uint32 = 0xDEADBEEF
	cfg := UDPRuntimeConfig{UDPServerKey: 0x12345678, UDPPortObf: 5567, TCPPortObf: 5565}

	req := NewBuffer(4)
	_ = req.PutUInt32LE(challenge)
	reply := cryptProbe(t, cfg, req.Bytes())
	if reply == nil {
		t.Fatal("no reply to the crypt-ping")
	}
	pt := decryptServerReply(t, reply, challenge)
	if pt == nil {
		t.Fatal("reply not decryptable")
	}
	// proto(1) + opcode(1) + 40 payload bytes + 4 observed-IP bytes.
	t.Logf("input: crypt-ping from a loopback client")
	t.Logf("output: decrypted payload %d bytes % x", len(pt), pt)
	if len(pt) != 2+44 {
		t.Fatalf("decrypted length = %d, want %d (2 header + 40 stat + 4 observed IP)", len(pt), 2+44)
	}
	observed := net.IP(pt[len(pt)-4:]).To4()
	t.Logf("output: observed client IP at payload +40 = %s", observed)
	if !observed.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("observed IP = %s, want 127.0.0.1 (cryptProbe's client binds loopback)", observed)
	}
}

// TestBuildStatResOmitsObservedIPWhenUnknown pins the no-regression half: a caller that
// sets no ObservedIP gets the packet byte-for-byte as it was before reflection existed.
func TestBuildStatResOmitsObservedIPWhenUnknown(t *testing.T) {
	without, err := BuildGlobServStatResPacket(1, UDPConfig{UDPPortObf: 5567, TCPPortObf: 5565}, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	with, err := BuildGlobServStatResPacket(1, UDPConfig{
		UDPPortObf: 5567, TCPPortObf: 5565, ObservedIP: net.ParseIP("192.168.65.1"),
	}, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("without ObservedIP: %d bytes % x", len(without.Bytes()), without.Bytes())
	t.Logf("with ObservedIP:    %d bytes % x", len(with.Bytes()), with.Bytes())
	if len(without.Bytes()) != 42 {
		t.Errorf("no-reflection form = %d bytes, want 42 (2 header + 40 payload)", len(without.Bytes()))
	}
	if len(with.Bytes()) != 46 {
		t.Errorf("reflection form = %d bytes, want 46 — matches eserver's measured reply", len(with.Bytes()))
	}
	// A v6 address has no 4-byte form and must be omitted rather than truncated.
	v6, err := BuildGlobServStatResPacket(1, UDPConfig{
		UDPPortObf: 5567, TCPPortObf: 5565, ObservedIP: net.ParseIP("2001:db8::1"),
	}, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("with an IPv6 ObservedIP: %d bytes (field omitted)", len(v6.Bytes()))
	if len(v6.Bytes()) != 42 {
		t.Fatalf("v6 observed address produced %d bytes; it must be omitted, not truncated", len(v6.Bytes()))
	}
}

// The crypt-ping heuristic must be tight: only 4..19-byte undecryptable datagrams,
// and never a zero challenge (eMule never sends one and would not decrypt a
// zero-keyed reply).
func TestUDPCryptPingRejectsNonPings(t *testing.T) {
	cfg := UDPRuntimeConfig{UDPServerKey: 0x12345678}

	cases := []struct {
		name    string
		request []byte
	}{
		{"too short (<4)", []byte{0x01, 0x02, 0x03}},
		{"too long (>19)", make([]byte, 20)},
		{"zero challenge", []byte{0x00, 0x00, 0x00, 0x00, 0xAB, 0xCD}},
	}
	// A 20-byte all-zero datagram starts with 0x00 (not PR_ED2K), so it reaches the
	// heuristic and is rejected purely on length.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply := cryptProbe(t, cfg, tc.request)
			t.Logf("input: %s len=%d", tc.name, len(tc.request))
			t.Logf("output: reply=%d bytes", len(reply))
			if reply != nil {
				t.Fatalf("%s: expected no reply, got %d bytes", tc.name, len(reply))
			}
		})
	}
}

// Regression: a genuine obfuscated packet keyed on the fixed server key must still
// decrypt and dispatch — the crypt-ping hook only fires when fixed-key decryption
// fails, so it must not swallow real traffic.
func TestUDPObfuscatedStatReqStillDispatches(t *testing.T) {
	const (
		serverKey  uint32 = 0x12345678
		challenge2 uint32 = 0x55AA1234
	)
	cfg := UDPRuntimeConfig{UDPServerKey: serverKey, UDPPortObf: 5567, TCPPortObf: 5565}
	// A real client obfuscates with the per-client key it was handed, keyed on its
	// own IP — here the loopback address cryptProbe's client binds to.
	udpKey := deriveUDPKey(serverKey, net.IPv4(127, 0, 0, 1))

	inner := NewBuffer(6)
	_ = inner.PutUInt8(PrED2K)
	_ = inner.PutUInt8(OpGlobServStatReq)
	_ = inner.PutUInt32LE(challenge2)
	obfReq := encryptClientToServer(inner.Bytes(), udpKey)

	reply := cryptProbe(t, cfg, obfReq)
	t.Logf("input: obfuscated OP_GLOBSERVSTATREQ challenge=0x%08x udpKey=0x%08x len=%d", challenge2, udpKey, len(obfReq))
	t.Logf("output: reply=%d bytes", len(reply))
	if reply == nil {
		t.Fatal("no reply to a valid obfuscated stat request")
	}

	// The obf listener re-encrypts its reply with the same per-client key, so
	// decrypt with udpKey (not the challenge, not the raw secret).
	pt := decryptServerReply(t, reply, udpKey)
	if pt == nil {
		t.Fatal("reply not decryptable with the per-client key")
	}
	db := NewBufferFromBytes(pt)
	proto, _ := db.GetUInt8()
	opcode, _ := db.GetUInt8()
	gotChallenge, _ := db.GetUInt32LE()
	t.Logf("decrypted: proto=0x%02x opcode=0x%02x challenge=0x%08x", proto, opcode, gotChallenge)

	if proto != PrED2K || opcode != OpGlobServStatRes || gotChallenge != challenge2 {
		t.Fatalf("got proto=0x%02x opcode=0x%02x challenge=0x%08x, want 0x%02x/0x%02x/0x%08x",
			proto, opcode, gotChallenge, PrED2K, OpGlobServStatRes, challenge2)
	}
}
