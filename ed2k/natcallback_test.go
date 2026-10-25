package ed2k

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unsafe"

	"enode/storage"
)

// tcpClientSizeBeforeNatCallback is unsafe.Sizeof(tcpClient{}) on 64-bit before the
// Lugdunum callback was added. The callback must not make an idle session bigger.
const tcpClientSizeBeforeNatCallback = 488

func TestNatCallbackAddsNoSessionMemory(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("size pinned for 64-bit")
	}
	got := unsafe.Sizeof(tcpClient{})
	t.Logf("input: tcpClient{}, output: %d bytes (before: %d)", got, tcpClientSizeBeforeNatCallback)
	if got > tcpClientSizeBeforeNatCallback {
		t.Fatalf("tcpClient grew to %d bytes, was %d", got, tcpClientSizeBeforeNatCallback)
	}
}

func TestLowIDParity(t *testing.T) {
	l := NewLowIDClients(true, 1, 0xffffff)
	for i := 0; i < 500; i++ {
		ip := net.IPv4(198, 51, 100, byte(i))
		odd, ok := l.AddByAddress(ip, 0, uint16(4000+i), i, LowIDOddParity)
		if !ok || odd&1 != 1 {
			t.Fatalf("odd request %d: id=%d ok=%t", i, odd, ok)
		}
		even, ok := l.AddByAddress(ip, 0, uint16(5000+i), i, LowIDEvenParity)
		if !ok || even&1 != 0 || even == 0 {
			t.Fatalf("even request %d: id=%d ok=%t", i, even, ok)
		}
		if i < 3 {
			t.Logf("input: %s odd/even, output: %d / %d", ip, odd, even)
		}
	}
	if l.Count() != 1000 || l.oddCount != 500 {
		t.Fatalf("count=%d odd=%d, want 1000/500", l.Count(), l.oddCount)
	}
}

// The parity changes nothing for a server without the callback: the same seed gets
// the same ID it got before.
func TestLowIDAnyParityUnchanged(t *testing.T) {
	a := NewLowIDClients(true, 1, 0xffffff)
	b := NewLowIDClients(true, 1, 0xffffff)
	ip := net.ParseIP("1.2.3.4")
	ipv4, _ := IPv4ToUint32LE(ip)
	want, _ := a.AddByEndpoint(ipv4, 4662, "x")
	got, _ := b.AddByAddress(ip, ipv4, 4662, "x", LowIDAnyParity)
	t.Logf("input: 1.2.3.4:4662, output: endpoint=%d address/any=%d", want, got)
	if got != want {
		t.Fatalf("any parity gave %d, want %d", got, want)
	}
}

func TestLowIDParityExhaustion(t *testing.T) {
	// [2,5] holds two odd IDs (3, 5) and two even ones (2, 4).
	l := NewLowIDClients(true, 2, 5)
	var odd []uint32
	for i := 0; i < 3; i++ {
		id, ok := l.AddByAddress(nil, uint32(i), 1, i, LowIDOddParity)
		t.Logf("input: odd #%d, output: id=%d ok=%t", i, id, ok)
		if ok {
			odd = append(odd, id)
		}
	}
	if len(odd) != 2 {
		t.Fatalf("got %d odd IDs from [2,5], want 2", len(odd))
	}
	// The even half is still free.
	for i := 0; i < 2; i++ {
		id, ok := l.AddByAddress(nil, uint32(10+i), 1, i, LowIDEvenParity)
		t.Logf("input: even #%d, output: id=%d ok=%t", i, id, ok)
		if !ok || id&1 != 0 {
			t.Fatalf("even #%d: id=%d ok=%t", i, id, ok)
		}
	}
	l.Remove(odd[0])
	id, ok := l.AddByAddress(nil, 99, 1, "again", LowIDOddParity)
	t.Logf("input: odd after removing %d, output: id=%d ok=%t", odd[0], id, ok)
	if !ok || id != odd[0] {
		t.Fatalf("got %d ok=%t, want the freed %d", id, ok, odd[0])
	}

	// A one-element range has no ID of the other parity.
	single := NewLowIDClients(true, 2, 2)
	if id, ok := single.AddByAddress(nil, 1, 1, "x", LowIDOddParity); ok {
		t.Fatalf("[2,2] gave odd id %d", id)
	}
}

func TestLowIDRestoreCountsParity(t *testing.T) {
	l := NewLowIDClients(true, 1, 0xffffff)
	l.Restore(7, "a")
	l.Restore(8, "b")
	t.Logf("input: restore 7, 8, output: count=%d odd=%d", l.Count(), l.oddCount)
	if l.Count() != 2 || l.oddCount != 1 {
		t.Fatalf("count=%d odd=%d, want 2/1", l.Count(), l.oddCount)
	}
	l.Remove(7)
	if l.oddCount != 0 {
		t.Fatalf("odd=%d after removing 7", l.oddCount)
	}
}

// The live capture table of docs/lugdunum-nat-callback.local.md, "Flags byte and hash".
func TestNatCallbackCryptMatchesCapture(t *testing.T) {
	const none, supports, requests, requires = 0x00, 0x01, 0x03, 0x07
	cases := []struct {
		requester, target byte
		wantFlags         byte
		wantHash, wantOK  bool
	}{
		{supports, supports, 0x01, false, true},
		{none, supports, 0x00, false, true},
		{requests, supports, 0x83, true, true},
		{requires, supports, 0x87, true, true},
		{supports, requests, 0x81, true, true},
		{none, requests, 0x00, false, true},
		{requests, none, 0x03, false, true},
		{requires, none, 0, false, false},
	}
	for _, tc := range cases {
		flags, withHash, ok := NatCallbackCrypt(tc.requester, tc.target)
		wire := flags
		if withHash {
			wire |= 0x80
		}
		t.Logf("input: requester=0x%02x target=0x%02x, output: flags=0x%02x hash=%t ok=%t", tc.requester, tc.target, wire, withHash, ok)
		if ok != tc.wantOK || (ok && (wire != tc.wantFlags || withHash != tc.wantHash)) {
			t.Fatalf("requester=0x%02x target=0x%02x: got 0x%02x/%t/%t, want 0x%02x/%t/%t",
				tc.requester, tc.target, wire, withHash, ok, tc.wantFlags, tc.wantHash, tc.wantOK)
		}
	}
}

func TestBuildNatCallbackNotice(t *testing.T) {
	ip, _ := IPv4ToUint32LE(net.ParseIP("223.204.218.167"))
	hash := bytes.Repeat([]byte{0xab}, 16)
	plain := BuildNatCallbackNotice(ip, 0x10c5, 1, 0x01, nil)
	t.Logf("input: ip=223.204.218.167 port=0x10c5 id=1 flags=1, output: % x", plain)
	want := []byte{0xdf, 0xcc, 0xda, 0xa7, 0xc5, 0x10, 0x01, 0x00, 0x00, 0x00, 0x01}
	if !bytes.Equal(plain, want) {
		t.Fatalf("notice % x, want % x (capture)", plain, want)
	}
	withHash := BuildNatCallbackNotice(ip, 0xfef7, 9, 0x03, hash)
	t.Logf("input: with hash, output: % x", withHash)
	if len(withHash) != 27 || withHash[10] != 0x83 || !bytes.Equal(withHash[11:], hash) {
		t.Fatalf("notice with hash % x", withHash)
	}
	tcp, err := BuildNatCallbackRequestedPacket(ip, 0x10c5, 1, 0x01, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := tcp.Bytes()
	t.Logf("input: tcp 0x37, output: % x", raw)
	if raw[5] != OpNatCallbackRequested || !bytes.Equal(raw[6:], want) {
		t.Fatalf("tcp 0x37 % x, body want % x", raw, want)
	}
}

// The notice lands on the client's client/Kad socket, so its marker byte must never
// look like eMule or Kad traffic, and it must still decrypt.
func TestEncryptForClientSocketMarker(t *testing.T) {
	crypt := NewUDPCrypt(true, 0x11223344)
	payload := []byte{PrED2K, OpNatCallbackRequestedUDP, 1, 2, 3}
	for i := 0; i < 3000; i++ {
		out := crypt.EncryptForClientSocket(payload)
		switch out[0] {
		case PrED2K, PrEMule, PrZlib, PrKad, PrKadZlib:
			t.Fatalf("marker 0x%02x after %d datagrams", out[0], i)
		}
		if i == 0 {
			pt := decryptServerReply(t, out, 0x11223344)
			t.Logf("input: % x, output: marker=0x%02x decrypted=% x", payload, out[0], pt)
			if !bytes.Equal(pt, payload) {
				t.Fatalf("decrypted % x", pt)
			}
		}
	}
}

func TestBuildFlagsNatCallback(t *testing.T) {
	tcpOn := BuildTCPFlags(TCPServerConfig{NatCallback: true})
	tcpOff := BuildTCPFlags(TCPServerConfig{})
	udpOn := BuildUDPFlags(UDPServerConfig{NatCallback: true})
	udpOff := BuildUDPFlags(UDPServerConfig{})
	t.Logf("input: NatCallback on/off, output: tcp=0x%x/0x%x udp=0x%x/0x%x", tcpOn, tcpOff, udpOn, udpOff)
	if tcpOn&FlagNatCallback == 0 || tcpOff&FlagNatCallback != 0 || udpOn&FlagNatCallback == 0 || udpOff&FlagNatCallback != 0 {
		t.Fatal("FlagNatCallback not driven by NatCallback")
	}
}

// natLogin logs in a firewalled client from remote with the given CT_SERVER_FLAGS
// and returns its session and the OP_IDCHANGE payload.
func natLogin(t *testing.T, serverFlags, loginFlags uint32, remote string) (*tcpClient, []byte) {
	t.Helper()
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address:     "127.0.0.1",
		Port:        4661,
		Hash:        []byte("1111111111111111"),
		AllowLowIDs: true,
		Flags:       serverFlags,
	}, UDPRuntimeConfig{TCPPortObf: 4665}, storage.NewMemoryEngine())
	rt.firewallProbe = func(*tcpClient) bool { return true }
	client, conn := newReflectClient(t, rt, remote)
	items := loginItems(bytes.Repeat([]byte{0x5a}, 16), 0, 4662)
	items[len(items)-1] = PacketItem{Type: TypeTags, Value: []Tag{{Type: TypeUint32, Code: TagFlags, Data: loginFlags}}}
	wire, err := MakePacket(PrED2K, items)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPacket()
	if err := p.Init(NewBufferFromBytes(wire.Bytes())); err != nil {
		t.Fatal(err)
	}
	client.handlePacket(p)
	return client, payloadOfOpcode(t, conn.written(), OpIDChange)
}

func TestLoginNatCallbackParityAndIDChange(t *testing.T) {
	const on = FlagNatCallback | FlagTcpObfusc
	cases := []struct {
		name        string
		server      uint32
		login       uint32
		wantLen     int
		wantOdd     bool
		parityBound bool
	}{
		{"nat+crypt", on, SrvCapNatTraversal | FlagSupportCrypt, 24, true, true},
		{"nat only", on, SrvCapNatTraversal, 16, true, true},
		{"crypt only", on, FlagSupportCrypt, 16, false, true},
		{"feature off", FlagTcpObfusc, SrvCapNatTraversal | FlagSupportCrypt, 16, false, false},
	}
	for _, tc := range cases {
		c, idc := natLogin(t, tc.server, tc.login, "203.0.113.9")
		id := binary.LittleEndian.Uint32(idc[0:4])
		t.Logf("input: %s server=0x%x login=0x%x, output: id=%d len=%d payload=% x", tc.name, tc.server, tc.login, id, len(idc), idc)
		if len(idc) != tc.wantLen {
			t.Fatalf("%s: OP_IDCHANGE %d bytes, want %d", tc.name, len(idc), tc.wantLen)
		}
		if HasHighID(id) {
			t.Fatalf("%s: got HighID %d", tc.name, id)
		}
		if tc.parityBound && (id&1 == 1) != tc.wantOdd {
			t.Fatalf("%s: id %d, want odd=%t", tc.name, id, tc.wantOdd)
		}
		if got := binary.LittleEndian.Uint32(idc[12:16]); got != binary.LittleEndian.Uint32(net.ParseIP("203.0.113.9").To4()) {
			t.Fatalf("%s: observed IP %#x at +12", tc.name, got)
		}
		if tc.wantLen == 24 {
			obf := binary.LittleEndian.Uint32(idc[16:20])
			port := binary.LittleEndian.Uint32(idc[20:24])
			if obf != 4665 || port != 50000 {
				t.Fatalf("%s: +16=%d +20=%d, want 4665 / 50000 (source port)", tc.name, obf, port)
			}
		}
		c.infoMu.RLock()
		natt := c.nattCapable
		c.infoMu.RUnlock()
		if natt != (tc.parityBound && tc.wantOdd) {
			t.Fatalf("%s: nattCapable=%t", tc.name, natt)
		}
	}
}

// natRig is a server with two logged-in LowID sessions and a UDP socket for each.
type natRig struct {
	rt         *ServerRuntime
	handler    func([]byte, *net.UDPAddr, UDPReplyConn)
	server     *net.UDPConn
	a, b       *tcpClient
	aTCP, bTCP *captureConn
	aUDP, bUDP *net.UDPConn
}

func newNatRig(t *testing.T, serverFlags uint32, bNatt bool) *natRig {
	t.Helper()
	rt := NewServerRuntime(TCPRuntimeConfig{Port: 4661, AllowLowIDs: true, Flags: serverFlags},
		UDPRuntimeConfig{UDPServerKey: 0x12345678}, storage.NewMemoryEngine())
	r := &natRig{rt: rt, handler: rt.UDPHandler(true)}
	var err error
	if r.server, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.server.Close() })
	r.a, r.aTCP, r.aUDP = natSession(t, rt, 3, true, 0x5a)
	r.b, r.bTCP, r.bUDP = natSession(t, rt, 5, bNatt, 0x6b)
	return r
}

func natSession(t *testing.T, rt *ServerRuntime, id uint32, natt bool, hashByte byte) (*tcpClient, *captureConn, *net.UDPConn) {
	t.Helper()
	conn := &captureConn{mockConn: mockConn{remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000 + int(id)}}}
	c := newTCPClient(rt, conn, false)
	c.infoMu.Lock()
	c.info.ID = id
	c.info.IPv4, _ = IPv4ToUint32LE(net.IPv4(127, 0, 0, 1))
	c.info.Hash = bytes.Repeat([]byte{hashByte}, 16)
	c.info.CryptOptions = 0x03
	c.info.LowID = true
	c.hasLowID = true
	c.logged = true
	c.nattCapable = natt
	c.infoMu.Unlock()
	if !rt.LowIDs.Restore(id, c) {
		t.Fatalf("restore %d", id)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	return c, conn, udp
}

// request sends 0xa6 <target><requester> from the socket of from, obfuscated unless plain.
func (r *natRig) request(from *net.UDPConn, target, requester uint32, plain bool) {
	payload := []byte{PrED2K, OpNatCallbackRequest}
	payload = binary.LittleEndian.AppendUint32(payload, target)
	payload = binary.LittleEndian.AppendUint32(payload, requester)
	data := payload
	if !plain {
		data = encryptClientToServer(payload, deriveUDPKey(LegacyUDPSecret(0x12345678), net.IPv4(127, 0, 0, 1)))
	}
	r.handler(data, from.LocalAddr().(*net.UDPAddr), r.server)
}

func readUDP(conn *net.UDPConn) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

// The mutual callback: A's request reaches B over TCP 0x37 (B has not sent one), and
// B's answering request reaches A over UDP 0xa7 (A sent one moments ago).
func TestNatCallbackMutual(t *testing.T) {
	r := newNatRig(t, FlagNatCallback, true)
	aPort := uint16(r.aUDP.LocalAddr().(*net.UDPAddr).Port)
	bPort := uint16(r.bUDP.LocalAddr().(*net.UDPAddr).Port)
	loop, _ := IPv4ToUint32LE(net.IPv4(127, 0, 0, 1))

	r.request(r.aUDP, 5, 3, false)
	notice := payloadOfOpcode(t, r.bTCP.written(), OpNatCallbackRequested)
	t.Logf("input: A(3) asks for B(5), output: B gets TCP 0x37 % x", notice)
	want := BuildNatCallbackNotice(loop, aPort, 3, 0x03, bytes.Repeat([]byte{0x5a}, 16))
	if !bytes.Equal(notice, want) {
		t.Fatalf("0x37 % x, want % x", notice, want)
	}
	if got := readUDP(r.bUDP); got != nil {
		t.Fatalf("B also got UDP % x", got)
	}

	r.request(r.bUDP, 3, 5, false)
	raw := readUDP(r.aUDP)
	if raw == nil {
		t.Fatal("A got no UDP 0xa7")
	}
	pt := decryptServerReply(t, raw, deriveUDPKey(LegacyUDPSecret(0x12345678), net.IPv4(127, 0, 0, 1)))
	t.Logf("input: B(5) asks for A(3), output: A gets UDP marker=0x%02x % x", raw[0], pt)
	want = append([]byte{PrED2K, OpNatCallbackRequestedUDP}, BuildNatCallbackNotice(loop, bPort, 5, 0x03, bytes.Repeat([]byte{0x6b}, 16))...)
	if !bytes.Equal(pt, want) {
		t.Fatalf("0xa7 % x, want % x", pt, want)
	}
	if len(r.aTCP.written()) != 0 {
		t.Fatalf("A also got TCP % x", r.aTCP.written())
	}
}

func TestNatCallbackRefusals(t *testing.T) {
	cases := []struct {
		name   string
		flags  uint32
		bNatt  bool
		plain  bool
		target uint32
		from   uint32
		spoof  bool
	}{
		{"plaintext", FlagNatCallback, true, true, 5, 3, false},
		{"feature off", 0, true, false, 5, 3, false},
		{"target without 0x1000", FlagNatCallback, false, false, 5, 3, false},
		{"unknown target", FlagNatCallback, true, false, 7, 3, false},
		{"self", FlagNatCallback, true, false, 3, 3, false},
		{"requester not ours", FlagNatCallback, true, false, 5, 9, false},
		{"requester from another IP", FlagNatCallback, true, false, 5, 3, true},
	}
	for _, tc := range cases {
		r := newNatRig(t, tc.flags, tc.bNatt)
		if tc.spoof {
			r.a.peerIP = net.IPv4(10, 0, 0, 1)
		}
		r.request(r.aUDP, tc.target, tc.from, tc.plain)
		tcp, udp := r.bTCP.written(), readUDP(r.bUDP)
		t.Logf("input: %s, output: tcp=%d bytes udp=%d bytes", tc.name, len(tcp), len(udp))
		if len(tcp) != 0 || udp != nil || len(r.aTCP.written()) != 0 {
			t.Fatalf("%s: a notice was sent", tc.name)
		}
	}
}

func TestNatCallbackWindowExpires(t *testing.T) {
	var n natCallbackState
	now := time.Now()
	n.remember(5, natCallbackRecent{ipv4: 1, port: 2, at: now.Add(-20 * time.Second)})
	_, fresh := n.recentFor(5, now)
	n.remember(6, natCallbackRecent{ipv4: 1, port: 2, at: now})
	_, kept := n.recent[5]
	t.Logf("input: entry 20 s old, output: usable=%t kept after sweep=%t", fresh, kept)
	if fresh || kept {
		t.Fatalf("stale entry usable=%t kept=%t", fresh, kept)
	}
}

// The budget is per requester, so LowIDs sharing one IPv4 (carrier-grade NAT) do not
// use up each other's requests.
func TestNatCallbackRateLimitPerRequester(t *testing.T) {
	r := newNatRig(t, FlagNatCallback, true)
	_, _, cUDP := natSession(t, r.rt, 7, true, 0x7c)
	sent := func() int { return len(r.bTCP.written()) }

	for i := 0; i < natCallbackPerRequesterPerMinute; i++ {
		r.request(r.aUDP, 5, 3, false)
	}
	full := sent()
	r.request(r.aUDP, 5, 3, false)
	overBudget := sent()
	r.request(cUDP, 5, 7, false)
	other := sent()
	t.Logf("input: %d requests from A(3), one more from A, one from C(7) on the same IP, output: B bytes %d, %d, %d",
		natCallbackPerRequesterPerMinute, full, overBudget, other)
	if full == 0 || overBudget != full {
		t.Fatalf("A over budget still delivered: %d -> %d", full, overBudget)
	}
	if other == overBudget {
		t.Fatal("C on the same IP was limited by A's budget")
	}
}
