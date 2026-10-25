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
	}, UDPRuntimeConfig{TCPPortObf: 4665, UDPFlags: FlagForeignCallback}, storage.NewMemoryEngine())
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

// natCallbackKey is the UDP key the rigs give ip.
func natCallbackKey(ip net.IP) uint32 {
	return deriveUDPKey(LegacyUDPSecret(0x12345678), ip)
}

// foreignRig is a server offering the foreign callback with one LowID target T (5)
// that set 0x1000 and 0x100000, and a requester socket R that is not logged in.
type foreignRig struct {
	*natRig
	r *net.UDPConn
	// timers holds the armed fallback timers; fire runs them.
	timers []func()
}

// fire runs and drops the armed fallback timers, as if 3 s had passed.
func (f *foreignRig) fire() {
	timers := f.timers
	f.timers = nil
	for _, fn := range timers {
		fn()
	}
}

func newForeignRig(t *testing.T, tcpFlags, udpFlags uint32) *foreignRig {
	t.Helper()
	rt := NewServerRuntime(TCPRuntimeConfig{Port: 4661, AllowLowIDs: true, Flags: tcpFlags},
		UDPRuntimeConfig{UDPServerKey: 0x12345678, UDPFlags: udpFlags, ForeignPerMinute: 60, ForeignBurst: 10}, storage.NewMemoryEngine())
	n := &natRig{rt: rt, handler: rt.UDPHandler(true)}
	var err error
	if n.server, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.server.Close() })
	n.b, n.bTCP, n.bUDP = natSession(t, rt, 5, true, 0x6b)
	n.b.holePunchExt = true
	rt.registerSession(n.b.info.Hash, n.b)
	r, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	f := &foreignRig{natRig: n, r: r}
	rt.natCallback.afterFunc = func(d time.Duration, fn func()) {
		if d != natForeignFallback {
			t.Errorf("fallback armed for %s, want %s", d, natForeignFallback)
		}
		f.timers = append(f.timers, fn)
	}
	return f
}

// foreign sends 0xa6 <target><0>[extra] from remote, obfuscated with remote's key
// unless plain.
func (f *foreignRig) foreign(remote *net.UDPAddr, target uint32, plain bool, extra ...byte) {
	payload := []byte{PrED2K, OpNatCallbackRequest}
	payload = binary.LittleEndian.AppendUint32(payload, target)
	payload = binary.LittleEndian.AppendUint32(payload, 0)
	payload = append(payload, extra...)
	data := payload
	if !plain {
		data = encryptClientToServer(payload, natCallbackKey(remote.IP))
	}
	f.handler(data, remote, f.server)
}

// keepalive sends OpNatKeepalive <hash> from conn, obfuscated unless plain.
func (f *foreignRig) keepalive(conn *net.UDPConn, hash []byte, plain bool) {
	payload := append([]byte{PrED2K, OpNatKeepalive}, hash...)
	data := payload
	if !plain {
		data = encryptClientToServer(payload, natCallbackKey(net.IPv4(127, 0, 0, 1)))
	}
	f.handler(data, conn.LocalAddr().(*net.UDPAddr), f.server)
}

func (f *foreignRig) rAddr() *net.UDPAddr { return f.r.LocalAddr().(*net.UDPAddr) }

// natPacketCount counts framed packets with opcode in a captured TCP stream.
func natPacketCount(raw []byte, opcode byte) int {
	n := 0
	for off := 0; off+6 <= len(raw); {
		size := int(binary.LittleEndian.Uint32(raw[off+1 : off+5]))
		if size < 1 || off+5+size > len(raw) {
			break
		}
		if raw[off+5] == opcode {
			n++
		}
		off += 5 + size
	}
	return n
}

// A foreign request wakes T with TCP 0x37 naming R's datagram source, ID 0 and no
// hash; the optional 9th byte is R's crypt bits (low 3 only), absent means 0. R hears
// nothing until T's keepalive.
func TestForeignCallbackWakesTarget(t *testing.T) {
	f := newForeignRig(t, FlagNatCallback, FlagForeignCallback)
	loop, _ := IPv4ToUint32LE(net.IPv4(127, 0, 0, 1))
	rPort := uint16(f.rAddr().Port)

	f.foreign(f.rAddr(), 5, false)
	notice := payloadOfOpcode(t, f.bTCP.written(), OpNatCallbackRequested)
	t.Logf("input: 8-byte foreign 0xa6 for 5, output: T gets TCP 0x37 % x", notice)
	if want := BuildNatCallbackNotice(loop, rPort, 0, 0, nil); len(notice) != 11 || !bytes.Equal(notice, want) {
		t.Fatalf("0x37 % x, want % x", notice, want)
	}

	f2 := newForeignRig(t, FlagNatCallback, FlagForeignCallback)
	f2.foreign(f2.rAddr(), 5, false, 0xff)
	notice = payloadOfOpcode(t, f2.bTCP.written(), OpNatCallbackRequested)
	t.Logf("input: 9-byte foreign 0xa6 crypt=0xff, output: T gets TCP 0x37 % x", notice)
	if want := BuildNatCallbackNotice(loop, uint16(f2.rAddr().Port), 0, 0x07, nil); len(notice) != 11 || !bytes.Equal(notice, want) {
		t.Fatalf("0x37 % x, want % x", notice, want)
	}
	if got := readUDP(f.r); got != nil {
		t.Fatalf("R got UDP % x before the keepalive", got)
	}
}

// With the 9th byte the crypt rule applies: a mismatch sends no 0x37, a match puts
// the requester's bits in it. Without it the 0x37 says 0.
func TestForeignCallbackCryptRule(t *testing.T) {
	cases := []struct {
		name        string
		targetCrypt byte
		extra       []byte
		wantWake    bool
		wantFlags   byte
	}{
		{"target requires, requester none", 0x07, []byte{0x00}, false, 0},
		{"requester requires, target none", 0x00, []byte{0x05}, false, 0},
		{"both support", 0x03, []byte{0x01}, true, 0x01},
		{"target requires, byte absent", 0x07, nil, true, 0},
	}
	for _, tc := range cases {
		f := newForeignRig(t, FlagNatCallback, FlagForeignCallback)
		f.b.info.CryptOptions = tc.targetCrypt
		f.foreign(f.rAddr(), 5, false, tc.extra...)
		raw := f.bTCP.written()
		t.Logf("input: %s, output: %d bytes TCP", tc.name, len(raw))
		if !tc.wantWake {
			if natPacketCount(raw, OpNatCallbackRequested) != 0 {
				t.Fatalf("%s: 0x37 sent on a crypt mismatch", tc.name)
			}
			continue
		}
		notice := payloadOfOpcode(t, raw, OpNatCallbackRequested)
		if len(notice) != 11 || notice[10] != tc.wantFlags || binary.LittleEndian.Uint32(notice[6:10]) != 0 {
			t.Fatalf("%s: 0x37 % x, want flags 0x%02x, ID 0, no hash", tc.name, notice, tc.wantFlags)
		}
	}
}

// IP-filtered sources are dropped by UDPHandler before any parsing.
func TestForeignCallbackIPFiltered(t *testing.T) {
	f := newForeignRig(t, FlagNatCallback, FlagForeignCallback)
	f.rt.SetAccessFilter(&stubFilter{blockIP: "127.0.0.1"})
	f.foreign(f.rAddr(), 5, false)
	t.Logf("input: request from a filtered address, output: %d bytes TCP", len(f.bTCP.written()))
	if len(f.bTCP.written()) != 0 || len(f.timers) != 0 {
		t.Fatal("filtered requester woke the target")
	}
}

func TestForeignCallbackRefusals(t *testing.T) {
	cases := []struct {
		name               string
		tcpFlags, udpFlags uint32
		plain, connected   bool
		natt, holePunch    bool
		target             uint32
	}{
		{"plaintext", FlagNatCallback, FlagForeignCallback, true, false, true, true, 5},
		{"foreign callback off", FlagNatCallback, 0, false, false, true, true, 5},
		{"lugdunum callback off", 0, FlagForeignCallback, false, false, true, true, 5},
		{"requester connected here", FlagNatCallback, FlagForeignCallback, false, true, true, true, 5},
		{"target without 0x100000", FlagNatCallback, FlagForeignCallback, false, false, true, false, 5},
		{"target without 0x1000", FlagNatCallback, FlagForeignCallback, false, false, false, true, 5},
		{"unknown target", FlagNatCallback, FlagForeignCallback, false, false, true, true, 7},
	}
	for _, tc := range cases {
		f := newForeignRig(t, tc.tcpFlags, tc.udpFlags)
		f.b.nattCapable, f.b.holePunchExt = tc.natt, tc.holePunch
		if tc.connected {
			f.rt.acquireConnSlot(addressKey(net.IPv4(127, 0, 0, 1)))
		}
		f.foreign(f.rAddr(), tc.target, tc.plain)
		f.keepalive(f.bUDP, f.b.info.Hash, false)
		tcp, udp := f.bTCP.written(), readUDP(f.r)
		t.Logf("input: %s, output: tcp=%d bytes udp=%d bytes", tc.name, len(tcp), len(udp))
		if len(tcp) != 0 || udp != nil {
			t.Fatalf("%s: a notice was sent", tc.name)
		}
	}
}

// Per source address a burst of 10 (then 1/s), per target 6/min over all requesters.
func TestForeignCallbackRateLimits(t *testing.T) {
	f := newForeignRig(t, FlagNatCallback, FlagForeignCallback)
	targets := []*captureConn{f.bTCP}
	for _, id := range []uint32{7, 9} {
		c, conn, _ := natSession(t, f.rt, id, true, byte(id))
		c.holePunchExt = true
		targets = append(targets, conn)
	}
	wakes := func() int {
		n := 0
		for _, c := range targets {
			n += natPacketCount(c.written(), OpNatCallbackRequested)
		}
		return n
	}
	for i := 0; i < 11; i++ {
		f.foreign(f.rAddr(), []uint32{5, 7, 9}[i%3], false)
	}
	perAddress := wakes()
	t.Logf("input: 11 requests from one address over 3 targets, output: %d wakes", perAddress)
	if perAddress != 10 {
		t.Fatalf("per-address burst: %d wakes, want 10", perAddress)
	}

	g := newForeignRig(t, FlagNatCallback, FlagForeignCallback)
	for i := 0; i < natForeignPerTargetPerMinute+1; i++ {
		g.foreign(&net.UDPAddr{IP: net.IPv4(127, 0, 1, byte(i+1)), Port: 4672}, 5, false)
	}
	perTarget := natPacketCount(g.bTCP.written(), OpNatCallbackRequested)
	t.Logf("input: %d requesters for one target, output: %d wakes", natForeignPerTargetPerMinute+1, perTarget)
	if perTarget != 6 {
		t.Fatalf("per-target limit: %d wakes, want 6", perTarget)
	}

	// Config changes reach the limiter: burst 2.
	h := newForeignRig(t, FlagNatCallback, FlagForeignCallback)
	cfg := h.rt.UDPConfig()
	cfg.ForeignBurst = 2
	h.rt.ApplyRuntimeConfig(h.rt.TCPConfig(), cfg)
	for i := 0; i < 3; i++ {
		h.foreign(h.rAddr(), 5, false)
	}
	reloaded := natPacketCount(h.bTCP.written(), OpNatCallbackRequested)
	t.Logf("input: burst 2 via reload, 3 requests, output: %d wakes", reloaded)
	if reloaded != 2 {
		t.Fatalf("reloaded burst: %d wakes, want 2", reloaded)
	}
}

// One address names at most 60 distinct targets per 10 minutes; a repeat does not
// count again, and made-up targets never reach the count.
func TestForeignCallbackDistinctTargets(t *testing.T) {
	var n natCallbackState
	now := time.Now()
	for i := uint32(1); i <= natForeignMaxTargetsPerAddress; i++ {
		if !n.allowForeignNamed("a", i, now) {
			t.Fatalf("target %d refused below the cap", i)
		}
	}
	over := n.allowForeignNamed("a", 1000, now)
	repeat := n.allowForeignNamed("a", 7, now.Add(time.Minute))
	other := n.allowForeignNamed("b", 1000, now)
	later := n.allowForeignNamed("a", 1000, now.Add(natForeignTargetWindow+time.Second))
	t.Logf("input: 60 targets then a 61st / a repeat / another address / 10 min later, output: %t %t %t %t", over, repeat, other, later)
	if over || !repeat || !other || !later {
		t.Fatal("distinct-target cap wrong")
	}
	if got := len(n.foreignNamed["a"]); got != 2 {
		t.Fatalf("expired targets kept: %d, want 2 (7 and 1000)", got)
	}
	n.allowForeignNamed("c", 1, now.Add(time.Hour))
	if _, ok := n.foreignNamed["b"]; ok {
		t.Fatal("sweep left an expired address")
	}

	f := newForeignRig(t, FlagNatCallback, FlagForeignCallback)
	cfg := f.rt.UDPConfig()
	cfg.ForeignPerMinute = 0
	f.rt.ApplyRuntimeConfig(f.rt.TCPConfig(), cfg)
	for i := uint32(100); i < 300; i += 2 {
		f.foreign(f.rAddr(), i+1, false)
	}
	f.foreign(f.rAddr(), 5, false)
	t.Logf("input: 100 unknown targets then T, output: %d named", len(f.rt.natCallback.foreignNamed[addressKey(f.rAddr().IP)]))
	if natPacketCount(f.bTCP.written(), OpNatCallbackRequested) != 1 {
		t.Fatal("unknown targets used up the distinct-target cap")
	}
}

// T's keepalive reports its UDP endpoint: R gets UDP 0xa7 under its own key with T's
// IP, the keepalive's source port, T's LowID, T's crypt bits and T's hash, since both
// use the crypt layer. The entry is then gone.
func TestNatKeepaliveDeliversForeignNotice(t *testing.T) {
	f := newForeignRig(t, FlagNatCallback, FlagForeignCallback)
	loop, _ := IPv4ToUint32LE(net.IPv4(127, 0, 0, 1))
	tPort := uint16(f.bUDP.LocalAddr().(*net.UDPAddr).Port)

	f.foreign(f.rAddr(), 5, false, 0x03)
	f.keepalive(f.bUDP, f.b.info.Hash, false)
	raw := readUDP(f.r)
	if raw == nil {
		t.Fatal("R got no UDP 0xa7")
	}
	pt := decryptServerReply(t, raw, natCallbackKey(net.IPv4(127, 0, 0, 1)))
	t.Logf("input: T keepalive from port %d, output: R gets marker=0x%02x % x", tPort, raw[0], pt)
	want := append([]byte{PrED2K, OpNatCallbackRequestedUDP}, BuildNatCallbackNotice(loop, tPort, 5, 0x03, f.b.info.Hash)...)
	if !bytes.Equal(pt, want) {
		t.Fatalf("0xa7 % x, want % x", pt, want)
	}
	f.keepalive(f.bUDP, f.b.info.Hash, false)
	if got := readUDP(f.r); got != nil {
		t.Fatalf("second keepalive sent R % x again", got)
	}

	// Crypt unknown (8-byte request): T's bits, no hash.
	f.foreign(f.rAddr(), 5, false)
	f.keepalive(f.bUDP, f.b.info.Hash, false)
	raw = readUDP(f.r)
	if raw == nil {
		t.Fatal("R got no UDP 0xa7 for the 8-byte request")
	}
	pt = decryptServerReply(t, raw, natCallbackKey(net.IPv4(127, 0, 0, 1)))
	t.Logf("input: 8-byte request, output: R gets % x", pt)
	want = append([]byte{PrED2K, OpNatCallbackRequestedUDP}, BuildNatCallbackNotice(loop, tPort, 5, 0x03, nil)...)
	if !bytes.Equal(pt, want) {
		t.Fatalf("0xa7 % x, want % x", pt, want)
	}
}

// No keepalive within 3 s: R gets the same 0xa7 with T's last known UDP port, from
// T's own recent 0xa6 or else its last keepalive. None known: nothing.
func TestForeignCallbackFallback(t *testing.T) {
	loop, _ := IPv4ToUint32LE(net.IPv4(127, 0, 0, 1))
	tPort := uint16(0)
	read := func(f *foreignRig) []byte {
		raw := readUDP(f.r)
		if raw == nil {
			return nil
		}
		return decryptServerReply(t, raw, natCallbackKey(net.IPv4(127, 0, 0, 1)))
	}

	// Unknown port.
	f := newForeignRig(t, FlagNatCallback, FlagForeignCallback)
	f.foreign(f.rAddr(), 5, false)
	armed := len(f.timers)
	f.fire()
	got := read(f)
	t.Logf("input: no keepalive, no known port, output: armed=%d R got %d bytes", armed, len(got))
	if armed != 1 || got != nil {
		t.Fatalf("armed=%d, R got % x", armed, got)
	}

	// Port from an earlier keepalive.
	f = newForeignRig(t, FlagNatCallback, FlagForeignCallback)
	tPort = uint16(f.bUDP.LocalAddr().(*net.UDPAddr).Port)
	f.keepalive(f.bUDP, f.b.info.Hash, false)
	f.foreign(f.rAddr(), 5, false)
	f.fire()
	got = read(f)
	want := append([]byte{PrED2K, OpNatCallbackRequestedUDP}, BuildNatCallbackNotice(loop, tPort, 5, 0x03, nil)...)
	t.Logf("input: keepalive before the request, output: R gets % x", got)
	if !bytes.Equal(got, want) {
		t.Fatalf("0xa7 % x, want % x", got, want)
	}

	// Port from T's own 0xa6, preferred over its keepalive.
	f = newForeignRig(t, FlagNatCallback, FlagForeignCallback)
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	f.keepalive(other, f.b.info.Hash, false)
	f.request(f.bUDP, 99, 5, false)
	tPort = uint16(f.bUDP.LocalAddr().(*net.UDPAddr).Port)
	f.foreign(f.rAddr(), 5, false)
	f.fire()
	got = read(f)
	want = append([]byte{PrED2K, OpNatCallbackRequestedUDP}, BuildNatCallbackNotice(loop, tPort, 5, 0x03, nil)...)
	t.Logf("input: T's own 0xa6 and an older keepalive, output: R gets % x", got)
	if !bytes.Equal(got, want) {
		t.Fatalf("0xa7 % x, want % x", got, want)
	}

	// Keepalive before 3 s: one 0xa7 only. A new batch has its own timer, which the
	// old one does not fire early.
	f = newForeignRig(t, FlagNatCallback, FlagForeignCallback)
	f.foreign(f.rAddr(), 5, false)
	f.keepalive(f.bUDP, f.b.info.Hash, false)
	first := read(f)
	old := f.timers
	f.timers = nil
	for _, fn := range old {
		fn()
	}
	dup := read(f)
	f.foreign(f.rAddr(), 5, false)
	for _, fn := range old {
		fn()
	}
	early := read(f)
	f.fire()
	second := read(f)
	t.Logf("input: keepalive then timer / new batch then old timer / new timer, output: %d, %d, %d, %d bytes",
		len(first), len(dup), len(early), len(second))
	if first == nil || dup != nil || early != nil || second == nil {
		t.Fatal("want exactly one 0xa7 per batch, at the right time")
	}
}

func TestNatKeepaliveRefusals(t *testing.T) {
	f := newForeignRig(t, FlagNatCallback, FlagForeignCallback)
	f.foreign(f.rAddr(), 5, false)

	f.keepalive(f.bUDP, f.b.info.Hash, true)
	plain := readUDP(f.r)
	f.keepalive(f.bUDP, bytes.Repeat([]byte{0x77}, 16), false)
	wrongHash := readUDP(f.r)
	f.b.peerIP = net.IPv4(10, 0, 0, 1)
	f.keepalive(f.bUDP, f.b.info.Hash, false)
	wrongIP := readUDP(f.r)
	f.b.peerIP = net.IPv4(127, 0, 0, 1)
	t.Logf("input: plain / unknown hash / wrong IP keepalive, output: R got %d / %d / %d bytes", len(plain), len(wrongHash), len(wrongIP))
	if plain != nil || wrongHash != nil || wrongIP != nil {
		t.Fatal("a bad keepalive reached R")
	}
	f.keepalive(f.bUDP, f.b.info.Hash, false)
	if readUDP(f.r) == nil {
		t.Fatal("bad keepalives consumed the pending entry")
	}
}

// Pending entries live natCallbackWindow (19 s); a target holds at most 4, the oldest
// going first, and a repeat from the same requester only refreshes its entry.
func TestForeignCallbackPendingExpiresAndCaps(t *testing.T) {
	var n natCallbackState
	now := time.Now()
	n.addForeign(5, natForeignPending{ipv4: 1, port: 1, at: now.Add(-20 * time.Second)})
	stale := n.takeForeign(5, now)
	t.Logf("input: entry 20 s old, output: %d live", len(stale))
	if len(stale) != 0 {
		t.Fatalf("stale entry delivered: %v", stale)
	}

	for i := 1; i <= 5; i++ {
		n.addForeign(6, natForeignPending{ipv4: uint32(i), port: 1, at: now})
	}
	n.addForeign(6, natForeignPending{ipv4: 3, port: 1, crypt: 1, at: now})
	got := n.takeForeign(6, now)
	var ips []uint32
	for _, e := range got {
		ips = append(ips, e.ipv4)
	}
	t.Logf("input: 5 requesters, then 3 again, output: %v", ips)
	if len(got) != natForeignMaxPerTarget || ips[0] != 2 || ips[3] != 3 || got[3].crypt != 1 {
		t.Fatalf("pending %v, want [2 4 5 3] with 3 refreshed", ips)
	}
	if again := n.takeForeign(6, now); len(again) != 0 {
		t.Fatalf("entries not dropped after take: %v", again)
	}

	n.addForeign(7, natForeignPending{ipv4: 9, port: 1, at: now})
	n.addForeign(8, natForeignPending{ipv4: 9, port: 1, at: now.Add(natCallbackWindow + time.Second)})
	_, kept := n.foreign[7]
	t.Logf("input: add after a window, output: old target kept=%t", kept)
	if kept {
		t.Fatal("sweep left a stale target")
	}
}

// Login bit 0x100000 is stored only when the server offers the foreign callback.
func TestLoginHolePunchExtBit(t *testing.T) {
	for _, tc := range []struct {
		server, login uint32
		want          bool
	}{
		{FlagNatCallback | FlagTcpObfusc, SrvCapNatTraversal | SrvCapHolePunchExt | FlagSupportCrypt, true},
		{FlagNatCallback | FlagTcpObfusc, SrvCapNatTraversal | FlagSupportCrypt, false},
		{FlagTcpObfusc, SrvCapHolePunchExt | FlagSupportCrypt, false},
	} {
		c, _ := natLogin(t, tc.server, tc.login, "203.0.113.9")
		c.infoMu.RLock()
		got := c.holePunchExt
		c.infoMu.RUnlock()
		t.Logf("input: server=0x%x login=0x%x, output: holePunchExt=%t", tc.server, tc.login, got)
		if got != tc.want {
			t.Fatalf("server=0x%x login=0x%x: holePunchExt=%t, want %t", tc.server, tc.login, got, tc.want)
		}
	}
}
