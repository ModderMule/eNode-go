package ed2k

import (
	"bytes"
	"net"
	"testing"

	"enode/storage"
)

func loginPacketTags(t *testing.T, hash []byte, port uint16, tags []Tag) *Packet {
	t.Helper()
	wire, err := MakePacket(PrED2K, []PacketItem{
		{Type: TypeUint8, Value: OpLoginRequest},
		{Type: TypeHash, Value: hash},
		{Type: TypeUint32, Value: uint32(0)},
		{Type: TypeUint16, Value: port},
		{Type: TypeTags, Value: tags},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := NewPacket()
	if err := p.Init(NewBufferFromBytes(wire.Bytes())); err != nil {
		t.Fatal(err)
	}
	return p
}

func tokenTag(token []byte) []Tag {
	return []Tag{{Type: TypeHash, Code: TagNatToken, Data: token}}
}

// HighID recheck from an IPv6 session: the IPv4 login sends the session's token, takes
// it over without a gap and keeps its IPv6 registered, though it advertises none.
func TestTokenTakeoverIPv4OverIPv6KeepsIPv6(t *testing.T) {
	engine := storage.NewMemoryEngine()
	rt := newHandoverRuntime(engine)
	hash := bytes.Repeat([]byte{0xc1}, 16)

	firstConn := v6Conn(handoverV6)
	first := newTCPClient(rt, firstConn, false)
	first.handlePacket(loginPacket(t, hash, 0, 4662))
	token := first.issuedSessionToken()
	if !first.logged || len(token) != 16 {
		t.Fatalf("ipv6 login: logged=%t token=%d (reason=%q)", first.logged, len(token), first.getCloseReason())
	}

	secondConn := v4Conn()
	second := newTCPClient(rt, secondConn, false)
	second.handlePacket(loginPacketTags(t, hash, 4662, tokenTag(token)))
	info := second.snapshotInfo()
	t.Logf("output: ipv4 logged=%t ipv6=%s capable=%t; ipv6 session reason=%q",
		second.logged, net.IP(info.IPv6), second.ipv6Capable, first.getCloseReason())

	if !second.logged {
		t.Fatalf("ipv4 login with the token refused (reason=%q)", second.getCloseReason())
	}
	if got := first.getCloseReason(); got != "replaced-by-takeover" {
		t.Fatalf("ipv6 session close reason=%q want replaced-by-takeover", got)
	}
	if !net.IP(info.IPv6).Equal(handoverV6) || !second.ipv6Capable {
		t.Fatalf("ipv6 not kept: %s capable=%t", net.IP(info.IPv6), second.ipv6Capable)
	}
	if rt.sessionByHash(hash) != second || !engine.IsConnected(storage.ClientInfo{Hash: hash}) {
		t.Fatal("ipv4 session is not the online one")
	}
	if bytes.Equal(second.issuedSessionToken(), token) {
		t.Fatal("token not renewed on the new session")
	}
}

// IPv4 → IPv6 behind NAT66: the IPv4 session advertised no IPv6 (none is local), so only
// the token proves the IPv6 login.
func TestTokenTakeoverIPv6OverIPv4WithoutAdvertisedAddress(t *testing.T) {
	rt := newHandoverRuntime(storage.NewMemoryEngine())
	hash := bytes.Repeat([]byte{0xc2}, 16)

	first := newTCPClient(rt, v4Conn(), false)
	first.handlePacket(loginPacket(t, hash, 0, 4662))
	token := first.issuedSessionToken()

	second := newTCPClient(rt, v6Conn(handoverV6), false)
	second.handlePacket(loginPacketTags(t, hash, 4662, tokenTag(token)))
	t.Logf("output: ipv6 logged=%t; ipv4 reason=%q", second.logged, first.getCloseReason())
	if !second.logged || first.getCloseReason() != "replaced-by-takeover" {
		t.Fatalf("token takeover failed: logged=%t reason=%q", second.logged, second.getCloseReason())
	}
}

// A wrong token, or the token of a session already replaced, takes over nothing.
func TestTokenTakeoverRefusesWrongOrSpentToken(t *testing.T) {
	rt := newHandoverRuntime(storage.NewMemoryEngine())
	hash := bytes.Repeat([]byte{0xc3}, 16)

	firstConn := v6Conn(handoverV6)
	first := newTCPClient(rt, firstConn, false)
	first.handlePacket(loginPacket(t, hash, 0, 4662))
	token := first.issuedSessionToken()

	wrong := newTCPClient(rt, v4Conn(), false)
	wrong.handlePacket(loginPacketTags(t, hash, 4662, tokenTag(bytes.Repeat([]byte{0x5a}, 16))))
	if wrong.logged || firstConn.closed != 0 {
		t.Fatalf("wrong token: logged=%t victim closed=%d", wrong.logged, firstConn.closed)
	}

	second := newTCPClient(rt, v4Conn(), false)
	second.handlePacket(loginPacketTags(t, hash, 4662, tokenTag(token)))
	if !second.logged {
		t.Fatalf("takeover refused (reason=%q)", second.getCloseReason())
	}
	thirdConn := &mockConn{remote: &net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 50012}}
	third := newTCPClient(rt, thirdConn, false)
	third.handlePacket(loginPacketTags(t, hash, 4662, tokenTag(token)))
	t.Logf("output: spent token logged=%t reason=%q", third.logged, third.getCloseReason())
	if third.logged || rt.sessionByHash(hash) != second {
		t.Fatal("a spent token took over the new session")
	}
}
