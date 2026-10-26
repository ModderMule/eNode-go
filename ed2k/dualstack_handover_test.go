package ed2k

import (
	"bytes"
	"net"
	"testing"
	"time"

	"enode/storage"
)

// A global-unicast IPv6 the dual-stack client advertises over IPv4 and later connects from.
var handoverV6 = net.ParseIP("2a01:4f8:c0c:1234::2")

func newHandoverRuntime(engine storage.Engine) *ServerRuntime {
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address:           "127.0.0.1",
		Port:              4661,
		Hash:              []byte("1111111111111111"),
		AllowLowIDs:       true,
		IPv6:              true,
		PublishV6Sources:  true,
		ConnectionTimeout: 50 * time.Millisecond,
	}, UDPRuntimeConfig{}, engine)
	// A refused duplicate probes the held session; mock sessions never die of it.
	rt.staleProbeWait = 10 * time.Millisecond
	return rt
}

func loginPacketIPv6(t *testing.T, hash []byte, port uint16, v6 net.IP) *Packet {
	t.Helper()
	wire, err := MakePacket(PrED2K, []PacketItem{
		{Type: TypeUint8, Value: OpLoginRequest},
		{Type: TypeHash, Value: hash},
		{Type: TypeUint32, Value: uint32(0)},
		{Type: TypeUint16, Value: port},
		{Type: TypeTags, Value: []Tag{{Type: TypeHash, Code: TagModIPv6, Data: []byte(v6.To16())}}},
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

func v4Conn() *mockConn {
	return &mockConn{remote: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 20), Port: 50010}}
}

func v6Conn(ip net.IP) *mockConn {
	return &mockConn{remote: &net.TCPAddr{IP: ip, Port: 50011}}
}

// A dual-stack client moves its session to IPv6: it connects from the IPv6 its IPv4
// session advertised, same listen port. The new login is granted and the IPv4 session
// released only then, so the client is never offline in between.
func TestDualStackHandoverReplacesIPv4Session(t *testing.T) {
	engine := storage.NewMemoryEngine()
	rt := newHandoverRuntime(engine)
	hash := bytes.Repeat([]byte{0xb1}, 16)

	firstConn := v4Conn()
	first := newTCPClient(rt, firstConn, false)
	first.handlePacket(loginPacketIPv6(t, hash, 4662, handoverV6))
	if !first.logged {
		t.Fatalf("ipv4 login refused (reason=%q)", first.getCloseReason())
	}
	t.Logf("input: ipv4 session remote=%s advertised=%s port=4662", first.remoteHost, handoverV6)

	secondConn := v6Conn(handoverV6)
	second := newTCPClient(rt, secondConn, false)
	second.handlePacket(loginPacket(t, hash, 0, 4662))
	t.Logf("output: ipv6 logged=%t closed=%d; ipv4 closed=%d reason=%q",
		second.logged, secondConn.closed, firstConn.closed, first.getCloseReason())

	if !second.logged {
		t.Fatalf("ipv6 handover login refused (reason=%q)", second.getCloseReason())
	}
	if got := first.getCloseReason(); got != "replaced-by-ipv6-session" {
		t.Fatalf("ipv4 session close reason=%q want replaced-by-ipv6-session", got)
	}
	if rt.sessionByHash(hash) != second {
		t.Fatal("hash index does not point at the ipv6 session")
	}
	if !engine.IsConnected(storage.ClientInfo{Hash: hash}) {
		t.Fatal("ipv6 session is not online in storage")
	}
}

// The takeover needs the advertised address *and* the listen port. A peer that only
// knows the public hash, from any other IPv6, is refused and the victim stays.
func TestDualStackHandoverRefusesOtherAddressOrPort(t *testing.T) {
	cases := []struct {
		name string
		from net.IP
		port uint16
	}{
		{"other ipv6", net.ParseIP("2a01:4f8:c0c:9999::7"), 4662},
		{"same ipv6, other port", handoverV6, 4663},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newHandoverRuntime(storage.NewMemoryEngine())
			hash := bytes.Repeat([]byte{0xb2}, 16)

			firstConn := v4Conn()
			first := newTCPClient(rt, firstConn, false)
			first.handlePacket(loginPacketIPv6(t, hash, 4662, handoverV6))
			if !first.logged {
				t.Fatalf("ipv4 login refused (reason=%q)", first.getCloseReason())
			}

			secondConn := v6Conn(tc.from)
			second := newTCPClient(rt, secondConn, false)
			second.handlePacket(loginPacket(t, hash, 0, tc.port))
			t.Logf("input: from=%s port=%d; output: logged=%t reason=%q victim closed=%d",
				tc.from, tc.port, second.logged, second.getCloseReason(), firstConn.closed)

			if second.logged {
				t.Fatal("login granted without the advertised address and port")
			}
			if firstConn.closed != 0 || !first.logged {
				t.Fatal("the live session was kicked")
			}
		})
	}
}

// Only IPv4 → IPv6. The reverse would trust a CT_MOD_IP_V6 the newcomer itself sends,
// which anyone can forge.
func TestDualStackHandoverNotFromIPv6ToIPv4(t *testing.T) {
	rt := newHandoverRuntime(storage.NewMemoryEngine())
	hash := bytes.Repeat([]byte{0xb3}, 16)

	firstConn := v6Conn(handoverV6)
	first := newTCPClient(rt, firstConn, false)
	first.handlePacket(loginPacket(t, hash, 0, 4662))
	if !first.logged {
		t.Fatalf("ipv6 login refused (reason=%q)", first.getCloseReason())
	}

	secondConn := v4Conn()
	second := newTCPClient(rt, secondConn, false)
	second.handlePacket(loginPacketIPv6(t, hash, 4662, handoverV6))
	t.Logf("output: ipv4 logged=%t reason=%q; ipv6 closed=%d", second.logged, second.getCloseReason(), firstConn.closed)

	if second.logged {
		t.Fatal("ipv4 login took over an ipv6 session on a claimed address")
	}
	if firstConn.closed != 0 {
		t.Fatal("the ipv6 session was kicked")
	}
}

// The IPv4 session ended on its own while the IPv6 login ran: nothing to release, the
// login goes through.
func TestDualStackHandoverOldSessionGoneMeanwhile(t *testing.T) {
	engine := storage.NewMemoryEngine()
	rt := newHandoverRuntime(engine)
	hash := bytes.Repeat([]byte{0xb4}, 16)

	first := newTCPClient(rt, v4Conn(), false)
	first.handlePacket(loginPacketIPv6(t, hash, 4662, handoverV6))
	second := newTCPClient(rt, v6Conn(handoverV6), false)
	second.info.Hash = hash
	second.info.Port = 4662
	first.releaseSession()
	t.Logf("input: ipv4 session released before the ipv6 handshake")

	ok := second.completeDualStackHandover()
	t.Logf("output: completeDualStackHandover=%t", ok)
	if !ok {
		t.Fatal("handover refused although the old session was already gone")
	}
}
