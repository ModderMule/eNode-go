package ed2k

import (
	"bytes"
	"net"
	"testing"

	"enode/storage"
)

// reflectConn is a captureConn with a settable peer address, so a test can drive
// both the v4- and the v6-connected path through newTCPClient's address
// derivation instead of mockConn's hard-coded 127.0.0.2.
type reflectConn struct {
	captureConn
	remote net.Addr
}

func (c *reflectConn) RemoteAddr() net.Addr { return c.remote }

// newReflectClient builds a session whose peer address is exactly remote, which
// is what decides connectedV6 and therefore what gets reflected.
func newReflectClient(t *testing.T, rt *ServerRuntime, remote string) (*tcpClient, *reflectConn) {
	t.Helper()
	ip := net.ParseIP(remote)
	if ip == nil {
		t.Fatalf("bad remote address %q", remote)
	}
	conn := &reflectConn{remote: &net.TCPAddr{IP: ip, Port: 50000}}
	return newTCPClient(rt, conn, false), conn
}

// sentIdentTags runs sendServerIdent and decodes the tags off the wire.
func sentIdentTags(t *testing.T, c *tcpClient, conn *reflectConn) map[string]any {
	t.Helper()
	c.sendServerIdent()
	raw := conn.written()
	if len(raw) == 0 {
		t.Fatal("no OP_SERVERIDENT written")
	}
	return parseServerIdentTags(t, NewBufferFromBytes(raw))
}

// TestServerIdentReflectsClientIPv6 checks the CT_MOD_YOUR_IP (0xad) hash tag
// carries the address the server *observed* the session on. The tag exists so a
// client with RFC 4941 temporary addresses or several prefixes learns which of
// its addresses actually egressed — so it must never be an echo of the client's
// own CT_MOD_IP_V6 claim, and must be absent whenever the server did not observe
// a public IPv6 for itself.
func TestServerIdentReflectsClientIPv6(t *testing.T) {
	advertised := net.ParseIP("2001:db8::dead:beef").To16()

	cases := []struct {
		name     string
		serverV6 bool   // ipv6.enabled on the server
		remote   string // the address the session arrives from
		wantV6   string // "" means the tag must be absent
	}{
		{
			name:     "v6-connected session gets its observed address back",
			serverV6: true,
			remote:   "2001:db8::1",
			wantV6:   "2001:db8::1",
		},
		{
			name:     "v4-connected session gets no tag even though it advertised an IPv6",
			serverV6: true,
			remote:   "192.0.2.10",
			wantV6:   "",
		},
		{
			name:     "link-local peer is not a reflectable address",
			serverV6: true,
			remote:   "fe80::1",
			wantV6:   "",
		},
		{
			name:     "ULA peer is not a reflectable address",
			serverV6: true,
			remote:   "fd00::1",
			wantV6:   "",
		},
		{
			name:     "server with IPv6 off reflects nothing",
			serverV6: false,
			remote:   "2001:db8::1",
			wantV6:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := NewServerRuntime(TCPRuntimeConfig{
				Name:             "eNode",
				Address:          "192.0.2.1",
				Port:             4661,
				Hash:             bytes.Repeat([]byte{0x01}, 16),
				IPv6:             tc.serverV6,
				PublishV6Sources: tc.serverV6,
			}, UDPRuntimeConfig{}, storage.NewMemoryEngine())

			c, conn := newReflectClient(t, rt, tc.remote)
			// Every session claims the same IPv6 in its login tags. Only the observed
			// address may ever come back, so this value must never appear on the wire.
			c.infoMu.Lock()
			c.info.IPv6 = advertised
			c.infoMu.Unlock()

			t.Logf("input: serverIPv6=%t remote=%s advertisedIPv6=%s",
				tc.serverV6, tc.remote, net.IP(advertised).String())

			tags := sentIdentTags(t, c, conn)
			got, present := tags["yourip"]

			if tc.wantV6 == "" {
				if present {
					t.Fatalf("output: yourip=%x, want the tag absent", got)
				}
				t.Log("output: yourip absent, as expected")
				return
			}

			b, ok := got.([]byte)
			if !present || !ok {
				t.Fatalf("output: yourip missing or not a hash tag (%T)", got)
			}
			if want := net.ParseIP(tc.wantV6).To16(); !bytes.Equal(b, want) {
				t.Fatalf("output: yourip=%s, want %s", net.IP(b).String(), tc.wantV6)
			}
			if bytes.Equal(b, advertised) {
				t.Fatal("output: reflected the client's own CT_MOD_IP_V6 claim instead of the observed address")
			}
			t.Logf("output: yourip=%s", net.IP(b).String())
		})
	}
}

// TestServerIdentIPv6Status checks the TagIPv6Status (0xab) bitfield. It is the
// half of the feature that reaches a v4-connected dual-stack client: reflection
// cannot serve it, but it still needs to know whether the IPv6 it advertised was
// found reachable, i.e. whether it is being published as an IPv6 source. The
// Probed bit separates a verified verdict from an assumed one.
func TestServerIdentIPv6Status(t *testing.T) {
	clientV6 := net.ParseIP("2001:db8::abcd").To16()

	cases := []struct {
		name       string
		remote     string
		publishV6  bool
		probeIPv6  bool
		hasV6      bool
		reachable  bool
		logged     bool
		wantStatus uint8 // 0 means the tag must be absent
	}{
		{
			name:       "v6-connected session is reachable without a probe",
			remote:     "2001:db8::1",
			publishV6:  true,
			probeIPv6:  true,
			hasV6:      true,
			reachable:  true,
			logged:     true,
			wantStatus: IPv6StatusHave | IPv6StatusReachable,
		},
		{
			name:       "v4-connected session with a passing dial-back is verified",
			remote:     "192.0.2.10",
			publishV6:  true,
			probeIPv6:  true,
			hasV6:      true,
			reachable:  true,
			logged:     true,
			wantStatus: IPv6StatusHave | IPv6StatusReachable | IPv6StatusProbed,
		},
		{
			name:       "v4-connected session with a failing dial-back is told so",
			remote:     "192.0.2.10",
			publishV6:  true,
			probeIPv6:  true,
			hasV6:      true,
			reachable:  false,
			logged:     true,
			wantStatus: IPv6StatusHave | IPv6StatusProbed,
		},
		{
			name:       "probing off means reachable but not verified",
			remote:     "192.0.2.10",
			publishV6:  true,
			probeIPv6:  false,
			hasV6:      true,
			reachable:  true,
			logged:     true,
			wantStatus: IPv6StatusHave | IPv6StatusReachable,
		},
		{
			name:       "no verdict is computed when v6 publication is off",
			remote:     "192.0.2.10",
			publishV6:  false,
			probeIPv6:  true,
			hasV6:      true,
			reachable:  true,
			logged:     true,
			wantStatus: 0,
		},
		{
			name:       "a session with no IPv6 gets no status",
			remote:     "192.0.2.10",
			publishV6:  true,
			probeIPv6:  true,
			hasV6:      false,
			reachable:  false,
			logged:     true,
			wantStatus: 0,
		},
		{
			name:       "pre-login ident carries no verdict yet",
			remote:     "192.0.2.10",
			publishV6:  true,
			probeIPv6:  true,
			hasV6:      true,
			reachable:  true,
			logged:     false,
			wantStatus: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := NewServerRuntime(TCPRuntimeConfig{
				Name:             "eNode",
				Address:          "192.0.2.1",
				Port:             4661,
				Hash:             bytes.Repeat([]byte{0x01}, 16),
				IPv6:             true,
				PublishV6Sources: tc.publishV6,
				ProbeIPv6:        tc.probeIPv6,
			}, UDPRuntimeConfig{}, storage.NewMemoryEngine())

			c, conn := newReflectClient(t, rt, tc.remote)
			c.infoMu.Lock()
			if tc.hasV6 {
				c.info.IPv6 = clientV6
			}
			c.info.IPv6Reachable = tc.reachable
			c.logged = tc.logged
			c.infoMu.Unlock()

			t.Logf("input: remote=%s publishV6=%t probeIPv6=%t hasV6=%t reachable=%t logged=%t",
				tc.remote, tc.publishV6, tc.probeIPv6, tc.hasV6, tc.reachable, tc.logged)

			tags := sentIdentTags(t, c, conn)
			got, present := tags["ipv6status"]

			if tc.wantStatus == 0 {
				if present {
					t.Fatalf("output: ipv6status=0x%02x, want the tag absent", got)
				}
				t.Log("output: ipv6status absent, as expected")
				return
			}
			if !present {
				t.Fatalf("output: ipv6status missing, want 0x%02x", tc.wantStatus)
			}
			// A uint8 tag decodes through the same widening the C++ reader applies
			// (packets.cpp:470-472 reads one byte, then relabels the tag as uint32).
			var status uint8
			switch v := got.(type) {
			case uint8:
				status = v
			case uint32:
				status = uint8(v)
			case uint64:
				status = uint8(v)
			default:
				t.Fatalf("output: ipv6status has unexpected type %T", got)
			}
			if status != tc.wantStatus {
				t.Fatalf("output: ipv6status=0x%02x, want 0x%02x", status, tc.wantStatus)
			}
			t.Logf("output: ipv6status=0x%02x (have=%t reachable=%t probed=%t)", status,
				status&IPv6StatusHave != 0, status&IPv6StatusReachable != 0, status&IPv6StatusProbed != 0)
		})
	}
}

// TestServerIdentUnchangedForLegacySession is the backward-compatibility gate: a
// v4-only session on a v6-disabled server must receive exactly the bytes the
// pre-reflection server sent — the per-session tags add nothing at all.
func TestServerIdentUnchangedForLegacySession(t *testing.T) {
	conf := ServerConfig{
		Name:        "eNode",
		Description: "test",
		Address:     "192.0.2.1",
		Hash:        bytes.Repeat([]byte{0x01}, 16),
		TCPPort:     4661,
	}
	want, err := BuildServerIdentPacket(conf)
	if err != nil {
		t.Fatal(err)
	}

	rt := NewServerRuntime(TCPRuntimeConfig{
		Name:        conf.Name,
		Description: conf.Description,
		Address:     conf.Address,
		Port:        conf.TCPPort,
		Hash:        conf.Hash,
		Flags:       conf.TCPFlags,
	}, UDPRuntimeConfig{}, storage.NewMemoryEngine())

	c, conn := newReflectClient(t, rt, "192.0.2.10")
	c.infoMu.Lock()
	c.logged = true
	c.infoMu.Unlock()
	c.sendServerIdent()

	got := conn.written()
	t.Logf("input: v4-only session on a v6-disabled server")
	t.Logf("output: % x", got)
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("legacy OP_SERVERIDENT changed:\n got % x\nwant % x", got, want.Bytes())
	}
	t.Log("output: byte-identical to the server-only ident packet")
}

// TestReflectionTagWireTypes pins the tag *types* on the wire. eMule dispatches on
// the tag name but consumes the value by type: an unknown name is skipped safely,
// while an unknown type falls through without consuming its value
// (srchybrid/packets.cpp:504-510) and desyncs every following tag. So both new
// tags must use types the reference reads by fixed length — TAGTYPE_HASH (16
// bytes) and TAGTYPE_UINT8 (1 byte) — in the classic name-length-1 framing.
func TestReflectionTagWireTypes(t *testing.T) {
	clientV6 := net.ParseIP("2001:db8::1").To16()
	conf := ServerConfig{
		Name:             "eNode",
		Address:          "192.0.2.1",
		Hash:             bytes.Repeat([]byte{0x01}, 16),
		TCPPort:          4661,
		ClientIPv6:       clientV6,
		ClientIPv6Status: IPv6StatusHave | IPv6StatusReachable | IPv6StatusProbed,
	}
	t.Logf("input: clientIPv6=%s status=0x%02x", net.IP(clientV6).String(), conf.ClientIPv6Status)

	buf, err := BuildServerIdentPacket(conf)
	if err != nil {
		t.Fatal(err)
	}
	_, payload := tcpFoundSourcesPayload(t, buf)
	t.Logf("output: % x", payload)

	// Classic tag framing is <type:1><nameLen:2 = 1><nameID:1><value>. Locate each
	// tag by its name byte and check the type byte immediately before it.
	for _, tc := range []struct {
		label    string
		nameID   uint8
		wantType uint8
		valueLen int
	}{
		{"CT_MOD_YOUR_IP", TagModYourIP, TypeHash, 16},
		{"ST_IPV6_STATUS", TagIPv6Status, TypeUint8, 1},
	} {
		idx := bytes.Index(payload, []byte{tc.wantType, 0x01, 0x00, tc.nameID})
		if idx < 0 {
			t.Fatalf("%s (0x%02x): no tag with type 0x%02x and a 1-byte name found in the payload",
				tc.label, tc.nameID, tc.wantType)
		}
		if got := len(payload) - (idx + 4); got < tc.valueLen {
			t.Fatalf("%s: %d value bytes follow the tag header, want at least %d", tc.label, got, tc.valueLen)
		}
		t.Logf("output: %s at offset %d, type=0x%02x nameLen=1 value=%d bytes",
			tc.label, idx, tc.wantType, tc.valueLen)
	}

	// The reflection tags come last, so a client that mis-handles them cannot
	// corrupt the server name or description that precede them.
	yourIP := bytes.Index(payload, []byte{TypeHash, 0x01, 0x00, TagModYourIP})
	name := bytes.Index(payload, []byte{TypeString, 0x01, 0x00, TagName})
	if name < 0 || yourIP < name {
		t.Fatalf("reflection tag at %d precedes the server name at %d", yourIP, name)
	}
	t.Log("output: reflection tags follow the classic server tags")
}
