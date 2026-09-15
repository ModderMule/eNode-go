package ed2k

import (
	"bytes"
	"net"
	"testing"
	"time"

	"enode/storage"
)

// gateProbe drives the real UDP dispatcher and reports whether it answered.
func gateProbe(t *testing.T, udpCfg UDPRuntimeConfig, request []byte) []byte {
	t.Helper()

	engine := storage.NewMemoryEngine()
	owner := storage.ClientInfo{Hash: []byte("0123456789abcdef"), ID: 0x0100007F, Port: 4662}
	engine.Connect(owner)
	engine.AddFile(storage.File{Hash: []byte("fedcba9876543210"), Size: 1024, Name: "food.bin"}, owner)

	rt := NewServerRuntime(TCPRuntimeConfig{}, udpCfg, engine)
	handler := rt.UDPHandler(false)

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

// getSources/getFiles reached BuildUDPFlags and nothing else, so the server
// cleared FLAG_UDP_EXTGETSOURCES from what it advertised and then served the
// opcode regardless. Conforming clients gate their requests on the advertised
// flag, so the exposure was exactly to clients that ignore it — which is the
// reason the option exists.
func TestUDPExtendedOpcodesRespectConfig(t *testing.T) {
	fileHash := []byte("fedcba9876543210")

	globGetSources := append([]byte{PrED2K, OpGlobGetSources}, fileHash...)
	globSearch := append([]byte{PrED2K, OpGlobSearchReq}, 0x01, 0x04, 0x00, 'f', 'o', 'o', 'd')

	cases := []struct {
		name      string
		cfg       UDPRuntimeConfig
		request   []byte
		wantReply bool
	}{
		{"getSources enabled answers 0x9A", UDPRuntimeConfig{GetSources: true}, globGetSources, true},
		{"getSources disabled ignores 0x9A", UDPRuntimeConfig{GetSources: false}, globGetSources, false},
		{"getFiles enabled answers the search", UDPRuntimeConfig{GetFiles: true}, globSearch, true},
		{"getFiles disabled ignores the search", UDPRuntimeConfig{GetFiles: false}, globSearch, false},
		{"the two gates are independent", UDPRuntimeConfig{GetSources: true, GetFiles: false}, globSearch, false},
		{"and in the other direction", UDPRuntimeConfig{GetSources: false, GetFiles: true}, globGetSources, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply := gateProbe(t, tc.cfg, tc.request)
			t.Logf("input: opcode=0x%02x getSources=%t getFiles=%t",
				tc.request[1], tc.cfg.GetSources, tc.cfg.GetFiles)
			t.Logf("output: reply=%d bytes", len(reply))

			if got := reply != nil; got != tc.wantReply {
				t.Fatalf("replied=%t, want %t", got, tc.wantReply)
			}
		})
	}
}

// OP_GLOBSEARCHREQ2 (0x92) had no dispatch case at all: it fell through to the
// unknown-opcode branch and the client got nothing back. It is 0x98 with a
// different client belief about us — a bare search tree, no tag block — and
// eMule reaches for it when its cached UDP flags carry EXT_GETFILES without
// LARGEFILES (SearchExprParser.cpp:999-1000), which a stale or third-party
// server.met entry can say even though BuildUDPFlags never does.
//
// Driven through the real dispatcher on purpose: udpGlobSearchReq itself was
// always fine, so a test calling it directly passes with or without the fix.
// Counting FindBySearch alongside the reply is what separates "the switch
// routed it" from "something else answered".
func TestGlobSearchReq2IsRouted(t *testing.T) {
	spy := &searchSpy{Engine: seededEngine(t)}
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{GetFiles: true}, spy)

	request := append([]byte{PrED2K, OpGlobSearchReq2}, 0x01, 0x04, 0x00, 'f', 'o', 'o', 'd')
	t.Logf("input: % x", request)

	reply := probeUDP(t, rt, request)
	t.Logf("output: searches=%d reply=% x", spy.searches, reply)

	if spy.searches != 1 {
		t.Fatalf("ran %d search(es), want 1 — the dispatcher dropped 0x92", spy.searches)
	}
	if len(reply) < 2 {
		t.Fatalf("reply = %d bytes, want a full OP_GLOBSEARCHRES datagram", len(reply))
	}
	if reply[1] != OpGlobSearchRes {
		t.Fatalf("reply opcode = 0x%02x, want 0x%02x", reply[1], OpGlobSearchRes)
	}
	if !bytes.Contains(reply, []byte("food.bin")) {
		t.Fatal("reply carried no seeded file, so the search result never made it back")
	}
}

// OP_GLOBSERVSTATREQ and OP_SERVERDESCREQ carry no such flag. Gating them would
// make the server invisible in client server lists, so they must answer even
// with everything else switched off.
func TestUDPStatusOpcodesStayUngated(t *testing.T) {
	cfg := UDPRuntimeConfig{GetSources: false, GetFiles: false}

	for _, tc := range []struct {
		name    string
		request []byte
	}{
		{"OP_GLOBSERVSTATREQ", []byte{PrED2K, OpGlobServStatReq, 0x01, 0x02, 0x03, 0x04}},
		{"OP_SERVERDESCREQ", []byte{PrED2K, OpServerDescReq}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := gateProbe(t, cfg, tc.request)
			t.Logf("input: opcode=0x%02x with both gates off", tc.request[1])
			t.Logf("output: reply=%d bytes", len(reply))

			if reply == nil {
				t.Fatal("no reply — the server would be invisible in server lists")
			}
		})
	}
}
