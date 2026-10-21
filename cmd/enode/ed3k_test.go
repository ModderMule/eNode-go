package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"enode/config"
	"enode/ed3k"
	"enode/storage"
)

// TestEd3kOffByDefault: without ed3k.enabled nothing is built, nothing is
// advertised and the engine the runtime serves is the engine itself.
func TestEd3kOffByDefault(t *testing.T) {
	var cfg config.Config
	cfg.TCP.Port = 4661
	engine := storage.NewMemoryEngine()
	rt, err := buildEd3k(context.Background(), cfg, engine, "81.2.3.4", nil, nil)
	t.Logf("input: ed3k.enabled=false output: runtime=%v err=%v advert=%q", rt, err, rt.advertisement())
	if err != nil || rt != nil || rt.advertisement() != "" {
		t.Fatal("ed3k built while disabled")
	}
	if rt.wrapSources(engine) != storage.Engine(engine) {
		t.Fatal("sources wrapped while disabled")
	}
	stop, err := rt.start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if rt.adminStats() != nil {
		t.Fatal("admin stats while disabled")
	}
}

// TestEd3kBuildAndAdvertise builds the node from a config on a free port and
// checks the advertised link.
func TestEd3kBuildAndAdvertise(t *testing.T) {
	var cfg config.Config
	cfg.TCP.Port = freeUDPPort(t)
	cfg.Ed3k.Enabled = true
	cfg.Ed3k.Listen = "127.0.0.1"
	cfg.Ed3k.KeyFile = filepath.Join(t.TempDir(), "ed3k.key")
	rt, err := buildEd3k(context.Background(), cfg, storage.NewMemoryEngine(), "81.2.3.4",
		netip.MustParseAddr("2a00:1450::1").AsSlice(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stop, err := rt.start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	link := rt.advertisement()
	t.Logf("input: tcp.port=%d output: link=%s", cfg.TCP.Port, link)
	want := "ed3k:node?id=" + rt.node.ID().String() + "&ep=81.2.3.4:" + itoa(cfg.TCP.Port) + "&ep=[2a00:1450::1]:" + itoa(cfg.TCP.Port)
	if link != want {
		t.Fatalf("link %s, want %s", link, want)
	}
	if st := rt.adminStats(); st == nil || st.NodeID != rt.node.ID().String() || !st.Bridge {
		t.Fatalf("admin stats %+v", st)
	}
}

// TestEd3kBridgePairing: an ed3k node that stored a SOURCE and a KEYWORD record
// naming the eD2K hash is listed once its TCP port answers; it carries the user
// hash of its CT_ED3K login only when that session comes from its own address; a
// node whose TCP port does not answer is never listed.
func TestEd3kBridgePairing(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	store := storage.NewMemoryEngine()
	node, err := ed3k.New(ed3k.Config{Key: priv, Listen: netip.MustParseAddrPort("127.0.0.1:0"), Store: store})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	open := netip.MustParseAddrPort(ln.Addr().String())
	closed := netip.AddrPortFrom(open.Addr(), freeUDPPort(t)) // nothing listens on it over TCP

	ctx := context.Background()
	now := time.Now()
	ed2kHash := [16]byte{0xed, 2}
	publish := func(id [16]byte, ep netip.AddrPort) {
		root := [32]byte{id[0], 0xaa}
		var fileTarget [16]byte
		copy(fileTarget[:], root[:16])
		store.StoreEd3kSource(ctx, storage.Ed3kSource{Target: fileTarget, NodeID: id, Peer: []byte("p"), Host: ep.String(),
			Site: ep.String(), EP4: ep, ED2K: true, LifetimeEnd: now.Add(time.Hour)}, storage.Ed3kLimits{}, now)
		store.StoreEd3kKeyword(ctx, storage.Ed3kKeyword{Target: [16]byte{1}, Root: root, PubKey: [32]byte{id[0]},
			PublisherID: id, Signed: []byte{id[0]}, ED2K: ed2kHash[:], Host: ep.String(), Site: ep.String(),
			Expires: now.Add(time.Hour)}, storage.Ed3kLimits{}, now, nil)
	}
	reachable, unreachable := [16]byte{1}, [16]byte{2}
	publish(reachable, open)
	publish(unreachable, closed)

	userHash := [16]byte{0xab, 0xcd}
	pairIP := net.ParseIP("127.0.0.1")
	e := &ed3kBridgeEngine{Engine: store, node: node, max: 5,
		pairing: func(n [16]byte) ([16]byte, byte, net.IP, bool) { return userHash, 0x07, pairIP, n == reachable }}

	first := e.GetSourcesByHash(ed2kHash[:])
	t.Logf("first request (TCP tests start): %d sources", len(first))
	if len(first) != 0 {
		t.Fatal("listed before the TCP test")
	}
	var got []storage.Source
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got = e.GetSourcesByHash(ed2kHash[:]); len(got) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("after the tests: %+v", got)
	if len(got) != 1 || got[0].Port != open.Port() || string(got[0].UserHash) != string(userHash[:]) || got[0].CryptOptions != 0x07 {
		t.Fatalf("bridged sources %+v", got)
	}
	pairIP = net.ParseIP("10.9.9.9") // the CT_ED3K session comes from elsewhere
	got = e.GetSourcesByHash(ed2kHash[:])
	t.Logf("pairing from another address: %+v", got)
	if len(got) != 1 || got[0].UserHash != nil {
		t.Fatal("user hash of a session at another address")
	}
	again := e.add(ed2kHash[:], []storage.Source{got[0]})
	if len(again) != 1 {
		t.Fatalf("a source the engine lists was added twice: %d", len(again))
	}
}

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

func itoa(p uint16) string { return netip.AddrPortFrom(netip.IPv4Unspecified(), p).String()[8:] }
