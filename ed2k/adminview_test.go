package ed2k

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"

	"enode/storage"
)

func TestLoginSoftware(t *testing.T) {
	cases := []struct {
		name string
		tags []NamedTag
		want string
	}{
		{"eMule 0.50a", []NamedTag{{Name: "muleversion", Value: uint64(0<<24 | 0<<17 | 50<<10 | 0<<7)}}, "eMule 0.50a"},
		{"eMule 0.60d", []NamedTag{{Name: "muleversion", Value: uint64(0<<17 | 60<<10 | 3<<7)}}, "eMule 0.60d"},
		{"aMule 2.3.3", []NamedTag{{Name: "muleversion", Value: uint64(3<<24 | 2<<17 | 3<<10 | 3<<7)}}, "aMule 2.3.3"},
		{"no version tag", []NamedTag{{Name: "name", Value: "someone"}}, "eDonkey"},
		{"unknown id", []NamedTag{{Name: "muleversion", Value: uint64(99<<24 | 1<<17)}}, "client 99 (1.0.0)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := loginSoftware(tc.tags)
			t.Logf("input: %+v", tc.tags)
			t.Logf("output: %q", got)
			if got != tc.want {
				t.Fatalf("loginSoftware = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoginNickIsCappedOnARuneBoundary(t *testing.T) {
	long := strings.Repeat("é", 100) // 200 bytes
	got := loginNick([]NamedTag{{Name: "name", Value: long}})
	t.Logf("input: %d-byte nick", len(long))
	t.Logf("output: %d bytes %q", len(got), got)
	if len(got) != maxNickBytes || got != strings.Repeat("é", maxNickBytes/2) {
		t.Fatalf("nick = %d bytes, want %d whole runes", len(got), maxNickBytes)
	}
	if empty := loginNick(nil); empty != "" {
		t.Fatalf("nick without a name tag = %q, want empty", empty)
	}
}

func TestClientSnapshotAndDisconnect(t *testing.T) {
	rt := newLoginTestRuntime(storage.NewMemoryEngine())
	hash := bytes.Repeat([]byte{0xc1}, 16)
	conn := &mockConn{remote: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 40), Port: 50001}}
	c := newTCPClient(rt, conn, false)

	wire, err := MakePacket(PrED2K, []PacketItem{
		{Type: TypeUint8, Value: OpLoginRequest},
		{Type: TypeHash, Value: hash},
		{Type: TypeUint32, Value: uint32(0)},
		{Type: TypeUint16, Value: uint16(4662)},
		{Type: TypeTags, Value: []Tag{
			{Type: TypeString, Code: TagName, Data: "tester"},
			{Type: TypeUint32, Code: TagMuleVersion, Data: uint32(3<<24 | 2<<17 | 3<<10 | 3<<7)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := NewPacket()
	if err := p.Init(NewBufferFromBytes(wire.Bytes())); err != nil {
		t.Fatal(err)
	}
	c.handlePacket(p)

	views := rt.ClientSnapshot()
	t.Logf("input: login hash=%x nick=tester muleversion=aMule 2.3.3 from %s", hash, conn.remote)
	t.Logf("output: snapshot=%+v", views)
	if len(views) != 1 {
		t.Fatalf("snapshot holds %d clients, want 1", len(views))
	}
	v := views[0]
	if !bytes.Equal(v.Hash[:], hash) || v.Nick != "tester" || v.Software != "aMule 2.3.3" || !v.IP.Equal(net.IPv4(203, 0, 113, 40)) {
		t.Fatalf("view = %+v", v)
	}
	if v.StoreID == 0 || v.ConnectedAt.IsZero() {
		t.Fatalf("view lacks its store id or connect time: %+v", v)
	}

	unknown := rt.DisconnectClient(bytes.Repeat([]byte{0xee}, 16))
	closedBefore := conn.closed
	found := rt.DisconnectClient(hash)
	t.Logf("input: disconnect an unknown hash, then the session's")
	t.Logf("output: unknown=%t found=%t closed=%d reason=%q", unknown, found, conn.closed, c.getCloseReason())
	if unknown || closedBefore != 0 {
		t.Fatalf("an unknown hash disconnected something")
	}
	if !found || conn.closed == 0 || c.getCloseReason() != "admin-disconnect" {
		t.Fatalf("the session was not closed: found=%t closed=%d", found, conn.closed)
	}
}

func TestGossipPeersCarryNoKeyMaterial(t *testing.T) {
	rt := newLoginTestRuntime(storage.NewMemoryEngine())
	if got := rt.GossipPeers(); got != nil || rt.GossipEnabled() {
		t.Fatalf("gossip off: peers=%v enabled=%t", got, rt.GossipEnabled())
	}
	g := NewGossipHandler(GossipConfig{MaxServers: 10, MaxFailures: 2},
		[]PeerAddr{{IP: net.IPv4(203, 0, 113, 50), Port: 4661}})
	g.mu.Lock()
	for _, p := range g.peers {
		p.Name, p.Desc = "peer name", "peer desc"
		p.ServerKey, p.OurChallenge, p.PrevChallenge, p.PlainChallenge = 0xDEADBEEF, 0xCAFEF00D, 0x0BADF00D, 0xFEEDFACE
		p.Users, p.Files, p.Failures = 12, 3400, 2
	}
	g.mu.Unlock()
	rt.SetGossipHandler(g)

	peers := rt.GossipPeers()
	encoded := fmt.Sprintf("%+v", peers)
	t.Logf("input: one seed with server key 0xDEADBEEF and three challenges, 2 failures at maxFailures=2")
	t.Logf("output: %s", encoded)
	if len(peers) != 1 || peers[0].Name != "peer name" || peers[0].Users != 12 || !peers[0].Parked {
		t.Fatalf("peers = %+v", peers)
	}
	for _, secret := range []uint32{0xDEADBEEF, 0xCAFEF00D, 0x0BADF00D, 0xFEEDFACE} {
		if strings.Contains(encoded, fmt.Sprint(secret)) || strings.Contains(strings.ToLower(encoded), fmt.Sprintf("%x", secret)) {
			t.Fatalf("the peer view exposes key material %#x", secret)
		}
	}
}

func TestBlockStatsCountRateLimitAndBots(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{
		RateLimitPerIPPerMinute: 5,
		BotDetection:            BotDetectionConfig{Enabled: true},
	}, storage.NewMemoryEngine())
	remote := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 60), Port: 4672}
	allowed := 0
	for i := 0; i < 700; i++ {
		if rt.udpOpcodeEnabled(true, 0x98, remote) {
			allowed++
		}
	}
	stats := rt.BlockStats()
	bots := rt.Bots()
	t.Logf("input: 700 UDP queries at once from %s, rate limit 5/min", remote.IP)
	t.Logf("output: allowed=%d stats=%+v bots=%+v", allowed, stats, bots)
	if allowed != 5 || stats.RateLimited != 695 {
		t.Fatalf("allowed=%d rateLimited=%d, want 5 and 695", allowed, stats.RateLimited)
	}
	// The detector saw every query, the limited ones included.
	if stats.Bots != 1 || len(bots) != 1 || bots[0].Source != "203.0.113.60" {
		t.Fatalf("bot detection behind the limiter: stats=%+v bots=%+v", stats, bots)
	}
}
