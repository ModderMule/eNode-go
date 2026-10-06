package ed2k

import (
	"net"
	"testing"

	"github.com/ModderMule/enodemeta/tags"
)

// TestServerSearchNumbersMatchTheContract pins the tag ids and the flag bit to the
// shared contract, which the other implementations read them from.
func TestServerSearchNumbersMatchTheContract(t *testing.T) {
	t.Logf("input:  contract url=0x%02X fingerprint=0x%02X flag=0x%X", tags.STServerSearch, tags.STServerSearchFingerprint, tags.FlagServerSearch)
	t.Logf("output: ours     url=0x%02X fingerprint=0x%02X flag=0x%X", TagServerSearch, TagServerSearchFingerprint, FlagServerSearch)
	if TagServerSearch != tags.STServerSearch || TagServerSearchFingerprint != tags.STServerSearchFingerprint {
		t.Errorf("the server search tags differ from the contract")
	}
	if FlagServerSearch != tags.FlagServerSearch {
		t.Errorf("FlagServerSearch differs from the contract")
	}
}

// TestDescResCarriesTheSearchAdvert: the extended description reply carries the
// advert when one is configured and is byte-identical to before when none is, and a
// reader that knows nothing of the tags still gets the name and the description.
func TestDescResCarriesTheSearchAdvert(t *testing.T) {
	advert := ServerSearchAdvert{URL: "https://203.0.113.9:4673", Fingerprint: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	plain, err := BuildServerDescResPacket(0x1234F0FF, UDPConfig{Name: "n", Description: "d"})
	if err != nil {
		t.Fatal(err)
	}
	with, err := BuildServerDescResPacket(0x1234F0FF, UDPConfig{Name: "n", Description: "d", ServerSearch: advert})
	if err != nil {
		t.Fatal(err)
	}
	urlOnly, err := BuildServerDescResPacket(0x1234F0FF, UDPConfig{Name: "n", Description: "d", ServerSearch: ServerSearchAdvert{URL: advert.URL}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input:  advert %+v", advert)
	t.Logf("output: %d bytes without, %d with the url, %d with both", len(plain.Bytes()), len(urlOnly.Bytes()), len(with.Bytes()))

	for _, c := range []struct {
		label  string
		packet *Buffer
		want   ServerSearchAdvert
	}{
		{"no advert", plain, ServerSearchAdvert{}},
		{"url only", urlOnly, ServerSearchAdvert{URL: advert.URL}},
		{"url and fingerprint", with, advert},
	} {
		d, err := ParseServerDesc(NewBufferFromBytes(c.packet.Bytes()[2:]))
		t.Logf("output: %s -> %+v err=%v", c.label, d, err)
		if err != nil || d.Name != "n" || d.Desc != "d" || d.ServerSearch != c.want {
			t.Errorf("%s: got %+v, %v", c.label, d, err)
		}
		name, desc, err := ParseServerDescRes(NewBufferFromBytes(c.packet.Bytes()[2:]))
		if err != nil || name != "n" || desc != "d" {
			t.Errorf("%s: the name-and-description reader got %q/%q, %v", c.label, name, desc, err)
		}
	}
}

// TestGossipLearnsAndForgetsTheSearchAdvert walks the advert through the dispatcher:
// an admitted peer that sends the tags is a search peer, one that
// stops sending them is not, and a URL that is not a plain http(s) one is refused.
func TestGossipLearnsAndForgetsTheSearchAdvert(t *testing.T) {
	rt, g := dispatchRuntime(t, true, nil)
	conn := dispatchConn(t)
	addr := PeerAddr{IP: net.ParseIP("203.0.113.9"), Port: 4661}
	g.mu.Lock()
	g.peers[addr.String()] = &PeerServer{Addr: addr, State: peerKeyed, ServerKey: 1}
	g.mu.Unlock()

	send := func(advert ServerSearchAdvert) {
		t.Helper()
		pkt, err := BuildServerDescResPacket(0x1234F0FF, UDPConfig{Name: "peer", Description: "a peer", ServerSearch: advert})
		if err != nil {
			t.Fatal(err)
		}
		feed(t, rt, conn, "203.0.113.9", pkt.Bytes(), true)
	}

	if g.IsServer(addr.IP) {
		t.Fatal("a peer that has not answered the description probe counts as a server")
	}

	good := ServerSearchAdvert{URL: "https://203.0.113.9:4673", Fingerprint: "sha256/abc="}
	send(good)
	peers := g.SearchPeers()
	t.Logf("input:  a description reply with %+v", good)
	t.Logf("output: is server=%t, %d search peer(s)", g.IsServer(addr.IP), len(peers))
	if !g.IsServer(addr.IP) || len(peers) != 1 || peers[0].ServerSearch != good {
		t.Fatalf("search peers = %+v", peers)
	}
	if g.IsServer(net.ParseIP("203.0.113.77")) {
		t.Error("an address not in the table counts as a server")
	}

	for _, bad := range []string{"ftp://203.0.113.9/", "https://user:pw@203.0.113.9/", "https://203.0.113.9/?x=1", "not a url", "https://"} {
		send(ServerSearchAdvert{URL: bad})
		n := len(g.SearchPeers())
		t.Logf("input:  advert url %q", bad)
		t.Logf("output: %d search peer(s)", n)
		if n != 0 {
			t.Errorf("%q was accepted as a search URL", bad)
		}
		send(good)
	}

	send(ServerSearchAdvert{})
	t.Logf("input:  a description reply without the tags")
	t.Logf("output: %d search peer(s)", len(g.SearchPeers()))
	if n := len(g.SearchPeers()); n != 0 {
		t.Errorf("%d search peers after the peer stopped advertising", n)
	}

	// The flags word plays no part: the tag alone makes a search peer, because the
	// bit is never sent (see FlagServerSearch).
	send(good)
	g.mu.Lock()
	g.peers[addr.String()].UDPFlags = 0
	g.mu.Unlock()
	if n := len(g.SearchPeers()); n != 1 {
		t.Errorf("%d search peers for a peer that sent the tag without the flag, want 1", n)
	}
}
