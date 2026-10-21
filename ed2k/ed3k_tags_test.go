package ed2k

import (
	"bytes"
	"net"
	"testing"

	"github.com/ModderMule/enodemeta/tags"
)

const testEd3kLink = "ed3k:node?id=cf617f4479e97358c9d31741900a90ae&ep=81.2.3.4:4661"

// TestServerIdentAdvertisesEd3k: ST_ED3K (0xe3) is a string tag of OP_SERVERIDENT
// when ed3k is on, and the packet is unchanged when it is off.
func TestServerIdentAdvertisesEd3k(t *testing.T) {
	base := ServerConfig{Name: "eNode", Description: "test", Address: "192.0.2.1",
		Hash: bytes.Repeat([]byte{0x01}, 16), TCPPort: 4661}
	off, err := BuildServerIdentPacket(base)
	if err != nil {
		t.Fatal(err)
	}
	on := base
	on.Ed3k = testEd3kLink
	buf, err := BuildServerIdentPacket(on)
	if err != nil {
		t.Fatal(err)
	}
	got := parseServerIdentTags(t, buf)
	t.Logf("input: Ed3k=%q output: ed3k=%v; %d bytes off, %d on", on.Ed3k, got["ed3k"], len(off.Bytes()), len(buf.Bytes()))
	if got["ed3k"] != testEd3kLink {
		t.Fatalf("ed3k tag = %v", got["ed3k"])
	}
	if _, ok := parseServerIdentTags(t, off)["ed3k"]; ok {
		t.Fatal("ed3k tag present with ed3k off")
	}
	// The enodemeta tags contract fixes both directions at 0xe3.
	t.Logf("TagEd3k=%#x tags.STEd3k=%#x tags.CTEd3k=%#x", TagEd3k, tags.STEd3k, tags.CTEd3k)
	for name, v := range map[string]uint8{"STEd3k": tags.STEd3k, "CTEd3k": tags.CTEd3k} {
		if TagEd3k != v {
			t.Errorf("TagEd3k = %#x, contract %s = %#x", TagEd3k, name, v)
		}
	}
}

// TestDescResCarriesEd3k: the extended OP_SERVER_DESC_RES carries ST_ED3K, a peer
// parses it, and a reader that knows nothing of it still gets name and description.
func TestDescResCarriesEd3k(t *testing.T) {
	plain, _ := BuildServerDescResPacket(0x1234F0FF, UDPConfig{Name: "n", Description: "d"})
	with, err := BuildServerDescResPacket(0x1234F0FF, UDPConfig{Name: "n", Description: "d", Ed3k: testEd3kLink})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		label  string
		packet *Buffer
		want   string
	}{{"without", plain, ""}, {"with", with, testEd3kLink}} {
		d, err := ParseServerDesc(NewBufferFromBytes(c.packet.Bytes()[2:]))
		t.Logf("%s: %d bytes -> %+v err=%v", c.label, len(c.packet.Bytes()), d, err)
		if err != nil || d.Name != "n" || d.Desc != "d" || d.Ed3k != c.want {
			t.Errorf("%s: got %+v", c.label, d)
		}
	}
}

func TestLoginEd3k(t *testing.T) {
	id := bytes.Repeat([]byte{0xab}, 16)
	cases := []struct {
		name string
		tags []NamedTag
		want []byte
	}{
		{"hash tag", []NamedTag{{Name: "name", Value: "x"}, {Name: "ed3k", Value: id, Type: TypeHash}}, id},
		{"absent", []NamedTag{{Name: "name", Value: "x"}}, nil},
		{"15 bytes", []NamedTag{{Name: "ed3k", Value: id[:15], Type: TypeHash}}, nil},
		{"blob, not hash", []NamedTag{{Name: "ed3k", Value: id, Type: TypeBlob}}, nil},
	}
	for _, c := range cases {
		got := loginEd3k(c.tags)
		t.Logf("%s -> %x", c.name, got)
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s: got %x want %x", c.name, got, c.want)
		}
	}
}

func TestGossipNoteEd3k(t *testing.T) {
	g := newTestGossipWithPeer(t)
	ip := net.ParseIP("203.0.113.5")
	peer := func() *PeerServer {
		for _, p := range g.peers {
			return p
		}
		return nil
	}
	g.NoteEd3k(ip, testEd3kLink)
	t.Logf("valid link -> peer.Ed3k=%q, admitted peers with ed3k: %d", peer().Ed3k, len(g.Ed3kPeers()))
	if peer().Ed3k != testEd3kLink {
		t.Fatal("link not recorded")
	}
	g.NoteEd3k(ip, "ed3k:node?id=nothex")
	if peer().Ed3k != "" {
		t.Fatal("invalid link kept")
	}
}

func newTestGossipWithPeer(t *testing.T) *GossipHandler {
	t.Helper()
	return NewGossipHandler(GossipConfig{MaxServers: 10, MaxFailures: 5},
		[]PeerAddr{{IP: net.ParseIP("203.0.113.5"), Port: 4661}})
}
