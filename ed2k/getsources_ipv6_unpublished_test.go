package ed2k

import (
	"encoding/binary"
	"net"
	"testing"

	"enode/storage"
)

// A dual-stack server advertises SRVCAP_IPV6, so OP_GETSOURCES_IPV6 must be answered
// even with ipv6.publishSources off. It used to be dropped, leaving the client
// without sources for the file; it now gets the IPv4 list in the IPv6 form.
func TestGetSourcesIPv6AnsweredWhenPublishOff(t *testing.T) {
	engine := storage.NewMemoryEngine()
	src := storage.ClientInfo{ID: 0x0b0a0a0a, Port: 4662, Hash: []byte("v6-source-hash-1"),
		IPv6: net.ParseIP("2001:db8::7").To16(), IPv6Reachable: true}
	src.StoreID, _ = engine.Connect(src)
	fileHash := []byte("unpublished-v6-1")
	engine.AddFile(storage.File{Hash: fileHash, Name: "f.iso", Size: 1000}, src)

	rt := NewServerRuntime(TCPRuntimeConfig{Address: "127.0.0.1", Port: 4661, IPv6: true, PublishV6Sources: false},
		UDPRuntimeConfig{}, engine)
	conn := &captureConn{}
	c := newTCPClient(rt, conn, false)
	c.logged = true

	req := append(append([]byte{}, fileHash...), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(req[16:], 1000)
	t.Logf("input: OP_GETSOURCES_IPV6 for a file with one v6-reachable source, publishSources=false")
	c.handleED2K(OpGetSourcesIPv6, NewBufferFromBytes(req))

	b := conn.written()
	t.Logf("output: % x", b)
	if len(b) < 6 || b[5] != OpFoundSourcesIPv6 {
		t.Fatalf("want OP_FOUNDSOURCES_IPV6, got % x", b)
	}
	// opcode, hash(16), count(1), then id(4) port(2) tagcount(1)
	p := b[6:]
	if p[16] != 1 || binary.LittleEndian.Uint32(p[17:21]) != src.ID || p[23] != 0 {
		t.Fatalf("want one IPv4 source with no IPv6 tag, got % x", p)
	}
}
