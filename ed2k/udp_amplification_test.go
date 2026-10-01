package ed2k

import (
	"fmt"
	"net"
	"testing"

	"enode/storage"
)

// amplificationEngine holds n files named "amp-NNNN.bin", each offered by one client.
func amplificationEngine(t *testing.T, n int) (*storage.MemoryEngine, [][]byte) {
	t.Helper()
	engine := storage.NewMemoryEngine()
	owner := storage.ClientInfo{Hash: []byte("amplifier-owner1"), ID: 0x0100007F, Port: 4662}
	owner.StoreID, _ = engine.Connect(owner)
	hashes := make([][]byte, n)
	for i := range n {
		hashes[i] = []byte(fmt.Sprintf("amp-hash-%07d", i))
		engine.AddFile(storage.File{Hash: hashes[i], Size: 1000, Name: fmt.Sprintf("amp-%04d.bin", i)}, owner)
	}
	return engine, hashes
}

// One spoofed OP_GLOBGETSOURCES with thousands of hashes was answered once per hash.
// eMule asks for at most 35 files per datagram, so that is all the server answers.
func TestUDPGetSourcesCapsHashesPerDatagram(t *testing.T) {
	engine, hashes := amplificationEngine(t, 100)
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{GetSources: true}, engine)
	server, remote, gotReply := udpProbe(t)

	var req []byte
	for _, h := range hashes {
		req = append(req, h...)
	}
	rt.udpGlobGetSources(NewBufferFromBytes(req), remote, server, nil, "udp")
	replies := 0
	for gotReply() != nil {
		replies++
	}
	t.Logf("input: OP_GLOBGETSOURCES with %d hashes, output: %d replies", len(hashes), replies)
	if replies != maxUDPGetSourcesHashes {
		t.Fatalf("want %d replies, got %d", maxUDPGetSourcesHashes, replies)
	}
}

// A ten-byte UDP search matched up to 1000 files, each sent as its own datagram. The
// answer is capped and its records packed several to a datagram, as eMule reads them.
func TestUDPSearchCappedAndPacked(t *testing.T) {
	engine, _ := amplificationEngine(t, 300)
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{GetFiles: true}, engine)
	server, remote, gotReply := udpProbe(t)

	query := []byte{0x01, 0x03, 0x00, 'a', 'm', 'p'}
	rt.udpGlobSearchReq(NewBufferFromBytes(query), remote, server, nil, "udp")
	datagrams, records, largest := 0, 0, 0
	for d := gotReply(); d != nil; d = gotReply() {
		datagrams++
		records += countGlobSearchRecords(t, d)
		largest = max(largest, len(d))
	}
	t.Logf("input: query %q matching 300 files, output: %d records in %d datagrams, largest %d bytes",
		"amp", records, datagrams, largest)
	if records != maxUDPSearchResults {
		t.Fatalf("want %d records, got %d", maxUDPSearchResults, records)
	}
	if datagrams >= records/4 || largest > udpSearchDatagramBudget {
		t.Fatalf("records are not packed: %d datagrams, largest %d bytes", datagrams, largest)
	}
}

// 255 sources in the IPv6 forms are up to ~6 KB; eMule and eMuleQt read a datagram
// into a 5000-byte buffer and lose the rest.
func TestUDPSourceRepliesFitClientBuffer(t *testing.T) {
	sources := make([]storage.Source, 255)
	for i := range sources {
		sources[i] = storage.Source{ID: uint32(i + 1), Port: 4662,
			IPv6: net.ParseIP(fmt.Sprintf("2001:db8::%x", i+1)).To16(), IPv6Reachable: true}
	}
	hash := []byte("budget-hash-0001")
	sentinel, err := BuildGlobFoundSourcesSentinelPacket(hash, sources)
	if err != nil {
		t.Fatal(err)
	}
	tagged, err := BuildGlobFoundSourcesIPv6Packet(hash, sources)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: 255 v6-only sources, output: sentinel %d bytes (%d sources), tag-block %d bytes (%d sources)",
		len(sentinel.Bytes()), sentinel.Bytes()[18], len(tagged.Bytes()), tagged.Bytes()[18])
	for _, b := range [][]byte{sentinel.Bytes(), tagged.Bytes()} {
		if len(b) > udpSourceDatagramBudget {
			t.Fatalf("reply is %d bytes, over %d", len(b), udpSourceDatagramBudget)
		}
	}
}

// Every reply to a UDP search or source request is many datagrams for one, sent to an
// address nobody verified. Past the per-address budget requests go unanswered.
func TestUDPRateLimitPerAddress(t *testing.T) {
	engine, hashes := amplificationEngine(t, 1)
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{GetSources: true, RateLimitPerIPPerMinute: 5}, engine)
	server, remote, gotReply := udpProbe(t)

	handle := rt.UDPHandler(false)
	answered := 0
	for range 8 {
		packet := append([]byte{PrED2K, OpGlobGetSources}, hashes[0]...)
		handle(packet, remote, server)
		if gotReply() != nil {
			answered++
		}
	}
	other := &net.UDPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 1}
	sameNet := &net.UDPAddr{IP: net.ParseIP("2001:db8:1:2::ffff"), Port: 1}
	t.Logf("input: 8 requests at a budget of 5/min, output: %d answered; v6 keys %q %q",
		answered, addressKey(other.IP), addressKey(sameNet.IP))
	if answered != 5 {
		t.Fatalf("want 5 answered, got %d", answered)
	}
	if addressKey(other.IP) != addressKey(sameNet.IP) {
		t.Fatal("one IPv6 /64 must share a budget")
	}
}
