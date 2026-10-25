package ed2k

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"enode/storage"
)

const wireHashHex = "D5CD3DE9DD2558D8268D4AD0FB41C23D"

func wireHash(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(wireHashHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// loggedSearchClient logs a session in to a runtime over engine with cfg, ready to search.
func loggedSearchClient(t *testing.T, engine storage.Engine, cfg TCPRuntimeConfig) (*tcpClient, *recordingConn) {
	t.Helper()
	cfg.Address, cfg.Port, cfg.AllowLowIDs = "127.0.0.1", 4661, true
	rt := NewServerRuntime(cfg, UDPRuntimeConfig{}, engine)
	rt.firewallProbe = func(*tcpClient) bool { return true }
	conn := &recordingConn{}
	client := newTCPClient(rt, conn, false)
	client.handlePacket(loginPacket(t, bytes.Repeat([]byte{0x5c}, 16), 0, 4662))
	if !client.isLogged() {
		t.Fatal("setup: login failed")
	}
	conn.mu.Lock()
	conn.written = nil
	conn.mu.Unlock()
	return client, conn
}

// searchResultNames decodes an OP_SEARCHRESULT into "name/size sources=n" rows.
func searchResultNames(t *testing.T, raw []byte) []string {
	t.Helper()
	payload := raw[6:]
	if raw[0] == PrZlib {
		inflated, err := InflateZlibPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		payload = inflated
	}
	if raw[5] != OpSearchResult {
		t.Fatalf("opcode 0x%02x, want OP_SEARCHRESULT", raw[5])
	}
	records, err := NewBufferFromBytes(payload).GetFileList()
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, r := range records {
		out = append(out, fmt.Sprintf("%s/%d sources=%d", r.Name, r.Size, r.Sources))
	}
	return out
}

// hashSearchEngine holds the file ed2k.shortypower.org looks up in its example, from
// two clients, and an unrelated one.
func hashSearchEngine(t *testing.T) storage.Engine {
	t.Helper()
	engine := storage.NewMemoryEngine()
	for i, hash := range []string{"hash-wire-owner1", "hash-wire-owner2"} {
		owner := storage.ClientInfo{Hash: []byte(hash), ID: uint32(0x0100007F + i<<24), Port: 4662}
		id, err := engine.Connect(owner)
		if err != nil {
			t.Fatal(err)
		}
		owner.StoreID = id
		engine.AddFile(storage.File{Hash: wireHash(t), Size: 378234567, Name: "Example Movie.avi", Type: "Video"}, owner)
		engine.AddFile(storage.File{Hash: fmt.Appendf(nil, "hash-wire-other%d", i), Size: 99, Name: "Example Other.avi", Type: "Video"}, owner)
	}
	return engine
}

func TestParseSearchExprReadsHashAndRelatedTerms(t *testing.T) {
	cases := []struct {
		term string
		want string
	}{
		{"ed2k::" + wireHashHex, "HASH(d5cd3de9dd2558d8268d4ad0fb41c23d)"},
		{"ed2k:378234567:" + wireHashHex, "HASH(d5cd3de9dd2558d8268d4ad0fb41c23d,size=378234567)"},
		{"related::" + wireHashHex, "RELATED(1)"},
		{"ed2k::nothex", `TEXT("ed2k::nothex")`},
		{"example movie", `TEXT("example movie")`},
	}
	for _, c := range cases {
		expr, err := ParseSearchExpr(searchFor(t, c.term))
		if err != nil {
			t.Fatal(err)
		}
		got := formatSearchExpr(expr)
		t.Logf("input: %q -> output: %s", c.term, got)
		if got != c.want {
			t.Fatalf("%q parsed as %s, want %s", c.term, got, c.want)
		}
	}
}

func TestTCPHashSearch(t *testing.T) {
	client, conn := loggedSearchClient(t, hashSearchEngine(t), TCPRuntimeConfig{})
	for _, term := range []string{"ed2k::" + wireHashHex, "ed2k://|file|x.avi|378234567|" + wireHashHex + "|/"} {
		client.handleSearchRequest(searchFor(t, term))
		got := searchResultNames(t, conn.takeWritten())
		t.Logf("input: OP_SEARCHREQUEST %q -> output: %v", term, got)
		if !slices.Equal(got, []string{"Example Movie.avi/378234567 sources=2"}) {
			t.Fatalf("hash search %q returned %v", term, got)
		}
	}
	client.handleSearchRequest(searchFor(t, "ed2k:1:"+wireHashHex))
	got := searchResultNames(t, conn.takeWritten())
	t.Logf("input: hash with the wrong size -> output: %v", got)
	if len(got) != 0 {
		t.Fatalf("a hash at a size nobody shares returned %v", got)
	}
}

// globSearchPayload is an OP_GLOBSEARCHREQ payload: one string term.
func globSearchPayload(term string) []byte {
	b := []byte{0x01, byte(len(term)), byte(len(term) >> 8)}
	return append(b, term...)
}

func TestUDPHashSearch(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, hashSearchEngine(t))
	server, remote, gotReply := udpProbe(t)
	term := "ed2k::" + wireHashHex

	rt.udpGlobSearchReq(NewBufferFromBytes(globSearchPayload(term)), remote, server, nil, "udp")
	reply := gotReply()
	t.Logf("input: OP_GLOBSEARCHREQ %q -> output: %d bytes", term, len(reply))
	if reply == nil || !bytes.Contains(reply, wireHash(t)) || bytes.Contains(reply, []byte("Example Other")) {
		t.Fatalf("UDP hash search reply % x", reply)
	}

	req3 := append([]byte{0x01, 0x00, 0x00, 0x00, 0x90, 0x01}, globSearchPayload(term)...)
	rt.udpGlobSearchReq3(NewBufferFromBytes(req3), remote, server, nil, "udp")
	reply = gotReply()
	t.Logf("input: OP_GLOBSEARCHREQ3 %q -> output: %d bytes", term, len(reply))
	if reply == nil || !bytes.Contains(reply, wireHash(t)) {
		t.Fatalf("UDP REQ3 hash search reply % x", reply)
	}
}

// relatedEngine has 6 clients sharing the seed; 4 of them also share "Related
// Often" and 1 "Related Once".
func relatedEngine(t *testing.T) storage.Engine {
	t.Helper()
	engine := storage.NewMemoryEngine()
	for i := range 6 {
		c := storage.ClientInfo{Hash: fmt.Appendf(nil, "related-wire-%03d", i), ID: uint32(0x0200007F + i<<24), Port: 4662}
		id, err := engine.Connect(c)
		if err != nil {
			t.Fatal(err)
		}
		c.StoreID = id
		engine.AddFile(storage.File{Hash: wireHash(t), Size: 1000, Name: "Seed.avi", Type: "Video"}, c)
		switch {
		case i < 4:
			engine.AddFile(storage.File{Hash: []byte("related-wire-oft"), Size: 2000, Name: "Related Often.avi", Type: "Video"}, c)
		case i == 4:
			engine.AddFile(storage.File{Hash: []byte("related-wire-one"), Size: 30, Name: "Related Once.mp3", Type: "Audio"}, c)
		}
	}
	return engine
}

func TestTCPRelatedSearch(t *testing.T) {
	term := "related::" + wireHashHex
	client, conn := loggedSearchClient(t, relatedEngine(t), TCPRuntimeConfig{RelatedSearch: true, RelatedMinClients: 5})
	client.handleSearchRequest(searchFor(t, term))
	got := searchResultNames(t, conn.takeWritten())
	t.Logf("input: %q, minClients 5 -> output: %v", term, got)
	if !slices.Equal(got, []string{"Related Often.avi/2000 sources=4", "Related Once.mp3/30 sources=1"}) {
		t.Fatalf("related search returned %v", got)
	}

	// A size filter AND-ed with the term, as eMule's search window adds it.
	expr := NewBuffer(64)
	_ = expr.PutUInt8(0x00)
	_ = expr.PutUInt8(0x00) // AND
	_ = expr.PutUInt8(0x01)
	_ = expr.PutString(term)
	_ = expr.PutUInt8(TypeUint32)
	_ = expr.PutUInt32LE(1000)
	_ = expr.PutUInt8(storage.SearchOpGreaterEqual)
	_ = expr.PutUInt16LE(1)
	_ = expr.PutUInt8(storage.SearchTagSize)
	expr.Pos(0)
	client.handleSearchRequest(expr)
	got = searchResultNames(t, conn.takeWritten())
	t.Logf("input: %q AND size>=1000 -> output: %v", term, got)
	if !slices.Equal(got, []string{"Related Often.avi/2000 sources=4"}) {
		t.Fatalf("filtered related search returned %v", got)
	}

	// Seven sharers asked for, six there: nothing.
	strict, strictConn := loggedSearchClient(t, relatedEngine(t), TCPRuntimeConfig{RelatedSearch: true, RelatedMinClients: 7})
	strict.handleSearchRequest(searchFor(t, term))
	got = searchResultNames(t, strictConn.takeWritten())
	t.Logf("input: %q, minClients 7 -> output: %v", term, got)
	if len(got) != 0 {
		t.Fatalf("below minClients the related search returned %v", got)
	}

	// Off: still answered, with an empty page, so the client is not left waiting.
	off, offConn := loggedSearchClient(t, relatedEngine(t), TCPRuntimeConfig{})
	off.handleSearchRequest(searchFor(t, term))
	got = searchResultNames(t, offConn.takeWritten())
	t.Logf("input: %q, related search off -> output: %v", term, got)
	if len(got) != 0 {
		t.Fatalf("with related search off it returned %v", got)
	}
}

func TestUDPRelatedSearchIsNotAnswered(t *testing.T) {
	spy := &searchSpy{Engine: relatedEngine(t)}
	rt := NewServerRuntime(TCPRuntimeConfig{RelatedSearch: true, RelatedMinClients: 1}, UDPRuntimeConfig{}, spy)
	server, remote, gotReply := udpProbe(t)
	rt.udpGlobSearchReq(NewBufferFromBytes(globSearchPayload("related::"+wireHashHex)), remote, server, nil, "udp")
	reply := gotReply()
	t.Logf("input: OP_GLOBSEARCHREQ related:: -> output: reply=%d bytes, searches=%d", len(reply), spy.searches)
	if reply != nil || spy.searches != 0 {
		t.Fatal("a related search over UDP must not be answered")
	}
}

func TestRelatedSearchFlag(t *testing.T) {
	on := BuildTCPFlags(TCPServerConfig{RelatedSearch: true})
	off := BuildTCPFlags(TCPServerConfig{})
	t.Logf("input: RelatedSearch on/off -> output: 0x%x / 0x%x", on, off)
	if on&FlagRelatedSearch == 0 || off&FlagRelatedSearch != 0 || on^off != FlagRelatedSearch {
		t.Fatalf("SRV_TCPFLG_RELATEDSEARCH: on 0x%x, off 0x%x", on, off)
	}
}
