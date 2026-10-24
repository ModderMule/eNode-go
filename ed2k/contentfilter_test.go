package ed2k

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"

	"enode/storage"
)

// stubContent is a ContentFilter with fixed answers: hashes in banned are refused and
// sanctioned, hashes in filtered are refused, and a name or query term containing
// keyword is refused. Bans are recorded so a test can assert on them.
type stubContent struct {
	banned    map[string]bool
	filtered  map[string]bool
	keyword   string
	threshold int
	// keywordThreshold is KeywordBanThreshold; 0 never sanctions a keyword hit.
	keywordThreshold int

	mu         sync.Mutex
	bans       [][]byte
	bannedUser []byte
}

func (s *stubContent) CheckOffer(hash []byte, name string) (bool, bool, bool) {
	switch {
	case s.banned[string(hash)]:
		return true, true, false
	case s.filtered[string(hash)]:
		return true, false, false
	case s.keyword != "" && strings.Contains(name, s.keyword):
		return true, false, true
	}
	return false, false, false
}

func (s *stubContent) Withheld(hash []byte, name string) bool {
	refused, _, _ := s.CheckOffer(hash, name)
	return refused
}

func (s *stubContent) QueryBlocked(terms []string) bool {
	for _, term := range terms {
		if s.keyword != "" && strings.Contains(term, s.keyword) {
			return true
		}
	}
	return false
}

func (s *stubContent) BanThreshold() int { return s.threshold }

func (s *stubContent) KeywordBanThreshold() int { return s.keywordThreshold }

func (s *stubContent) Ban(userHash []byte, _ net.IP, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bans = append(s.bans, append([]byte(nil), userHash...))
}

func (s *stubContent) Banned(userHash []byte, _ net.IP) bool {
	return s.bannedUser != nil && bytes.Equal(userHash, s.bannedUser)
}

func hashSet(hashes ...[]byte) map[string]bool {
	set := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		set[string(h)] = true
	}
	return set
}

// TestOfferFilesRefusedByContentFilter: a refused record is not stored and is charged
// against neither publish limit, whichever layer refused it, and the session stays up.
func TestOfferFilesRefusedByContentFilter(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 0, 0)
	client.server.SetContentFilter(&stubContent{
		banned:    hashSet(offerHash(1)),
		filtered:  hashSet(offerHash(2)),
		keyword:   "-003",
		threshold: 3,
	})

	t.Logf("input: OP_OFFERFILES of 5 files; #1 on the ban list, #2 on the filter list, #3 named with a keyword")
	offerFiles(t, client, 0, 5)
	t.Logf("output: FilesCount=%d offeredFiles=%d banlistHits=%d closed=%d messages=%q",
		engine.FilesCount(), offeredCount(client), len(client.banlistHits), conn.closed, serverMessages(t, conn))

	if engine.FilesCount() != 2 {
		t.Fatalf("FilesCount = %d, want 2: only files #0 and #4 may be indexed", engine.FilesCount())
	}
	for i := 1; i <= 3; i++ {
		if n := len(engine.GetSourcesByHash(offerHash(i))); n != 0 {
			t.Errorf("refused file #%d has %d source(s)", i, n)
		}
	}
	if offeredCount(client) != 2 {
		t.Errorf("offeredFiles = %d, want 2: a refused record must not count toward the limits", offeredCount(client))
	}
	if len(client.banlistHits) != 1 {
		t.Errorf("banlistHits = %d, want 1: only the ban-list record is held against the publisher", len(client.banlistHits))
	}
	if conn.closed != 0 || len(serverMessages(t, conn)) != 0 {
		t.Errorf("closed=%d messages=%q: below the threshold the session must stay up, silently", conn.closed, serverMessages(t, conn))
	}
}

// TestOfferFilesBanlistThresholdDropsAndBans: more distinct ban-list files than the
// threshold tolerates gets the session told why, closed, and the publisher banned. A
// re-offer of the same file must not count twice.
func TestOfferFilesBanlistThresholdDropsAndBans(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 0, 0)
	filter := &stubContent{banned: hashSet(offerHash(1), offerHash(2), offerHash(3)), threshold: 2}
	client.server.SetContentFilter(filter)

	offerFiles(t, client, 1, 2) // two distinct hits: at the threshold, tolerated
	offerFiles(t, client, 1, 2) // the same two again
	t.Logf("input: 2 distinct ban-list files offered twice, threshold 2; output: hits=%d closed=%d bans=%d",
		len(client.banlistHits), conn.closed, len(filter.bans))
	if conn.closed != 0 || len(filter.bans) != 0 {
		t.Fatalf("closed=%d bans=%d: re-offering the same files must not pass the threshold", conn.closed, len(filter.bans))
	}

	offerFiles(t, client, 3, 2) // #3 is the third distinct hit; #4 is clean
	msgs := serverMessages(t, conn)
	t.Logf("input: a third distinct ban-list file; output: hits=%d closed=%d bans=%x messages=%q FilesCount=%d",
		len(client.banlistHits), conn.closed, filter.bans, msgs, engine.FilesCount())
	if conn.closed == 0 {
		t.Fatal("the session must be closed once the threshold is passed")
	}
	if len(msgs) != 1 || msgs[0] != msgBanlisted {
		t.Fatalf("messages = %q, want exactly %q", msgs, msgBanlisted)
	}
	if len(filter.bans) != 1 || !bytes.Equal(filter.bans[0], bytes.Repeat([]byte{0x5a}, 16)) {
		t.Fatalf("bans = %x, want the session's user hash once", filter.bans)
	}
	if engine.FilesCount() != 0 {
		t.Errorf("FilesCount = %d, want 0: nothing of the dropping packet is stored", engine.FilesCount())
	}

	// Bytes already in the socket buffer still reach the handler after the close.
	offerFiles(t, client, 10, 2)
	if engine.FilesCount() != 0 || len(serverMessages(t, conn)) != 1 {
		t.Errorf("a dropped session still indexed files or was messaged again: FilesCount=%d messages=%d",
			engine.FilesCount(), len(serverMessages(t, conn)))
	}
}

func TestOfferFilesThresholdZeroNeverSanctions(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 0, 0)
	filter := &stubContent{banned: hashSet(offerHash(0), offerHash(1), offerHash(2), offerHash(3))}
	client.server.SetContentFilter(filter)

	offerFiles(t, client, 0, 5)
	t.Logf("input: 4 ban-list files, threshold 0; output: FilesCount=%d closed=%d bans=%d", engine.FilesCount(), conn.closed, len(filter.bans))
	if engine.FilesCount() != 1 || conn.closed != 0 || len(filter.bans) != 0 {
		t.Fatalf("FilesCount=%d closed=%d bans=%d, want 1/0/0: files refused, nobody sanctioned",
			engine.FilesCount(), conn.closed, len(filter.bans))
	}
}

func TestLoginRefusedWhileBanned(t *testing.T) {
	user := bytes.Repeat([]byte{0x5c}, 16)
	rt := NewServerRuntime(TCPRuntimeConfig{Address: "127.0.0.1", Port: 4661, AllowLowIDs: true},
		UDPRuntimeConfig{}, storage.NewMemoryEngine())
	rt.firewallProbe = func(*tcpClient) bool { return true }
	rt.SetContentFilter(&stubContent{bannedUser: user})

	conn := &recordingConn{}
	client := newTCPClient(rt, conn, false)
	client.handlePacket(loginPacket(t, user, 0, 4662))
	msgs := serverMessages(t, conn)
	t.Logf("input: login by banned user %x; output: logged=%t closed=%d messages=%q", user[:2], client.isLogged(), conn.closed, msgs)
	if client.isLogged() || conn.closed == 0 {
		t.Fatalf("logged=%t closed=%d: a banned publisher must be refused", client.isLogged(), conn.closed)
	}
	if len(msgs) != 1 || msgs[0] != msgBanned {
		t.Fatalf("messages = %q, want exactly %q", msgs, msgBanned)
	}

	other := newTCPClient(rt, &recordingConn{}, false)
	other.handlePacket(loginPacket(t, bytes.Repeat([]byte{0x5d}, 16), 0, 4662))
	if !other.isLogged() {
		t.Fatal("another user must still log in")
	}
}

// TestSearchWithholdsFilteredRows covers the TCP search path, including the pages cut
// before a hash was listed.
func TestSearchWithholdsFilteredRows(t *testing.T) {
	const total = storage.MaxSearchPage + 40
	client, conn := searchPagingClient(t, total)
	rowHash := func(i int) []byte {
		h := make([]byte, 16)
		h[0], h[1] = byte(i>>8), byte(i)
		return h
	}
	filter := &stubContent{filtered: hashSet(rowHash(3)), keyword: "paging-0007"}
	client.server.SetContentFilter(filter)

	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	page1 := decodeSearchRecords(t, conn.takeWritten())
	t.Logf("input: %d files, one on the filter list and one named with a keyword; output: page1=%d pending=%d",
		total, len(page1), len(client.pendingRows()))
	if len(page1)+len(client.pendingRows()) != total-2 {
		t.Fatalf("served %d rows, want %d", len(page1)+len(client.pendingRows()), total-2)
	}
	for _, r := range page1 {
		if bytes.Equal(r.Hash, rowHash(3)) || recordName(r) == "paging-0007.bin" {
			t.Fatalf("a refused row was served: %x %q", r.Hash, recordName(r))
		}
	}

	// A hash listed after the pages were cut must not ride out on the next page.
	late := append([]byte(nil), client.pendingRows()[0].Hash...)
	filter.filtered[string(late)] = true
	pending := len(client.pendingRows())
	client.handleED2K(OpQueryMoreResult, NewBuffer(0))
	page2 := decodeSearchRecords(t, conn.takeWritten())
	t.Logf("input: %x listed between pages; output: page2=%d of %d pending", late[:2], len(page2), pending)
	if len(page2) != pending-1 {
		t.Fatalf("page 2 carried %d rows, want %d", len(page2), pending-1)
	}
	for _, r := range page2 {
		if bytes.Equal(r.Hash, late) {
			t.Fatal("a hash listed between pages was served on the next one")
		}
	}
}

func TestSearchForAKeywordReturnsNothing(t *testing.T) {
	client, conn := searchPagingClient(t, 5)
	engine := &countingSearchEngine{Engine: client.server.Storage}
	client.server.Storage = engine
	client.server.SetContentFilter(&stubContent{keyword: "paging"})

	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	count, more, _ := decodeSearchResult(t, conn.takeWritten())
	t.Logf("input: search for a filtered keyword; output: count=%d more=%d indexSearches=%d", count, more, engine.searches)
	if count != 0 || more != 0 {
		t.Fatalf("count=%d more=%d, want an empty result page", count, more)
	}
	if engine.searches != 0 {
		t.Fatalf("the index was searched %d time(s); a blocked query must not reach it", engine.searches)
	}
}

// countingSearchEngine counts FindBySearch calls.
type countingSearchEngine struct {
	storage.Engine
	searches int
}

func (e *countingSearchEngine) FindBySearch(expr *storage.SearchExpr) []storage.File {
	e.searches++
	return e.Engine.FindBySearch(expr)
}

func TestUDPSearchWithholdsAndBlocks(t *testing.T) {
	search := []byte{0x01, 0x04, 0x00, 'f', 'o', 'o', 'd'}
	req3 := func() []byte {
		b := NewBuffer(64)
		_ = b.PutTags([]Tag{{Type: TypeUint32, Code: TagSearchTree, Data: uint32(0x01)}})
		return append(b.Bytes()[:b.Pos()], search...)
	}
	cases := []struct {
		name   string
		filter *stubContent
		want   int
	}{
		{"no hit", &stubContent{}, 1},
		{"hash listed", &stubContent{filtered: hashSet([]byte("fedcba9876543210"))}, 0},
		{"keyword in the name", &stubContent{keyword: "food.bin"}, 0},
		{"keyword in the query", &stubContent{keyword: "food"}, 0},
	}
	for _, tc := range cases {
		for _, v3 := range []bool{false, true} {
			rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, seededEngine(t))
			rt.SetContentFilter(tc.filter)
			server, remote, gotReply := udpProbe(t)
			if v3 {
				rt.udpGlobSearchReq3(NewBufferFromBytes(req3()), remote, server, nil, "udp")
			} else {
				rt.udpGlobSearchReq(NewBufferFromBytes(search), remote, server, nil, "udp")
			}
			records := 0
			for d := gotReply(); d != nil; d = gotReply() {
				records += countGlobSearchRecords(t, d)
			}
			t.Logf("input: %s req3=%t; output: records=%d", tc.name, v3, records)
			if records != tc.want {
				t.Errorf("%s req3=%t: %d record(s), want %d", tc.name, v3, records, tc.want)
			}
		}
	}
}

// TestSourcesWithheldForListedHash drives every source request path. TCP must still
// answer, with an empty list; UDP sends nothing for the hash.
func TestSourcesWithheldForListedHash(t *testing.T) {
	hash := []byte("fedcba9876543210")
	sizeReq := append(append([]byte(nil), hash...), 0x00, 0x04, 0x00, 0x00) // size 1024

	for _, listed := range []bool{false, true} {
		filter := &stubContent{}
		if listed {
			filter.filtered = hashSet(hash)
		}

		// UDP: OP_GLOBGETSOURCES, ...2 and the IPv6 form.
		udp := map[string]func(rt *ServerRuntime, remote *net.UDPAddr, server *net.UDPConn){
			"OP_GLOBGETSOURCES": func(rt *ServerRuntime, remote *net.UDPAddr, server *net.UDPConn) {
				rt.udpGlobGetSources(NewBufferFromBytes(hash), remote, server, nil, "udp")
			},
			"OP_GLOBGETSOURCES2": func(rt *ServerRuntime, remote *net.UDPAddr, server *net.UDPConn) {
				rt.udpGlobGetSources2(NewBufferFromBytes(sizeReq), remote, server, nil, "udp")
			},
		}
		for name, send := range udp {
			rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, seededEngine(t))
			rt.SetContentFilter(filter)
			server, remote, gotReply := udpProbe(t)
			send(rt, remote, server)
			replied := gotReply() != nil
			t.Logf("input: %s listed=%t; output: replied=%t", name, listed, replied)
			if replied == listed {
				t.Errorf("%s listed=%t: replied=%t, want %t", name, listed, replied, !listed)
			}
		}

		// TCP: OP_GETSOURCES.
		rt := NewServerRuntime(TCPRuntimeConfig{Address: "127.0.0.1", Port: 4661, AllowLowIDs: true},
			UDPRuntimeConfig{}, seededEngine(t))
		rt.firewallProbe = func(*tcpClient) bool { return true }
		rt.SetContentFilter(filter)
		conn := &recordingConn{}
		client := newTCPClient(rt, conn, false)
		client.handlePacket(loginPacket(t, bytes.Repeat([]byte{0x5e}, 16), 0, 4662))
		conn.mu.Lock()
		conn.written = nil
		conn.mu.Unlock()
		client.handleED2K(OpGetSources, NewBufferFromBytes(sizeReq))
		frame := conn.takeWritten()
		if len(frame) < 6+17 || frame[5] != OpFoundSources {
			t.Fatalf("listed=%t: no OP_FOUNDSOURCES reply (% x)", listed, frame)
		}
		count := int(frame[6+16])
		t.Logf("input: OP_GETSOURCES listed=%t; output: sources=%d", listed, count)
		if (count == 0) != listed {
			t.Errorf("OP_GETSOURCES listed=%t: %d source(s)", listed, count)
		}
	}
}

func TestWithholdFilesLeavesTheInputAlone(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	files := []storage.File{
		{Hash: []byte("aaaaaaaaaaaaaaaa"), Name: "a"},
		{Hash: []byte("bbbbbbbbbbbbbbbb"), Name: "b"},
		{Hash: []byte("cccccccccccccccc"), Name: "c"},
	}
	if got := rt.withholdFiles(files); len(got) != 3 {
		t.Fatalf("no filter: %d rows, want all 3", len(got))
	}
	rt.SetContentFilter(&stubContent{filtered: hashSet([]byte("bbbbbbbbbbbbbbbb"))})
	got := rt.withholdFiles(files)
	t.Logf("input: a,b,c with b listed; output: %d rows, input still %q %q %q", len(got), files[0].Name, files[1].Name, files[2].Name)
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "c" {
		t.Fatalf("got %+v, want a and c", got)
	}
	if files[1].Name != "b" || files[2].Name != "c" {
		t.Fatal("the input slice was modified; it can be a result another search shares")
	}
}

func TestSearchTermsSkipsTheExcludedSide(t *testing.T) {
	term := func(s string) *storage.SearchExpr { return &storage.SearchExpr{Kind: storage.SearchText, Text: s} }
	expr := &storage.SearchExpr{Kind: storage.SearchAndNot,
		Left:  &storage.SearchExpr{Kind: storage.SearchAnd, Left: term("one"), Right: term("two")},
		Right: term("three"),
	}
	got := searchTerms(expr, nil)
	t.Logf("input: (one AND two) ANDNOT three; output: %q", got)
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("terms = %q, want one and two only", got)
	}
}
