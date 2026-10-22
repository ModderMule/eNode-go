package index

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"enode/ed3k/ed3kpb"
	"enode/ed3k/ident"
	"enode/ed3k/sig"
	"enode/ed3k/token"
	"enode/storage"
)

var now = time.Unix(1_800_000_000, 0)

type pub struct {
	priv ed25519.PrivateKey
	peer Peer
}

func newPub(t *testing.T, addr string) pub {
	t.Helper()
	pk, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub{priv: priv, peer: Peer{ID: ident.NodeIDOf(pk), Key: pk, Remote: netip.MustParseAddrPort(addr), ED2K: true, Open: true}}
}

func newIndex() *Index {
	return New(Config{Store: storage.NewMemoryEngine(), Now: func() time.Time { return now }})
}

func keywordRecord(t *testing.T, p pub, name string, root []byte, word string, expires time.Time) (*ed3kpb.KadRequest, [16]byte) {
	t.Helper()
	target := token.KeywordTarget(0, word)
	body, _ := proto.Marshal(&ed3kpb.Record{Expires: uint64(expires.Unix()),
		File: &ed3kpb.FileInfo{Root: root, Size: 1000, Name: name, Ed2K: make([]byte, 16)}})
	s := sig.Sign(p.priv, ed3kpb.Kind_KEYWORD, target[:], body)
	return &ed3kpb.KadRequest{Target: target[:], Kind: ed3kpb.Kind_KEYWORD, Store: &ed3kpb.Store{Files: []*ed3kpb.Signed{s}}}, target
}

func handle(t *testing.T, x *Index, req *ed3kpb.KadRequest, p Peer) (*ed3kpb.KadAnswer, *ed3kpb.Error) {
	t.Helper()
	ans, e, err := x.Handle(context.Background(), req, p)
	if err != nil {
		t.Fatalf("internal error: %v", err)
	}
	return ans, e
}

func TestLayoutAndKinds(t *testing.T) {
	x := newIndex()
	p := newPub(t, "81.2.3.4:4662").peer
	tgt := make([]byte, 16)
	cases := []struct {
		name        string
		req         *ed3kpb.KadRequest
		err         ed3kpb.Error_Code
		responsible bool
	}{
		{"short target", &ed3kpb.KadRequest{Target: []byte{1}, Kind: ed3kpb.Kind_SOURCE, Search: &ed3kpb.Query{}}, ed3kpb.Error_MALFORMED, false},
		{"search and store", &ed3kpb.KadRequest{Target: tgt, Kind: ed3kpb.Kind_SOURCE, Search: &ed3kpb.Query{}, Store: &ed3kpb.Store{}}, ed3kpb.Error_MALFORMED, false},
		{"neither", &ed3kpb.KadRequest{Target: tgt, Kind: ed3kpb.Kind_KEYWORD}, -1, true},
		{"kind HEAD", &ed3kpb.KadRequest{Target: tgt, Kind: ed3kpb.Kind_HEAD, Search: &ed3kpb.Query{}}, -1, false},
		{"level 16", &ed3kpb.KadRequest{Target: tgt, Kind: ed3kpb.Kind_KEYWORD, Level: 16, Search: &ed3kpb.Query{}}, -1, false},
		{"65 terms", &ed3kpb.KadRequest{Target: tgt, Kind: ed3kpb.Kind_KEYWORD, Search: &ed3kpb.Query{All: make([]string, 65)}}, ed3kpb.Error_MALFORMED, false},
		{"also not n×16", &ed3kpb.KadRequest{Target: tgt, Kind: ed3kpb.Kind_SOURCE, Store: &ed3kpb.Store{Source: &ed3kpb.Peer{}, Also: make([]byte, 5)}}, ed3kpb.Error_MALFORMED, false},
		{"signer of 31 bytes", &ed3kpb.KadRequest{Target: tgt, Kind: ed3kpb.Kind_KEYWORD, Store: &ed3kpb.Store{Signer: make([]byte, 31)}}, ed3kpb.Error_MALFORMED, false},
		{"store without a record of the kind", &ed3kpb.KadRequest{Target: tgt, Kind: ed3kpb.Kind_KEYWORD, Store: &ed3kpb.Store{Note: &ed3kpb.Signed{}}}, ed3kpb.Error_MALFORMED, false},
		// signer is MALFORMED only for a kind that uses it (§10.7).
		{"kind 14, signer of 64 bytes", &ed3kpb.KadRequest{Target: tgt, Kind: 14, Store: &ed3kpb.Store{Signer: make([]byte, 64)}}, -1, false},
		{"kind NONE, signer of 64 bytes", &ed3kpb.KadRequest{Target: tgt, Kind: ed3kpb.Kind_NONE, Store: &ed3kpb.Store{Signer: make([]byte, 64)}}, -1, false},
		{"kind HEAD, signer of 64 bytes", &ed3kpb.KadRequest{Target: tgt, Kind: ed3kpb.Kind_HEAD, Store: &ed3kpb.Store{Signer: make([]byte, 64)}}, ed3kpb.Error_MALFORMED, false},
	}
	for _, c := range cases {
		ans, e := handle(t, x, c.req, p)
		t.Logf("%s -> answer=%v error=%v", c.name, ans, e)
		if c.err >= 0 {
			if e == nil || e.Code != c.err {
				t.Errorf("%s: want error %v", c.name, c.err)
			}
			continue
		}
		if e != nil || ans.Responsible != c.responsible {
			t.Errorf("%s: responsible=%v err=%v", c.name, ans.GetResponsible(), e)
		}
	}
}

func TestKeywordStoreAndSearch(t *testing.T) {
	x := newIndex()
	a := newPub(t, "81.2.3.4:4662")
	root := make([]byte, 32)
	rand.Read(root)
	req, target := keywordRecord(t, a, "The.Big_Sleep (1946) [1080p].mkv", root, "sleep", now.Add(time.Hour))
	ans, e := handle(t, x, req, a.peer)
	t.Logf("store: results=%v err=%v", ans.GetResults(), e)
	if e != nil || len(ans.Results) != 0 {
		t.Fatal("valid record not stored")
	}
	ans, _ = handle(t, x, req, a.peer)
	t.Logf("again, byte for byte: %v", ans.Results)
	if len(ans.Results) != 1 || ans.Results[0] != ed3kpb.StoreResult_OLDER {
		t.Fatal("byte-identical record not OLDER")
	}
	search := func(q *ed3kpb.Query) *ed3kpb.KadAnswer {
		ans, e := handle(t, x, &ed3kpb.KadRequest{Target: target[:], Kind: ed3kpb.Kind_KEYWORD, Search: q}, a.peer)
		if e != nil {
			t.Fatal(e)
		}
		return ans
	}
	found := search(&ed3kpb.Query{All: []string{"big"}, Ext: "mkv"})
	t.Logf("search big ext=mkv: files=%d keys=%d load=%d", len(found.Files), len(found.Keys), found.Load)
	if len(found.Files) != 1 || len(found.Keys) != 1 || found.Files[0].Key != 0 {
		t.Fatal("record not found")
	}
	if err := sig.CheckSigned(found.Files[0], ed3kpb.Kind_KEYWORD, target[:], found.Keys[0]); err != nil {
		t.Fatalf("answered record does not verify: %v", err)
	}
	if n := len(search(&ed3kpb.Query{All: []string{"big"}, None: []string{"1946"}}).Files); n != 0 {
		t.Fatalf("none=1946 matched %d", n)
	}

	// Records that fail a check.
	b := newPub(t, "81.2.4.5:4662")
	wrongWord, _ := keywordRecord(t, b, "Another Film.mkv", root, "sleep", now.Add(time.Hour))
	expired, _ := keywordRecord(t, b, "Sleep.mkv", root, "sleep", now.Add(-time.Minute))
	tooFar, _ := keywordRecord(t, b, "Sleep.mkv", root, "sleep", now.Add(26*time.Hour))
	forged, _ := keywordRecord(t, b, "Sleep.mkv", root, "sleep", now.Add(time.Hour))
	forged.Store.Files[0].Sigs[0].Sig[0] ^= 1
	extOnly, _ := keywordRecord(t, b, "film.sleep", root, "sleep", now.Add(time.Hour))
	for name, r := range map[string]*ed3kpb.KadRequest{"no such keyword": wrongWord, "expired": expired,
		"beyond lifetime": tooFar, "forged": forged, "extension word": extOnly} {
		ans, _ := handle(t, x, r, b.peer)
		t.Logf("%s -> %v", name, ans.Results)
		if len(ans.Results) != 1 || ans.Results[0] != ed3kpb.StoreResult_REJECTED {
			t.Errorf("%s: %v", name, ans.Results)
		}
	}
}

func TestSourceBinding(t *testing.T) {
	x := newIndex()
	a := newPub(t, "81.2.3.4:4662")
	target := make([]byte, 16)
	rand.Read(target)
	also := make([]byte, 32)
	rand.Read(also)
	claimed := ident.EncodeEndpoint(netip.MustParseAddrPort("9.9.9.9:1"))
	req := &ed3kpb.KadRequest{Target: target, Kind: ed3kpb.Kind_SOURCE,
		Store: &ed3kpb.Store{Source: &ed3kpb.Peer{Ep4: claimed}, Also: also}}
	ans, _ := handle(t, x, req, a.peer)
	t.Logf("store with 2 also targets: %v", ans.Results)
	if len(ans.Results) != 0 {
		t.Fatal("source not stored under all targets")
	}
	for _, tg := range [][]byte{target, also[:16], also[16:]} {
		ans, _ := handle(t, x, &ed3kpb.KadRequest{Target: tg, Kind: ed3kpb.Kind_SOURCE, Search: &ed3kpb.Query{}}, a.peer)
		if len(ans.Sources) != 1 {
			t.Fatalf("target %x: %d sources", tg, len(ans.Sources))
		}
		ep, _, _ := ident.DecodeEndpoint(ans.Sources[0].Ep4)
		t.Logf("target %x: id=%x ep4=%v", tg, ans.Sources[0].Id, ep)
		if ep != a.peer.Remote || ident.NodeID(ans.Sources[0].Id) != a.peer.ID {
			t.Fatal("source not bound to the connection")
		}
	}
	named := proto.Clone(req).(*ed3kpb.KadRequest)
	named.Store.Source.Id = make([]byte, 16)
	named.Store.Also = nil
	ans, _ = handle(t, x, named, a.peer)
	if ans.Results[0] != ed3kpb.StoreResult_REJECTED {
		t.Fatal("source with an id accepted")
	}
	private := newPub(t, "192.168.1.5:4662")
	ans, _ = handle(t, x, &ed3kpb.KadRequest{Target: target, Kind: ed3kpb.Kind_SOURCE, Store: &ed3kpb.Store{Source: &ed3kpb.Peer{}}}, private.peer)
	t.Logf("source from a private address on the public network: %v", ans.Results)
	if ans.Results[0] != ed3kpb.StoreResult_REJECTED {
		t.Fatal("private source accepted")
	}
}

func TestNotes(t *testing.T) {
	x := newIndex()
	a := newPub(t, "81.2.3.4:4662")
	target := make([]byte, 16)
	rand.Read(target)
	body, _ := proto.Marshal(&ed3kpb.Record{Expires: uint64(now.Add(time.Hour).Unix()), Note: &ed3kpb.Note{Rating: 4, Text: "good"}})
	s := sig.Sign(a.priv, ed3kpb.Kind_NOTE, target, body)
	ans, _ := handle(t, x, &ed3kpb.KadRequest{Target: target, Kind: ed3kpb.Kind_NOTE, Store: &ed3kpb.Store{Note: s}}, a.peer)
	if len(ans.Results) != 0 {
		t.Fatalf("note: %v", ans.Results)
	}
	ans, _ = handle(t, x, &ed3kpb.KadRequest{Target: target, Kind: ed3kpb.Kind_NOTE, Search: &ed3kpb.Query{}}, a.peer)
	t.Logf("notes: %d keys: %d", len(ans.Notes), len(ans.Keys))
	if len(ans.Notes) != 1 || len(ans.Keys) != 1 {
		t.Fatal("note not found")
	}
	bad, _ := proto.Marshal(&ed3kpb.Record{Expires: uint64(now.Add(time.Hour).Unix()), Note: &ed3kpb.Note{Rating: 6}})
	ans, _ = handle(t, x, &ed3kpb.KadRequest{Target: target, Kind: ed3kpb.Kind_NOTE, Store: &ed3kpb.Store{Note: sig.Sign(a.priv, ed3kpb.Kind_NOTE, target, bad)}}, a.peer)
	if ans.Results[0] != ed3kpb.StoreResult_REJECTED {
		t.Fatal("rating 6 accepted")
	}
}

func TestRateAndRecordLimit(t *testing.T) {
	x := New(Config{Store: storage.NewMemoryEngine(), Now: func() time.Time { return now }, RequestsPerMinute: 2})
	a := newPub(t, "81.2.3.4:4662")
	target := make([]byte, 16)
	q := &ed3kpb.KadRequest{Target: target, Kind: ed3kpb.Kind_SOURCE, Search: &ed3kpb.Query{}}
	var last *ed3kpb.Error
	for range 3 {
		_, last = handle(t, x, q, a.peer)
	}
	t.Logf("third search of the minute (limit 2): %v", last)
	if last == nil || last.Code != ed3kpb.Error_BUSY || last.RetryAfter == 0 {
		t.Fatal("search beyond the rate not BUSY")
	}
	st := &ed3kpb.KadRequest{Target: target, Kind: ed3kpb.Kind_SOURCE, Store: &ed3kpb.Store{Source: &ed3kpb.Peer{}}}
	for range 2 {
		handle(t, x, st, a.peer)
	}
	ans, _ := handle(t, x, st, a.peer)
	t.Logf("third store of the minute: %v", ans.Results)
	if ans.Results[0] != ed3kpb.StoreResult_BUSY {
		t.Fatal("store beyond the rate not BUSY")
	}

	y := newIndex()
	files := make([]*ed3kpb.Signed, 257)
	for i := range files {
		files[i] = &ed3kpb.Signed{Body: []byte{0xff}}
	}
	ans, _ = handle(t, y, &ed3kpb.KadRequest{Target: target, Kind: ed3kpb.Kind_KEYWORD, Store: &ed3kpb.Store{Files: files}}, a.peer)
	t.Logf("257 records: %d results, last %v", len(ans.Results), ans.Results[256])
	if len(ans.Results) != 257 || ans.Results[256] != ed3kpb.StoreResult_REJECTED {
		t.Fatal("record 257")
	}
}

// Bug 7: a KEYWORD record stored with level above 15 is REJECTED, never
// truncated to a byte; levels 1 to 15 are stored like level 0 (§10.8).
func TestStoreLevel(t *testing.T) {
	x := newIndex()
	a := newPub(t, "81.2.3.4:4662")
	root := make([]byte, 32)
	for _, level := range []uint32{16, 256, 1} {
		rand.Read(root)
		target := token.KeywordTarget(uint8(level), "sleep")
		body, _ := proto.Marshal(&ed3kpb.Record{Expires: uint64(now.Add(time.Hour).Unix()),
			File: &ed3kpb.FileInfo{Root: root, Size: 1000, Name: "The Big Sleep.mkv"}})
		req := &ed3kpb.KadRequest{Target: target[:], Kind: ed3kpb.Kind_KEYWORD, Level: level,
			Store: &ed3kpb.Store{Files: []*ed3kpb.Signed{sig.Sign(a.priv, ed3kpb.Kind_KEYWORD, target[:], body)}}}
		ans, e := handle(t, x, req, a.peer)
		t.Logf("level %d -> results=%v error=%v", level, ans.GetResults(), e)
		stored := e == nil && len(ans.Results) == 0
		if stored != (level <= MaxLevel) {
			t.Errorf("level %d: stored=%v", level, stored)
		}
	}
}

// Bugs 8 and 9: load and spill in every answer of a responsible node: store
// answers, contacts-only answers, and SOURCE and NOTE searches (§10.8).
func TestLoadAndSpill(t *testing.T) {
	x := New(Config{Store: storage.NewMemoryEngine(), Now: func() time.Time { return now },
		Limits: storage.Ed3kLimits{SourcesPerTarget: 1, KeywordFiles: 4}})
	a := newPub(t, "81.2.3.4:4662")
	b := newPub(t, "82.2.3.4:4662")
	target := make([]byte, 16)
	rand.Read(target)
	src := &ed3kpb.KadRequest{Target: target, Kind: ed3kpb.Kind_SOURCE, Store: &ed3kpb.Store{Source: &ed3kpb.Peer{}}}
	ans, _ := handle(t, x, src, a.peer)
	t.Logf("source 1: results=%v spill=%v", ans.Results, ans.Spill)
	if len(ans.Results) != 0 || ans.Spill {
		t.Fatal("first source")
	}
	ans, _ = handle(t, x, src, b.peer)
	t.Logf("source 2 at a full target: results=%v spill=%v", ans.Results, ans.Spill)
	if ans.Results[0] != ed3kpb.StoreResult_FULL || !ans.Spill {
		t.Fatal("FULL store answer without spill")
	}
	ans, _ = handle(t, x, &ed3kpb.KadRequest{Target: target, Kind: ed3kpb.Kind_SOURCE, Search: &ed3kpb.Query{}}, a.peer)
	t.Logf("source search: %d sources, spill=%v", len(ans.Sources), ans.Spill)
	if !ans.Spill {
		t.Fatal("SOURCE search without spill")
	}
	ans, _ = handle(t, x, &ed3kpb.KadRequest{Target: target, Kind: ed3kpb.Kind_SOURCE}, a.peer)
	t.Logf("contacts-only SOURCE: responsible=%v spill=%v", ans.Responsible, ans.Spill)
	if !ans.Responsible || !ans.Spill {
		t.Fatal("contacts-only answer without spill")
	}

	req, kw := keywordRecord(t, a, "The Big Sleep.mkv", make([]byte, 32), "sleep", now.Add(time.Hour))
	ans, _ = handle(t, x, req, a.peer)
	t.Logf("keyword store (1 file of 4): results=%v load=%d", ans.Results, ans.Load)
	if ans.Load != 25 {
		t.Fatalf("keyword store answer load %d, want 25", ans.Load)
	}
	ans, _ = handle(t, x, &ed3kpb.KadRequest{Target: kw[:], Kind: ed3kpb.Kind_KEYWORD}, a.peer)
	t.Logf("contacts-only KEYWORD: responsible=%v load=%d", ans.Responsible, ans.Load)
	if !ans.Responsible || ans.Load != 25 {
		t.Fatal("contacts-only KEYWORD answer without load")
	}
}

// Bug 10: StrictRecordFields refuses a KEYWORD record that also carries a field
// of an extension; by default such a record is stored.
func TestStrictRecordFields(t *testing.T) {
	a := newPub(t, "81.2.3.4:4662")
	target := token.KeywordTarget(0, "sleep")
	root := make([]byte, 32)
	rand.Read(root)
	body, _ := proto.Marshal(&ed3kpb.Record{Expires: uint64(now.Add(time.Hour).Unix()),
		File:  &ed3kpb.FileInfo{Root: root, Size: 1000, Name: "The Big Sleep.mkv"},
		Alias: &ed3kpb.Alias{}})
	req := &ed3kpb.KadRequest{Target: target[:], Kind: ed3kpb.Kind_KEYWORD,
		Store: &ed3kpb.Store{Files: []*ed3kpb.Signed{sig.Sign(a.priv, ed3kpb.Kind_KEYWORD, target[:], body)}}}
	for _, strict := range []bool{false, true} {
		x := New(Config{Store: storage.NewMemoryEngine(), Now: func() time.Time { return now }, StrictRecordFields: strict})
		ans, _ := handle(t, x, req, a.peer)
		t.Logf("file + alias, strict=%v -> results=%v", strict, ans.Results)
		rejected := len(ans.Results) == 1 && ans.Results[0] == ed3kpb.StoreResult_REJECTED
		if rejected != strict {
			t.Errorf("strict=%v: rejected=%v", strict, rejected)
		}
	}
}
