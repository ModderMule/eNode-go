package storage

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestMemoryEd3kStore(t *testing.T) {
	testEd3kStore(t, NewMemoryEngine())
}

func TestDecideKeywordPlaces(t *testing.T) {
	lim := DefaultEd3kLimits
	at := time.Unix(1_800_000_000, 0)
	k := func(b byte) [32]byte { var x [32]byte; x[0] = b; return x }
	held := []ed3kHeldKeyword{
		{PubKey: k(1), Site: "a", StoredAt: at, Expires: at.Add(time.Hour)},
		{PubKey: k(2), Site: "b", StoredAt: at.Add(time.Second), Expires: at.Add(time.Hour)},
		{PubKey: k(3), Site: "c", StoredAt: at.Add(2 * time.Second), Expires: at.Add(time.Hour)},
	}
	cases := []struct {
		name    string
		r       Ed3kKeyword
		want    Ed3kResult
		replace byte
	}{
		{"rule 1: own place, newer", Ed3kKeyword{PubKey: k(2), Site: "z", Expires: at.Add(2 * time.Hour)}, Ed3kStored, 2},
		{"own place, not newer", Ed3kKeyword{PubKey: k(2), Site: "b", Expires: at.Add(time.Hour)}, Ed3kOlder, 0},
		{"rule 2: same site", Ed3kKeyword{PubKey: k(9), Site: "c", Expires: at.Add(time.Hour)}, Ed3kStored, 3},
		{"rule 3: least fresh", Ed3kKeyword{PubKey: k(9), Site: "d", Expires: at.Add(time.Hour)}, Ed3kStored, 1},
		{"rule 3 with signer", Ed3kKeyword{PubKey: k(9), Site: "d", Expires: at.Add(time.Hour), ViaSigner: true}, Ed3kRejected, 0},
	}
	for _, c := range cases {
		d := decideKeyword(ed3kKeywordView{Held: held, Files: 1}, c.r, lim)
		got := byte(0)
		if d.Replace != nil {
			got = d.Replace[0]
		}
		t.Logf("%s: result=%v replace=%d insert=%v", c.name, d.Result, got, d.Insert)
		if d.Result != c.want || got != c.replace {
			t.Errorf("%s: got %v/%d want %v/%d", c.name, d.Result, got, c.want, c.replace)
		}
	}
}

// testEd3kStore is the conformance suite every Ed3kStore engine runs. Every
// subtest uses fresh targets, keys and addresses, so the engines may share one
// database across subtests.
func testEd3kStore(t *testing.T, s Ed3kStore) {
	ctx := context.Background()
	if err := s.InitEd3k(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	now := time.Now().Truncate(time.Second)
	lim := Ed3kLimits{SourcesPerTarget: 4, SourcesPerHost: 2, SourcesPerSite: 3,
		KeywordFiles: 3, KeywordPerKey: 2, KeywordPerSite: 3,
		NotesPerTarget: 3, NotesPerHost: 1, NotesPerSite: 2}

	t.Run("sources", func(t *testing.T) {
		target := rnd16()
		var ids [][16]byte
		for i := range 4 {
			id := rnd16()
			ids = append(ids, id)
			r := testSource(target, id, fmt.Sprintf("s-host-%d", i), fmt.Sprintf("s-site-%d", i), now)
			res, err := s.StoreEd3kSource(ctx, r, lim, now)
			t.Logf("store source %d -> %v %v", i, res, err)
			if err != nil || res != Ed3kStored {
				t.Fatalf("store %d: %v %v", i, res, err)
			}
		}
		res, _ := s.StoreEd3kSource(ctx, testSource(target, rnd16(), "s-host-x", "s-site-x", now), lim, now)
		t.Logf("fifth source on a full target -> %v", res)
		if res != Ed3kFull {
			t.Fatalf("want FULL, got %v", res)
		}
		renew := testSource(target, ids[0], "s-host-0", "s-site-0", now)
		renew.Peer = []byte("renewed")
		if res, _ := s.StoreEd3kSource(ctx, renew, lim, now); res != Ed3kStored {
			t.Fatalf("renewal on a full target: %v", res)
		}
		var got [][16]byte
		seen := map[[16]byte]bool{}
		for off := 0; ; off += 3 {
			page, more, err := s.SearchEd3kSources(ctx, target, off, 3, now)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("page offset=%d n=%d more=%v", off, len(page), more)
			for _, p := range page {
				if seen[p.NodeID] {
					t.Fatalf("source %x twice", p.NodeID)
				}
				seen[p.NodeID] = true
				got = append(got, p.NodeID)
				if p.NodeID == ids[0] && string(p.Peer) != "renewed" {
					t.Errorf("renewal not stored: %q", p.Peer)
				}
			}
			if !more {
				break
			}
		}
		if len(got) != 4 {
			t.Fatalf("paged %d sources, want 4", len(got))
		}
	})

	t.Run("source address limits", func(t *testing.T) {
		target := rnd16()
		for i := range 2 {
			res, _ := s.StoreEd3kSource(ctx, testSource(target, rnd16(), "sa-host", fmt.Sprintf("sa-site-%d", i), now), lim, now)
			if res != Ed3kStored {
				t.Fatalf("store %d: %v", i, res)
			}
		}
		res, _ := s.StoreEd3kSource(ctx, testSource(target, rnd16(), "sa-host", "sa-site-9", now), lim, now)
		t.Logf("third source of one host -> %v", res)
		if res != Ed3kRejected {
			t.Fatalf("host limit: %v", res)
		}
		res, _ = s.StoreEd3kSource(ctx, testSource(target, rnd16(), "sa-host-2", "sa-site-0", now), lim, now)
		if res != Ed3kStored {
			t.Fatalf("other host: %v", res)
		}
	})

	t.Run("kept sources", func(t *testing.T) {
		target := rnd16()
		kept := testSource(target, rnd16(), "k-host-0", "k-site-0", now)
		kept.LifetimeEnd = now.Add(time.Hour)
		kept.KeptBy = "conn-" + fmt.Sprint(now.UnixNano())
		if res, _ := s.StoreEd3kSource(ctx, kept, lim, now); res != Ed3kStored {
			t.Fatal("store kept")
		}
		s.KeepEd3kSources(ctx, kept.KeptBy, now.Add(3*time.Hour))
		later := now.Add(2 * time.Hour)
		if _, err := s.ExpireEd3k(ctx, later); err != nil {
			t.Fatal(err)
		}
		page, _, _ := s.SearchEd3kSources(ctx, target, 0, 10, later)
		t.Logf("kept source after its lifetime: %d found", len(page))
		if len(page) != 1 {
			t.Fatal("kept source expired with its lifetime")
		}
		// Past its lifetime it gives its place before the target answers FULL.
		for i := range 3 {
			s.StoreEd3kSource(ctx, testSource(target, rnd16(), fmt.Sprintf("k-host-%d", i+1), fmt.Sprintf("k-site-%d", i+1), later), lim, later)
		}
		res, _ := s.StoreEd3kSource(ctx, testSource(target, rnd16(), "k-host-9", "k-site-9", later), lim, later)
		page, _, _ = s.SearchEd3kSources(ctx, target, 0, 10, later)
		t.Logf("fifth source with one kept past lifetime -> %v, %d held", res, len(page))
		if res != Ed3kStored || len(page) != 4 {
			t.Fatalf("eviction of a kept record: %v, %d", res, len(page))
		}
		other := testSource(rnd16(), rnd16(), "k-host-r", "k-site-r", now)
		other.LifetimeEnd = now.Add(time.Hour)
		other.KeptBy = kept.KeptBy + "-b"
		s.StoreEd3kSource(ctx, other, lim, now)
		s.KeepEd3kSources(ctx, other.KeptBy, now.Add(3*time.Hour))
		s.ReleaseEd3kSources(ctx, other.KeptBy)
		s.ExpireEd3k(ctx, later)
		page, _, _ = s.SearchEd3kSources(ctx, other.Target, 0, 10, later)
		t.Logf("released source after its lifetime: %d found", len(page))
		if len(page) != 0 {
			t.Fatal("released source outlived its lifetime")
		}
	})

	t.Run("keywords", func(t *testing.T) {
		target := rnd16()
		root := rnd32()
		calls := 0
		ok := func() error { calls++; return nil }
		bad := func() error { return errors.New("bad signature") }
		keys := []([32]byte){rnd32(), rnd32(), rnd32(), rnd32()}
		for i := range 3 {
			r := testKeyword(target, root, keys[i], fmt.Sprintf("kw-site-%d", i), now.Add(time.Hour))
			res, err := s.StoreEd3kKeyword(ctx, r, lim, now.Add(time.Duration(i)*time.Second), ok)
			if err != nil || res != Ed3kStored {
				t.Fatalf("place %d: %v %v", i, res, err)
			}
		}
		same := testKeyword(target, root, keys[0], "kw-site-0", now.Add(time.Hour))
		before := calls
		res, _ := s.StoreEd3kKeyword(ctx, same, lim, now, ok)
		t.Logf("byte-identical record -> %v, verify calls %d", res, calls-before)
		if res != Ed3kOlder || calls != before {
			t.Fatalf("OLDER shortcut: %v, %d verify calls", res, calls-before)
		}
		notNewer := testKeyword(target, root, keys[0], "kw-site-0", now.Add(time.Hour))
		notNewer.Signed = append(notNewer.Signed, 'x')
		if res, _ := s.StoreEd3kKeyword(ctx, notNewer, lim, now, ok); res != Ed3kOlder {
			t.Fatalf("not newer: %v", res)
		}
		forged := testKeyword(target, root, keys[3], "kw-site-9", now.Add(2*time.Hour))
		if res, _ := s.StoreEd3kKeyword(ctx, forged, lim, now, bad); res != Ed3kRejected {
			t.Fatalf("bad signature: %v", res)
		}
		// Rule 3: a fourth site takes the place of the least fresh (keys[0]).
		fourth := testKeyword(target, root, keys[3], "kw-site-3", now.Add(2*time.Hour))
		if res, _ := s.StoreEd3kKeyword(ctx, fourth, lim, now.Add(10*time.Second), ok); res != Ed3kStored {
			t.Fatalf("rule 3: %v", res)
		}
		p, err := s.SearchEd3kKeywords(ctx, target, Ed3kQuery{}, 0, 10, now)
		if err != nil {
			t.Fatal(err)
		}
		pubs := map[[32]byte]bool{}
		for _, r := range p.Records {
			pubs[r.PubKey] = true
		}
		t.Logf("after rule 3: %d records, files=%d, first key kept=%v", len(p.Records), p.Files, pubs[keys[0]])
		if len(p.Records) != 3 || pubs[keys[0]] || !pubs[keys[3]] || p.Files != 1 {
			t.Fatalf("places after rule 3 wrong")
		}
	})

	t.Run("keyword limits", func(t *testing.T) {
		target := rnd16()
		key := rnd32()
		for i := range 2 {
			r := testKeyword(target, rnd32(), key, fmt.Sprintf("kl-site-%d", i), now.Add(time.Hour))
			if res, _ := s.StoreEd3kKeyword(ctx, r, lim, now, nil); res != Ed3kStored {
				t.Fatalf("file %d: %v", i, res)
			}
		}
		res, _ := s.StoreEd3kKeyword(ctx, testKeyword(target, rnd32(), key, "kl-site-9", now.Add(time.Hour)), lim, now, nil)
		t.Logf("third file of one key (limit 2) -> %v", res)
		if res != Ed3kRejected {
			t.Fatalf("key limit: %v", res)
		}
		res, _ = s.StoreEd3kKeyword(ctx, testKeyword(target, rnd32(), rnd32(), "kl-site-8", now.Add(time.Hour)), lim, now, nil)
		if res != Ed3kStored {
			t.Fatalf("third file: %v", res)
		}
		res, _ = s.StoreEd3kKeyword(ctx, testKeyword(target, rnd32(), rnd32(), "kl-site-7", now.Add(time.Hour)), lim, now, nil)
		p, _ := s.SearchEd3kKeywords(ctx, target, Ed3kQuery{}, 0, 10, now)
		t.Logf("fourth file at level size 3 -> %v, spill=%v files=%d", res, p.Spill, p.Files)
		if res != Ed3kFull || !p.Spill || p.Files != 3 {
			t.Fatalf("level size: %v spill=%v files=%d", res, p.Spill, p.Files)
		}
	})

	t.Run("keyword query", func(t *testing.T) {
		target := rnd16()
		mk := func(words []string, ext string, size uint64, sources uint32) {
			r := testKeyword(target, rnd32(), rnd32(), "q-site-"+fmt.Sprint(size), now.Add(time.Hour))
			r.Words, r.Ext, r.Size, r.Sources = words, ext, size, sources
			if res, _ := s.StoreEd3kKeyword(ctx, r, Ed3kLimits{}, now, nil); res != Ed3kStored {
				t.Fatalf("store: %v", res)
			}
		}
		mk([]string{"big", "sleep", "mkv"}, "mkv", 100, 5)
		mk([]string{"big", "lebowski", "avi"}, "avi", 200, 1)
		mk([]string{"big", "sleep", "1946", "avi"}, "avi", 300, 9)
		cases := []struct {
			name string
			q    Ed3kQuery
			want int
		}{
			{"all", Ed3kQuery{}, 3},
			{"all=sleep", Ed3kQuery{All: []string{"sleep"}}, 2},
			{"all=sleep none=1946", Ed3kQuery{All: []string{"sleep"}, None: []string{"1946"}}, 1},
			{"ext=avi", Ed3kQuery{Ext: "avi"}, 2},
			{"size 150..250", Ed3kQuery{MinSize: 150, MaxSize: 250}, 1},
			{"min_sources 5", Ed3kQuery{MinSources: 5}, 2},
			{"substring sle", Ed3kQuery{All: []string{"sle"}}, 0},
			{"percent sign", Ed3kQuery{All: []string{"%"}}, 0},
		}
		for _, c := range cases {
			p, err := s.SearchEd3kKeywords(ctx, target, c.q, 0, 10, now)
			t.Logf("%s -> %d records", c.name, len(p.Records))
			if err != nil || len(p.Records) != c.want {
				t.Errorf("%s: got %d (%v), want %d", c.name, len(p.Records), err, c.want)
			}
		}
	})

	t.Run("notes", func(t *testing.T) {
		target := rnd16()
		key := rnd32()
		n := Ed3kNote{Target: target, PubKey: key, Signed: []byte("note-1"), Host: "n-host-0", Site: "n-site-0", Expires: now.Add(time.Hour)}
		if res, _ := s.StoreEd3kNote(ctx, n, lim, now, nil); res != Ed3kStored {
			t.Fatalf("note: %v", res)
		}
		n2 := n
		n2.Signed = []byte("note-2")
		if res, _ := s.StoreEd3kNote(ctx, n2, lim, now, nil); res != Ed3kOlder {
			t.Fatalf("note not newer: %v", res)
		}
		n2.Expires = now.Add(2 * time.Hour)
		if res, _ := s.StoreEd3kNote(ctx, n2, lim, now, nil); res != Ed3kStored {
			t.Fatalf("note newer: %v", res)
		}
		res, _ := s.StoreEd3kNote(ctx, Ed3kNote{Target: target, PubKey: rnd32(), Signed: []byte("x"), Host: "n-host-0", Site: "n-site-1", Expires: now.Add(time.Hour)}, lim, now, nil)
		t.Logf("second note of one host (limit 1) -> %v", res)
		if res != Ed3kRejected {
			t.Fatalf("note host limit: %v", res)
		}
		for i := range 2 {
			s.StoreEd3kNote(ctx, Ed3kNote{Target: target, PubKey: rnd32(), Signed: []byte("y"), Host: fmt.Sprintf("n-host-%d", i+1), Site: fmt.Sprintf("n-site-%d", i+5), Expires: now.Add(time.Hour)}, lim, now, nil)
		}
		res, _ = s.StoreEd3kNote(ctx, Ed3kNote{Target: target, PubKey: rnd32(), Signed: []byte("z"), Host: "n-host-8", Site: "n-site-8", Expires: now.Add(time.Hour)}, lim, now, nil)
		notes, _, _ := s.SearchEd3kNotes(ctx, target, 0, 10, now)
		t.Logf("fourth note (limit 3) -> %v, %d held", res, len(notes))
		if res != Ed3kFull || len(notes) != 3 {
			t.Fatalf("notes full: %v %d", res, len(notes))
		}
	})

	t.Run("node-wide host bound", func(t *testing.T) {
		host := "nw-host-" + fmt.Sprint(now.UnixNano())
		l := lim
		l.RecordsPerHost = 2
		for i := range 2 {
			if res, _ := s.StoreEd3kSource(ctx, testSource(rnd16(), rnd16(), host, fmt.Sprintf("nw-site-%d", i), now), l, now); res != Ed3kStored {
				t.Fatalf("source %d: %v", i, res)
			}
		}
		res, _ := s.StoreEd3kKeyword(ctx, testKeyword(rnd16(), rnd32(), rnd32(), "nw-site-k", now.Add(time.Hour)), l, now, nil)
		_ = res
		kw := testKeyword(rnd16(), rnd32(), rnd32(), "nw-site-k2", now.Add(time.Hour))
		kw.Host = host
		res, _ = s.StoreEd3kKeyword(ctx, kw, l, now, nil)
		t.Logf("third record of a host over all targets (bound 2) -> %v", res)
		if res != Ed3kRejected {
			t.Fatalf("node-wide bound: %v", res)
		}
	})

	t.Run("bridge", func(t *testing.T) {
		root := rnd32()
		var fileTarget [16]byte
		copy(fileTarget[:], root[:16])
		pub := rnd32()
		node := rnd16()
		ed2k := rnd16()
		src := testSource(fileTarget, node, "b-host", "b-site", now)
		src.ED2K = true
		src.EP4 = netip.MustParseAddrPort("81.2.3.4:4662")
		s.StoreEd3kSource(ctx, src, lim, now)
		kw := testKeyword(rnd16(), root, pub, "b-site", now.Add(time.Hour))
		kw.PublisherID = node
		kw.ED2K = ed2k[:]
		s.StoreEd3kKeyword(ctx, kw, lim, now, nil)
		// A source of another node for the same file, without a keyword record.
		lone := testSource(fileTarget, rnd16(), "b-host-2", "b-site-2", now)
		lone.ED2K = true
		lone.EP4 = netip.MustParseAddrPort("81.2.3.5:4662")
		s.StoreEd3kSource(ctx, lone, lim, now)
		got, err := s.Ed3kBridge(ctx, ed2k, 10, now)
		t.Logf("bridge for %x: %+v %v", ed2k, got, err)
		if err != nil || len(got) != 1 || got[0].NodeID != node || got[0].EP4 != src.EP4 {
			t.Fatalf("bridge: %+v %v", got, err)
		}
	})

	t.Run("expiry and stats", func(t *testing.T) {
		target := rnd16()
		s.StoreEd3kKeyword(ctx, testKeyword(target, rnd32(), rnd32(), "e-site", now.Add(time.Hour)), lim, now, nil)
		st, _ := s.Ed3kStats(ctx, now)
		t.Logf("stats before expiry: %+v", st)
		if st.Keywords == 0 || st.Sources == 0 || st.Notes == 0 {
			t.Fatalf("stats: %+v", st)
		}
		far := now.Add(48 * time.Hour)
		n, err := s.ExpireEd3k(ctx, far)
		p, _ := s.SearchEd3kKeywords(ctx, target, Ed3kQuery{}, 0, 10, far)
		st, _ = s.Ed3kStats(ctx, far)
		t.Logf("expired %d (%v); after: %+v, target now %d", n, err, st, len(p.Records))
		if err != nil || n == 0 || len(p.Records) != 0 || st.Keywords != 0 {
			t.Fatalf("expiry")
		}
	})

	t.Run("secret rotation", func(t *testing.T) {
		target := rnd16()
		// Later than 24 h after the rotation the expiry subtest caused (at +48 h).
		later := now.Add(100 * time.Hour)
		for i := range 5 {
			r := testSource(target, rnd16(), fmt.Sprintf("r-host-%d", i), fmt.Sprintf("r-site-%d", i), now)
			r.LifetimeEnd = now.Add(200 * time.Hour)
			if res, _ := s.StoreEd3kSource(ctx, r, Ed3kLimits{}, now); res != Ed3kStored {
				t.Fatalf("source %d: %v", i, res)
			}
		}
		before, _, _ := s.SearchEd3kSources(ctx, target, 0, 10, later)
		if _, err := s.ExpireEd3k(ctx, later); err != nil {
			t.Fatal(err)
		}
		seen := map[[16]byte]bool{}
		for off := 0; ; off += 2 {
			page, more, err := s.SearchEd3kSources(ctx, target, off, 2, later)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range page {
				if seen[p.NodeID] {
					t.Fatalf("source %x twice after rotation", p.NodeID)
				}
				seen[p.NodeID] = true
			}
			if !more {
				break
			}
		}
		after, _, _ := s.SearchEd3kSources(ctx, target, 0, 10, later)
		sameOrder := len(before) == len(after)
		for i := range before {
			if sameOrder && before[i].NodeID != after[i].NodeID {
				sameOrder = false
			}
		}
		t.Logf("after the 24 h rotation: %d sources paged, order unchanged=%v", len(seen), sameOrder)
		if len(seen) != 5 {
			t.Fatalf("paged %d of 5 after rotation", len(seen))
		}
	})

	t.Run("concurrent stores", func(t *testing.T) {
		target := rnd16()
		var wg sync.WaitGroup
		results := make(chan Ed3kResult, 16)
		for i := range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := s.StoreEd3kSource(ctx, testSource(target, rnd16(), fmt.Sprintf("c-host-%d", i), fmt.Sprintf("c-site-%d", i), now), lim, now)
				if err != nil {
					t.Error(err)
				}
				results <- res
			}()
		}
		wg.Wait()
		close(results)
		stored := 0
		for r := range results {
			if r == Ed3kStored {
				stored++
			}
		}
		page, _, _ := s.SearchEd3kSources(ctx, target, 0, 100, now)
		t.Logf("16 parallel stores, limit 4: %d stored, %d held", stored, len(page))
		if stored != 4 || len(page) != 4 {
			t.Fatalf("concurrent limit: %d stored, %d held", stored, len(page))
		}
	})
}

func testSource(target, id [16]byte, host, site string, now time.Time) Ed3kSource {
	return Ed3kSource{Target: target, NodeID: id, Peer: append([]byte("peer-"), id[:4]...), Host: host, Site: site, LifetimeEnd: now.Add(5 * time.Hour)}
}

func testKeyword(target [16]byte, root, pub [32]byte, site string, expires time.Time) Ed3kKeyword {
	return Ed3kKeyword{Target: target, Root: root, PubKey: pub, PublisherID: rnd16(),
		Signed: append(append([]byte("signed-"), root[:4]...), pub[:4]...), Words: []string{"word"},
		Ext: "mkv", Size: 1, Host: "host-of-" + site, Site: site, Expires: expires}
}

func rnd16() (b [16]byte) { rand.Read(b[:]); return }
func rnd32() (b [32]byte) { rand.Read(b[:]); return }
