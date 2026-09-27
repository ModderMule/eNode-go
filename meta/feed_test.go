package meta

import (
	"context"
	"testing"
	"time"

	"enode/storage"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
)

func upsert(seq uint64, entry *metav1.MetaEntry) *metav1.ReleaseChange {
	return &metav1.ReleaseChange{Seq: seq, CatalogId: entry.GetCatalogId(), Op: metav1.ChangeOp_CHANGE_OP_UPSERT,
		Entries: []*metav1.MetaEntry{entry}}
}

func retract(seq uint64, entry *metav1.MetaEntry) *metav1.ReleaseChange {
	return &metav1.ReleaseChange{Seq: seq, CatalogId: entry.GetCatalogId(), Op: metav1.ChangeOp_CHANGE_OP_RETRACT,
		Reason: metav1.RetractReason_RETRACT_REASON_EXPIRED}
}

func newTestFeed(maxRows int) *Feed {
	return NewFeed("torrent", nil, maxRows, time.Millisecond, time.Millisecond)
}

// TestFeedAppliesContractRules walks the contract's feed semantics in order: an
// upsert replaces a release's rows, a retract removes them, a reset drops everything,
// and snapshot_end drops whatever the snapshot did not re-send.
func TestFeedAppliesContractRules(t *testing.T) {
	f := newTestFeed(100)
	a, b, c := torrentEntry("alpha.mkv", 10), torrentEntry("bravo.mkv", 20), torrentEntry("charlie.mkv", 30)

	f.apply(&metav1.SubscribeResponse{Reset_: true, Changes: []*metav1.ReleaseChange{upsert(1, a), upsert(2, b)}, Cursor: 2})
	f.apply(&metav1.SubscribeResponse{Changes: []*metav1.ReleaseChange{upsert(3, c)}, Cursor: 3, SnapshotEnd: true, CaughtUp: true})
	t.Logf("after snapshot: rows=%d cursor=%d", f.Rows(), f.cursor)
	if f.Rows() != 3 || f.cursor != 3 {
		t.Fatalf("rows=%d cursor=%d, want 3/3", f.Rows(), f.cursor)
	}

	renamed := torrentEntry("alpha.mkv", 99)
	f.apply(&metav1.SubscribeResponse{Changes: []*metav1.ReleaseChange{upsert(4, renamed), retract(5, b)}, Cursor: 5})
	t.Logf("after upsert(alpha)+retract(bravo): rows=%d", f.Rows())
	if f.Rows() != 2 {
		t.Fatalf("rows=%d, want 2 (upsert replaces, retract removes)", f.Rows())
	}
	if f.releases[a.GetCatalogId()][0].file.Meta.Seeders != 99 {
		t.Fatal("the upsert did not replace alpha's row")
	}

	// A new snapshot that re-sends only charlie: alpha must go at snapshot_end.
	f.apply(&metav1.SubscribeResponse{Reset_: true, Changes: []*metav1.ReleaseChange{upsert(6, c)}, Cursor: 6})
	f.apply(&metav1.SubscribeResponse{Cursor: 6, SnapshotEnd: true})
	t.Logf("after reset+snapshot of charlie only: rows=%d releases=%v", f.Rows(), len(f.releases))
	if f.Rows() != 1 {
		t.Fatalf("rows=%d, want only charlie", f.Rows())
	}
	if _, ok := f.releases[c.GetCatalogId()]; !ok {
		t.Fatal("charlie was dropped")
	}
}

func TestFeedSnapshotEndPrunesUnresent(t *testing.T) {
	f := newTestFeed(100)
	a, b := torrentEntry("alpha.mkv", 1), torrentEntry("bravo.mkv", 1)
	f.apply(&metav1.SubscribeResponse{Changes: []*metav1.ReleaseChange{upsert(1, a), upsert(2, b)}, Cursor: 2})
	// A reset arrives without re-sending b in the same message; b is gone by the end.
	f.apply(&metav1.SubscribeResponse{Reset_: true, Cursor: 3})
	f.apply(&metav1.SubscribeResponse{Changes: []*metav1.ReleaseChange{upsert(4, a)}, Cursor: 4, SnapshotEnd: true})
	t.Logf("input: a,b then snapshot of a; output: rows=%d", f.Rows())
	if _, ok := f.releases[b.GetCatalogId()]; ok || f.Rows() != 1 {
		t.Fatalf("rows=%d, b present=%t; want only a", f.Rows(), ok)
	}
}

func TestFeedMaxRowsCap(t *testing.T) {
	f := newTestFeed(2)
	f.apply(&metav1.SubscribeResponse{Changes: []*metav1.ReleaseChange{
		upsert(1, torrentEntry("one.mkv", 1)), upsert(2, torrentEntry("two.mkv", 1)), upsert(3, torrentEntry("three.mkv", 1)),
	}, Cursor: 3})
	t.Logf("input: 3 releases, maxRows=2; output: rows=%d", f.Rows())
	if f.Rows() != 2 {
		t.Fatalf("rows=%d, want the cap of 2", f.Rows())
	}
}

func TestFeedMatchFiltersAndRanks(t *testing.T) {
	f := newTestFeed(100)
	f.apply(&metav1.SubscribeResponse{Changes: []*metav1.ReleaseChange{
		upsert(1, torrentEntry("Ubuntu.24.04.Desktop.iso", 5)),
		upsert(2, torrentEntry("Ubuntu.24.04.Server.iso", 50)),
		upsert(3, torrentEntry("Debian.12.iso", 500)),
		upsert(4, torrentEntry("Ubuntu.22.04.Desktop.iso", 20)),
	}, Cursor: 4})

	expr := node(storage.SearchAndNot, text("ubuntu"), text("desktop"))
	got := f.Match(expr, []string{"ubuntu"}, 10)
	t.Logf("input: ubuntu AND NOT desktop; output: %s", fileNames(got))
	if len(got) != 1 || got[0].Name != "Ubuntu.24.04.Server.iso" {
		t.Fatalf("got %s, want only the server iso", fileNames(got))
	}

	got = f.Match(text("ubuntu"), []string{"ubuntu"}, 2)
	t.Logf("input: ubuntu, limit 2; output: %s", fileNames(got))
	if len(got) != 2 || got[0].Name != "Ubuntu.24.04.Server.iso" || got[1].Name != "Ubuntu.22.04.Desktop.iso" {
		t.Fatalf("got %s, want the two best-seeded ubuntu rows", fileNames(got))
	}
}

// TestFeedRunSubscribesAndReconnects runs the real stream against an in-process
// daemon: the first Subscribe asks for a snapshot, and the rows land.
func TestFeedRunSubscribesAndReconnects(t *testing.T) {
	a := torrentEntry("stream.alpha.mkv", 3)
	d := &fakeDaemon{feed: []*metav1.SubscribeResponse{
		{Reset_: true, Changes: []*metav1.ReleaseChange{upsert(7, a)}, Cursor: 7, SnapshotEnd: true, CaughtUp: true},
	}}
	f := NewFeed("torrent", d.client(), 100, 10*time.Millisecond, 20*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for f.Rows() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	d.mu.Lock()
	subs := append([]uint64(nil), d.subscribes...)
	d.mu.Unlock()
	t.Logf("input: daemon feed with one release at seq 7; output: rows=%d cursor=%d subscribes(after_seq)=%v", f.Rows(), f.cursor, subs)
	if f.Rows() != 1 || f.cursor != 7 {
		t.Fatalf("rows=%d cursor=%d, want 1/7", f.Rows(), f.cursor)
	}
	if len(subs) == 0 || subs[0] != 0 {
		t.Fatalf("first Subscribe after_seq=%v, want a snapshot (0)", subs)
	}
}

// TestFeedMatchSubFiles: feed rows follow the live rule — a file row is found by
// "Release - path", and a release matched by its own name answers with its whole-set
// row only.
func TestFeedMatchSubFiles(t *testing.T) {
	f := newTestFeed(100)
	pack := packEntries(nzbEntry("Foo.Season.1"), "foo.s01e01.mkv", "foo.s01e02.mkv")
	f.apply(&metav1.SubscribeResponse{Changes: []*metav1.ReleaseChange{
		{Seq: 1, CatalogId: pack[0].GetCatalogId(), Op: metav1.ChangeOp_CHANGE_OP_UPSERT, Entries: pack},
	}, Cursor: 1})

	got := f.Match(text("foo"), []string{"foo"}, 10)
	t.Logf("input: foo; output: %s", fileNames(got))
	if len(got) != 1 || got[0].Name != "Foo.Season.1" {
		t.Fatalf("got %s, want only the whole-set row", fileNames(got))
	}

	expr := node(storage.SearchAnd, text("season"), text("e02"))
	got = f.Match(expr, []string{"season", "e02"}, 10)
	t.Logf("input: season AND e02; output: %s", fileNames(got))
	if len(got) != 1 || got[0].Name != "Foo.Season.1 - foo.s01e02.mkv" {
		t.Fatalf("got %s, want the second episode under its release's name", fileNames(got))
	}
}
