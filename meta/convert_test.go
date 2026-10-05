package meta

import (
	"bytes"
	"fmt"
	"testing"

	"enode/storage"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/metahash"
)

func TestEntryToFileTorrent(t *testing.T) {
	entry := torrentEntry("Big.Buck.Bunny.1080p.mkv", 350)
	file, err := EntryToFile(entry)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: %v", entry)
	t.Logf("output: hash=%x name=%q size=%d sources=%d meta=%+v", file.Hash, file.Name, file.Size, file.Sources, *file.Meta)

	parsed, err := metahash.Parse(file.Hash)
	if err != nil {
		t.Fatalf("the minted hash does not parse: %v", err)
	}
	if parsed.Kind != metahash.KindBTV1 || !metahash.IsMetaHash(file.Hash) {
		t.Fatalf("hash kind %v, want bt-v1", parsed.Kind)
	}
	h, _ := metahash.FromBytes(file.Hash)
	if !h.VerifyIdentity(entry.GetIdentity()) {
		t.Fatal("the hash does not fold the entry's identity")
	}
	if file.Sources != 99 || file.Completed != 99 {
		t.Fatalf("sources=%d completed=%d, want seeders capped at 99", file.Sources, file.Completed)
	}
	if file.Name != entry.GetName() || file.SourceID != 0 || file.SourcePort != 0 {
		t.Fatalf("name=%q source=%d:%d, want the unprefixed name and no source", file.Name, file.SourceID, file.SourcePort)
	}
	if file.Meta.Kind != 1 || file.Meta.Version != metahash.Version1 || file.Meta.CatalogID != entry.GetCatalogId() ||
		file.Meta.Seeders != 350 || file.Meta.Magnet != entry.GetMagnet() {
		t.Fatalf("meta tags lost information: %+v", *file.Meta)
	}
}

func TestEntryToFileNZBHasNoSources(t *testing.T) {
	file, err := EntryToFile(nzbEntry("Some.Release.2026.1080p"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: nzb row seeders=98 (completion %%); output: sources=%d kind=%d seedersTag=%d", file.Sources, file.Meta.Kind, file.Meta.Seeders)
	if file.Sources != 0 || file.Completed != 0 {
		t.Fatalf("an NZB reported %d sources; completion is not a source count", file.Sources)
	}
	if file.Meta.Kind != 3 || file.Meta.Seeders != 98 {
		t.Fatalf("meta %+v", *file.Meta)
	}
}

// TestEntryToFileKad: a Kad row keeps the file's own MD4 as its hash — nothing is
// minted — and its sources are what Kad reported, not the seldom-known complete count.
func TestEntryToFileKad(t *testing.T) {
	entry := kadEntry("Night.Of.The.Living.Dead.1968.avi", 250, 3)
	file, err := EntryToFile(entry)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: %v", entry)
	t.Logf("output: hash=%x name=%q size=%d sources=%d completed=%d meta=%+v",
		file.Hash, file.Name, file.Size, file.Sources, file.Completed, *file.Meta)

	if !bytes.Equal(file.Hash, entry.GetIdentity()) || metahash.IsMetaHash(file.Hash) {
		t.Fatalf("hash %x, want the file's own MD4 %x", file.Hash, entry.GetIdentity())
	}
	if !file.Meta.Native() || file.Meta.Kind != storage.MetaKindED2K || file.Meta.CatalogID != entry.GetCatalogId() {
		t.Fatalf("meta %+v, want a native row", *file.Meta)
	}
	if file.Sources != 99 || file.Completed != 3 {
		t.Fatalf("sources=%d completed=%d, want peers capped at 99 and the 3 complete", file.Sources, file.Completed)
	}
	if file.Name != entry.GetName() || file.SourceID != 0 || file.SourcePort != 0 {
		t.Fatalf("name=%q source=%d:%d, want the unprefixed name and no source", file.Name, file.SourceID, file.SourcePort)
	}

	unknown, err := EntryToFile(kadEntry("no.complete.count.avi", 12, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: 12 sources, 0 complete; output: sources=%d completed=%d", unknown.Sources, unknown.Completed)
	if unknown.Sources != 12 || unknown.Completed != 0 {
		t.Fatalf("sources=%d completed=%d, want 12/0", unknown.Sources, unknown.Completed)
	}

	lookalike := kadEntry("lookalike.avi", 5, 0)
	lookalike.Identity = torrentFile(t).Hash
	lookalike.CatalogId = fmt.Sprintf("ed2k:%X", lookalike.Identity)
	_, err = EntryToFile(lookalike)
	t.Logf("input: a Kad row whose MD4 %x reads as a meta hash; output: err=%v", lookalike.Identity, err)
	if err == nil {
		t.Fatal("a real hash that looks like a meta hash must be refused, or capable clients would read it as a torrent")
	}
}

// torrentFile is a converted torrent row, for a test that needs a genuine meta hash.
func torrentFile(t *testing.T) storage.File {
	t.Helper()
	file, err := EntryToFile(torrentEntry("some.torrent.mkv", 1))
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func TestEntryToFileRejectsBadRows(t *testing.T) {
	noIdentity := torrentEntry("a", 1)
	noIdentity.Identity = nil
	noSize := torrentEntry("b", 1)
	noSize.Size, noSize.TotalSize = 0, 0
	noName := torrentEntry("c", 1)
	noName.Name = " "
	nzbMagnet := nzbEntry("d")
	nzbMagnet.Magnet = "magnet:?xt=urn:btih:00"

	cases := []struct {
		name  string
		entry *metav1.MetaEntry
	}{
		{"no identity", noIdentity},
		{"no size", noSize},
		{"no name", noName},
		{"nzb with magnet", nzbMagnet},
	}
	for _, tc := range cases {
		_, err := EntryToFile(tc.entry)
		t.Logf("input: %s; output: err=%v", tc.name, err)
		if err == nil {
			t.Errorf("%s: accepted a row a client could not use", tc.name)
		}
	}
}

// TestNameSubFiles: a file row of a multi-file release is named "Release - path",
// the whole-set row and a single-file release keep their names.
func TestNameSubFiles(t *testing.T) {
	var entries []*metav1.MetaEntry
	entries = append(entries, packEntries(torrentEntry("Foo.Season.1", 50), "Disc1/S01E01.mkv", "Disc1/S01E02.mkv")...)
	entries = append(entries, packEntries(nzbEntry("Bar.Release.2026"), "bar.part01.rar", "bar.part02.rar")...)
	entries = append(entries, torrentEntry("Single.File.mkv", 5))

	var rows []storage.File
	for _, entry := range entries {
		file, err := EntryToFile(entry)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, file)
	}
	t.Logf("input: %s", fileNames(rows))
	NameSubFiles(rows)
	t.Logf("output: %s", fileNames(rows))

	want := []string{
		"Foo.Season.1",
		"Foo.Season.1 - Disc1/S01E01.mkv",
		"Foo.Season.1 - Disc1/S01E02.mkv",
		"Bar.Release.2026",
		"Bar.Release.2026 - bar.part01.rar",
		"Bar.Release.2026 - bar.part02.rar",
		"Single.File.mkv",
	}
	for i, name := range want {
		if rows[i].Name != name {
			t.Fatalf("row %d named %q, want %q", i, rows[i].Name, name)
		}
	}
}
