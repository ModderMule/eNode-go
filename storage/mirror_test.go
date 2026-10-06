package storage

import (
	"fmt"
	"slices"
	"testing"
)

func mirrorFile(i int, name string, sources uint32) File {
	return File{Hash: []byte(fmt.Sprintf("mirror-hash-%04d", i)), Name: name, Size: uint64(100 + i), Sources: sources, Completed: sources / 2}
}

func mirrorNames(files []File) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, fmt.Sprintf("%s sources=%d", f.Name, f.Sources))
	}
	slices.Sort(out)
	return out
}

func mirrorQuery(text string) *SearchExpr {
	return &SearchExpr{Kind: SearchText, Text: text}
}

// TestMirrorSweepIsHowAFileLeaves: a file stays through a walk that does not see
// it until that walk completes, and a file two origins report stays until both
// have dropped it.
func TestMirrorSweepIsHowAFileLeaves(t *testing.T) {
	m := NewMirror(100)
	m.Put(1, 1, []File{mirrorFile(1, "ubuntu.server.iso", 4), mirrorFile(2, "ubuntu.desktop.iso", 2), mirrorFile(3, "debian.netinst.iso", 1)})
	m.Put(2, 1, []File{mirrorFile(2, "ubuntu.desktop.iso", 9)})

	got := mirrorNames(m.Search(mirrorQuery("ubuntu"), 10))
	t.Logf("input:  origin 1 reports three files, origin 2 one of them with more sources")
	t.Logf("output: %v", got)
	want := []string{"ubuntu.desktop.iso sources=9", "ubuntu.server.iso sources=4"}
	if !slices.Equal(got, want) {
		t.Fatalf("search = %v, want %v: counts take the larger, never the sum", got, want)
	}

	// Walk 2 of origin 1 sees only the server image.
	m.Put(1, 2, []File{mirrorFile(1, "ubuntu.server.iso", 5)})
	before := m.Len()
	removed := m.Sweep(1, 2)
	got = mirrorNames(m.Search(mirrorQuery("iso"), 10))
	t.Logf("input:  origin 1's next walk sees one file; %d files before its sweep", before)
	t.Logf("output: %d removed, left %v", removed, got)
	want = []string{"ubuntu.desktop.iso sources=9", "ubuntu.server.iso sources=5"}
	if before != 3 || removed != 1 || !slices.Equal(got, want) {
		t.Fatalf("before=%d removed=%d left=%v, want 3, 1, %v", before, removed, got, want)
	}

	removed = m.Drop(2)
	got = mirrorNames(m.Search(mirrorQuery("iso"), 10))
	t.Logf("input:  origin 2 is dropped")
	t.Logf("output: %d removed, left %v", removed, got)
	if removed != 1 || !slices.Equal(got, []string{"ubuntu.server.iso sources=5"}) {
		t.Fatalf("removed=%d left=%v", removed, got)
	}

	// The freed ids are reused, and must not answer for the words of the files
	// that held them.
	m.Put(3, 1, []File{mirrorFile(7, "fedora.workstation.iso", 3), mirrorFile(8, "arch.linux.iso", 3)})
	if got := m.Search(mirrorQuery("debian"), 10); len(got) != 0 {
		t.Errorf("a reused id still answers for a removed file's name: %v", mirrorNames(got))
	}
	if got := mirrorNames(m.Search(mirrorQuery("fedora"), 10)); !slices.Equal(got, []string{"fedora.workstation.iso sources=3"}) {
		t.Errorf("new file not found: %v", got)
	}
	t.Logf("output: %d files, origin 3 holds %d", m.Len(), m.OriginFiles(3))
	if m.Len() != 3 || m.OriginFiles(3) != 2 || m.OriginFiles(2) != 0 {
		t.Errorf("len=%d origin3=%d origin2=%d", m.Len(), m.OriginFiles(3), m.OriginFiles(2))
	}
}

// TestMirrorIsBoundedAndKeepsNoSource: the cap holds, a file already held is
// still updated at the cap, and nothing that names a source is kept.
func TestMirrorIsBoundedAndKeepsNoSource(t *testing.T) {
	m := NewMirror(2)
	leaky := mirrorFile(1, "first.file.iso", 1)
	leaky.SourceID, leaky.SourcePort, leaky.Meta = 0x0a000001, 4662, &MetaInfo{CatalogID: "x"}
	taken := m.Put(1, 1, []File{leaky, mirrorFile(2, "second.file.iso", 1), mirrorFile(3, "third.file.iso", 1)})
	t.Logf("input:  three files into a mirror of two, the first naming a source")
	t.Logf("output: %d taken, %d held", taken, m.Len())
	if taken != 2 || m.Len() != 2 {
		t.Fatalf("taken=%d len=%d, want 2 and 2", taken, m.Len())
	}

	taken = m.Put(1, 2, []File{mirrorFile(1, "first.renamed.iso", 6), mirrorFile(4, "fourth.file.iso", 1)})
	got := m.Search(mirrorQuery("renamed"), 10)
	t.Logf("input:  at the cap, an update of a held file and a new file")
	t.Logf("output: %d taken, found %v", taken, mirrorNames(got))
	if taken != 1 || len(got) != 1 || got[0].Sources != 6 {
		t.Fatalf("taken=%d got=%v", taken, mirrorNames(got))
	}
	if f := got[0]; f.SourceID != 0 || f.SourcePort != 0 || f.Meta != nil {
		t.Errorf("the mirror kept a source: id=%d port=%d meta=%v", f.SourceID, f.SourcePort, f.Meta)
	}
	if old := m.Search(mirrorQuery("first.file"), 10); len(old) != 0 {
		t.Errorf("the old name still matches: %v", mirrorNames(old))
	}
}
