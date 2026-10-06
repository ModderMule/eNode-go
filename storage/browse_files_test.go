package storage

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

// browseFilesScenario is BrowseFiles' contract, for any engine: a walk in small
// pages returns every file an online client offers exactly once, names no source,
// leaves out a file whose only offerer has gone, and ends with a nil cursor.
func browseFilesScenario(t *testing.T, engine Engine) {
	t.Helper()
	a := ClientInfo{ID: 0x0a000003, IPv4: 0x0300000a, Port: 4662, Hash: []byte("browse-files-a-1")}
	b := ClientInfo{ID: 0x0b000003, IPv4: 0x0300000b, Port: 4663, Hash: []byte("browse-files-b-1")}
	c := ClientInfo{ID: 0x0c000003, IPv4: 0x0300000c, Port: 4664, Hash: []byte("browse-files-c-1")}
	for _, client := range []*ClientInfo{&a, &b, &c} {
		id, err := engine.Connect(*client)
		if err != nil {
			t.Fatal(err)
		}
		client.StoreID = id
	}

	const n = 23
	var want []string
	for i := range n {
		hash := []byte(fmt.Sprintf("browse-file-%04d", i))
		name := fmt.Sprintf("browsed%04d.iso", i)
		engine.AddFile(File{Hash: hash, Name: name, Size: uint64(1000 + i), Type: "Pro"}, a)
		sources := 1
		if i%2 == 0 {
			engine.AddFile(File{Hash: hash, Name: name, Size: uint64(1000 + i), Type: "Pro"}, b)
			sources = 2
		}
		want = append(want, fmt.Sprintf("%s/%d sources=%d", name, 1000+i, sources))
	}
	engine.AddFile(File{Hash: []byte("browse-file-left"), Name: "browsedleft.iso", Size: 30, Type: "Pro"}, c)
	engine.Disconnect(c)

	walk := func(limit int) (got []string, pages int) {
		var cursor []byte
		for {
			files, next, err := engine.BrowseFiles(cursor, limit)
			if err != nil {
				t.Fatalf("browse page %d: %v", pages, err)
			}
			pages++
			if len(files) > limit {
				t.Fatalf("page %d holds %d files, limit %d", pages, len(files), limit)
			}
			for _, f := range files {
				if f.SourceID != 0 || f.SourcePort != 0 {
					t.Fatalf("%s names a source: id=%d port=%d", f.Name, f.SourceID, f.SourcePort)
				}
				got = append(got, fmt.Sprintf("%s/%d sources=%d", f.Name, f.Size, f.Sources))
			}
			if next == nil {
				break
			}
			if pages > 10*n {
				t.Fatal("the walk does not end")
			}
			cursor = next
		}
		slices.Sort(got)
		return got, pages
	}

	for _, limit := range []int{5, 23, 1000} {
		got, pages := walk(limit)
		t.Logf("input:  %d files from two clients and one whose client left, pages of %d", n, limit)
		t.Logf("output: %d files in %d page(s)", len(got), pages)

		if !slices.Equal(got, want) {
			t.Fatalf("pages of %d: walked %v, want %v", limit, got, want)
		}
	}

	_, _, err := engine.BrowseFiles([]byte("not a cursor"), 5)
	t.Logf("input:  a cursor the engine did not issue")
	t.Logf("output: %v", err)
	if !errors.Is(err, ErrBrowseCursor) {
		t.Fatalf("a foreign cursor answered %v, want ErrBrowseCursor", err)
	}
}

func TestMemoryBrowseFiles(t *testing.T) {
	browseFilesScenario(t, NewMemoryEngine())
}

func TestMySQLBrowseFiles(t *testing.T) {
	requireIntegration(t)
	engine, _ := startMySQL(t, "enode")
	browseFilesScenario(t, engine)
}

func TestMongoBrowseFiles(t *testing.T) {
	requireIntegration(t)
	browseFilesScenario(t, startMongoEngine(t, "enode_browse_files"))
}

// TestMemoryBrowseFilesCursorDiesWithTheLayout pins why the memory engine's cursor
// carries the layout: rebuilding the index renumbers the records, so a walk that
// went on from its old position would skip the files that moved below it.
func TestMemoryBrowseFilesCursorDiesWithTheLayout(t *testing.T) {
	engine := NewMemoryEngine()
	client := ClientInfo{ID: 0x0a000004, IPv4: 0x0400000a, Port: 4662, Hash: []byte("browse-layout-a1")}
	id, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = id
	for i := range 10 {
		engine.AddFile(File{Hash: []byte(fmt.Sprintf("browse-lay-%05d", i)), Name: fmt.Sprintf("layout%d.iso", i), Size: 50}, client)
	}

	files, cursor, err := engine.BrowseFiles(nil, 4)
	if err != nil || len(files) != 4 || cursor == nil {
		t.Fatalf("first page: %d files, cursor %v, err %v", len(files), cursor, err)
	}

	engine.mu.Lock()
	engine.rebuildIndexLocked()
	engine.mu.Unlock()

	_, _, err = engine.BrowseFiles(cursor, 4)
	t.Logf("input:  a cursor from before the index was rebuilt")
	t.Logf("output: %v", err)
	if !errors.Is(err, ErrBrowseCursor) {
		t.Fatalf("a cursor from an older layout answered %v, want ErrBrowseCursor", err)
	}

	files, _, err = engine.BrowseFiles(nil, 100)
	t.Logf("input:  a walk restarted from the beginning")
	t.Logf("output: %d files, err %v", len(files), err)
	if err != nil || len(files) != 10 {
		t.Fatalf("restarted walk: %d files, err %v, want all 10", len(files), err)
	}
}
