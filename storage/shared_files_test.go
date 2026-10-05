package storage

import (
	"fmt"
	"slices"
	"testing"
)

// sharedFilesScenario is SharedFiles' contract, for any engine: the files with one
// of the hashes that an online client offers, each size on its own, and nothing for
// a hash whose only offerer has gone or that nobody ever offered.
func sharedFilesScenario(t *testing.T, engine Engine) {
	t.Helper()
	a := ClientInfo{ID: 0x0a000002, IPv4: 0x0200000a, Port: 4662, Hash: []byte("shared-files-a-1")}
	b := ClientInfo{ID: 0x0b000002, IPv4: 0x0200000b, Port: 4663, Hash: []byte("shared-files-b-1")}
	c := ClientInfo{ID: 0x0c000002, IPv4: 0x0200000c, Port: 4664, Hash: []byte("shared-files-c-1")}
	for _, client := range []*ClientInfo{&a, &b, &c} {
		id, err := engine.Connect(*client)
		if err != nil {
			t.Fatal(err)
		}
		client.StoreID = id
	}

	both := []byte("shared-by-both-1")
	sizes := []byte("shared-two-sizes")
	left := []byte("shared-then-left")
	never := []byte("shared-by-nobody")

	engine.AddFile(File{Hash: both, Name: "sharedboth.iso", Size: 10, Type: "Pro"}, a)
	engine.AddFile(File{Hash: both, Name: "sharedboth.iso", Size: 10, Type: "Pro"}, b)
	engine.AddFile(File{Hash: sizes, Name: "sharedsmall.iso", Size: 100, Type: "Pro"}, a)
	engine.AddFile(File{Hash: sizes, Name: "sharedlarge.iso", Size: 200, Type: "Pro"}, b)
	engine.AddFile(File{Hash: left, Name: "sharedleft.iso", Size: 30, Type: "Pro"}, c)
	engine.Disconnect(c)

	list := func(files []File) []string {
		out := make([]string, 0, len(files))
		for _, f := range files {
			out = append(out, fmt.Sprintf("%s/%d sources=%d", f.Name, f.Size, f.Sources))
		}
		slices.Sort(out)
		return out
	}

	got := list(engine.SharedFiles([][]byte{both, sizes, left, never}))
	t.Logf("input:  one file from two clients, one hash at two sizes, one file whose client left, one hash never offered")
	t.Logf("output: %v", got)

	want := []string{"sharedboth.iso/10 sources=2", "sharedlarge.iso/200 sources=1", "sharedsmall.iso/100 sources=1"}
	if !slices.Equal(got, want) {
		t.Fatalf("shared files %v, want %v", got, want)
	}

	engine.Disconnect(b)

	after := engine.SharedFiles([][]byte{both, sizes})
	names := make([]string, 0, len(after))
	for _, f := range after {
		names = append(names, f.Name)
	}
	slices.Sort(names)
	t.Logf("input:  the second client leaves")
	t.Logf("output: %v", names)

	if !slices.Equal(names, []string{"sharedboth.iso", "sharedsmall.iso"}) {
		t.Fatalf("after the second client left the shared files are %v, want the two the first still offers", names)
	}

	if none := engine.SharedFiles(nil); len(none) != 0 {
		t.Fatalf("no hashes asked about, %d file(s) answered", len(none))
	}
}

func TestMemorySharedFiles(t *testing.T) {
	sharedFilesScenario(t, NewMemoryEngine())
}

func TestMySQLSharedFiles(t *testing.T) {
	requireIntegration(t)
	engine, _ := startMySQL(t, "enode")
	sharedFilesScenario(t, engine)
}

func TestMongoSharedFiles(t *testing.T) {
	requireIntegration(t)
	sharedFilesScenario(t, startMongoEngine(t, "enode_shared_files"))
}
