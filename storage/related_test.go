package storage

import (
	"fmt"
	"slices"
	"testing"
)

// relatedScenario is the related search contract for any engine: the files the
// seed's sharers also share, by how many of them do, nothing below minClients,
// and the seed itself left out.
func relatedScenario(t *testing.T, engine Engine) {
	t.Helper()
	clients := make([]ClientInfo, 7)
	for i := range clients {
		clients[i] = ClientInfo{
			ID: uint32(0x0a000010 + i), IPv4: uint32(0x0400000a + i), Port: uint16(4662 + i),
			Hash: fmt.Appendf(nil, "related-client-%d", i),
		}
		id, err := engine.Connect(clients[i])
		if err != nil {
			t.Fatal(err)
		}
		clients[i].StoreID = id
	}
	seed := []byte("related-seed-001")
	y := []byte("related-yyyy-001")
	z := []byte("related-zzzz-001")
	w := []byte("related-wwww-001")
	// Clients 0-5 share the seed; 0-3 also share Y, 4 shares Z. Client 6 shares W
	// but not the seed, so W is unrelated.
	for i := 0; i < 6; i++ {
		engine.AddFile(File{Hash: seed, Name: "relseed.avi", Size: 10, Type: "Video"}, clients[i])
	}
	for i := 0; i < 4; i++ {
		engine.AddFile(File{Hash: y, Name: "relyyy.avi", Size: 20, Type: "Video"}, clients[i])
	}
	engine.AddFile(File{Hash: z, Name: "relzzz.mp3", Size: 30, Type: "Audio"}, clients[4])
	engine.AddFile(File{Hash: w, Name: "relwww.iso", Size: 40, Type: "Pro"}, clients[6])

	names := func(files []File) []string {
		out := make([]string, 0, len(files))
		for _, f := range files {
			out = append(out, fmt.Sprintf("%s/%d sources=%d", f.Name, f.Size, f.Sources))
		}
		return out
	}
	check := func(what string, got []File, want ...string) {
		t.Helper()
		g := names(got)
		t.Logf("input: %s -> output: %v", what, g)
		if want == nil {
			want = []string{}
		}
		if !slices.Equal(g, want) {
			t.Fatalf("%s: got %v, want %v", what, g, want)
		}
	}

	check("related::seed, minClients 5", engine.RelatedFiles([]FileKey{{Hash: seed}}, 5, 500),
		"relyyy.avi/20 sources=4", "relzzz.mp3/30 sources=1")
	check("related:10:seed, minClients 5", engine.RelatedFiles([]FileKey{{Hash: seed, Size: 10}}, 5, 500),
		"relyyy.avi/20 sources=4", "relzzz.mp3/30 sources=1")
	check("related:99:seed (no such size)", engine.RelatedFiles([]FileKey{{Hash: seed, Size: 99}}, 1, 500))
	check("related::seed, minClients 7", engine.RelatedFiles([]FileKey{{Hash: seed}}, 7, 500))
	check("related::W, minClients 1", engine.RelatedFiles([]FileKey{{Hash: w}}, 1, 500))
	check("related::Y::Z, minClients 5", engine.RelatedFiles([]FileKey{{Hash: y}, {Hash: z}}, 5, 500),
		"relseed.avi/10 sources=6")
	check("no seeds", engine.RelatedFiles(nil, 1, 500))

	// After a disconnect only the names are compared: the SQL and MongoDB engines
	// keep a file's source counter until the cleanup sweep.
	checkNames := func(what string, got []File, want ...string) {
		t.Helper()
		g := make([]string, 0, len(got))
		for _, f := range got {
			g = append(g, f.Name)
		}
		t.Logf("input: %s -> output: %v", what, g)
		if want == nil {
			want = []string{}
		}
		if !slices.Equal(g, want) {
			t.Fatalf("%s: got %v, want %v", what, g, want)
		}
	}
	engine.Disconnect(clients[4])
	checkNames("client 4 left, minClients 5", engine.RelatedFiles([]FileKey{{Hash: seed}}, 5, 500), "relyyy.avi")
	engine.Disconnect(clients[3])
	checkNames("client 3 left too, 4 sharers < minClients 5", engine.RelatedFiles([]FileKey{{Hash: seed}}, 5, 500))
	checkNames("4 sharers, minClients 4", engine.RelatedFiles([]FileKey{{Hash: seed}}, 4, 500), "relyyy.avi")
}

func TestMemoryRelatedFiles(t *testing.T) {
	relatedScenario(t, NewMemoryEngine())
}

func TestMySQLRelatedFiles(t *testing.T) {
	requireIntegration(t)
	engine, _ := startMySQL(t, "enode")
	relatedScenario(t, engine)
}

func TestMariaDBRelatedFiles(t *testing.T) {
	requireIntegration(t)
	relatedScenario(t, startMariaDB(t, "enode"))
}

func TestMongoRelatedFiles(t *testing.T) {
	requireIntegration(t)
	relatedScenario(t, startMongoEngine(t, "enode_related"))
}

// TestMemoryRelatedFilesMaxClients checks the walk stops at maxClients users: with
// one user walked, no file can weigh more than one.
func TestMemoryRelatedFilesMaxClients(t *testing.T) {
	m := NewMemoryEngine()
	seed := []byte("related-cap-seed")
	other := []byte("related-cap-othr")
	for i := range 3 {
		c := ClientInfo{ID: uint32(0x0b000010 + i), IPv4: uint32(0x0500000a + i), Port: 4662, Hash: fmt.Appendf(nil, "related-capcl-%02d", i)}
		id, _ := m.Connect(c)
		c.StoreID = id
		m.AddFile(File{Hash: seed, Name: "capseed.avi", Size: 1}, c)
		m.AddFile(File{Hash: other, Name: "capother.avi", Size: 2}, c)
	}
	got := m.RelatedFiles([]FileKey{{Hash: seed}}, 1, 1)
	t.Logf("input: 3 sharers, maxClients 1 -> output: %d file(s)", len(got))
	if len(got) != 1 || got[0].Name != "capother.avi" {
		t.Fatalf("got %v", got)
	}
	// maxClients below minClients is raised to it: the floor still counts.
	got = m.RelatedFiles([]FileKey{{Hash: seed}}, 3, 1)
	t.Logf("input: 3 sharers, minClients 3, maxClients 1 -> output: %d file(s)", len(got))
	if len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestManticoreRelatedFiles(t *testing.T) {
	requireIntegration(t)
	relatedScenario(t, wrapManticore(t, startMariaDB(t, "enode"), startManticore(t)))
}
