package storage

import (
	"fmt"
	"sort"
	"testing"
)

func TestMemoryEngineClientAndFiles(t *testing.T) {
	m := NewMemoryEngine()
	_ = m.Init()
	c := ClientInfo{ID: 1, Port: 4662}
	if m.IsConnected(c) {
		t.Fatalf("should be disconnected")
	}
	if _, err := m.Connect(c); err != nil {
		t.Fatal(err)
	}
	if !m.IsConnected(c) || m.ClientsCount() != 1 {
		t.Fatalf("connect failed")
	}

	hash := []byte("0123456789abcdef")
	m.AddFile(File{
		Hash: hash, Name: "movie.mkv", Size: 100, SourceID: 1, SourcePort: 4662,
	}, c)
	if m.FilesCount() != 1 {
		t.Fatalf("files count mismatch")
	}
	if len(m.GetSources(hash, 100)) != 1 {
		t.Fatalf("sources mismatch")
	}
	if len(m.FindByNameContains("movie")) != 1 {
		t.Fatalf("find mismatch")
	}
	m.Disconnect(c)
	if m.ClientsCount() != 0 {
		t.Fatalf("disconnect failed")
	}
	if len(m.GetSources(hash, 100)) != 0 {
		t.Fatalf("disconnect should remove client sources from OP_GETSOURCES result")
	}
}

// AddFiles is specified as AddFile applied to each file in order. The memory engine
// is the reference the DB engines' batched writes are held to, so it must meet that
// contract exactly — including a duplicate (hash, size) inside one batch, where the
// later record wins, and one hash at two sizes, which are two files.
func TestMemoryAddFilesMatchesAddFile(t *testing.T) {
	h1 := []byte("1111111111111111")
	h2 := []byte("2222222222222222")
	offer := []File{
		{Hash: h1, Size: 100, Name: "first.avi"},
		{Hash: h1, Size: 200, Name: "other-size.avi"},
		{Hash: h2, Size: 300, Name: "song.mp3", Type: "Audio"},
		{Hash: h1, Size: 100, Name: "renamed.avi"},
	}
	client := ClientInfo{ID: 7, Port: 4662, Hash: []byte("cccccccccccccccc"), CryptOptions: 0x03}
	t.Logf("input: %d records (one duplicate of h1/100), client id=%d port=%d", len(offer), client.ID, client.Port)

	sequential := NewMemoryEngine()
	for _, f := range offer {
		sequential.AddFile(f, client)
	}
	batched := NewMemoryEngine()
	batched.AddFiles(offer, client)

	describe := func(m *MemoryEngine) []string {
		var out []string
		for _, f := range m.FindByNameContains("") {
			out = append(out, fmt.Sprintf("%x/%d name=%s type=%s sources=%d",
				f.Hash[:2], f.Size, f.Name, f.Type, len(m.GetSources(f.Hash, f.Size))))
		}
		sort.Strings(out)
		return out
	}
	want, got := describe(sequential), describe(batched)
	t.Logf("output: sequential=%q", want)
	t.Logf("output: batched=%q", got)

	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("AddFiles stored %q, AddFile in order stored %q", got, want)
	}
	if batched.FilesCount() != 3 {
		t.Fatalf("stored %d files, want 3 — h1 at two sizes is two files, the duplicate is one", batched.FilesCount())
	}
	for _, f := range batched.FindByNameContains("") {
		if string(f.Hash) == string(h1) && f.Size == 100 && f.Name != "renamed.avi" {
			t.Fatalf("h1/100 is named %q, want the later record's %q", f.Name, "renamed.avi")
		}
	}
}
