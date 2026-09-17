package storage

import (
	"strings"
	"testing"
)

func TestNormalizeFileTruncatesToColumnWidths(t *testing.T) {
	cases := []struct {
		name  string
		field string
		in    File
		want  int
	}{
		{"name at varchar(255)", "Name", File{Name: strings.Repeat("a", 400) + ".mp3"}, maxNameLen},
		{"title at varchar(128)", "Title", File{Title: strings.Repeat("t", 300)}, maxTitleLen},
		{"artist at varchar(128)", "Artist", File{Artist: strings.Repeat("r", 300)}, maxArtistLen},
		{"album at varchar(128)", "Album", File{Album: strings.Repeat("l", 300)}, maxAlbumLen},
		{"codec at varchar(32)", "Codec", File{Codec: strings.Repeat("c", 100)}, maxCodecLen},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeFile(tc.in)
			var out string
			switch tc.field {
			case "Name":
				out = got.Name
			case "Title":
				out = got.Title
			case "Artist":
				out = got.Artist
			case "Album":
				out = got.Album
			case "Codec":
				out = got.Codec
			}
			t.Logf("input: %s of %d runes", tc.field, len([]rune(tc.in.Name+tc.in.Title+tc.in.Artist+tc.in.Album+tc.in.Codec)))
			t.Logf("output: %s of %d runes", tc.field, len([]rune(out)))
			if len([]rune(out)) != tc.want {
				t.Fatalf("%s: got %d runes, want %d", tc.field, len([]rune(out)), tc.want)
			}
		})
	}
}

// Truncation is by rune, not byte: MySQL counts varchar in characters, and
// cutting a multi-byte character in half would store invalid UTF-8.
func TestNormalizeFileTruncatesByRuneNotByte(t *testing.T) {
	in := File{Codec: strings.Repeat("日", 100)} // 3 bytes per rune
	got := NormalizeFile(in)
	t.Logf("input: codec of %d runes / %d bytes", len([]rune(in.Codec)), len(in.Codec))
	t.Logf("output: codec of %d runes / %d bytes", len([]rune(got.Codec)), len(got.Codec))

	if len([]rune(got.Codec)) != maxCodecLen {
		t.Fatalf("expected %d runes, got %d", maxCodecLen, len([]rune(got.Codec)))
	}
	if !strings.HasSuffix(got.Codec, "日") {
		t.Fatal("truncation split a multi-byte rune")
	}
}

func TestNormalizeFileTypeMapsToEnum(t *testing.T) {
	cases := []struct {
		name string
		typ  string
		file string
		want string
	}{
		{"enum member is kept", "Audio", "song.mp3", "Audio"},
		{"empty is allowed", "", "song.mp3", ""},
		{"Doc is an enum member", "Doc", "readme.txt", "Doc"},
		// eMule internal values that are not in the ENUM.
		{"Arc maps to Pro", "Arc", "bundle.rar", "Pro"},
		{"Iso maps to Pro", "Iso", "disc.iso", "Pro"},
		// The one eMule sends routinely for collection files.
		{"EmuleCollection falls back to the filename", "EmuleCollection", "pack.mp3", "Audio"},
		{"EmuleCollection with no usable extension", "EmuleCollection", "pack.emulecollection", ""},
		{"an invented type falls back", "TotallyMadeUp", "clip.avi", "Video"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeFile(File{Type: tc.typ, Name: tc.file})
			t.Logf("input: type=%q name=%q", tc.typ, tc.file)
			t.Logf("output: type=%q", got.Type)
			if got.Type != tc.want {
				t.Fatalf("got %q, want %q", got.Type, tc.want)
			}
			if _, ok := enumFileTypes[got.Type]; !ok {
				t.Fatalf("normalized type %q is not an ENUM member", got.Type)
			}
		})
	}
}

// ext is varchar(8), the tightest column. Dropping an over-long extension beats
// truncating it: a clipped value would silently fail to match an "ext =" search.
func TestNormalizeExtDropsOverlongExtensions(t *testing.T) {
	cases := []struct {
		name string
		file string
		want string
	}{
		{"ordinary extension", "movie.avi", "avi"},
		{"exactly 8 characters", "archive.tarballs", "tarballs"},
		{"9 characters is dropped", "archive.tarball12", ""},
		{"the dashed case from the audit", "archive.torrent-part001", ""},
		{"no extension", "README", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeExt(tc.file)
			t.Logf("input: %q (raw ext %q, %d runes)", tc.file, Ext(tc.file), len([]rune(Ext(tc.file))))
			t.Logf("output: %q", got)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if len([]rune(got)) > maxExtLen {
				t.Fatalf("normalized ext exceeds varchar(%d): %q", maxExtLen, got)
			}
		})
	}
}

// GetFileType can only ever produce ENUM members. Recorded so the fallback in
// normalizeFileType stays safe if the classifier gains new categories.
func TestGetFileTypeOnlyProducesEnumMembers(t *testing.T) {
	names := []string{
		"a.avi", "a.mp3", "a.jpg", "a.zip", "a.iso", "a.unknownext", "a", "a.txt",
	}
	for _, n := range names {
		got := GetFileType(n)
		t.Logf("input: %q -> output: %q", n, got)
		if _, ok := enumFileTypes[got]; !ok {
			t.Fatalf("GetFileType(%q) returned %q, which is not an ENUM member", n, got)
		}
	}
}

// prepareOfferBatch is what both DB engines write, so it owns three guarantees at once:
// normalization identical to the per-file path, last-wins on a duplicate key, and an
// order fixed by (hash, size) regardless of the order the client sent.
func TestPrepareOfferBatchNormalizesDedupesAndSorts(t *testing.T) {
	hA := []byte("aaaaaaaaaaaaaaaa")
	hB := []byte("bbbbbbbbbbbbbbbb")
	in := []File{
		{Hash: hB, Size: 10, Name: "clip.avi"},
		{Hash: hA, Size: 20, Name: "first.mp3"},
		// Clamping cuts the extension off, so the type has to come from the alias.
		{Hash: hA, Size: 10, Name: strings.Repeat("n", 300) + ".iso", Type: "Iso"},
		{Hash: hA, Size: 20, Name: "second.mp3", Type: "EmuleCollection"},
	}
	for i, f := range in {
		t.Logf("input[%d]: hash=%c size=%d name=%d runes type=%q", i, f.Hash[0], f.Size, len([]rune(f.Name)), f.Type)
	}

	out := prepareOfferBatch(in)
	for i, f := range out {
		t.Logf("output[%d]: hash=%c size=%d name=%.20q (%d runes) type=%q", i, f.Hash[0], f.Size, f.Name, len([]rune(f.Name)), f.Type)
	}

	want := []struct {
		hash byte
		size uint64
		name string
		typ  string
	}{
		{'a', 10, "", "Pro"},
		{'a', 20, "second.mp3", "Audio"},
		{'b', 10, "clip.avi", "Video"},
	}
	if len(out) != len(want) {
		t.Fatalf("got %d files, want %d — the duplicate a/20 was not collapsed", len(out), len(want))
	}
	for i, w := range want {
		got := out[i]
		if got.Hash[0] != w.hash || got.Size != w.size {
			t.Fatalf("output[%d] is %c/%d, want %c/%d — not sorted by (hash, size)", i, got.Hash[0], got.Size, w.hash, w.size)
		}
		if w.name != "" && got.Name != w.name {
			t.Errorf("output[%d] name %q, want %q — the later duplicate must win", i, got.Name, w.name)
		}
		if got.Type != w.typ {
			t.Errorf("output[%d] type %q, want %q", i, got.Type, w.typ)
		}
	}
	if n := len([]rune(out[0].Name)); n != maxNameLen {
		t.Errorf("name is %d runes, want it clamped to %d", n, maxNameLen)
	}
}
