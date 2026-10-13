package ed2k

import (
	"testing"

	"enode/storage"
)

// A client that holds the whole file signals it with the (id, port) sentinel
// pair 0xFBFBFBFB/0xFBFB. Separately, the "completesources" tag is its count of
// *other* complete sources it knows about — commonly 0, which is legal and says
// nothing about the sender.
//
// Letting that tag win meant `complete sentinel + completesources=0` recorded
// the source as incomplete, so a file whose only seeder was that client showed
// as having no complete source at all.
func TestFileFromRecordCompleteMarkerWinsOverTag(t *testing.T) {
	info := storage.ClientInfo{ID: 0x0100007F, Port: 4662}

	cases := []struct {
		name          string
		complete      bool
		tags          map[string]any
		wantCompleted uint32
	}{
		{
			"complete sentinel with completesources=0",
			true,
			map[string]any{"name": "movie.avi", "completesources": uint64(0)},
			1,
		},
		{
			"complete sentinel with no tag at all",
			true,
			map[string]any{"name": "movie.avi"},
			1,
		},
		{
			"complete sentinel with a large completesources",
			true,
			map[string]any{"name": "movie.avi", "completesources": uint64(42)},
			1,
		},
		{
			// A client without the whole file cannot mark itself complete, no
			// matter what count it reports for others.
			"incomplete source claiming many complete sources",
			false,
			map[string]any{"name": "movie.avi", "completesources": uint64(99)},
			0,
		},
		{
			"incomplete source with no tag",
			false,
			map[string]any{"name": "movie.avi"},
			0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := recordWithTags(FileRecord{
				Hash:     []byte("0123456789abcdef"),
				Size:     1024,
				Complete: tc.complete,
			}, tc.tags)
			file := fileFromRecord(record, info)

			t.Logf("input: completeSentinel=%t tags=%v", tc.complete, tc.tags)
			t.Logf("output: File.Completed=%d (want %d)", file.Completed, tc.wantCompleted)

			if file.Completed != tc.wantCompleted {
				t.Fatalf("Completed=%d, want %d", file.Completed, tc.wantCompleted)
			}
		})
	}
}

// The sentinel itself is decoded in GetFileList, so pin the wire encoding too:
// a record carrying the complete pair must arrive with Complete set, and the
// partial pair must clear it.
func TestGetFileListCompleteSentinelRoundTrip(t *testing.T) {
	cases := []struct {
		name         string
		id           uint32
		port         uint16
		wantComplete bool
	}{
		{"complete sentinel", ValCompleteID, ValCompletePort, true},
		{"partial sentinel", ValPartialID, ValPartialPort, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := NewBuffer(4 + 16 + 4 + 2 + 4)
			_ = buf.PutUInt32LE(1) // one file record
			_ = buf.PutHash([]byte("0123456789abcdef"))
			_ = buf.PutUInt32LE(tc.id)
			_ = buf.PutUInt16LE(tc.port)
			_ = buf.PutUInt32LE(0) // no tags
			buf.Pos(0)

			files, err := buf.GetFileList()
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 1 {
				t.Fatalf("got %d records, want 1", len(files))
			}
			t.Logf("input: id=0x%08x port=0x%04x -> output: Complete=%t", tc.id, tc.port, files[0].Complete)

			if files[0].Complete != tc.wantComplete {
				t.Fatalf("Complete=%t, want %t", files[0].Complete, tc.wantComplete)
			}
		})
	}
}
