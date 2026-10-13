package ed2k

import (
	"testing"
)

// tagMap returns a decoded record's tags by name, the way a record used to carry
// them: the fields that are set, and everything in Extra. Tests read search results
// through it, where most of what they check is a tag with no field.
func (r FileRecord) tagMap() map[string]any {
	tags := make(map[string]any, len(r.Extra)+4)
	for _, t := range r.Extra {
		tags[t.Name] = t.Value
	}
	for name, value := range map[string]string{
		"name": r.Name, "type": r.Type, "title": r.Title, "artist": r.Artist, "album": r.Album, "codec": r.Codec,
	} {
		if value != "" {
			tags[name] = value
		}
	}
	for name, value := range map[string]uint32{"sources": r.Sources, "length": r.Length, "bitrate": r.Bitrate} {
		if value != 0 {
			tags[name] = uint64(value)
		}
	}
	return tags
}

// recordWithTags returns record with tags applied as the decoder applies them.
func recordWithTags(record FileRecord, tags map[string]any) FileRecord {
	for name, value := range tags {
		if !record.SetTag(name, value) {
			record.Extra = append(record.Extra, NamedTag{Name: name, Value: value})
		}
	}
	return record
}

// A record's fields must hold exactly what a lookup in the old tag map gave: the
// last tag of a name wins, and one of the wrong type reads as absent.
func TestFileRecordSetTagMatchesMapSemantics(t *testing.T) {
	cases := []struct {
		name string
		tags []NamedTag
		want FileRecord
	}{
		{"plain", []NamedTag{{Name: "name", Value: "a.avi"}, {Name: "size", Value: uint64(7)}, {Name: "bitrate", Value: uint64(128)}},
			FileRecord{Name: "a.avi", Size: 7, SizeLo: 7, Bitrate: 128}},
		{"last name wins", []NamedTag{{Name: "name", Value: "a.avi"}, {Name: "name", Value: "b.avi"}},
			FileRecord{Name: "b.avi"}},
		{"a later non-string name clears it", []NamedTag{{Name: "name", Value: "a.avi"}, {Name: "name", Value: uint64(1)}},
			FileRecord{}},
		{"sizehi before size", []NamedTag{{Name: "sizehi", Value: uint64(1)}, {Name: "size", Value: uint64(5)}},
			FileRecord{Size: 0x100000005, SizeLo: 5, SizeHi: 1}},
		{"a string size is no size", []NamedTag{{Name: "size", Value: "12"}},
			FileRecord{}},
		{"oversized count saturates", []NamedTag{{Name: "sources", Value: uint64(1) << 40}},
			FileRecord{Sources: 0xffffffff}},
		{"a string length reads as zero", []NamedTag{{Name: "length", Value: "3:21"}},
			FileRecord{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got FileRecord
			for _, tag := range tc.tags {
				if !got.SetTag(tag.Name, tag.Value) {
					t.Fatalf("tag %q has no field", tag.Name)
				}
			}
			t.Logf("input: tags=%v", tc.tags)
			t.Logf("output: name=%q size=%d lo=%d hi=%d sources=%d length=%d bitrate=%d",
				got.Name, got.Size, got.SizeLo, got.SizeHi, got.Sources, got.Length, got.Bitrate)
			if got.Name != tc.want.Name || got.Size != tc.want.Size || got.SizeLo != tc.want.SizeLo ||
				got.SizeHi != tc.want.SizeHi || got.Sources != tc.want.Sources || got.Length != tc.want.Length ||
				got.Bitrate != tc.want.Bitrate {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
	var other FileRecord
	if other.SetTag("completesources", uint64(3)) {
		t.Fatal("a tag without a field was reported as stored")
	}
}

// GetOfferedFiles is GetFileList without the tags nothing reads.
func TestGetOfferedFilesDropsExtraTags(t *testing.T) {
	tags := []Tag{
		{Type: TypeString, Code: TagName, Data: "movie.mkv"},
		{Type: TypeUint32, Code: TagSize, Data: uint32(9)},
		{Type: TypeUint32, Code: 0x30, Data: uint32(4)},
	}
	hash := []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	full, err := encodeFileList(t, hash, tags).GetFileList()
	if err != nil {
		t.Fatal(err)
	}
	offered, err := encodeFileList(t, hash, tags).GetOfferedFiles()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: one record with name, size and tag 0x30")
	t.Logf("output: GetFileList name=%q size=%d extra=%v; GetOfferedFiles name=%q size=%d extra=%v",
		full[0].Name, full[0].Size, full[0].Extra, offered[0].Name, offered[0].Size, offered[0].Extra)
	if len(full[0].Extra) != 1 || full[0].Tag("0x30") != uint64(4) {
		t.Fatalf("GetFileList lost the tag without a field: %v", full[0].Extra)
	}
	if len(offered[0].Extra) != 0 {
		t.Fatalf("GetOfferedFiles kept %v", offered[0].Extra)
	}
	if offered[0].Name != full[0].Name || offered[0].Size != full[0].Size || offered[0].Complete != full[0].Complete {
		t.Fatalf("the two decoders disagree: %+v vs %+v", offered[0], full[0])
	}
}
