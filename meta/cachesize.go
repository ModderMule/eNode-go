package meta

import (
	"unsafe"

	"enode/storage"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
)

// The sizers below estimate the heap bytes a cached value keeps alive: struct sizes
// plus the backing arrays of its strings and byte slices. They ignore allocator
// rounding and strings shared with other values, so they undercount slightly;
// meta/cachesize_test.go pins them against a measured heap.
const (
	fileRowSize   = int64(unsafe.Sizeof(storage.File{}))
	metaInfoSize  = int64(unsafe.Sizeof(storage.MetaInfo{}))
	metaEntrySize = int64(unsafe.Sizeof(metav1.MetaEntry{}))
	releaseSize   = int64(unsafe.Sizeof(Release{}))
	pointerSize   = int64(unsafe.Sizeof(uintptr(0)))
)

// FileRowsBytes estimates the bytes rows hold, for the eD2K meta search cache.
func FileRowsBytes(rows []storage.File) int64 {
	n := int64(cap(rows)) * fileRowSize
	for i := range rows {
		f := &rows[i]
		n += int64(cap(f.Hash) + len(f.Name) + len(f.Type) + len(f.Title) + len(f.Artist) + len(f.Album) + len(f.Codec))
		if m := f.Meta; m != nil {
			n += metaInfoSize + int64(len(m.FilePath)+len(m.CatalogID)+len(m.Indexer)+len(m.Magnet))
		}
	}
	return n
}

// ChunkBytes estimates the bytes a catalogue chunk holds, for the MetaApi.Search cache.
func ChunkBytes(chunk Chunk) int64 {
	n := int64(cap(chunk.Releases)) * releaseSize
	for _, release := range chunk.Releases {
		n += int64(cap(release)) * pointerSize
		for _, e := range release {
			n += metaEntryBytes(e)
		}
	}
	return n
}

func metaEntryBytes(e *metav1.MetaEntry) int64 {
	if e == nil {
		return 0
	}
	return metaEntrySize + int64(cap(e.MetaHash)+cap(e.Identity)+len(e.FilePath)+len(e.Name)+
		len(e.Type)+len(e.Indexer)+len(e.CatalogId)+len(e.Magnet))
}
