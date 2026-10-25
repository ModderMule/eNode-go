package meta

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"enode/storage"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
)

// heapGrowth is the live heap build adds, with the value kept alive until measured.
func heapGrowth(build func() any) (int64, any) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	v := build()
	runtime.GC()
	runtime.ReadMemStats(&after)
	return int64(after.HeapAlloc) - int64(before.HeapAlloc), v
}

// checkEstimate fails when the estimate is off the measured heap by more than 2×.
func checkEstimate(t *testing.T, what string, estimate, measured int64) {
	t.Helper()
	ratio := float64(estimate) / float64(measured)
	t.Logf("input: %s; output: estimate=%d measured=%d ratio=%.2f", what, estimate, measured, ratio)
	if ratio < 0.5 || ratio > 2 {
		t.Fatalf("%s: estimate %d is %.2f× the measured %d, want within 0.5-2×", what, estimate, ratio, measured)
	}
}

func TestFileRowsBytesTracksHeap(t *testing.T) {
	const n = 10000
	var rows []storage.File
	measured, keep := heapGrowth(func() any {
		rows = make([]storage.File, n)
		for i := range rows {
			rows[i] = storage.File{
				Hash: make([]byte, 16),
				Name: fmt.Sprintf("Some.Release.Name.%06d.1080p.WEB-DL.x264-GROUP.mkv", i),
				Type: "Video",
				Meta: &storage.MetaInfo{
					Kind:      1,
					CatalogID: fmt.Sprintf("catalog-%08d", i),
					Indexer:   "indexer" + strings.Repeat("x", i%8),
					Magnet:    "magnet:?xt=urn:btih:" + strings.Repeat("a", 40),
				},
			}
		}
		return rows
	})
	checkEstimate(t, fmt.Sprintf("%d meta rows", n), FileRowsBytes(rows), measured)
	runtime.KeepAlive(keep)
}

func TestChunkBytesTracksHeap(t *testing.T) {
	const chunks = 200
	var all []Chunk
	measured, keep := heapGrowth(func() any {
		all = make([]Chunk, chunks)
		for c := range all {
			releases := make([]Release, ChunkSize)
			for r := range releases {
				release := make(Release, 3)
				for e := range release {
					release[e] = &metav1.MetaEntry{
						MetaHash:  make([]byte, 16),
						Kind:      metav1.MetaKind(1),
						FilePath:  fmt.Sprintf("Release.%d.%d/file%d.mkv", c, r, e),
						Name:      fmt.Sprintf("Some.Release.Name.%d.%d.1080p.WEB-DL.x264-GROUP", c, r),
						Type:      "Video",
						Indexer:   "indexer",
						CatalogId: fmt.Sprintf("catalog-%d-%d", c, r),
						Magnet:    "magnet:?xt=urn:btih:" + strings.Repeat("a", 40),
					}
				}
				releases[r] = release
			}
			all[c] = Chunk{Releases: releases, More: true}
		}
		return all
	})
	var estimate int64
	for _, c := range all {
		estimate += ChunkBytes(c)
	}
	checkEstimate(t, fmt.Sprintf("%d chunks × %d releases × 3 entries", chunks, ChunkSize), estimate, measured)
	runtime.KeepAlive(keep)
}
