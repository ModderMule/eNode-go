package meta

import (
	"fmt"

	"enode/storage"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/metahash"
	"github.com/ModderMule/enodemeta/model"
	"github.com/ModderMule/enodemeta/pbconv"
	"github.com/ModderMule/enodemeta/tags"
)

// EntryToFile turns one daemon row into a search result. The daemon supplies the
// identity and the server mints the 16-byte pseudo-hash — hash construction lives in
// enodemeta alone, so a daemon cannot put a malformed or colliding hash on the wire.
//
// The result carries no source address (0/0, which eMule records as "no source") and
// its unprefixed name; the network's prefix is applied when the row is sent, so the
// prefix itself can never match a keyword.
func EntryToFile(pb *metav1.MetaEntry) (storage.File, error) {
	entry, err := mint(pb)
	if err != nil {
		return storage.File{}, err
	}
	parsed, err := metahash.Parse(entry.MetaHash)
	if err != nil {
		return storage.File{}, fmt.Errorf("minted hash does not parse: %w", err)
	}

	size := entry.Size
	if size == 0 {
		size = entry.TotalSize
	}
	if size == 0 {
		// eMule discards a zero-size search result (srchybrid/SearchList.cpp:355).
		return storage.File{}, fmt.Errorf("release %s has no size", entry.CatalogID)
	}

	// Honest availability (docs/meta-search-torrent-usenet-plan.local.md §4.2): a
	// torrent reports its seeders, capped below the 100 at which eMule's spam
	// heuristic starts to count sources; an NZB has no sources at all. Its seeders
	// field is a completion percentage, which is not a source count.
	var sources uint32
	if entry.Kind != metahash.KindNZB {
		sources = min(entry.Seeders, uint32(tags.MaxSources))
	}

	return storage.File{
		Hash:      entry.MetaHash,
		Name:      entry.Name,
		Size:      size,
		Type:      entry.Type,
		Sources:   sources,
		Completed: sources,
		Meta: &storage.MetaInfo{
			Kind:      uint8(entry.Kind),
			Version:   parsed.Version,
			FileIndex: entry.FileIndex,
			FilePath:  entry.FilePath,
			TotalSize: entry.TotalSize,
			CatalogID: entry.CatalogID,
			Seeders:   entry.Seeders,
			Peers:     entry.Peers,
			AgeDays:   entry.AgeDays,
			Indexer:   entry.Indexer,
			Flags:     entry.Flags,
			Magnet:    entry.Magnet,
		},
	}, nil
}

// MintEntry validates one daemon row and returns it with the server-minted meta_hash
// set, for MetaApi.Search. It runs the same checks as EntryToFile, except the
// zero-size rule, which exists for eMule's search list only.
func MintEntry(pb *metav1.MetaEntry) (*metav1.MetaEntry, error) {
	entry, err := mint(pb)
	if err != nil {
		return nil, err
	}
	return pbconv.EntryToProto(entry), nil
}

// SubFileSeparator joins a release's name and a file's path in a file row's name.
const SubFileSeparator = " - "

// NameSubFiles renames every file row of a multi-file release to
// "Release Name - path/inside/release", so an eMule user sees which release a file
// belongs to, and a search matches terms spread across the release's name and the
// file's path. The release name is taken from the whole-set row the daemon sends
// with the file rows; a release without one (a single-file release) keeps its names.
//
// The name is not part of the meta hash, so renaming a row cannot break it. The
// file's own extension stays last, so extension searches still see it.
func NameSubFiles(rows []storage.File) {
	roots := map[string]string{}
	for _, row := range rows {
		if row.Meta != nil && isWholeSet(row) {
			roots[row.Meta.CatalogID] = row.Name
		}
	}
	if len(roots) == 0 {
		return
	}
	for i := range rows {
		row := &rows[i]
		if row.Meta == nil || isWholeSet(*row) {
			continue
		}
		root, ok := roots[row.Meta.CatalogID]
		if !ok {
			continue
		}
		sub := row.Meta.FilePath
		if sub == "" {
			sub = row.Name
		}
		row.Name = root + SubFileSeparator + sub
	}
}

func mint(pb *metav1.MetaEntry) (model.Entry, error) {
	entry := pbconv.EntryFromProto(pb)
	if err := entry.Validate(); err != nil {
		return model.Entry{}, err
	}
	if err := entry.Mint(); err != nil {
		return model.Entry{}, err
	}
	return entry, nil
}

// isWholeSet reports whether a row stands for its whole release rather than one file.
func isWholeSet(row storage.File) bool {
	return row.Meta.FileIndex == metahash.FileIndexWholeSet32
}
