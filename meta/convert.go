package meta

import (
	"fmt"

	"enode/storage"

	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/metahash"
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
	entry := pbconv.EntryFromProto(pb)
	if err := entry.Validate(); err != nil {
		return storage.File{}, err
	}
	if err := entry.Mint(); err != nil {
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
