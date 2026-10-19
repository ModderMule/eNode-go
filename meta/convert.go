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
// A native row (Kad) is the exception: its hash is the file's own MD4.
//
// The result carries no source address (0/0, which eMule records as "no source") and
// its unprefixed name; the network's prefix is applied when the row is sent, so the
// prefix itself can never match a keyword.
func EntryToFile(pb *metav1.MetaEntry) (storage.File, error) {
	entry, err := mint(pb)
	if err != nil {
		return storage.File{}, err
	}
	if entry.Kind.Native() {
		return nativeEntryToFile(entry)
	}
	parsed, err := metahash.Parse(entry.MetaHash)
	if err != nil {
		return storage.File{}, fmt.Errorf("minted hash does not parse: %w", err)
	}

	size := entry.Size
	if size == 0 {
		size = entry.TotalSize
	}
	if size == 0 && !mayHaveNoSize(entry) {
		// eMule discards a zero-size search result (srchybrid/SearchList.cpp:355). A
		// web row is the exception (ingest contract, amendment 25): a stream has no
		// size to state, and a client that knows the amendment shows the row as one.
		// So are a link container and a magnet that names no size (amendment 27).
		return storage.File{}, fmt.Errorf("release %s has no size", entry.CatalogID)
	}

	// Honest availability (docs/meta-search-torrent-usenet-plan.local.md §4.2): a
	// torrent reports its seeders, capped below the 100 at which eMule's spam
	// heuristic starts to count sources; an NZB has no sources at all. Its seeders
	// field is a completion percentage, which is not a source count. A web row
	// reports the mirrors last found alive, which is a count and is capped the same.
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
// zero-size rule, which exists for eMule's search list only (and there not for a web
// row, whose size 0 says "a stream").
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

// nativeEntryToFile builds the row of a real eD2K file found on Kad. Mint has put the
// file's MD4 in MetaHash. Its sources are what the Kad network reported (peers), the
// complete ones the seeders, both capped like every catalogue row (tags.MaxSources);
// Kad seldom reports a complete count, so Completed is usually 0.
//
// Meta carries the kind and the catalogue id for the feed and the release matching;
// on the wire the row has FT_META_NETWORK alone (ed2k.AddFile).
func nativeEntryToFile(entry model.Entry) (storage.File, error) {
	if entry.Size == 0 {
		return storage.File{}, fmt.Errorf("file %s has no size", entry.CatalogID)
	}
	sources := min(entry.Peers, uint32(tags.MaxSources))
	return storage.File{
		Hash:      entry.MetaHash,
		Name:      entry.Name,
		Size:      entry.Size,
		Type:      entry.Type,
		Sources:   sources,
		Completed: min(entry.Seeders, sources),
		Meta: &storage.MetaInfo{
			Kind:      uint8(entry.Kind),
			CatalogID: entry.CatalogID,
			Seeders:   entry.Seeders,
			Peers:     entry.Peers,
			AgeDays:   entry.AgeDays,
			Indexer:   entry.Indexer,
		},
	}, nil
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

// mayHaveNoSize reports whether a row of size 0 is passed on: a web row (a
// stream), a link container, whose bytes say nothing of the files behind it, and
// a torrent known only by a magnet that states no size.
func mayHaveNoSize(entry model.Entry) bool {
	switch entry.Kind {
	case metahash.KindWeb, metahash.KindContainer:
		return true
	case metahash.KindBTV1, metahash.KindBTV2:
		return entry.Flags&model.FlagMagnetOnly != 0
	default:
		return false
	}
}

// isWholeSet reports whether a row stands for its whole release rather than one file.
func isWholeSet(row storage.File) bool {
	return row.Meta.FileIndex == metahash.FileIndexWholeSet32
}

// available reports whether a row of network passes that network's onlyAvailable
// check, the row-side twin of the filter a live Search asks for. It is what keeps a
// feed row, which no request filtered, to the same rule:
//
//   - torrent: a seeder or a leecher at the last scrape (Search.alive)
//   - Kad: at least one source (amendment 20)
//   - Usenet: seeders is min(99, completion%) (amendment 9), so 99 is the most
//     complete a row can say; a live Search asks for 100% exactly
//   - web: a web page or link container needs a mirror found alive. A torrent or
//     eD2K file a page offered carries no counts at all (amendment 27), so it is left
//     to the daemon's own alive check.
func available(network string, row storage.File) bool {
	m := row.Meta
	if m == nil {
		return true
	}
	switch network {
	case NetworkTorrent:
		return m.Seeders > 0 || m.Peers > 0
	case NetworkKad:
		return m.Peers > 0
	case NetworkUsenet:
		return m.Seeders >= usenetCompleteSeeders
	case NetworkWeb:
		switch metahash.Kind(m.Kind) {
		case metahash.KindWeb, metahash.KindContainer:
			return m.Seeders > 0
		}
	}
	return true
}

// usenetCompleteSeeders is the seeders figure of a complete Usenet row.
const usenetCompleteSeeders = 99
