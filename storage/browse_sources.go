package storage

import "time"

// IndexedSource is one source row as a search index mirrors it: the offered
// file's own fields plus who offers it and since when.
type IndexedSource struct {
	// File carries the hash, size and the metadata of this source's offer. Its
	// Completed is 1 for a complete source and 0 otherwise; Sources is unused.
	File       File
	ClientHash []byte
	// ClientID and ClientPort are the client's current ed2k id and port, which a
	// search result names as its source while the client is online.
	ClientID   uint32
	ClientPort uint16
	Online     bool
	TimeOffer  time.Time
}

// SourceBrowser is implemented by the engines a search index can be rebuilt from.
// BrowseSources walks every source row — online or not, since a search finds
// offline sources too — a page at a time, in the engine's own order. cursor is nil
// for the first page and then the next of the page before; a nil next ends the
// walk. ErrBrowseCursor says the cursor cannot be continued from.
type SourceBrowser interface {
	BrowseSources(cursor []byte, limit int) (sources []IndexedSource, next []byte, err error)
}
