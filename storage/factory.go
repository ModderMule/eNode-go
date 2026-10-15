package storage

import (
	"errors"
	"fmt"
	"time"

	"enode/logging"
)

type Config struct {
	Engine  string
	MySQL   MySQLConfig
	MongoDB MongoConfig
	// Manticore, when enabled, puts a Manticore full-text index in front of the
	// mysql or mongodb engine's searches. The memory engine has its own index and
	// ignores it.
	Manticore ManticoreConfig
	// KeepOnline leaves the online flags of the previous run alone in Init. Set for
	// a process taking over from a predecessor by handover (internal/handoff): the
	// predecessor's sessions are still connected, and move to this process with
	// their rows as they are. Not a config key.
	KeepOnline bool
}

// startupResetTimeout bounds what a DB engine's Init does after it has connected:
// marking offline whatever the previous run left online. After an unclean stop
// that is every session that was open, so it gets minutes, not the seconds a
// connect does.
const startupResetTimeout = 10 * time.Minute

type Engine interface {
	Init() error
	Close() error
	ClientsCount() int
	IsConnected(ClientInfo) bool
	Connect(ClientInfo) (uint64, error)
	Disconnect(ClientInfo)
	FilesCount() int
	// FilesCountEstimate is the file total for display: the status packets, the
	// dashboard, a peer's ServerInfo. It must be cheap at any table size, so a DB
	// engine answers from its own statistics and may be off by tens of percent.
	// Nothing may branch on it; FilesCount is the exact figure.
	FilesCountEstimate() int
	AddFile(File, ClientInfo)
	// AddFiles stores every file one client offered in one packet. The result must
	// equal calling AddFile for each file in order — a later duplicate of the same
	// (hash, size) wins — but a DB engine writes the batch in a fixed number of
	// round-trips instead of several per file, which is the difference between an
	// OP_OFFERFILES costing milliseconds and costing a minute over a WAN.
	AddFiles([]File, ClientInfo)
	// OfferedCount is how many distinct files the session sources now: what it has
	// offered since Connect, each file once however often it was re-offered. It is
	// what files.softLimit is held against, and is asked on every OP_OFFERFILES, so
	// it must not cost a round-trip: a DB engine answers from a count it keeps as
	// AddFiles writes.
	OfferedCount(ClientInfo) int
	// HasOffered reports, for each file, whether the session sources it now. Only
	// an offer that could cross the soft limit asks, to tell a re-offer, which is
	// always accepted, from a new file, which is not.
	HasOffered(ClientInfo, []File) []bool
	GetSources([]byte, uint64) []Source
	GetSourcesByHash([]byte) []Source
	// SharedFiles returns the files with one of the hashes that an online client
	// offers now, each with its name, size and source counts. A hash held at
	// two sizes comes back twice, and one nobody online offers not at all. It is
	// one lookup for the whole list, for a caller with a page of hashes to ask
	// about.
	SharedFiles(hashes [][]byte) []File
	// BrowseFiles walks the files an online client offers now, a page at a time,
	// for a caller that wants all of them rather than the ones matching a search.
	// cursor is nil for the first page and then the next of the page before; a nil
	// next ends the walk. The order is the engine's own. A file that appears or
	// goes while the walk runs may be missed or returned twice. ErrBrowseCursor
	// says the cursor can no longer be continued from and the walk must restart.
	//
	// The files name no source: SourceID and SourcePort are zero.
	BrowseFiles(cursor []byte, limit int) (files []File, next []byte, err error)
	FindByNameContains(string) []File
	FindBySearch(*SearchExpr) []File
	ServersCount() int
	AddServer(Server)
	// RemoveServer drops one server list entry and reports whether it was there.
	RemoveServer(Server) bool
	ServersAll() []Server
	// CleanupStale removes offline clients and sources untouched for longer than
	// maxAge, and returns how many of each it deleted. Implementations must
	// recompute the denormalized files.sources / files.completed counters for
	// every file they touch, or those counters overstate reality forever.
	CleanupStale(maxAge time.Duration, opts CleanupOptions) (CleanupResult, error)
}

// ErrBrowseCursor is BrowseFiles' answer to a cursor it cannot continue from: one
// it did not issue, or one the engine has since reorganised its files under.
var ErrBrowseCursor = errors.New("storage: browse cursor is no longer valid")

// MaxBrowsePage is the most files one BrowseFiles page holds.
const MaxBrowsePage = 2000

// CleanupOptions configures one sweep.
type CleanupOptions struct {
	// KeepZeroSourceFiles retains a file whose last source has expired. On by
	// default: the server's source list is not the only way a client finds peers
	// — Kad and source exchange can locate sources for a file the server knows
	// about but currently has none online for — so the entry is still what lets
	// a user discover the hash in the first place.
	KeepZeroSourceFiles bool
	// BatchSize bounds how many rows one DELETE removes, so a sweep cannot hold
	// locks across the whole table while AddFile is aggregating it. Zero uses
	// DefaultCleanupBatchSize.
	BatchSize int
}

type CleanupResult struct {
	Clients int
	Files   int
	Sources int
}

// DefaultCleanupBatchSize bounds a single DELETE. Large enough to make progress,
// small enough that the locks it takes do not collide with AddFile's per-file
// counter refresh for long.
const DefaultCleanupBatchSize = 1000

func NewEngine(cfg Config) (Engine, error) {
	var engine Engine
	var err error
	switch cfg.Engine {
	case "", "memory":
		if cfg.Manticore.Enabled {
			logging.Warnf("storage.manticore is enabled but the memory engine searches its own index; ignoring it")
		}
		return NewMemoryEngine(), nil
	case "mysql":
		cfg.MySQL.KeepOnline = cfg.KeepOnline
		engine, err = NewMySQLEngine(cfg.MySQL)
	case "mongodb":
		cfg.MongoDB.KeepOnline = cfg.KeepOnline
		engine, err = NewMongoDBEngine(cfg.MongoDB)
	default:
		return nil, fmt.Errorf("unknown storage engine: %s", cfg.Engine)
	}
	if err != nil {
		return nil, err
	}
	if !cfg.Manticore.Enabled {
		return engine, nil
	}
	return NewManticoreEngine(engine, cfg.Manticore)
}
