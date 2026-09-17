package storage

import (
	"fmt"
	"time"
)

type Config struct {
	Engine  string
	MySQL   MySQLConfig
	MongoDB MongoConfig
}

type Engine interface {
	Init() error
	Close() error
	ClientsCount() int
	IsConnected(ClientInfo) bool
	Connect(ClientInfo) (uint64, error)
	Disconnect(ClientInfo)
	FilesCount() int
	AddFile(File, ClientInfo)
	// AddFiles stores every file one client offered in one packet. The result must
	// equal calling AddFile for each file in order — a later duplicate of the same
	// (hash, size) wins — but a DB engine writes the batch in a fixed number of
	// round-trips instead of several per file, which is the difference between an
	// OP_OFFERFILES costing milliseconds and costing a minute over a WAN.
	AddFiles([]File, ClientInfo)
	GetSources([]byte, uint64) []Source
	GetSourcesByHash([]byte) []Source
	FindByNameContains(string) []File
	FindBySearch(*SearchExpr) []File
	ServersCount() int
	AddServer(Server)
	ServersAll() []Server
	// CleanupStale removes offline clients and sources untouched for longer than
	// maxAge, and returns how many of each it deleted. Implementations must
	// recompute the denormalized files.sources / files.completed counters for
	// every file they touch, or those counters overstate reality forever.
	CleanupStale(maxAge time.Duration, opts CleanupOptions) (CleanupResult, error)
}

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
	switch cfg.Engine {
	case "", "memory":
		return NewMemoryEngine(), nil
	case "mysql":
		return NewMySQLEngine(cfg.MySQL)
	case "mongodb":
		return NewMongoDBEngine(cfg.MongoDB)
	default:
		return nil, fmt.Errorf("unknown storage engine: %s", cfg.Engine)
	}
}
