package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"enode/logging"
)

var (
	ErrMySQLConfigInvalid  = errors.New("mysql config is invalid")
	ErrMySQLNotInitialized = errors.New("mysql engine is not initialized")
)

type MySQLConfig struct {
	Host            string
	Port            int
	User            string
	Pass            string
	Database        string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	// DeadlockDelay is the base pause between retries of a deadlocked statement,
	// doubled on each further attempt and randomized; see lockRetryDelay.
	// AddFile touches files and sources in an order two concurrent offers of the
	// same popular file can invert, which InnoDB resolves by killing one of them.
	DeadlockDelay time.Duration
	// DeadlockRetries bounds those retries. Zero means the default below.
	DeadlockRetries int
	// SchemaFile is the path to the DDL applied on first connect when the tables
	// are absent. Relative paths resolve against the process working directory,
	// so the server (run from the project root) finds the default below; tests
	// running from a subpackage should resolve it with tests.FixRelativeTestingPath.
	// Empty means the default below.
	SchemaFile string
	// Dialect selects the full-text search strategy. DialectMariaDB (the default
	// when empty) uses a plain word-based FULLTEXT index and word-prefix matching,
	// which both MariaDB 10.0.5+ and MySQL 5.6.4+ support. DialectMySQL uses the
	// ngram parser (MySQL 5.7.6+ only) for substring matching. See BuildSearchWhere
	// and specializeFulltextIndex.
	Dialect string
}

const (
	// DialectMariaDB is the portable, word-based full-text strategy (the default).
	// It is the only strategy MariaDB can index — MariaDB has no ngram parser.
	DialectMariaDB = "mariadb"
	// DialectMySQL uses MySQL's ngram full-text parser for substring search.
	DialectMySQL = "mysql"
)

type MySQLEngine struct {
	cfg     MySQLConfig
	db      *sql.DB
	servers []Server
}

func NewMySQLEngine(cfg MySQLConfig) (*MySQLEngine, error) {
	if cfg.Host == "" || cfg.User == "" || cfg.Database == "" || cfg.Port <= 0 {
		return nil, ErrMySQLConfigInvalid
	}
	if cfg.MaxOpenConns <= 0 {
		cfg.MaxOpenConns = 10
	}
	if cfg.MaxIdleConns < 0 {
		cfg.MaxIdleConns = 0
	}
	if cfg.ConnMaxLifetime <= 0 {
		cfg.ConnMaxLifetime = 5 * time.Minute
	}
	if cfg.DeadlockDelay <= 0 {
		cfg.DeadlockDelay = defaultDeadlockDelay
	}
	if cfg.DeadlockRetries <= 0 {
		cfg.DeadlockRetries = defaultDeadlockRetries
	}
	if cfg.SchemaFile == "" {
		cfg.SchemaFile = defaultSchemaFile
	}
	// Default to the portable word-based dialect so a directly-constructed config
	// (tests, embedders bypassing config.Load) never lands on an empty strategy.
	if cfg.Dialect == "" {
		cfg.Dialect = DialectMariaDB
	}
	return &MySQLEngine{cfg: cfg}, nil
}

// defaultSchemaFile is the DDL applied on first connect. Relative so a server
// started from the project root (as documented) finds misc/enode.sql; it can be
// overridden via config (storage.mysql.schemaFile) for other layouts.
const defaultSchemaFile = "misc/enode.sql"

const (
	defaultDeadlockDelay = 100 * time.Millisecond
	// Six, not three: measured under tests/dblatency's load test, concurrent offers
	// of popular files deadlock about once per offer, and three retries left some
	// 200-file chunks to fail over to file-by-file writes. See lockRetryDelay.
	defaultDeadlockRetries = 6
	// maxDeadlockDelay caps the doubling in lockRetryDelay.
	maxDeadlockDelay = 2 * time.Second

	// MySQL error numbers. These are NOT interchangeable:
	//
	//	1213 ER_LOCK_DEADLOCK — InnoDB has already rolled the whole transaction
	//	     back. Safe to retry from the start.
	//	1205 ER_LOCK_WAIT_TIMEOUT — with the default innodb_rollback_on_timeout=OFF
	//	     only the *statement* is rolled back and the transaction stays open and
	//	     partially applied. Retrying it blindly inside a multi-statement
	//	     transaction double-applies the earlier statements.
	//
	// Every statement here runs in autocommit and uses absolute SET values rather
	// than read-modify-write, so re-running one is idempotent and both codes can
	// be retried safely — but only because of that, and the distinction is kept
	// explicit so it survives any future move into a transaction.
	mysqlErrDeadlock        = 1213
	mysqlErrLockWaitTimeout = 1205
)

// dsn builds the driver connection string.
//
// interpolateParams makes the driver substitute placeholders client-side and send
// one COM_QUERY. Without it every parameterised statement is COM_STMT_PREPARE,
// wait for the reply, COM_STMT_EXECUTE, wait again, then COM_STMT_CLOSE — the
// statement is thrown away, so nothing amortises the extra round-trip. Invisible
// on loopback; it doubled every hot-path latency against a remote database
// (docs/remote-database.local.md).
//
// It is safe with this charset: the driver refuses interpolation under the
// multibyte collations where escaping is unsound (big5, sjis, gbk, cp932) at
// ParseDSN, and utf8mb4_unicode_ci is not one of them. A query that would exceed
// max_allowed_packet once interpolated falls back to a prepared statement inside
// the driver.
func (m *MySQLEngine) dsn() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4,utf8&collation=utf8mb4_unicode_ci&interpolateParams=true",
		m.cfg.User, m.cfg.Pass, m.cfg.Host, m.cfg.Port, m.cfg.Database)
}

func (m *MySQLEngine) ensureDB() error {
	if m.db == nil {
		return ErrMySQLNotInitialized
	}
	return nil
}

func (m *MySQLEngine) Init() error {
	db, err := sql.Open("mysql", m.dsn())
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(m.cfg.MaxOpenConns)
	db.SetMaxIdleConns(m.cfg.MaxIdleConns)
	db.SetConnMaxLifetime(m.cfg.ConnMaxLifetime)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return err
	}
	// Create the schema on first connect. No migration support: this only runs on
	// a fresh database (the clients table absent), so an existing deployment never
	// reads the file, and a partially-created schema is left untouched.
	if err := m.ensureSchema(ctx, db); err != nil {
		_ = db.Close()
		return err
	}
	if _, err := db.ExecContext(ctx, `UPDATE clients SET online = 0`); err != nil {
		_ = db.Close()
		return err
	}
	if _, err := db.ExecContext(ctx, `UPDATE sources SET online = 0`); err != nil {
		_ = db.Close()
		return err
	}
	m.db = db
	return nil
}

func (m *MySQLEngine) Close() error {
	if m.db == nil {
		return nil
	}
	return m.db.Close()
}

func (m *MySQLEngine) ClientsCount() int {
	if err := m.ensureDB(); err != nil {
		return 0
	}
	var c int
	if err := m.db.QueryRow(`SELECT COUNT(*) FROM clients WHERE online = 1`).Scan(&c); err != nil {
		logging.Errorf("mysql clients count failed: %v", err)
	}
	return c
}

func (m *MySQLEngine) IsConnected(info ClientInfo) bool {
	if err := m.ensureDB(); err != nil {
		return false
	}
	var id uint64
	err := m.db.QueryRow(`SELECT id FROM clients WHERE hash = ? AND online = 1 LIMIT 1`, info.Hash).Scan(&id)
	return err == nil
}

func (m *MySQLEngine) Connect(info ClientInfo) (uint64, error) {
	if err := m.ensureDB(); err != nil {
		return 0, err
	}
	_, err := m.db.Exec(
		`INSERT INTO clients(hash, id_ed2k, ipv4, port, crypt_options, ipv6, ipv6_reachable, online) VALUES(?,?,?,?,?,?,?,1)
		 ON DUPLICATE KEY UPDATE id_ed2k=VALUES(id_ed2k), ipv4=VALUES(ipv4), port=VALUES(port), crypt_options=VALUES(crypt_options), ipv6=VALUES(ipv6), ipv6_reachable=VALUES(ipv6_reachable), online=1`,
		info.Hash, info.ID, info.IPv4, info.Port, info.CryptOptions, nullableIPv6(info.IPv6), boolToTinyInt(info.IPv6Reachable),
	)
	if err != nil {
		return 0, err
	}
	var id uint64
	if err := m.db.QueryRow(`SELECT id FROM clients WHERE hash = ? LIMIT 1`, info.Hash).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (m *MySQLEngine) Disconnect(info ClientInfo) {
	if err := m.ensureDB(); err != nil {
		return
	}
	// Both through execRetry: marking a client's sources offline locks the same
	// sources rows a concurrent counter refresh reads, and under load InnoDB picks
	// this statement as the deadlock victim. Without a retry the sources stayed
	// online — advertised by GetSources for a client that had already gone.
	if err := m.execRetry("disconnect client", func() error {
		_, err := m.db.Exec(`UPDATE clients SET online = 0 WHERE id = ?`, info.StoreID)
		return err
	}); err != nil {
		logging.Errorf("mysql disconnect client storeID=%d failed: %v", info.StoreID, err)
	}
	if err := m.execRetry("disconnect sources", func() error {
		_, err := m.db.Exec(`UPDATE sources SET online = 0 WHERE id_client = ?`, info.StoreID)
		return err
	}); err != nil {
		logging.Errorf("mysql disconnect sources storeID=%d failed: %v", info.StoreID, err)
	}
}

func (m *MySQLEngine) FilesCount() int {
	if err := m.ensureDB(); err != nil {
		return 0
	}
	var c int
	if err := m.db.QueryRow(`SELECT COUNT(*) FROM files`).Scan(&c); err != nil {
		logging.Errorf("mysql files count failed: %v", err)
	}
	return c
}

func (m *MySQLEngine) AddFile(file File, clientInfo ClientInfo) {
	m.AddFiles([]File{file}, clientInfo)
}

// AddFiles writes one client's offer as four statements per offerBatchSize chunk,
// however many files the chunk holds. It used to be four statements per file,
// issued once per record of every OP_OFFERFILES — 1,600 round-trips for one
// 200-file packet before interpolateParams, which is 48 s against a database 30 ms
// away.
//
// A chunk that fails is retried file by file. Batching must not change failure
// isolation: when every file was its own statements, one record the server
// rejected could not take the other 199 down with it. NormalizeFile is what is
// meant to keep a rejection from happening at all; this is what bounds it if one
// still does. Every statement is idempotent, so re-running rows the failed chunk
// already wrote is harmless.
func (m *MySQLEngine) AddFiles(files []File, clientInfo ClientInfo) {
	if err := m.ensureDB(); err != nil {
		return
	}
	batch := prepareOfferBatch(files)
	for start := 0; start < len(batch); start += offerBatchSize {
		chunk := batch[start:min(start+offerBatchSize, len(batch))]
		err := m.addFilesChunk(chunk, clientInfo)
		if err == nil {
			continue
		}
		if len(chunk) > 1 {
			logging.Warnf("mysql add files batch of %d clientID=%d failed, retrying one by one: %v",
				len(chunk), clientInfo.StoreID, err)
			for _, file := range chunk {
				if err := m.addFilesChunk([]File{file}, clientInfo); err != nil {
					logMySQLAddFileError(file, clientInfo, err)
				}
			}
			continue
		}
		logMySQLAddFileError(chunk[0], clientInfo, err)
	}
}

func (m *MySQLEngine) GetSources(fileHash []byte, fileSize uint64) []Source {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	rows, err := m.db.Query(
		`SELECT c.id_ed2k, c.port, c.hash, c.crypt_options, c.ipv6, c.ipv6_reachable
		 FROM sources s
		 INNER JOIN clients c ON c.id = s.id_client
		 INNER JOIN files f ON f.id = s.id_file
		 WHERE f.hash = ? AND f.size = ? AND s.online = 1 AND c.online = 1
		 ORDER BY s.online DESC, s.time_offer DESC
		 LIMIT 255`,
		fileHash, fileSize,
	)
	if err != nil {
		logging.Errorf("mysql get sources hash=%x size=%d failed: %v", fileHash, fileSize, err)
		return nil
	}
	defer rows.Close()
	return scanSources(rows)
}

func (m *MySQLEngine) GetSourcesByHash(fileHash []byte) []Source {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	rows, err := m.db.Query(
		`SELECT c.id_ed2k, c.port, c.hash, c.crypt_options, c.ipv6, c.ipv6_reachable
		 FROM sources s
		 INNER JOIN clients c ON c.id = s.id_client
		 INNER JOIN files f ON f.id = s.id_file
		 WHERE f.hash = ? AND s.online = 1 AND c.online = 1
		 ORDER BY s.online DESC, s.time_offer DESC
		 LIMIT 255`,
		fileHash,
	)
	if err != nil {
		logging.Errorf("mysql get sources by hash=%x failed: %v", fileHash, err)
		return nil
	}
	defer rows.Close()
	return scanSources(rows)
}

// scanSources reads the shared source projection (id_ed2k, port, hash,
// crypt_options, ipv6, ipv6_reachable) into Source values. ipv6 is NULL for a
// client with no IPv6, which scans to a nil slice.
func scanSources(rows *sql.Rows) []Source {
	var out []Source
	for rows.Next() {
		var s Source
		var reachable int
		if err := rows.Scan(&s.ID, &s.Port, &s.UserHash, &s.CryptOptions, &s.IPv6, &reachable); err == nil {
			s.IPv6Reachable = reachable != 0
			out = append(out, s)
		}
	}
	return out
}

// nullableIPv6 maps a 16-byte IPv6 to itself and anything else (nil, wrong
// length) to a NULL column value, so a client with no IPv6 stores NULL rather
// than a zero blob.
func nullableIPv6(b []byte) any {
	if len(b) != 16 {
		return nil
	}
	return b
}

func (m *MySQLEngine) FindByNameContains(term string) []File {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	// Reuse the dialect-aware builder so this path matches FindBySearch's
	// full-text semantics exactly instead of falling back to a leading-`%` scan.
	where, args := buildSearchWhere(&SearchExpr{Kind: SearchText, Text: term}, m.cfg.Dialect)
	if where == "" {
		return nil
	}
	rows, err := m.db.Query(
		`SELECT s.name, f.completed, f.sources, f.hash, f.size, f.source_id, f.source_port,
		        s.type, s.title, s.artist, s.album, s.length, s.bitrate, s.codec
		 FROM sources s
		 INNER JOIN files f ON s.id_file = f.id
		 WHERE `+where+`
		 ORDER BY s.time_offer DESC
		 LIMIT 255`,
		args...,
	)
	if err != nil {
		logging.Errorf("mysql find by name %q failed: %v", term, err)
		return nil
	}
	defer rows.Close()
	var out []File
	for rows.Next() {
		var f File
		var typ string
		if err := rows.Scan(&f.Name, &f.Completed, &f.Sources, &f.Hash, &f.Size, &f.SourceID, &f.SourcePort,
			&typ, &f.Title, &f.Artist, &f.Album, &f.Runtime, &f.Bitrate, &f.Codec); err == nil {
			f.Type = typ
			out = append(out, f)
		}
	}
	return out
}

func (m *MySQLEngine) FindBySearch(expr *SearchExpr) []File {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	where, args := BuildSearchWhere(expr, m.cfg.Dialect)
	if where == "" {
		return nil
	}
	// One row per file, carrying metadata from an arbitrary representative
	// source — the semantics the MySQL 5.5 original relied on implicitly.
	//
	// Grouping is by s.id_file, and sources' only uniqueness covering it is
	// UNIQUE(id_file, id_client), so id_file alone does not determine a source
	// row — the s.* columns are non-aggregated. How that is spelled depends on the
	// server, and the two are mutually exclusive:
	//   - MySQL 8 defaults to ONLY_FULL_GROUP_BY and rejects a bare s.* with
	//     ER_1055, so each is wrapped in ANY_VALUE().
	//   - MariaDB has no ANY_VALUE() function at all, but its default sql_mode
	//     omits ONLY_FULL_GROUP_BY, so the bare column is both legal and the only
	//     option.
	// The f.* columns need no wrapping either way — they are functionally
	// dependent through s.id_file = f.id, where f.id is the primary key. The
	// dialect must match the actual server (the same requirement the ngram index
	// has); a mismatch here surfaces as an ER_1055 or unknown-function error
	// rather than silently.
	//
	// Deliberately not fixed by relaxing sql_mode in the DSN: that would also
	// decide STRICT_TRANS_TABLES, silently masking oversized/invalid client tags
	// instead of letting the normalization in NormalizeFile handle them.
	rep := groupRepFunc(m.cfg.Dialect)
	rows, err := m.db.Query(
		`SELECT `+rep("s.name")+`, f.completed, f.sources, f.hash, f.size, f.source_id, f.source_port,
		        `+rep("s.type")+`, `+rep("s.title")+`, `+rep("s.artist")+`, `+rep("s.album")+`,
		        `+rep("s.length")+`, `+rep("s.bitrate")+`, `+rep("s.codec")+`
		 FROM sources s
		 INNER JOIN files f ON s.id_file = f.id
		 WHERE `+where+`
		 GROUP BY s.id_file
		 LIMIT `+strconv.Itoa(MaxSearchResults)+``,
		args...,
	)
	if err != nil {
		logging.Errorf("mysql search failed (where=%q): %v", where, err)
		return nil
	}
	defer rows.Close()
	var out []File
	for rows.Next() {
		var f File
		var typ string
		if err := rows.Scan(&f.Name, &f.Completed, &f.Sources, &f.Hash, &f.Size, &f.SourceID, &f.SourcePort,
			&typ, &f.Title, &f.Artist, &f.Album, &f.Runtime, &f.Bitrate, &f.Codec); err == nil {
			f.Type = typ
			out = append(out, f)
		}
	}
	return out
}

func (m *MySQLEngine) ServersCount() int {
	return len(m.servers)
}

func (m *MySQLEngine) AddServer(server Server) {
	m.servers, _ = appendUniqueServer(m.servers, server)
}

func (m *MySQLEngine) ServersAll() []Server {
	return append([]Server(nil), m.servers...)
}

// CleanupStale removes offline clients and sources older than maxAge.
//
// Without it the index on clients.online only postpones the problem: nothing
// ever deleted a client row, so the table grew monotonically and every count or
// sweep scanned every client the server had ever seen.
func (m *MySQLEngine) CleanupStale(maxAge time.Duration, opts CleanupOptions) (CleanupResult, error) {
	var result CleanupResult
	if err := m.ensureDB(); err != nil {
		return result, err
	}
	if maxAge <= 0 {
		return result, fmt.Errorf("cleanup: maxAge must be positive, got %s", maxAge)
	}
	batch := opts.BatchSize
	if batch <= 0 {
		batch = DefaultCleanupBatchSize
	}
	cutoff := time.Now().Add(-maxAge)

	// Collect the affected files before deleting, so the counters can be
	// recomputed afterwards. Skipping this leaves files.sources permanently
	// overstating reality, and that column feeds both the search filters and the
	// source count advertised in OP_SEARCHRESULT.
	affected, err := m.staleAffectedFileIDs(cutoff)
	if err != nil {
		return result, err
	}

	// Clients first: the sources FK cascades on delete, so this also removes the
	// source rows belonging to every client that goes.
	//
	// online = 1 rows are never touched regardless of age. A long-lived session
	// is not stale, and on MySQL time_login is ON UPDATE CURRENT_TIMESTAMP rather
	// than a liveness signal.
	deleted, err := m.deleteInBatches(
		`DELETE FROM clients WHERE online = 0 AND time_login < ? LIMIT ?`, cutoff, batch)
	if err != nil {
		return result, err
	}
	result.Clients = deleted

	// A second pass for sources whose client is still connected.
	deleted, err = m.deleteInBatches(
		`DELETE FROM sources WHERE online = 0 AND time_offer < ? LIMIT ?`, cutoff, batch)
	if err != nil {
		return result, err
	}
	result.Sources = deleted

	// One statement per batch rather than per file: a day's sweep on a busy server
	// touches six figures of files, which was that many UPDATEs, each a round-trip
	// holding a pool connection. Bounded by the same batch size as the DELETEs, so
	// no single statement locks more files rows than a DELETE is allowed to.
	for start := 0; start < len(affected); start += batch {
		chunk := affected[start:min(start+batch, len(affected))]
		if err := m.refreshFileCounters(chunk, nil); err != nil {
			logging.Errorf("mysql cleanup refresh counters files=%d failed: %v", len(chunk), err)
		}
	}

	if !opts.KeepZeroSourceFiles {
		// time_offer < cutoff, not just sources = 0: a file an offer is writing right
		// now also has sources = 0, between the offer's files upsert and its counter
		// refresh. Deleting it then either failed the offer's sources INSERT on the
		// foreign key or, a moment later, cascaded away the source it had just
		// stored. The offer stamps time_offer before it inserts any source, so a
		// file past the cutoff has no offer in flight.
		deleted, err = m.deleteZeroSourceFiles(cutoff, batch)
		if err != nil {
			return result, err
		}
		result.Files = deleted
	}
	return result, nil
}

// staleAffectedFileIDs lists the files that will lose at least one source.
func (m *MySQLEngine) staleAffectedFileIDs(cutoff time.Time) ([]uint64, error) {
	rows, err := m.db.Query(
		`SELECT DISTINCT s.id_file FROM sources s
		 LEFT JOIN clients c ON c.id = s.id_client
		 WHERE (s.online = 0 AND s.time_offer < ?)
		    OR (c.online = 0 AND c.time_login < ?)`,
		cutoff, cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uint64
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// deleteInBatches runs a LIMIT-ed DELETE until it stops matching rows.
//
// One unbounded DELETE would hold locks across the whole sources table, which
// AddFile's counter refresh aggregates — straight into the deadlock path that
// execRetry exists to handle. Passing nil for cutoff runs a statement whose only
// placeholder is the limit.
func (m *MySQLEngine) deleteInBatches(query string, cutoff time.Time, batch int) (int, error) {
	total := 0
	for {
		var affected int64
		err := m.execRetry("cleanup delete", func() error {
			res, err := m.db.Exec(query, cutoff, batch)
			if err != nil {
				return err
			}
			affected, err = res.RowsAffected()
			return err
		})
		if err != nil {
			return total, err
		}
		total += int(affected)
		if int(affected) < batch {
			return total, nil
		}
	}
}

// deleteZeroSourceFiles removes files that have no source left and no offer since
// cutoff, batch rows at a time, and returns how many it removed.
//
// Candidates are read with a plain SELECT, then deleted by primary key with the
// condition repeated. files has no index on sources, so the single
// `DELETE ... WHERE sources = 0 LIMIT ?` it replaces scanned the whole table, and
// under REPEATABLE READ a DELETE locks every row it reads, matching or not: every
// offer then waited for the sweep, and under load deadlocked with it. The SELECT is
// a consistent read and takes no locks; the DELETE locks only the rows it removes,
// in primary-key order like the counter refresh.
func (m *MySQLEngine) deleteZeroSourceFiles(cutoff time.Time, batch int) (int, error) {
	total := 0
	for {
		ids, err := m.zeroSourceFileIDs(cutoff, batch)
		if err != nil || len(ids) == 0 {
			return total, err
		}
		args := append(ids, cutoff)
		var affected int64
		err = m.execRetry("cleanup delete", func() error {
			res, err := m.db.Exec(`DELETE FROM files WHERE id IN (`+sqlPlaceholders(len(ids))+`)
				 AND sources = 0 AND time_offer < ?`, args...)
			if err != nil {
				return err
			}
			affected, err = res.RowsAffected()
			return err
		})
		if err != nil {
			return total, err
		}
		total += int(affected)
		if len(ids) < batch {
			return total, nil
		}
	}
}

func (m *MySQLEngine) zeroSourceFileIDs(cutoff time.Time, batch int) ([]any, error) {
	rows, err := m.db.Query(`SELECT id FROM files WHERE sources = 0 AND time_offer < ? LIMIT ?`, cutoff, batch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []any
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// refreshFileCounters recomputes the denormalized sources/completed counters for a
// set of files in one statement.
//
// The aggregate is scoped with `WHERE id_file IN (…)`. It used to run
// `SELECT ... FROM sources GROUP BY id_file` across the whole table on every
// offered file, holding locks over rows belonging to unrelated files while
// taking an exclusive lock on the parent files row — which is what made
// concurrent offers of one popular file deadlock in the first place.
//
// src stamps the offering client's address onto every file, which is what an offer
// wants. A cleanup sweep passes nil and source_id/source_port are left alone: the
// sweep has no offering client, and writing zeros would wipe the last known source
// address off every file it touched.
//
// Callers bound len(ids) — offerBatchSize for an offer, the sweep's batch size for
// cleanup — so the files rows one statement locks stay bounded. The ids are sorted
// so two statements over overlapping files lock them in the same order.
func (m *MySQLEngine) refreshFileCounters(ids []uint64, src *counterSource) error {
	if len(ids) == 0 {
		return nil
	}
	sorted := slices.Clone(ids)
	slices.Sort(sorted)
	idArgs := make([]any, len(sorted))
	for i, id := range sorted {
		idArgs[i] = id
	}
	set := `f.completed = COALESCE(s.completed,0), f.sources = COALESCE(s.sources,0)`
	args := make([]any, 0, 2*len(idArgs)+2)
	args = append(args, idArgs...)
	if src != nil {
		set += `, f.source_id = ?, f.source_port = ?`
		args = append(args, src.ID, src.Port)
	}
	args = append(args, idArgs...)
	query := `UPDATE files f
		 LEFT JOIN (
		   SELECT id_file, SUM(complete) AS completed, COUNT(*) AS sources
		   FROM sources WHERE id_file IN (` + sqlPlaceholders(len(idArgs)) + `) GROUP BY id_file
		 ) s ON s.id_file = f.id
		 SET ` + set + `
		 WHERE f.id IN (` + sqlPlaceholders(len(idArgs)) + `)`
	return m.execRetry("refresh counters", func() error {
		_, err := m.db.Exec(query, args...)
		return err
	})
}

// execRetry re-runs a statement that InnoDB rejected for lock contention.
//
// Deliberately per statement rather than around all of AddFile: wrapping the
// four statements in one transaction to make retry atomic would hold their locks
// for the whole sequence and make deadlocks *more* likely, not less. Retrying
// individually is safe here only because every statement is idempotent —
// ON DUPLICATE KEY UPDATE with absolute SET values, and a counter refresh that
// recomputes from an aggregate rather than incrementing.
func (m *MySQLEngine) execRetry(what string, fn func() error) error {
	var err error
	for attempt := 0; attempt <= m.cfg.DeadlockRetries; attempt++ {
		if err = fn(); err == nil {
			return nil
		}
		if !isRetryableLockError(err) {
			return err
		}
		if attempt < m.cfg.DeadlockRetries {
			logging.Warnf("mysql %s hit lock contention, retrying (attempt %d/%d): %v",
				what, attempt+1, m.cfg.DeadlockRetries, err)
			time.Sleep(m.lockRetryDelay(attempt))
		}
	}
	return fmt.Errorf("%s failed after %d retries: %w", what, m.cfg.DeadlockRetries, err)
}

// lockRetryDelay is the pause before retry attempt+1: DeadlockDelay doubled per
// earlier attempt, capped at maxDeadlockDelay, then drawn uniformly from its upper
// half.
//
// A fixed pause is what made the retries fail. The two statements of a deadlock
// retry together after exactly the same delay, meet on the same rows again, and
// deadlock again — under load that used up all retries of an offer's sources
// INSERT, and the whole 200-file chunk fell back to file-by-file writes. The
// randomness separates the pair; the doubling backs off when many writers contend
// for one popular file.
func (m *MySQLEngine) lockRetryDelay(attempt int) time.Duration {
	d := m.cfg.DeadlockDelay
	for i := 0; i < attempt && d < maxDeadlockDelay; i++ {
		d *= 2
	}
	d = min(d, maxDeadlockDelay)
	return d/2 + rand.N(d/2+1)
}

// isRetryableLockError reports whether MySQL rejected the statement for lock
// contention rather than for anything about its content.
func isRetryableLockError(err error) bool {
	if err == nil {
		return false
	}
	var mysqlErr *mysqldriver.MySQLError
	if !errors.As(err, &mysqlErr) {
		return false
	}
	return mysqlErr.Number == mysqlErrDeadlock || mysqlErr.Number == mysqlErrLockWaitTimeout
}

func boolToTinyInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// ensureSchema applies the DDL file when the database has no clients table yet.
// The presence check keys on that single anchor table rather than all three: a
// fresh database has none, and anything past that is an operator-managed schema
// we must not rewrite (there is no migration support by design).
func (m *MySQLEngine) ensureSchema(ctx context.Context, db *sql.DB) error {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM information_schema.tables
		 WHERE table_schema = DATABASE() AND table_name = 'clients'`).Scan(&n)
	if err != nil {
		return fmt.Errorf("mysql schema check failed: %w", err)
	}
	if n > 0 {
		return nil
	}
	if err := m.applySchema(ctx); err != nil {
		return err
	}
	return m.specializeFulltextIndex(ctx, db)
}

// specializeFulltextIndex upgrades the portable word-based name_ft index created
// by the schema file to MySQL's ngram parser, which the word-prefix baseline
// cannot do but which the mysql dialect's substring matching requires. It runs
// only on a fresh install (right after applySchema, empty table → instant) and
// only for DialectMySQL — MariaDB has no ngram parser and keeps the baseline
// index untouched. An existing deployment is out of scope (matching the
// no-migration policy above); docs/database-engines.local.md gives the manual
// ALTER for that case.
func (m *MySQLEngine) specializeFulltextIndex(ctx context.Context, db *sql.DB) error {
	if m.cfg.Dialect != DialectMySQL {
		return nil
	}
	// A FULLTEXT index's parser is fixed at creation, so switch to ngram by
	// dropping and re-adding. These MUST be two separate statements: a combined
	// `DROP INDEX ..., ADD FULLTEXT ... WITH PARSER ngram` silently discards the
	// parser clause (verified on MySQL 8.0 — SHOW CREATE TABLE comes back without
	// WITH PARSER), leaving a word-based index that only matches whole tokens and
	// so never does the substring search the mysql dialect promises.
	if _, err := db.ExecContext(ctx, "ALTER TABLE sources DROP INDEX name_ft"); err != nil {
		return fmt.Errorf("mysql drop name_ft before ngram rebuild (dialect=mysql): %w", err)
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE sources ADD FULLTEXT INDEX name_ft (name) WITH PARSER ngram"); err != nil {
		return fmt.Errorf("mysql add ngram name_ft (dialect=mysql): %w", err)
	}
	logging.Infof("mysql: specialized sources.name_ft full-text index to ngram parser (dialect=mysql)")
	return nil
}

// applySchema reads the SchemaFile and executes it in one shot. It uses a
// throwaway connection with multiStatements enabled — the file is a
// multi-statement dump (CREATE TABLEs plus an ALTER for the foreign keys, with a
// phpMyAdmin SET preamble) — so the option never touches the engine's normal
// pool, whose queries are all single, parameterized statements.
func (m *MySQLEngine) applySchema(ctx context.Context) error {
	ddl, err := os.ReadFile(m.cfg.SchemaFile)
	if err != nil {
		return fmt.Errorf("mysql schema file %q unreadable (needed to create tables on first connect): %w", m.cfg.SchemaFile, err)
	}
	db, err := sql.Open("mysql", m.dsn()+"&multiStatements=true")
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, string(ddl)); err != nil {
		return fmt.Errorf("mysql apply schema from %q failed: %w", m.cfg.SchemaFile, err)
	}
	logging.Infof("mysql: created schema from %s", m.cfg.SchemaFile)
	return nil
}

// groupRepFunc returns how to render a non-aggregated source column under the
// GROUP BY in FindBySearch, which differs by server: ANY_VALUE() on MySQL (to
// satisfy ONLY_FULL_GROUP_BY) versus the bare column on MariaDB (which has no
// ANY_VALUE() but also no ONLY_FULL_GROUP_BY by default). See FindBySearch.
func groupRepFunc(dialect string) func(col string) string {
	if dialect == DialectMySQL {
		return func(col string) string { return "ANY_VALUE(" + col + ")" }
	}
	return func(col string) string { return col }
}

// addFilesChunk writes at most offerBatchSize files prepared by prepareOfferBatch:
// upsert the files, resolve their ids, upsert the sources, refresh the counters.
// Four round-trips regardless of len(files).
func (m *MySQLEngine) addFilesChunk(files []File, clientInfo ClientInfo) error {
	fileArgs := make([]any, 0, 2*len(files))
	hashArgs := make([]any, 0, len(files))
	for _, f := range files {
		fileArgs = append(fileArgs, f.Hash, f.Size)
		hashArgs = append(hashArgs, f.Hash)
	}
	if err := m.execRetry("add files", func() error {
		_, err := m.db.Exec(
			`INSERT INTO files(hash,size,time_offer) VALUES `+sqlRows("(?,?,NOW())", len(files))+`
			 ON DUPLICATE KEY UPDATE time_offer=NOW()`,
			fileArgs...,
		)
		return err
	}); err != nil {
		return err
	}

	// On hash alone rather than a row-constructor `(hash,size) IN ((?,?),…)`: a plain
	// IN is served by KEY hash on every MySQL and MariaDB version this engine
	// supports, which the row-constructor form is not. The same hash at another size
	// comes back too and simply matches no key below.
	ids := make(map[offerKey]uint64, len(files))
	if err := m.execRetry("lookup file ids", func() error {
		rows, err := m.db.Query(`SELECT id, hash, size FROM files WHERE hash IN (`+sqlPlaceholders(len(hashArgs))+`)`, hashArgs...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				id   uint64
				hash []byte
				size uint64
			)
			if err := rows.Scan(&id, &hash, &size); err != nil {
				return err
			}
			ids[offerKey{hash: string(hash), size: size}] = id
		}
		return rows.Err()
	}); err != nil {
		return err
	}

	type fileRow struct {
		id   uint64
		file File
	}
	resolved := make([]fileRow, 0, len(files))
	for _, f := range files {
		id, ok := ids[offerKey{hash: string(f.Hash), size: f.Size}]
		if !ok {
			return fmt.Errorf("lookup file ids: hash=%x size=%d missing right after its upsert", f.Hash, f.Size)
		}
		resolved = append(resolved, fileRow{id: id, file: f})
	}
	// Ordered by id, so concurrent batches insert into sources' UNIQUE(id_file, id_client)
	// in the same order as each other.
	slices.SortFunc(resolved, func(a, b fileRow) int {
		switch {
		case a.id < b.id:
			return -1
		case a.id > b.id:
			return 1
		}
		return 0
	})

	// Every value below originates in a client tag. prepareOfferBatch has already
	// clamped them to the column widths and mapped type into the ENUM; without
	// that, an over-length name/codec or a type such as "EmuleCollection" aborts
	// this INSERT under STRICT_TRANS_TABLES and the file is published but never
	// becomes searchable.
	sourceArgs := make([]any, 0, 13*len(resolved))
	fileIDs := make([]uint64, 0, len(resolved))
	for _, r := range resolved {
		f := r.file
		sourceArgs = append(sourceArgs,
			r.id, clientInfo.StoreID, f.Name, NormalizeExt(f.Name), f.Type, f.Title, f.Artist, f.Album,
			f.Runtime, f.Bitrate, f.Codec, 1, boolToTinyInt(f.Completed > 0),
		)
		fileIDs = append(fileIDs, r.id)
	}
	if err := m.execRetry("add sources", func() error {
		_, err := m.db.Exec(
			`INSERT INTO sources(id_file,id_client,name,ext,type,title,artist,album,length,bitrate,codec,online,complete,time_offer)
			 VALUES `+sqlRows("(?,?,?,?,?,?,?,?,?,?,?,?,?,NOW())", len(resolved))+`
			 ON DUPLICATE KEY UPDATE
			 name=VALUES(name), ext=VALUES(ext), type=VALUES(type), title=VALUES(title),
			 artist=VALUES(artist), album=VALUES(album), length=VALUES(length), bitrate=VALUES(bitrate),
			 codec=VALUES(codec), online=1, complete=VALUES(complete), time_offer=NOW()`,
			sourceArgs...,
		)
		return err
	}); err != nil {
		return err
	}

	return m.refreshFileCounters(fileIDs, &counterSource{ID: clientInfo.ID, Port: clientInfo.Port})
}

// logMySQLAddFileError reports one file that could not be stored even on its own.
func logMySQLAddFileError(file File, clientInfo ClientInfo, err error) {
	logging.Errorf("mysql add file hash=%x size=%d clientID=%d name=%q type=%q failed: %v",
		file.Hash, file.Size, clientInfo.StoreID, file.Name, file.Type, err)
}

// sqlPlaceholders returns n comma-separated placeholders for an IN list.
func sqlPlaceholders(n int) string {
	return sqlRows("?", n)
}

// sqlRows repeats one VALUES tuple n times, comma-separated.
func sqlRows(row string, n int) string {
	return strings.TrimSuffix(strings.Repeat(row+",", n), ",")
}
