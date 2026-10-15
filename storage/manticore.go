package storage

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"enode/logging"
)

// ManticoreConfig turns on Manticore Search as the full-text index of a mysql or
// mongodb engine. The database stays the store of record; Manticore mirrors its
// source rows and answers FindBySearch in its place. See docs/manticore-search.local.md.
type ManticoreConfig struct {
	Enabled bool
	// DSN is a go-sql-driver DSN for Manticore's MySQL-protocol port (9306), e.g.
	// "tcp(127.0.0.1:9306)/". A database name in it is ignored: Manticore has none.
	DSN string
	// Table is the real-time table the source rows are mirrored into.
	Table string
	// TableOptions follow the column list of CREATE TABLE. A change to them only
	// takes effect after a start with Recreate.
	TableOptions string
	// Timeout bounds one search: Manticore's max_query_time, and a client deadline
	// a second longer.
	Timeout time.Duration
	// BatchSize is how many documents one REPLACE statement writes.
	BatchSize int
	// QueueSize is how many offers and disconnects may wait for the writer. One
	// that does not fit is dropped and the next reconcile pass repairs it.
	QueueSize int
	// ReconcileInterval is how often the whole index is rewritten from the
	// database and its orphans removed, counted from the last pass that finished,
	// across restarts. Zero turns the periodic pass off; the first fill of a table
	// and the pass after a dropped write still run.
	ReconcileInterval time.Duration
	// FallbackToEngine runs a search on the database when Manticore fails it.
	// Off, such a search returns no results.
	FallbackToEngine bool
	// Recreate drops and recreates the table at startup and rebuilds it from the
	// database: what a changed TableOptions or a drifted table needs.
	Recreate bool
}

// Defaults for the ManticoreConfig fields left zero.
const (
	DefaultManticoreDSN               = "tcp(127.0.0.1:9306)/"
	DefaultManticoreTable             = "enode_sources"
	DefaultManticoreTableOptions      = "min_infix_len='2' charset_table='non_cont' ngram_len='1' ngram_chars='cont'"
	DefaultManticoreTimeout           = 2 * time.Second
	DefaultManticoreBatchSize         = 500
	DefaultManticoreQueueSize         = 20000
	DefaultManticoreReconcileInterval = 24 * time.Hour
)

const (
	// manticoreFlushInterval is the longest a queued document waits for a batch to
	// fill before it is written anyway.
	manticoreFlushInterval = 250 * time.Millisecond
	// manticoreRetryInterval is how often a Manticore that was unreachable at
	// startup is tried again.
	manticoreRetryInterval = 30 * time.Second
	// manticoreDirtyCheck is how soon a dropped write leads to a reconcile pass.
	manticoreDirtyCheck = time.Minute
	// manticoreSetupTimeout bounds connecting and checking the table.
	manticoreSetupTimeout = 30 * time.Second
	// manticoreWriteTimeout bounds one write statement.
	manticoreWriteTimeout = 30 * time.Second
	// manticoreStateID is the id of the one row of the state table.
	manticoreStateID = 1
	// manticoreLogEvery spaces out the warnings a failing Manticore would
	// otherwise log on every search and every offer.
	manticoreLogEvery = time.Minute
	// manticoreStatusTimeout bounds the row count the admin Runtime tab reads.
	manticoreStatusTimeout = time.Second
	// manticoreFieldWeights ranks a hit in the file name above one in the tags.
	manticoreFieldWeights = "field_weights=(name=10, title=2, artist=2, album=2)"
)

// ManticoreEngine is a storage engine whose searches Manticore answers. It embeds
// the database engine and passes everything else through to it; offers,
// disconnects and the cleanup sweep are mirrored into the index as they happen.
//
// The index is one document per source row, keyed by (file, client), so a
// search groups the matching sources back into files and counts them as it goes:
// the sources and completed a result carries are what the database's counter
// refresh computes, without being written anywhere.
//
// Writes go through a queue and never hold up an offer. Whatever the queue drops
// or Manticore refuses sets the index dirty, and a reconcile pass then rewrites
// every source from the database and deletes what the database no longer has.
type ManticoreEngine struct {
	Engine

	cfg ManticoreConfig
	db  *sql.DB
	// bumpOnDisconnect mirrors the mongodb engine, which stamps time_offer on the
	// sources of a client that leaves; mysql keeps the time of the last offer.
	bumpOnDisconnect bool

	// up is set once the table is checked; nothing is written before.
	up atomic.Bool
	// ready is set once a reconcile pass has finished on the table, in this run or
	// an earlier one (the state table remembers); until then every search runs on
	// the database.
	ready atomic.Bool
	// dirty is set when a write was lost, and cleared when a pass starts.
	dirty atomic.Bool
	// pass is the number of the latest reconcile pass, stamped on every document
	// written since it started.
	pass atomic.Uint64

	queue     chan manticoreOp
	stop      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once

	indexed     atomic.Uint64
	dropped     atomic.Uint64
	failures    atomic.Uint64
	unsupported atomic.Uint64
	lastWarning atomic.Int64

	// passWritten counts the documents of the pass that is running, from
	// passStarted (unix nanoseconds; 0 when no pass runs).
	passWritten atomic.Uint64
	passStarted atomic.Int64
	// statusMu guards lastPass and lastError, which only Status reads.
	statusMu    sync.Mutex
	lastPass    ManticorePass
	lastError   string
	lastErrorAt time.Time
}

// ManticoreStatus is what the admin Runtime tab shows of the index.
type ManticoreStatus struct {
	Table string
	// Up is set once Manticore answered and the table was checked.
	Up bool
	// Ready is set once searches run on Manticore instead of the database.
	Ready bool
	// Documents is the table's row count, or -1 when it could not be read.
	Documents int64
	// Filling is set while a reconcile pass runs; PassWritten documents of pass
	// Pass were written since PassStarted.
	Filling     bool
	Pass        uint64
	PassWritten uint64
	PassStarted time.Time
	// LastPass is the latest pass that finished; its Number is 0 before the first.
	LastPass ManticorePass
	// Dirty is set when a write was lost and the next pass will repair it.
	Dirty       bool
	Indexed     uint64
	Dropped     uint64
	Failures    uint64
	Unsupported uint64
	// LastError is the latest failure, with the DSN taken out, and when it
	// happened; empty if none.
	LastError   string
	LastErrorAt time.Time
}

// ManticorePass is one finished reconcile pass.
type ManticorePass struct {
	Number   uint64
	Written  uint64
	Orphans  int64
	Took     time.Duration
	Finished time.Time
}

// manticoreOp is one entry of the write queue: documents to write, or a client
// whose sources went offline.
type manticoreOp struct {
	docs      []manticoreDoc
	offline   bool
	clientKey uint64
	at        int64
}

// manticoreDoc is one source row as the table stores it.
type manticoreDoc struct {
	id, fileKey, clientKey uint64
	hash                   string
	size                   uint64
	name, title, artist    string
	album, typ, ext, codec string
	length, bitrate        uint32
	complete, online       bool
	timeOffer              int64
	srcID                  uint32
	srcPort                uint16
}

// NewManticoreEngine wraps inner. Nothing is connected until Init.
func NewManticoreEngine(inner Engine, cfg ManticoreConfig) (*ManticoreEngine, error) {
	cfg = cfg.withDefaults()
	dsn, err := manticoreDSN(cfg.DSN)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("manticore: opening %s: %w", cfg.DSN, err)
	}
	// The writer and the reconcile pass hold one connection each; searches are
	// short. Manticore is less forgiving than MySQL about a large idle pool.
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Hour)
	_, mongo := inner.(*MongoDBEngine)
	return &ManticoreEngine{
		Engine:           inner,
		cfg:              cfg,
		db:               db,
		bumpOnDisconnect: mongo,
		queue:            make(chan manticoreOp, cfg.QueueSize),
		stop:             make(chan struct{}),
	}, nil
}

// UnwrapEngine returns the engine underneath any wrapper that has one, for a
// caller that needs a capability of the database engine itself.
func UnwrapEngine(engine Engine) Engine {
	for {
		w, ok := engine.(interface{ Unwrap() Engine })
		if !ok {
			return engine
		}
		engine = w.Unwrap()
	}
}

// Unwrap returns the database engine.
func (m *ManticoreEngine) Unwrap() Engine {
	return m.Engine
}

// Init starts the database engine, then the index. An unreachable Manticore does
// not stop the server: searches run on the database while it is retried. A table
// that does not match this build does, because only the operator can decide to
// rebuild it.
func (m *ManticoreEngine) Init() error {
	if err := m.Engine.Init(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), manticoreSetupTimeout)
	err := m.setup(ctx)
	cancel()
	if errors.Is(err, ErrManticoreSchemaDrift) {
		return err
	}
	if err != nil {
		m.setError(err)
		logging.Warnf("manticore: %v; searches run on the database until it is reachable", err)
	}
	m.wg.Add(2)
	go m.writeLoop()
	go m.reconcileLoop(err != nil)
	return nil
}

// Close stops the writer after it has written what is queued, then closes the
// database engine.
func (m *ManticoreEngine) Close() error {
	m.closeOnce.Do(func() {
		close(m.stop)
		m.wg.Wait()
		_ = m.db.Close()
	})
	return m.Engine.Close()
}

func (m *ManticoreEngine) AddFile(file File, info ClientInfo) {
	m.Engine.AddFile(file, info)
	m.enqueue(manticoreOp{docs: offerDocs([]File{file}, info, time.Now())})
}

func (m *ManticoreEngine) AddFiles(files []File, info ClientInfo) {
	m.Engine.AddFiles(files, info)
	m.enqueue(manticoreOp{docs: offerDocs(files, info, time.Now())})
}

func (m *ManticoreEngine) Disconnect(info ClientInfo) {
	m.Engine.Disconnect(info)
	m.enqueue(manticoreOp{offline: true, clientKey: manticoreKey(info.Hash), at: time.Now().Unix()})
}

// CleanupStale runs the database's sweep, then deletes the same offline sources
// from the index: online = 0 AND time_offer < cutoff is the predicate both
// engines' source pass uses. A client the database expired by its login time has
// no source the predicate misses — none can be newer than the client's last
// session — so the two agree up to the writes still in the queue.
func (m *ManticoreEngine) CleanupStale(maxAge time.Duration, opts CleanupOptions) (CleanupResult, error) {
	cutoff := time.Now().Add(-maxAge)
	result, err := m.Engine.CleanupStale(maxAge, opts)
	if err != nil || !m.up.Load() {
		return result, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), manticoreWriteTimeout)
	defer cancel()
	if _, derr := m.db.ExecContext(ctx,
		"DELETE FROM "+m.cfg.Table+" WHERE online = 0 AND time_offer < ?", cutoff.Unix()); derr != nil {
		m.lost(0, fmt.Errorf("deleting stale sources: %w", derr))
	}
	return result, nil
}

// FindBySearch answers from Manticore once the index is complete, and from the
// database before that, for a tree Manticore cannot express, and — when
// FallbackToEngine is on — when Manticore fails.
func (m *ManticoreEngine) FindBySearch(expr *SearchExpr) []File {
	if !m.ready.Load() {
		return m.Engine.FindBySearch(expr)
	}
	// The same guard the database engines apply, so a search does not answer
	// differently depending on which of them ran it.
	if SearchNeedsScan(expr, manticoreMinInfix) {
		return nil
	}
	query, outcome := buildManticoreQuery(expr)
	switch outcome {
	case manticoreEmpty:
		return nil
	case manticoreUnsupported:
		m.unsupported.Add(1)
		logging.Debugf("manticore: search tree not expressible, running it on the database")
		return m.Engine.FindBySearch(expr)
	}
	files, err := m.search(query, MaxSearchResults)
	if err == nil {
		return files
	}
	m.failures.Add(1)
	m.setError(fmt.Errorf("search: %w", err))
	if m.cfg.FallbackToEngine {
		m.warn("manticore: search failed, running it on the database: %v", err)
		return m.Engine.FindBySearch(expr)
	}
	m.warn("manticore: search failed: %v", err)
	return nil
}

// Status reports the state of the index. The row count is read from Manticore
// with a short timeout, so a slow index shows as -1 rather than stalling the page.
func (m *ManticoreEngine) Status() ManticoreStatus {
	st := ManticoreStatus{
		Table:       m.cfg.Table,
		Up:          m.up.Load(),
		Ready:       m.ready.Load(),
		Documents:   -1,
		Pass:        m.pass.Load(),
		Dirty:       m.dirty.Load(),
		Indexed:     m.indexed.Load(),
		Dropped:     m.dropped.Load(),
		Failures:    m.failures.Load(),
		Unsupported: m.unsupported.Load(),
	}
	if started := m.passStarted.Load(); started != 0 {
		st.Filling = true
		st.PassWritten = m.passWritten.Load()
		st.PassStarted = time.Unix(0, started)
	}
	m.statusMu.Lock()
	st.LastPass = m.lastPass
	st.LastError, st.LastErrorAt = m.lastError, m.lastErrorAt
	m.statusMu.Unlock()
	if st.Up {
		ctx, cancel := context.WithTimeout(context.Background(), manticoreStatusTimeout)
		defer cancel()
		var count int64
		if err := m.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+m.cfg.Table).Scan(&count); err == nil {
			st.Documents = count
		}
	}
	return st
}

// withDefaults fills the fields left zero. ReconcileInterval stays zero if it
// is: that turns the periodic pass off.
func (c ManticoreConfig) withDefaults() ManticoreConfig {
	if c.DSN == "" {
		c.DSN = DefaultManticoreDSN
	}
	if c.Table == "" {
		c.Table = DefaultManticoreTable
	}
	if c.TableOptions == "" {
		c.TableOptions = DefaultManticoreTableOptions
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultManticoreTimeout
	}
	if c.BatchSize <= 0 {
		c.BatchSize = DefaultManticoreBatchSize
	}
	if c.QueueSize <= 0 {
		c.QueueSize = DefaultManticoreQueueSize
	}
	return c
}

// manticoreDSN fixes up a DSN for Manticore. It has no prepared statements, so
// every query with a placeholder must be interpolated client-side, and no
// schemas, so a database name would make every connection fail its USE.
func manticoreDSN(dsn string) (string, error) {
	cfg, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return "", fmt.Errorf("manticore: dsn %q: %w", dsn, err)
	}
	cfg.InterpolateParams = true
	cfg.DBName = ""
	return cfg.FormatDSN(), nil
}

// setup connects, makes sure the table is the one this build writes, and reads
// back where the previous run left it.
func (m *ManticoreEngine) setup(ctx context.Context) error {
	if err := m.db.PingContext(ctx); err != nil {
		return fmt.Errorf("connecting to %s: %w", m.cfg.DSN, err)
	}
	if m.cfg.Recreate {
		if err := m.recreateTable(ctx); err != nil {
			return err
		}
		logging.Infof("manticore: recreated table %s; it is rebuilt from the database in the background", m.cfg.Table)
	} else {
		if _, err := m.db.ExecContext(ctx, manticoreCreateStatement(m.cfg.Table, m.cfg.TableOptions)); err != nil {
			return fmt.Errorf("manticore: creating table %s: %w", m.cfg.Table, err)
		}
		if err := m.checkTable(ctx); err != nil {
			return err
		}
	}
	if _, err := m.db.ExecContext(ctx, manticoreStateStatement(m.cfg.Table)); err != nil {
		return fmt.Errorf("manticore: creating table %s: %w", manticoreStateTable(m.cfg.Table), err)
	}
	// The database engines start with every source offline, and so does the index.
	if _, err := m.db.ExecContext(ctx, "UPDATE "+m.cfg.Table+" SET online = 0 WHERE online = 1"); err != nil {
		return fmt.Errorf("manticore: resetting the online flags of %s: %w", m.cfg.Table, err)
	}
	// Manticore answers MAX over an empty table with no row at all, not a NULL.
	var pass sql.NullInt64
	err := m.db.QueryRowContext(ctx, "SELECT MAX(pass) FROM "+m.cfg.Table).Scan(&pass)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("manticore: reading the last pass of %s: %w", m.cfg.Table, err)
	}
	finished, err := m.readFinishedPass(ctx)
	if err != nil {
		return err
	}
	m.pass.Store(max(uint64(max(pass.Int64, 0)), finished.Number))
	var count int64
	if err := m.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+m.cfg.Table).Scan(&count); err != nil {
		return fmt.Errorf("manticore: counting %s: %w", m.cfg.Table, err)
	}
	// A table a pass has filled serves searches at once; the startup pass only
	// brings it up to date. One no pass has finished on — empty, or cut off by a
	// restart halfway through the first fill — would miss files the database has,
	// so it waits for the pass.
	m.ready.Store(finished.Number > 0 && count > 0)
	m.statusMu.Lock()
	m.lastPass = finished
	m.statusMu.Unlock()
	m.up.Store(true)
	if m.ready.Load() {
		logging.Infof("manticore: table %s holds %d source(s), filled by pass %d at %s",
			m.cfg.Table, count, finished.Number, finished.Finished.Format(time.RFC3339))
	} else {
		logging.Infof("manticore: table %s holds %d source(s) and no pass has finished on it; "+
			"searches run on the database until the startup pass does", m.cfg.Table, count)
	}
	return nil
}

// writeLoop drains the queue: documents are batched, and a disconnect writes the
// batch before it so the order of the queue is the order of the writes.
func (m *ManticoreEngine) writeLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(manticoreFlushInterval)
	defer ticker.Stop()
	var pending []manticoreDoc
	flush := func() {
		if len(pending) > 0 {
			m.write(pending)
			pending = pending[:0]
		}
	}
	handle := func(op manticoreOp) {
		if op.offline {
			flush()
			m.markOffline(op)
			return
		}
		pending = append(pending, op.docs...)
		if len(pending) >= m.cfg.BatchSize {
			flush()
		}
	}
	for {
		select {
		case op := <-m.queue:
			handle(op)
		case <-ticker.C:
			flush()
		case <-m.stop:
			for {
				select {
				case op := <-m.queue:
					handle(op)
				default:
					flush()
					return
				}
			}
		}
	}
}

// reconcileLoop runs a pass when one is due, one per interval after it, and one
// whenever a write was lost. With retrySetup it first waits for Manticore to come
// up.
func (m *ManticoreEngine) reconcileLoop(retrySetup bool) {
	defer m.wg.Done()
	if retrySetup && !m.retrySetup() {
		return
	}
	first, scheduled := m.firstPassDelay(time.Now())
	if scheduled && first > 0 {
		logging.Infof("manticore: the last pass finished less than %s ago; the next one runs in %s",
			m.cfg.ReconcileInterval, first.Round(time.Second))
	}
	if !scheduled {
		logging.Infof("manticore: the periodic pass is off; a pass runs only after a lost write")
	}
	var due <-chan time.Time
	timer := time.NewTimer(first)
	defer timer.Stop()
	if scheduled {
		due = timer.C
	} else {
		timer.Stop()
	}
	dirty := time.NewTicker(manticoreDirtyCheck)
	defer dirty.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-due:
			m.reconcile()
			due = m.scheduleNextPass(timer)
		case <-dirty.C:
			if m.dirty.Load() {
				m.reconcile()
				due = m.scheduleNextPass(timer)
			}
		}
	}
}

// retrySetup tries setup until it succeeds, and reports false when the engine
// closed first or the table turned out not to be this build's.
func (m *ManticoreEngine) retrySetup() bool {
	ticker := time.NewTicker(manticoreRetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return false
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), manticoreSetupTimeout)
		err := m.setup(ctx)
		cancel()
		switch {
		case err == nil:
			m.setError(nil)
			logging.Infof("manticore: reachable again at %s", m.cfg.DSN)
			return true
		case errors.Is(err, ErrManticoreSchemaDrift):
			m.setError(err)
			logging.Errorf("%v; searches keep running on the database", err)
			return false
		}
		m.setError(err)
		logging.Debugf("manticore: still unreachable: %v", err)
	}
}

// reconcile rewrites every source of the database into the index under a new
// pass number, then deletes the documents no pass reached: those the database
// no longer has. A document an offer writes while the pass runs carries the new
// number or a time_offer after the start, so it survives the delete either way.
func (m *ManticoreEngine) reconcile() {
	browser, ok := m.Engine.(SourceBrowser)
	if !ok {
		logging.Warnf("manticore: the storage engine cannot list its sources, so the index is never reconciled")
		return
	}
	pass := m.pass.Add(1)
	start := time.Now()
	m.dirty.Store(false)
	m.passWritten.Store(0)
	m.passStarted.Store(start.UnixNano())
	defer m.passStarted.Store(0)
	var cursor []byte
	written := 0
	for {
		select {
		case <-m.stop:
			return
		default:
		}
		sources, next, err := browser.BrowseSources(cursor, MaxBrowsePage)
		if err != nil {
			m.lost(0, fmt.Errorf("reconcile pass %d: reading sources: %w", pass, err))
			return
		}
		docs := make([]manticoreDoc, len(sources))
		for i, s := range sources {
			docs[i] = sourceDoc(s)
		}
		if err := m.replace(docs, pass); err != nil {
			m.lost(0, fmt.Errorf("reconcile pass %d: %w", pass, err))
			return
		}
		written += len(docs)
		m.passWritten.Add(uint64(len(docs)))
		if next == nil {
			break
		}
		cursor = next
	}
	ctx, cancel := context.WithTimeout(context.Background(), manticoreWriteTimeout)
	defer cancel()
	res, err := m.db.ExecContext(ctx, "DELETE FROM "+m.cfg.Table+" WHERE pass < ? AND time_offer < ?",
		pass, start.Unix())
	if err != nil {
		m.lost(0, fmt.Errorf("reconcile pass %d: deleting orphans: %w", pass, err))
		return
	}
	orphans, _ := res.RowsAffected()
	finished := ManticorePass{Number: pass, Written: uint64(written), Orphans: orphans,
		Took: time.Since(start), Finished: time.Now()}
	// The index is complete either way; a lost record only costs the next start a
	// pass on the database.
	if err := m.storeFinishedPass(finished); err != nil {
		m.setError(err)
		logging.Warnf("manticore: %v; the next start searches the database until its startup pass finishes", err)
	}
	m.ready.Store(true)
	m.statusMu.Lock()
	m.lastPass = finished
	m.statusMu.Unlock()
	logging.Infof("manticore: reconcile pass %d wrote %d source(s) and removed %d orphan(s) in %s",
		pass, written, orphans, time.Since(start).Round(time.Millisecond))
}

// enqueue hands an op to the writer, or drops it when the queue is full: an offer
// must never wait on the index.
func (m *ManticoreEngine) enqueue(op manticoreOp) {
	if !op.offline && len(op.docs) == 0 {
		return
	}
	select {
	case m.queue <- op:
	default:
		m.lost(max(len(op.docs), 1), errors.New("the write queue is full"))
	}
}

// write stores a batch under the current pass.
func (m *ManticoreEngine) write(docs []manticoreDoc) {
	if !m.up.Load() {
		m.dropped.Add(uint64(len(docs)))
		m.dirty.Store(true)
		return
	}
	if err := m.replace(docs, m.pass.Load()); err != nil {
		m.lost(len(docs), err)
	}
}

// markOffline mirrors a disconnect.
func (m *ManticoreEngine) markOffline(op manticoreOp) {
	if !m.up.Load() {
		m.dirty.Store(true)
		return
	}
	statement := "UPDATE " + m.cfg.Table + " SET online = 0 WHERE client_key = ?"
	args := []any{op.clientKey}
	if m.bumpOnDisconnect {
		statement = "UPDATE " + m.cfg.Table + " SET online = 0, time_offer = ? WHERE client_key = ?"
		args = []any{op.at, op.clientKey}
	}
	ctx, cancel := context.WithTimeout(context.Background(), manticoreWriteTimeout)
	defer cancel()
	if _, err := m.db.ExecContext(ctx, statement, args...); err != nil {
		m.lost(1, fmt.Errorf("marking a client offline: %w", err))
	}
}

// replace writes documents, BatchSize to a statement. REPLACE, because a re-offer
// rewrites the same (file, client) document and Manticore has no upsert.
func (m *ManticoreEngine) replace(docs []manticoreDoc, pass uint64) error {
	const columns = "id, name, title, artist, album, file_key, file_hash, size, client_key, type, ext, codec, " +
		"length, bitrate, complete, online, time_offer, src_id, src_port, pass"
	const row = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	for start := 0; start < len(docs); start += m.cfg.BatchSize {
		batch := docs[start:min(start+m.cfg.BatchSize, len(docs))]
		args := make([]any, 0, 20*len(batch))
		for _, d := range batch {
			args = append(args, d.id, d.name, d.title, d.artist, d.album, d.fileKey, d.hash, clampInt64(d.size),
				d.clientKey, d.typ, d.ext, d.codec, d.length, d.bitrate, boolToTinyInt(d.complete),
				boolToTinyInt(d.online), d.timeOffer, d.srcID, d.srcPort, pass)
		}
		statement := "REPLACE INTO " + m.cfg.Table + " (" + columns + ") VALUES " + sqlRows(row, len(batch))
		ctx, cancel := context.WithTimeout(context.Background(), manticoreWriteTimeout)
		_, err := m.db.ExecContext(ctx, statement, args...)
		cancel()
		if err != nil {
			return fmt.Errorf("writing %d source(s): %w", len(batch), err)
		}
		m.indexed.Add(uint64(len(batch)))
	}
	return nil
}

// search runs a rendered tree. One row per file: its sources are grouped, the
// online one offered last stands for the group, and the counters are counted
// over all of them, as the database's counter refresh counts them.
func (m *ManticoreEngine) search(query manticoreQuery, limit int) ([]File, error) {
	var where []string
	var args []any
	if query.match != "" {
		where = append(where, "MATCH(?)")
		args = append(args, query.match)
	}
	if query.filter != "" {
		where = append(where, query.filter)
		args = append(args, query.args...)
	}
	var sb strings.Builder
	sb.WriteString("SELECT name, file_hash, size, type, title, artist, album, length, bitrate, codec, " +
		"src_id, src_port, online, COUNT(*) AS sources, SUM(complete) AS completed, WEIGHT() AS w FROM ")
	sb.WriteString(m.cfg.Table)
	if len(where) > 0 {
		sb.WriteString(" WHERE ")
		sb.WriteString(strings.Join(where, " AND "))
	}
	sb.WriteString(" GROUP BY file_key WITHIN GROUP ORDER BY online DESC, time_offer DESC")
	having, havingArgs := query.having()
	if having != "" {
		sb.WriteString(" HAVING ")
		sb.WriteString(having)
		args = append(args, havingArgs...)
	}
	// Ranked by relevance, then by how widely the file is shared: the database
	// engines return an arbitrary 1000 of a large match, this the best 1000.
	fmt.Fprintf(&sb, " ORDER BY w DESC, sources DESC LIMIT %d OPTION max_matches=%d, max_query_time=%d, %s",
		limit, limit, m.cfg.Timeout.Milliseconds(), manticoreFieldWeights)

	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout+time.Second)
	defer cancel()
	rows, err := m.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	postFilter := query.agg != nil && having == ""
	var out []File
	for rows.Next() {
		var (
			f                  File
			hash               string
			online             int
			sources, completed uint64
			weight             sql.RawBytes
		)
		if err := rows.Scan(&f.Name, &hash, &f.Size, &f.Type, &f.Title, &f.Artist, &f.Album, &f.Runtime,
			&f.Bitrate, &f.Codec, &f.SourceID, &f.SourcePort, &online, &sources, &completed, &weight); err != nil {
			return nil, err
		}
		if postFilter && !query.agg.matches(sources, completed) {
			continue
		}
		raw, err := hex.DecodeString(hash)
		if err != nil {
			continue
		}
		f.Hash = raw
		f.Sources = uint32(min(sources, math.MaxUint32))
		f.Completed = uint32(min(completed, math.MaxUint32))
		// Only an online source is one a client can be sent to; the database engines
		// clear a departed client's address off the file the same way.
		if online == 0 {
			f.SourceID, f.SourcePort = 0, 0
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// lost records n documents that did not reach the index and sets it dirty, so the
// next reconcile pass rewrites them.
func (m *ManticoreEngine) lost(n int, err error) {
	m.dropped.Add(uint64(n))
	m.failures.Add(1)
	m.dirty.Store(true)
	m.setError(err)
	m.warn("manticore: %v; the next reconcile pass repairs the index", err)
}

// readFinishedPass reads the last pass that finished on the table; its Number is
// 0 when none has.
func (m *ManticoreEngine) readFinishedPass(ctx context.Context) (ManticorePass, error) {
	var number, written, orphans, tookMs, finished int64
	err := m.db.QueryRowContext(ctx, "SELECT pass, written, orphans, took_ms, finished FROM "+
		manticoreStateTable(m.cfg.Table)+" WHERE id = ?", manticoreStateID).
		Scan(&number, &written, &orphans, &tookMs, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return ManticorePass{}, nil
	}
	if err != nil {
		return ManticorePass{}, fmt.Errorf("manticore: reading %s: %w", manticoreStateTable(m.cfg.Table), err)
	}
	return ManticorePass{Number: uint64(max(number, 0)), Written: uint64(max(written, 0)), Orphans: orphans,
		Took: time.Duration(tookMs) * time.Millisecond, Finished: time.Unix(finished, 0)}, nil
}

// storeFinishedPass records a pass that finished, so the next start knows the
// table is complete.
func (m *ManticoreEngine) storeFinishedPass(p ManticorePass) error {
	ctx, cancel := context.WithTimeout(context.Background(), manticoreWriteTimeout)
	defer cancel()
	_, err := m.db.ExecContext(ctx, "REPLACE INTO "+manticoreStateTable(m.cfg.Table)+
		" (id, pass, written, orphans, took_ms, finished) VALUES (?, ?, ?, ?, ?, ?)",
		manticoreStateID, p.Number, p.Written, p.Orphans, p.Took.Milliseconds(), p.Finished.Unix())
	if err != nil {
		return fmt.Errorf("manticore: recording pass %d as finished: %w", p.Number, err)
	}
	return nil
}

// firstPassDelay is how long after now the first pass of this run is due, and
// false when none is scheduled. A table no pass has finished on is filled at
// once. A filled one is next due an interval after its last pass finished, so a
// restart does not rewrite an index that is still current; with the periodic
// pass off, it is only rewritten after a lost write.
func (m *ManticoreEngine) firstPassDelay(now time.Time) (time.Duration, bool) {
	if !m.ready.Load() {
		return 0, true
	}
	if m.cfg.ReconcileInterval <= 0 {
		return 0, false
	}
	m.statusMu.Lock()
	finished := m.lastPass.Finished
	m.statusMu.Unlock()
	return max(finished.Add(m.cfg.ReconcileInterval).Sub(now), 0), true
}

// scheduleNextPass sets timer one interval ahead and returns its channel, or nil
// when the periodic pass is off.
func (m *ManticoreEngine) scheduleNextPass(timer *time.Timer) <-chan time.Time {
	if m.cfg.ReconcileInterval <= 0 {
		return nil
	}
	timer.Reset(m.cfg.ReconcileInterval)
	return timer.C
}

// setError records err for Status, or clears it with nil. The DSN may carry a
// password, so it never reaches the admin page.
func (m *ManticoreEngine) setError(err error) {
	text, at := "", time.Time{}
	if err != nil {
		text, at = strings.ReplaceAll(err.Error(), m.cfg.DSN, "manticore"), time.Now()
	}
	m.statusMu.Lock()
	m.lastError, m.lastErrorAt = text, at
	m.statusMu.Unlock()
}

// warn logs at most once per manticoreLogEvery: a Manticore that is down would
// otherwise log on every search and every offer.
func (m *ManticoreEngine) warn(format string, args ...any) {
	now := time.Now().UnixNano()
	last := m.lastWarning.Load()
	if now-last < int64(manticoreLogEvery) || !m.lastWarning.CompareAndSwap(last, now) {
		return
	}
	logging.Warnf(format, args...)
}

// offerDocs turns one client's offer into documents, normalized exactly as the
// database engines store it.
func offerDocs(files []File, info ClientInfo, now time.Time) []manticoreDoc {
	batch := prepareOfferBatch(files)
	docs := make([]manticoreDoc, len(batch))
	for i, f := range batch {
		docs[i] = sourceDoc(IndexedSource{
			File:       f,
			ClientHash: info.Hash,
			ClientID:   info.ID,
			ClientPort: info.Port,
			Online:     true,
			TimeOffer:  now,
		})
	}
	return docs
}

// sourceDoc is the document of one source row.
func sourceDoc(s IndexedSource) manticoreDoc {
	f := s.File
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], f.Size)
	return manticoreDoc{
		id:        manticoreKey(f.Hash, size[:], s.ClientHash),
		fileKey:   manticoreKey(f.Hash, size[:]),
		clientKey: manticoreKey(s.ClientHash),
		hash:      hex.EncodeToString(f.Hash),
		size:      f.Size,
		name:      f.Name,
		title:     f.Title,
		artist:    f.Artist,
		album:     f.Album,
		typ:       f.Type,
		ext:       NormalizeExt(f.Name),
		codec:     f.Codec,
		length:    f.Runtime,
		bitrate:   f.Bitrate,
		complete:  f.Completed > 0,
		online:    s.Online,
		timeOffer: s.TimeOffer.Unix(),
		srcID:     s.ClientID,
		srcPort:   s.ClientPort,
	}
}

// manticoreKey derives a document id or grouping key: FNV-1a over the parts,
// kept positive and non-zero because Manticore stores both as signed bigints and
// reserves id 0. The parts are fixed-width where it matters (a 16-byte hash, an
// 8-byte size), so no two different inputs run together into one.
func manticoreKey(parts ...[]byte) uint64 {
	h := fnv.New64a()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	key := h.Sum64() & math.MaxInt64
	if key == 0 {
		return 1
	}
	return key
}
