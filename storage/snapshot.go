package storage

import (
	"bufio"
	"compress/gzip"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"enode/logging"
)

// On-disk persistence for MemoryEngine.
//
// The memory engine is the default (see NewEngine) and, unlike the MySQL and
// MongoDB engines, loses everything on restart. This writes its index to a gob
// file periodically and on shutdown, and reads it back at startup.
//
// # Parity with the database engines
//
// The snapshot deliberately reproduces what a mysql- or mongodb-backed server
// looks like after a restart, rather than what the memory engine held when it was
// written. Both DB engines run `UPDATE clients/sources SET online = 0` in Init
// (engine_mysql.go, engine_mongodb.go), their source lookups require
// `online = 1` on both the source and its client, and their searches do not filter
// on online at all. So after a restart a DB-backed server serves searchable files
// with no sources, and reports zero connected clients.
//
// The file therefore carries clients, files and sources — the same three entities
// the DB engines persist — but LoadSnapshot installs only the files. Clients and
// sources are counted and logged, then dropped, which is what `online = 0` amounts
// to for an engine that has no offline representation. Installing them instead
// would publish sources for peers that are not connected, and hand out LowID ids
// that the pool has since reassigned to somebody else.
//
// File.Sources is restored as written even though the live source lists come back
// empty. That is not a bug: MySQL's files.sources is a COUNT(*) over all source
// rows, online or not, and nothing recomputes it at startup either. CleanupStale
// brings both engines back in line on its first sweep.
//
// `servers` is not persisted, because no engine persists it — it is a plain in-RAM
// slice on all three, rebuilt from the config on every boot by seedServers.
//
// # What cannot be reproduced
//
// MemoryEngine.Disconnect deletes the client and strips its sources, where the DB
// engines retain both offline until CleanupStale expires them. A snapshot can only
// ever contain what was online when it was written, so the rolling window of
// recently-departed peers that a DB-backed server keeps has no equivalent here.
// Closing that gap means adding online flags and timestamps to the in-RAM structs.

const (
	// snapshotMagic identifies the format. Checked before anything is decoded, so
	// pointing the config at an unrelated file fails with a clear message instead
	// of a gob type error.
	snapshotMagic = "enode-storage-snapshot"

	// snapshotVersion is the format revision. An unknown version is refused rather
	// than guessed at: a half-understood index is worse than an empty one, because
	// the server would serve it.
	snapshotVersion = 1

	// snapshotBatchSize is how many files are copied out of the maps per lock
	// acquisition. The write must not hold the engine's lock across the whole file
	// — at the scale in docs/memory-footprint.md that is tens of seconds during
	// which no client can offer a file — so the keys are captured once and the
	// entries are copied in batches, releasing the lock between each.
	snapshotBatchSize = 10000

	// snapshotHashLen is the ed2k hash width, and the stride of the flat key buffer.
	snapshotHashLen = 16
)

// SnapshotHeader is the first value in the stream.
//
// The counts are what the engine held when the write started. They are advisory —
// the maps can change between the header and the batches — and are used to pre-size
// the maps on load and to report progress.
type SnapshotHeader struct {
	Magic        string
	Version      uint32
	WrittenAt    time.Time
	Engine       string
	Files        uint64
	Clients      uint64
	Sources      uint64
	NextClientID uint64
}

// SnapshotSources is one file's source list, keyed by the file hash so the loader
// can match it to a file without relying on ordering.
type SnapshotSources struct {
	FileHash []byte
	Sources  []Source
}

// SnapshotBatch is one chunk of the stream. Any of the three slices may be empty;
// the decoder reads batches until io.EOF.
type SnapshotBatch struct {
	Files   []File
	Sources []SnapshotSources
	Clients []ClientInfo
}

// SnapshotStats reports what a write produced or a load consumed. For a load,
// Clients and Sources are what the file contained, not what was installed — see
// the parity note above.
type SnapshotStats struct {
	Files   int
	Clients int
	Sources int
	Bytes   int64
	Took    time.Duration
}

// Snapshotter is implemented by engines that can persist themselves to a file.
//
// It is a capability interface rather than part of Engine: the DB engines already
// persist, so requiring them to carry a no-op WriteSnapshot would be noise. Callers
// type-assert, and an engine that does not implement it simply is not snapshotted.
type Snapshotter interface {
	WriteSnapshot(path string, compress bool) (SnapshotStats, error)
}

// StartSnapshot writes a snapshot every interval and returns a stop function that
// writes one final time.
//
// It mirrors StartCleanup's shape, with the refinement startServerMetPersistence
// uses: the write runs on the stop path too, so an orderly shutdown never loses the
// interval's worth of index that has not been written yet. The stopper is
// sync.Once-guarded because main registers it with defer alongside several other
// shutdown hooks and a double close would panic.
//
// An engine that does not implement Snapshotter is not an error — it persists
// natively — so this logs once and returns a no-op stopper.
func StartSnapshot(engine Engine, path string, interval time.Duration, compress bool) func() {
	noop := func() {}
	if path == "" {
		logging.Warnf("storage snapshot: no file configured, persistence disabled")
		return noop
	}
	snapshotter, ok := engine.(Snapshotter)
	if !ok {
		logging.Infof("storage snapshot: engine persists natively, snapshot not needed")
		return noop
	}
	if interval <= 0 {
		interval = defaultSnapshotInterval
	}

	write := func(reason string) {
		stats, err := snapshotter.WriteSnapshot(path, compress)
		if err != nil {
			logging.Warnf("storage snapshot: cannot write %s: %v", path, err)
			return
		}
		if stats.Files == 0 {
			logging.Debugf("storage snapshot: nothing to write (%s)", reason)
			return
		}
		logging.Infof("storage snapshot: wrote %d file(s), %d source(s), %d client(s) to %s "+
			"(%s, %s, %s)", stats.Files, stats.Sources, stats.Clients, path,
			humanBytes(stats.Bytes), stats.Took.Round(time.Millisecond), reason)
	}

	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				write("periodic")
			case <-done:
				write("shutdown")
				return
			}
		}
	}()

	// The stopper blocks until the final write has actually finished. Closing the
	// channel and returning would let main's remaining defers run and the process
	// exit while the encoder is still streaming — which is not a theoretical race:
	// a snapshot of any size loses to process teardown every time.
	var once sync.Once
	return func() {
		once.Do(func() { close(done) })
		<-finished
	}
}

// WriteSnapshot writes the engine's index to path, atomically.
//
// The file is built under a temporary name in the same directory and renamed into
// place, so a crash mid-write cannot leave a truncated snapshot that the next start
// would read as a short index. Nothing is written when the engine holds no files:
// truncating a good snapshot to nothing — on a server that has just started, say —
// would throw away the very index the file exists to preserve.
func (m *MemoryEngine) WriteSnapshot(path string, compress bool) (SnapshotStats, error) {
	var stats SnapshotStats
	if path == "" {
		return stats, errors.New("snapshot path is empty")
	}
	start := time.Now()

	// One pass under the lock to capture the identity of everything to be written.
	// The keys go into a single flat buffer rather than a []string: at a few million
	// files the slice header per key costs more than the keys themselves.
	m.mu.RLock()
	header := SnapshotHeader{
		Magic:        snapshotMagic,
		Version:      snapshotVersion,
		WrittenAt:    time.Now(),
		Engine:       "memory",
		Files:        uint64(len(m.files)),
		Clients:      uint64(len(m.clients)),
		NextClientID: m.nextClientID,
	}
	for _, sources := range m.sources {
		header.Sources += uint64(len(sources))
	}
	keys := make([]byte, 0, len(m.files)*snapshotHashLen)
	for k := range m.files {
		if len(k) != snapshotHashLen {
			// Defensive: every key is a 16-byte hash string via hashKey. A short one
			// could not be matched to its sources on load.
			continue
		}
		keys = append(keys, k...)
	}
	clients := make([]ClientInfo, 0, len(m.clients))
	for _, info := range m.clients {
		clients = append(clients, cloneClientInfo(info))
	}
	m.mu.RUnlock()

	if len(keys) == 0 {
		return stats, nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return stats, fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return stats, fmt.Errorf("create temp snapshot: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed

	stats, err = writeSnapshotStream(tmp, header, keys, clients, compress, m.batchAt)
	if err != nil {
		_ = tmp.Close()
		return SnapshotStats{}, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return SnapshotStats{}, fmt.Errorf("flush snapshot: %w", err)
	}
	if info, statErr := tmp.Stat(); statErr == nil {
		stats.Bytes = info.Size()
	}
	if err := tmp.Close(); err != nil {
		return SnapshotStats{}, fmt.Errorf("close snapshot: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return SnapshotStats{}, fmt.Errorf("install snapshot: %w", err)
	}

	stats.Took = time.Since(start)
	return stats, nil
}

// LoadSnapshot reads path into the engine, installing files only.
//
// A missing file is reported as (zero, nil): no snapshot yet is the normal state on
// a first start, not an error. Clients and sources present in the file are counted
// and returned but not installed — see the parity note at the top of this file.
func (m *MemoryEngine) LoadSnapshot(path string) (SnapshotStats, error) {
	var stats SnapshotStats
	if path == "" {
		return stats, errors.New("snapshot path is empty")
	}
	start := time.Now()

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return stats, nil
		}
		return stats, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if info, statErr := f.Stat(); statErr == nil {
		stats.Bytes = info.Size()
	}

	reader, closeReader, err := snapshotReader(f)
	if err != nil {
		return SnapshotStats{}, fmt.Errorf("%s: %w", path, err)
	}
	defer closeReader()

	dec := gob.NewDecoder(reader)
	var header SnapshotHeader
	if err := dec.Decode(&header); err != nil {
		return SnapshotStats{}, fmt.Errorf("%s: cannot read the snapshot header: %w", path, err)
	}
	if header.Magic != snapshotMagic {
		return SnapshotStats{}, fmt.Errorf("%s: not an eNode storage snapshot (magic %q)", path, header.Magic)
	}
	if header.Version != snapshotVersion {
		return SnapshotStats{}, fmt.Errorf("%s: snapshot version %d, this build reads version %d",
			path, header.Version, snapshotVersion)
	}

	files := make(map[string]File, header.Files)
	for {
		var batch SnapshotBatch
		if err := dec.Decode(&batch); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// A truncated tail is tolerated: the batches already decoded are valid,
			// and refusing all of them would turn a partial write into an empty
			// index. Anything else is a real decode failure and is reported.
			if errors.Is(err, io.ErrUnexpectedEOF) {
				logging.Warnf("storage snapshot: %s ends mid-batch, keeping the %d file(s) read so far",
					path, len(files))
				break
			}
			return SnapshotStats{}, fmt.Errorf("%s: %w", path, err)
		}
		for _, file := range batch.Files {
			if len(file.Hash) != snapshotHashLen {
				continue
			}
			files[hashKey(file.Hash)] = file
		}
		// Counted for the log line, then dropped: restoring them would advertise
		// peers that are not connected. See the parity note above.
		for _, group := range batch.Sources {
			stats.Sources += len(group.Sources)
		}
		stats.Clients += len(batch.Clients)
	}
	stats.Files = len(files)

	m.mu.Lock()
	m.files = files
	// The source map is left empty rather than merged, matching `online = 0`, and
	// nextClientID keeps climbing so a restored StoreID can never be reissued to a
	// live session — the memory-engine equivalent of clients.id AUTO_INCREMENT.
	m.sources = make(map[string][]Source)
	if header.NextClientID > m.nextClientID {
		m.nextClientID = header.NextClientID
	}
	m.mu.Unlock()

	stats.Took = time.Since(start)
	return stats, nil
}

const defaultSnapshotInterval = 15 * time.Minute

// gzipMagic is the two-byte header every gzip stream starts with. Sniffing it lets
// a snapshot be read back whatever the current `compress` setting is, so flipping
// the config key does not orphan the file already on disk.
var gzipMagic = [2]byte{0x1f, 0x8b}

// batchAt copies the entries for keys[from:to] out of the maps under one read lock.
//
// Copying rather than referencing matters: Source carries []byte fields that AddFile
// would otherwise mutate in place under a later lock, while the gob encoder is still
// reading them.
func (m *MemoryEngine) batchAt(keys []byte, from, to int) SnapshotBatch {
	batch := SnapshotBatch{
		Files:   make([]File, 0, (to-from)/snapshotHashLen),
		Sources: make([]SnapshotSources, 0, (to-from)/snapshotHashLen),
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for off := from; off < to; off += snapshotHashLen {
		key := string(keys[off : off+snapshotHashLen])
		file, ok := m.files[key]
		if !ok {
			// Deleted between the key sweep and now. Skipping it is what makes the
			// chunked write safe; the snapshot is a point-in-time-ish view, not a
			// transaction.
			continue
		}
		batch.Files = append(batch.Files, cloneFile(file))
		if sources := m.sources[key]; len(sources) > 0 {
			cloned := make([]Source, 0, len(sources))
			for _, s := range sources {
				cloned = append(cloned, cloneSource(s))
			}
			batch.Sources = append(batch.Sources, SnapshotSources{
				FileHash: append([]byte(nil), file.Hash...),
				Sources:  cloned,
			})
		}
	}
	return batch
}

// writeSnapshotStream encodes the header and then every batch, pulling each batch
// from next. It owns the buffering and optional compression so WriteSnapshot can
// stay concerned with the atomic-rename dance.
func writeSnapshotStream(
	w io.Writer,
	header SnapshotHeader,
	keys []byte,
	clients []ClientInfo,
	compress bool,
	next func(keys []byte, from, to int) SnapshotBatch,
) (SnapshotStats, error) {
	var stats SnapshotStats

	buf := bufio.NewWriterSize(w, 1<<20)
	var enc *gob.Encoder
	var gz *gzip.Writer
	if compress {
		gz = gzip.NewWriter(buf)
		enc = gob.NewEncoder(gz)
	} else {
		enc = gob.NewEncoder(buf)
	}

	if err := enc.Encode(header); err != nil {
		return stats, fmt.Errorf("encode snapshot header: %w", err)
	}

	stride := snapshotBatchSize * snapshotHashLen
	for from := 0; from < len(keys); from += stride {
		to := min(from+stride, len(keys))
		batch := next(keys, from, to)
		if len(batch.Files) == 0 && len(batch.Sources) == 0 {
			continue
		}
		if err := enc.Encode(batch); err != nil {
			return stats, fmt.Errorf("encode snapshot batch: %w", err)
		}
		stats.Files += len(batch.Files)
		for _, group := range batch.Sources {
			stats.Sources += len(group.Sources)
		}
	}

	// Clients last and in one batch: they are bounded by the number of connected
	// users, which is orders of magnitude below the file count.
	for from := 0; from < len(clients); from += snapshotBatchSize {
		to := min(from+snapshotBatchSize, len(clients))
		if err := enc.Encode(SnapshotBatch{Clients: clients[from:to]}); err != nil {
			return stats, fmt.Errorf("encode snapshot clients: %w", err)
		}
		stats.Clients += to - from
	}

	if gz != nil {
		if err := gz.Close(); err != nil {
			return stats, fmt.Errorf("finish snapshot compression: %w", err)
		}
	}
	if err := buf.Flush(); err != nil {
		return stats, fmt.Errorf("flush snapshot: %w", err)
	}
	return stats, nil
}

// snapshotReader wraps r in a gzip reader when the stream starts with the gzip
// magic, and returns a closer for it.
func snapshotReader(f *os.File) (io.Reader, func(), error) {
	var magic [2]byte
	n, err := io.ReadFull(f, magic[:])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("read the snapshot header: %w", err)
	}
	if n == 0 {
		return nil, nil, errors.New("empty file")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("rewind: %w", err)
	}

	buf := bufio.NewReaderSize(f, 1<<20)
	if n == 2 && magic == gzipMagic {
		gz, err := gzip.NewReader(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("open the compressed snapshot: %w", err)
		}
		return gz, func() { _ = gz.Close() }, nil
	}
	return buf, func() {}, nil
}

func cloneClientInfo(info ClientInfo) ClientInfo {
	info.Hash = append([]byte(nil), info.Hash...)
	info.IPv6 = append([]byte(nil), info.IPv6...)
	return info
}

func cloneFile(file File) File {
	file.Hash = append([]byte(nil), file.Hash...)
	return file
}

func cloneSource(s Source) Source {
	s.UserHash = append([]byte(nil), s.UserHash...)
	s.IPv6 = append([]byte(nil), s.IPv6...)
	return s
}

// humanBytes renders a size for the one-line write log. Snapshots span kilobytes on
// a test rig to gigabytes on a real server, and raw byte counts are unreadable at
// the top of that range.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for size := n / unit; size >= unit && exp < 3; size /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
