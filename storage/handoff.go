package storage

import (
	"bufio"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime/debug"
)

// Handoff is implemented by engines that hold state of the connected sessions in
// the process itself, which a successor taking over those sessions by handover
// (internal/handoff) needs:
//
//   - the memory engine holds everything, so all of it moves: files, sources,
//     clients and the StoreID counter, the sources in their offer order;
//   - the database engines hold their rows in the database, which the successor
//     reads as it is (Config.KeepOnline), and only the per-session offered counts
//     in the process.
//
// The export runs with the predecessor's sessions parked, so nothing writes while
// it is taken. The import runs in a successor that serves nothing yet, and expects
// an engine nothing has been stored in.
type Handoff interface {
	ExportHandoff(w io.Writer) error
	ImportHandoff(r io.Reader) error
}

// HandoffFiler is implemented by engines whose handover state is large enough that
// two copies of it may not fit: the memory engine. Its state goes through a file,
// and the engine lets go of it before the successor reads the file back, so the two
// processes never hold it at once.
type HandoffFiler interface {
	// ExportHandoffFile writes the state to path, empties the engine and writes to w
	// a stream that ImportHandoff follows to the file. On an error the engine is as
	// it was.
	ExportHandoffFile(w io.Writer, path string) error
	// RestoreHandoffFile reads path back into the emptied engine, after a handover
	// that did not happen, and removes the file.
	RestoreHandoffFile(path string) error
}

// ExportHandoff writes engine's handover state, or nothing for an engine that
// keeps none.
func ExportHandoff(engine Engine, w io.Writer) error {
	if h, ok := engine.(Handoff); ok {
		return h.ExportHandoff(w)
	}
	return nil
}

// ImportHandoff reads what ExportHandoff or ExportHandoffFile wrote.
func ImportHandoff(engine Engine, r io.Reader) error {
	if h, ok := engine.(Handoff); ok {
		return h.ImportHandoff(r)
	}
	return nil
}

// ExportHandoffFile is ExportHandoff through the file at path, for an engine that
// implements HandoffFiler. ok is false, and nothing is written, for any other.
func ExportHandoffFile(engine Engine, w io.Writer, path string) (ok bool, err error) {
	f, ok := engine.(HandoffFiler)
	if !ok {
		return false, nil
	}
	return true, f.ExportHandoffFile(w, path)
}

const (
	// memoryHandoffMagic and memoryHandoffVersion open the memory engine's stream.
	// Checked first, so a successor configured with another engine refuses the
	// stream instead of decoding it into something else.
	memoryHandoffMagic   = "enode-handoff-memory"
	memoryHandoffVersion = 1
	// memoryHandoffBatchFiles is how many files one batch carries.
	memoryHandoffBatchFiles = 10000
)

// memoryHandoffHeader opens the stream. The clients are all there are: bounded by
// the connected users, far below the file count.
//
// File is set instead when the index went through a file (ExportHandoffFile): the
// header is then all the stream carries, and the file holds a stream of its own.
type memoryHandoffHeader struct {
	Magic        string
	Version      uint32
	NextClientID uint64
	Clients      []ClientInfo
	File         string
}

// memoryHandoffBatch is a run of hashes: every file of each, then each one's
// sources in offer order. A hash never straddles two batches.
type memoryHandoffBatch struct {
	Files   []File
	Sources []memoryHandoffSource
}

// memoryHandoffSource is one memSource. Own is set when it carries an identity of
// its own rather than its session's; then the hash and address travel with it.
type memoryHandoffSource struct {
	Hash     [hashLen]byte
	Size     uint64
	StoreID  uint64
	ID       uint32
	Port     uint16
	Crypt    byte
	Flags    byte
	Own      bool
	PeerHash []byte
	PeerIPv6 []byte
}

// ExportHandoff writes the whole index, holding the read lock for the duration:
// unlike a snapshot, which runs beside a serving server and so copies in batches,
// this runs with every session parked, and a consistent picture is the point.
// Searches and UDP lookups, which only read, carry on.
func (m *MemoryEngine) ExportHandoff(w io.Writer) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	bw := bufio.NewWriterSize(w, 1<<20)
	enc := gob.NewEncoder(bw)
	header := memoryHandoffHeader{
		Magic:        memoryHandoffMagic,
		Version:      memoryHandoffVersion,
		NextClientID: m.nextClientID,
		Clients:      make([]ClientInfo, 0, len(m.clients)),
	}
	for _, c := range m.clients {
		header.Clients = append(header.Clients, cloneClientInfo(c.info))
	}
	if err := enc.Encode(header); err != nil {
		return fmt.Errorf("encode handoff header: %w", err)
	}
	var batch memoryHandoffBatch
	flush := func() error {
		if len(batch.Files) == 0 && len(batch.Sources) == 0 {
			return nil
		}
		if err := enc.Encode(batch); err != nil {
			return fmt.Errorf("encode handoff batch: %w", err)
		}
		batch = memoryHandoffBatch{}
		return nil
	}
	for key, head := range m.files {
		for id, more := head, true; more; {
			batch.Files = append(batch.Files, m.fileLocked(id, true))
			rec := m.recs.at(id)
			id, more = rec.next-1, rec.next != 0
		}
		m.eachSourceLocked(head, func(s *memSource) {
			src := memoryHandoffSource{
				Hash:    key,
				Size:    s.size,
				StoreID: s.peer.storeID,
				ID:      s.id,
				Port:    s.port,
				Crypt:   s.crypt,
				Flags:   s.flags,
			}
			if c := m.clients[s.peer.storeID]; c == nil || c.peer != s.peer {
				src.Own = true
				src.PeerHash = append([]byte(nil), s.peer.hash...)
				src.PeerIPv6 = append([]byte(nil), s.peer.ipv6...)
			}
			batch.Sources = append(batch.Sources, src)
		})
		if len(batch.Files) >= memoryHandoffBatchFiles {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	return bw.Flush()
}

// ImportHandoff replaces the engine's contents with a predecessor's export. The
// sources are appended in the order they were written, which is their offer order,
// so a source list reads newest-first exactly as it did.
func (m *MemoryEngine) ImportHandoff(r io.Reader) error {
	return m.importHandoff(r, true)
}

// ExportHandoffFile writes the index to path, under a temporary name first, then
// empties the engine and returns the freed memory to the system. Reading the file
// back is the successor's ImportHandoff, or RestoreHandoffFile here if the handover
// does not happen. The file is left for the predecessor to remove: the successor
// cannot tell whether the handover will be committed.
//
// Until the index is back, this process holds none of it: a UDP search answers
// nothing, which is how a restart would answer it. TCP sessions are parked.
func (m *MemoryEngine) ExportHandoffFile(w io.Writer, path string) error {
	if path == "" {
		return errors.New("handoff file path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create handoff file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	// Not synced: the successor reads it from the page cache within seconds, and a
	// crash of the machine ends the handover anyway.
	if err := m.ExportHandoff(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close handoff file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install handoff file: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := gob.NewEncoder(w).Encode(memoryHandoffHeader{
		Magic:   memoryHandoffMagic,
		Version: memoryHandoffVersion,
		File:    abs,
	}); err != nil {
		return fmt.Errorf("encode handoff header: %w", err)
	}
	m.releaseIndex()
	return nil
}

// RestoreHandoffFile reads back what ExportHandoffFile wrote and removes the file.
func (m *MemoryEngine) RestoreHandoffFile(path string) error {
	if err := m.importHandoffFile(path); err != nil {
		return err
	}
	return os.Remove(path)
}

// ExportHandoff writes the offered counts of the connected sessions; the rows are
// in the database.
func (m *MySQLEngine) ExportHandoff(w io.Writer) error {
	m.offeredMu.Lock()
	offered := maps.Clone(m.offered)
	m.offeredMu.Unlock()
	return gob.NewEncoder(w).Encode(offered)
}

// ImportHandoff reads what ExportHandoff wrote.
func (m *MySQLEngine) ImportHandoff(r io.Reader) error {
	var offered map[uint64]int
	if err := gob.NewDecoder(r).Decode(&offered); err != nil {
		return fmt.Errorf("read mysql handoff: %w", err)
	}
	m.offeredMu.Lock()
	defer m.offeredMu.Unlock()
	if m.offered == nil {
		m.offered = map[uint64]int{}
	}
	maps.Copy(m.offered, offered)
	return nil
}

// ExportHandoff writes the offered counts of the connected sessions; the rows are
// in the database.
func (m *MongoDBEngine) ExportHandoff(w io.Writer) error {
	m.offeredMu.Lock()
	offered := maps.Clone(m.offered)
	m.offeredMu.Unlock()
	return gob.NewEncoder(w).Encode(offered)
}

// ImportHandoff reads what ExportHandoff wrote.
func (m *MongoDBEngine) ImportHandoff(r io.Reader) error {
	var offered map[string]int
	if err := gob.NewDecoder(r).Decode(&offered); err != nil {
		return fmt.Errorf("read mongodb handoff: %w", err)
	}
	m.offeredMu.Lock()
	defer m.offeredMu.Unlock()
	if m.offered == nil {
		m.offered = map[string]int{}
	}
	maps.Copy(m.offered, offered)
	return nil
}

// ExportHandoff is the wrapped engine's: the index holds nothing per session.
func (m *ManticoreEngine) ExportHandoff(w io.Writer) error {
	return ExportHandoff(m.Engine, w)
}

// ImportHandoff is the wrapped engine's.
func (m *ManticoreEngine) ImportHandoff(r io.Reader) error {
	return ImportHandoff(m.Engine, r)
}

// importHandoff reads a handover stream. follow allows the stream to name a file
// holding the actual one; a file never names another.
func (m *MemoryEngine) importHandoff(r io.Reader, follow bool) error {
	dec := gob.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	var header memoryHandoffHeader
	if err := dec.Decode(&header); err != nil {
		return fmt.Errorf("read handoff header: %w", err)
	}
	if header.Magic != memoryHandoffMagic {
		return fmt.Errorf("not a memory engine handoff (magic %q): the predecessor runs another storage engine", header.Magic)
	}
	if header.Version != memoryHandoffVersion {
		return fmt.Errorf("memory engine handoff version %d, this build reads version %d", header.Version, memoryHandoffVersion)
	}
	if header.File != "" {
		if !follow {
			return errors.New("handoff file names another handoff file")
		}
		return m.importHandoffFile(header.File)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.installFilesLocked(nil)
	m.clients = make(map[uint64]*memClient, len(header.Clients))
	m.clientsByHash = make(map[string]uint64, len(header.Clients))
	for _, info := range header.Clients {
		m.clients[info.StoreID] = &memClient{info: info, peer: newMemPeer(info)}
		if len(info.Hash) > 0 {
			m.clientsByHash[hashKey(info.Hash)] = info.StoreID
		}
	}
	m.nextClientID = max(m.nextClientID, header.NextClientID)

	for {
		var batch memoryHandoffBatch
		if err := dec.Decode(&batch); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read handoff batch: %w", err)
		}
		for _, f := range batch.Files {
			m.storeFileLocked(f)
		}
		for _, hs := range batch.Sources {
			head, ok := m.files[hs.Hash]
			if !ok {
				continue
			}
			src := memSource{size: hs.Size, id: hs.ID, port: hs.Port, crypt: hs.Crypt, flags: hs.Flags}
			client := m.clients[hs.StoreID]
			if client != nil && !hs.Own {
				src.peer = client.peer
			} else {
				src.peer = &memPeer{storeID: hs.StoreID, hash: hs.PeerHash, ipv6: hs.PeerIPv6}
			}
			m.appendSourceLocked(head, src)
			// A session holds one source per hash, so each source of a session is one
			// entry of its offered list.
			if client != nil {
				client.offered = append(client.offered, head)
			}
		}
	}
}

// importHandoffFile reads the handover stream in the file at path.
func (m *MemoryEngine) importHandoffFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open handoff file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := m.importHandoff(f, false); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// releaseIndex empties the engine, keeping the StoreID counter, and hands the memory
// back to the system rather than leaving it to the next collection.
func (m *MemoryEngine) releaseIndex() {
	m.mu.Lock()
	m.installFilesLocked(nil)
	m.clients = map[uint64]*memClient{}
	m.clientsByHash = map[string]uint64{}
	m.mu.Unlock()
	debug.FreeOSMemory()
}

// appendSourceLocked adds src at the end of the sources of the hash whose first
// record is head, with none of putSourceLocked's take-over rules: the import
// replays a list that already obeyed them.
func (m *MemoryEngine) appendSourceLocked(head uint32, src memSource) {
	rec := m.recs.at(head)
	if rec.first.peer == nil {
		rec.first = src
		return
	}
	m.more[head] = append(m.more[head], src)
	rec.flags |= recMore
}
