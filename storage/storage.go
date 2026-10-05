package storage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

const (
	// hashLen is the ed2k hash width, and the width of a sources map key.
	hashLen = 16
	// fileMapKeyLen is the width of a files map key: hashLen plus an 8-byte size.
	// Fixed, because WriteSnapshot walks a flat key buffer at this stride.
	fileMapKeyLen = hashLen + 8
)

// MaxWireSources is the most sources any engine may return for one file. The
// ed2k source-list packets carry the count in a single byte, so 255 is a hard
// wire-format ceiling, not a tuning knob.
const MaxWireSources = 255

// MaxSearchResults is the most files FindBySearch may return for one query.
//
// Unlike MaxWireSources this *is* a tuning knob: OP_SEARCHRESULT carries its count in a
// uint32, so nothing on the wire forces a limit. Every engine previously capped at 255,
// which happened to equal the page size — so a deeper result set was silently truncated
// with no way for a client to ask for the rest. Now that OP_QUERY_MORE_RESULT paging
// exists the fetch ceiling and the page size are separate concerns, and this is the
// former. For scale, Lugdunum's own maxSearchCount defaults to 300.
const MaxSearchResults = 1000

// MaxSearchPage is how many results go in one OP_SEARCHRESULT packet. Kept at the
// historical 255 so a single reply is byte-for-byte the size it always was; the rest of
// the set is delivered through OP_QUERY_MORE_RESULT.
const MaxSearchPage = 255

// offerBatchSize is how many offered files the DB engines write per multi-row
// statement. A conforming eMule offers at most 200 files per OP_OFFERFILES
// (srchybrid/SharedFileList.cpp:832-834), so a real packet is one chunk; the cap
// exists for a client that crams up to the hard limit into one frame. At 500 the
// sources INSERT carries 6,500 placeholders, far below MySQL's 65,535 should the
// driver fall back to a prepared statement, and ~1.4 MB of worst-case row data,
// below every server's default max_allowed_packet.
const offerBatchSize = 500

type ClientInfo struct {
	ID    uint32
	IPv4  uint32
	Port  uint16
	Hash  []byte
	LowID bool
	// StoreID is the storage primary key for this client (clients.id, a
	// bigint unsigned), assigned by Connect. uint64 per the project's PK rule.
	StoreID uint64
	// CryptOptions holds the client's obfuscation capabilities as the eMule
	// OP_FOUNDSOURCES_OBFU byte: 0x01 supports, 0x02 requests, 0x04 requires crypt.
	// Parsed from the CT_SERVER_FLAGS login tag and re-published per source.
	CryptOptions byte
	// IPv6 is the client's public IPv6 as 16 network-order bytes, or nil. Learned
	// from the CT_MOD_IP_V6 login tag or a v6-family connection.
	IPv6 []byte
	// IPv6Reachable is set once the server has verified the client answers on its
	// IPv6:port. Only a reachable v6 is published as a source.
	IPv6Reachable bool
}

type Source struct {
	ID       uint32
	Port     uint16
	UserHash []byte
	// CryptOptions mirrors ClientInfo.CryptOptions for the offering client, so
	// BuildFoundSourcesObfuPacket can advertise the source's crypt support.
	CryptOptions byte
	// IPv6 / IPv6Reachable mirror ClientInfo so the source builders can emit the
	// IPv6 sentinel or tag-block form for a v6-reachable source.
	IPv6          []byte
	IPv6Reachable bool

	// storeID, complete and size are the memory engine's own bookkeeping: the
	// StoreID of the session that published this source, whether that session has
	// the whole file, and the size it offered. Unexported, so the DB engines leave them zero and the gob snapshot
	// format does not change.
	storeID  uint64
	complete bool
	// size is the file size this source offered under. Sources are bucketed by hash
	// alone (see fileMapKey), so GetSources filters on it; 0 matches any size.
	size uint64
}

// counterSource is the offering client whose address a counter refresh stamps
// onto files.source_id / files.source_port. A cleanup sweep passes nil: it has no
// offering client, and writing zeros would wipe the last known source address.
type counterSource struct {
	ID   uint32
	Port uint16
}

type File struct {
	Hash       []byte
	Name       string
	Size       uint64
	Type       string
	Sources    uint32
	Completed  uint32
	Title      string
	Artist     string
	Album      string
	Runtime    uint32
	Bitrate    uint32
	Codec      string
	SourceID   uint32
	SourcePort uint16
	// Meta is set on a row that stands for a torrent or Usenet release rather than an
	// eD2K file (see docs/meta-search.md), and nil on every row an engine returns.
	// Such rows are merged into search answers only and never stored.
	Meta *MetaInfo
}

// MetaInfo is what a catalogue row carries beyond an eD2K record: the
// FT_META_* tags (0x60-0x6C) of the enode.meta.v1 contract. Plain values, so
// storage takes no dependency on the contract module.
type MetaInfo struct {
	// Kind is the network: 1 BitTorrent v1/hybrid, 2 BitTorrent v2, 3 NZB, 4 a real
	// eD2K file found on Kad (see Native).
	Kind      uint8
	Version   uint8
	FileIndex uint32
	FilePath  string
	TotalSize uint64
	CatalogID string
	Seeders   uint32
	Peers     uint32
	AgeDays   uint32
	Indexer   string
	Flags     uint32
	Magnet    string
}

// MetaKindED2K is MetaInfo.Kind for a native row, META_KIND_ED2K of the contract.
const MetaKindED2K uint8 = 4

// Native reports whether the row is a real eD2K file — its Hash is the file's own
// MD4, not a pseudo-hash — which a catalogue daemon found on another network. Such a
// row is sent as an ordinary search result with FT_META_NETWORK as its only meta tag.
func (m *MetaInfo) Native() bool {
	return m != nil && m.Kind == MetaKindED2K
}

type Server struct {
	IP   string
	Port uint16
}

type MemoryEngine struct {
	mu           sync.RWMutex
	nextClientID uint64
	// clients is keyed by StoreID, the one identity no two live sessions share. The
	// ed2k ID is not: a HighID is the client's IP, so two users behind one NAT with
	// two forwarded ports both hold it, and keying on it let each overwrite, and on
	// disconnect delete, the other's row, hash index and sources.
	clients map[uint64]ClientInfo
	// clientsByHash indexes clients by user hash so IsConnected can be answered
	// on hash, as the MySQL and MongoDB engines do. The login path needs this:
	// at the point it checks, the ed2k ID is still the untrusted value supplied
	// by the client, so keying on ID would let a duplicate login through.
	clientsByHash map[string]uint64
	// offered lists, per StoreID, the source buckets (hashKey) that session has
	// published into, so Disconnect visits only its own files instead of scanning
	// every source under the write lock.
	offered map[uint64]map[string]struct{}
	// files is keyed by fileMapKey (hash+size); sources by hashKey (hash alone). The two
	// key spaces differ deliberately — see fileMapKey.
	//
	// files holds an id into recs rather than the record itself, so the name index can
	// list a file as a uint32. A removed file's slot has a nil Hash; its id waits in
	// dead until CleanupStale has purged it from the index, then in free for reuse.
	files   map[string]uint32
	recs    fileSlab
	dead    []uint32
	free    []uint32
	names   nameIndex
	sources map[string][]Source
	servers []Server

	// accts is the AccountStore half (accounts_memory.go), under its own lock.
	acctMu sync.Mutex
	accts  memoryAccounts
}

func NewMemoryEngine() *MemoryEngine {
	return &MemoryEngine{
		clients:       map[uint64]ClientInfo{},
		clientsByHash: map[string]uint64{},
		offered:       map[uint64]map[string]struct{}{},
		files:         map[string]uint32{},
		names:         newNameIndex(),
		sources:       map[string][]Source{},
	}
}

// hashKey keys the two maps whose identity really is a bare hash: clientsByHash, on
// the user hash, and sources, on the file hash. Files use fileMapKey instead.
func hashKey(hash []byte) string {
	return string(hash)
}

func (m *MemoryEngine) Init() error {
	return nil
}

func (m *MemoryEngine) Close() error {
	return nil
}

func (m *MemoryEngine) ClientsCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.clients)
}

func (m *MemoryEngine) IsConnected(info ClientInfo) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(info.Hash) > 0 {
		_, ok := m.clientsByHash[hashKey(info.Hash)]
		return ok
	}
	// Without a hash only the ed2k ID is left, which several sessions may share; any
	// of them answers the question. No production caller reaches this.
	for _, c := range m.clients {
		if c.ID == info.ID {
			return true
		}
	}
	return false
}

func (m *MemoryEngine) Connect(info ClientInfo) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextClientID++
	info.StoreID = m.nextClientID
	m.clients[info.StoreID] = info
	if len(info.Hash) > 0 {
		m.clientsByHash[hashKey(info.Hash)] = info.StoreID
	}
	return info.StoreID, nil
}

// Disconnect removes the session info.StoreID names, and only it: its row, its hash
// index entry if that still points at it, and the sources it published. Another
// session with the same ed2k ID, or a newer session with the same hash, is untouched.
func (m *MemoryEngine) Disconnect(info ClientInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info.StoreID == 0 {
		info.StoreID = m.resolveStoreIDLocked(info)
		if info.StoreID == 0 {
			return
		}
	}
	if existing, ok := m.clients[info.StoreID]; ok && len(existing.Hash) > 0 {
		// Only drop the hash index when it still points at this session, so a
		// late Disconnect from a replaced session cannot unregister the live one.
		if id, ok := m.clientsByHash[hashKey(existing.Hash)]; ok && id == info.StoreID {
			delete(m.clientsByHash, hashKey(existing.Hash))
		}
	}
	delete(m.clients, info.StoreID)
	for k := range m.offered[info.StoreID] {
		existing := m.sources[k]
		kept := existing[:0]
		for _, s := range existing {
			if s.storeID != info.StoreID {
				kept = append(kept, s)
			}
		}
		if len(kept) == 0 {
			delete(m.sources, k)
			continue
		}
		m.sources[k] = kept
	}
	delete(m.offered, info.StoreID)
}

func (m *MemoryEngine) FilesCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.files)
}

// CleanupStale has far less to do here than on the DB engines.
//
// Disconnect already removes a client and its source entries outright — there is
// no `online` flag and no retained row — so nothing ages out and maxAge is not
// consulted for clients or sources. What does accumulate is m.files: an entry
// stays after its last source has gone, and its Sources count keeps whatever
// value the offering client last reported.
//
// So this recomputes Sources and Completed from the live source lists and, when configured to,
// drops the files nobody serves. The recompute runs regardless, because a stale
// count feeds the `sources > N` search filter and the totals in OP_SEARCHRESULT.
func (m *MemoryEngine) CleanupStale(maxAge time.Duration, opts CleanupOptions) (CleanupResult, error) {
	var result CleanupResult
	if maxAge <= 0 {
		return result, fmt.Errorf("cleanup: maxAge must be positive, got %s", maxAge)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for key, id := range m.files {
		hk := key[:hashLen]
		sources := m.sources[hk]
		if len(sources) == 0 && !opts.KeepZeroSourceFiles {
			delete(m.files, key)
			m.names.removeFile(m.recs.at(id).Name)
			*m.recs.at(id) = File{}
			m.dead = append(m.dead, id)
			// Safe across sizes: the bucket is already empty, so this cannot strip
			// another size's sources. A sibling record is reaped on its own iteration.
			delete(m.sources, hk)
			result.Files++
			continue
		}
		file := m.recs.at(id)
		file.Sources, file.Completed = countSources(sources, file.Size)
	}
	m.maintainIndexLocked()
	return result, nil
}

func (m *MemoryEngine) AddFile(file File, clientInfo ClientInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addFileLocked(file, clientInfo)
}

// AddFiles stores one client's whole offer under a single lock acquisition. The
// memory engine has no round-trips to save, so it is AddFile in order — which is
// the contract the DB engines' batched writes are held to.
func (m *MemoryEngine) AddFiles(files []File, clientInfo ClientInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, file := range files {
		m.addFileLocked(file, clientInfo)
	}
}

func (m *MemoryEngine) GetSources(fileHash []byte, fileSize uint64) []Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Existence of the composite key *is* the size check: an offer at some other size
	// now lands in its own record instead of rewriting this one's Size.
	if _, ok := m.files[fileMapKey(fileHash, fileSize)]; !ok {
		return nil
	}
	return capSources(m.sources[hashKey(fileHash)], fileSize)
}

func (m *MemoryEngine) GetSourcesByHash(fileHash []byte) []Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return capSources(m.sources[hashKey(fileHash)], 0)
}

func (m *MemoryEngine) FindByNameContains(term string) []File {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []File
	for id := range m.recs.len() {
		f := *m.recs.at(uint32(id))
		if f.Hash == nil {
			continue
		}
		if term == "" || bytes.Contains([]byte(f.Name), []byte(term)) {
			m.liveFieldsLocked(&f)
			out = append(out, f)
		}
	}
	return out
}

func (m *MemoryEngine) FindBySearch(expr *SearchExpr) []File {
	if expr == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]File, 0, 32)
	// The index narrows the search to candidates and every one is re-checked, so the
	// answer is the one a full scan gives. A query it cannot narrow — no indexable
	// term, or a term in too many files to be worth collecting — scans instead, which
	// for a common term reaches the result cap early.
	ids, all := m.names.candidates(expr, max(candidateFloor, len(m.files)/8))
	if all {
		for id := range m.recs.len() {
			if out = m.matchLocked(expr, uint32(id), out); len(out) >= MaxSearchResults {
				break
			}
		}
		return out
	}
	for _, id := range ids {
		if out = m.matchLocked(expr, id, out); len(out) >= MaxSearchResults {
			break
		}
	}
	return out
}

func (m *MemoryEngine) ServersCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.servers)
}

func (m *MemoryEngine) AddServer(server Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.servers, _ = appendUniqueServer(m.servers, server)
}

func (m *MemoryEngine) ServersAll() []Server {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Server(nil), m.servers...)
}

// capSources returns up to MaxWireSources of a bucket's sources offered at size (0:
// any size), newest first. The MySQL and MongoDB engines get this from their
// ORDER BY time_offer DESC LIMIT 255. The memory engine used to return everything,
// which overflowed the count byte at 256, and then the oldest 255, so the newer
// sources of a popular file were never handed out. A bucket is in offer order: a new
// source and a re-offer are appended at the end.
func capSources(sources []Source, size uint64) []Source {
	out := make([]Source, 0, min(len(sources), MaxWireSources))
	for i := len(sources) - 1; i >= 0 && len(out) < MaxWireSources; i-- {
		if size == 0 || sources[i].size == 0 || sources[i].size == size {
			out = append(out, sources[i])
		}
	}
	return out
}

// fileMapKey identifies a file the way the protocol does — by hash *and* size together.
//
// eserver has policed size conflicts since 17.3 ("Make sure the size of a published file
// matches the known file size. A lot of buggy or malicious clients try to mislead the
// network", lugdunum-eserver/docs/kiten-20071012.txt:189-190), eMule's own identity type
// compares MD4 and size and AICH (srchybrid/FileIdentifier.cpp:84-93), and eMule changed
// its Kad index to store same-hash/different-size files separately in 0.49a. Both DB
// engines here already encode it — UNIQUE(hash,size) in misc/enode.sql:72 and the
// {hash,size} index in engine_mongodb.go:89-92.
//
// Keying files on the hash alone let any offer overwrite another file's whole record,
// including its Size, after which GetSources rejected every lookup for the real size and
// nothing ever reconciled it.
//
// Fixed width, and big-endian so a key orders by hash then size: WriteSnapshot packs
// these into one flat []byte and walks it at a constant stride. The hash is normalized
// to exactly hashLen bytes, which every production path already guarantees — GetFileList
// fails the packet otherwise (ed2k/buffer.go:606-609), as does decodeHash for fixtures.
//
// sources stays keyed by hashKey, not by this: the legacy UDP OP_GLOBGETSOURCES (0x9a)
// carries bare hashes with no size and must stay an O(1) lookup. The cost is that two
// sizes of one hash share a source list, which GetSources filters on each source's
// size; GetSourcesByHash, the size-less lookup, returns them all.
func fileMapKey(hash []byte, size uint64) string {
	var buf [fileMapKeyLen]byte
	copy(buf[:hashLen], hash)
	binary.BigEndian.PutUint64(buf[hashLen:], size)
	return string(buf[:])
}

// addFileLocked is AddFile's body; the caller holds m.mu for writing.
func (m *MemoryEngine) addFileLocked(file File, clientInfo ClientInfo) {
	// An offer still in flight when its session was released (replaced by a
	// re-login, or dropped) lands after Disconnect; storing it would leave sources
	// that no Disconnect will ever remove.
	if clientInfo.StoreID != 0 {
		if _, ok := m.clients[clientInfo.StoreID]; !ok {
			return
		}
	}
	// Normalized here too, so all three engines agree on what a given offer
	// stores. The memory engine has no schema to violate, but a search result
	// that differs by engine is its own bug.
	file = NormalizeFile(file)
	// Completed arrives as this source's own 0/1 and Sources as whatever the client
	// claimed; both are aggregates on the way out, computed from m.sources.
	complete := file.Completed > 0
	file.Sources, file.Completed = 0, 0
	m.storeFileLocked(file)
	// Sources stay keyed on the hash alone; see fileMapKey for why the two key spaces
	// differ and what it costs.
	k := hashKey(file.Hash)
	src := Source{
		ID:            clientInfo.ID,
		Port:          clientInfo.Port,
		UserHash:      append([]byte(nil), clientInfo.Hash...),
		CryptOptions:  clientInfo.CryptOptions,
		IPv6:          append([]byte(nil), clientInfo.IPv6...),
		IPv6Reachable: clientInfo.IPv6Reachable,
		storeID:       clientInfo.StoreID,
		complete:      complete,
		size:          file.Size,
	}
	if src.storeID == 0 {
		// Every production caller passes the StoreID Connect returned; resolve it
		// for one that does not, so its sources still leave with its Disconnect.
		src.storeID = m.resolveStoreIDLocked(clientInfo)
	}
	if src.storeID != 0 {
		m.markOfferedLocked(src.storeID, k)
	}
	existing := m.sources[k]
	for i, s := range existing {
		// The same session re-offering, or an entry left at this address by a
		// session that has since gone: either way the new offer takes it over, with
		// refreshed hash, crypt options and IPv6. Two live sessions behind one NAT
		// share the ID but not the port, so they never collide here.
		// The entry moves to the end, so the bucket stays in offer order.
		if (src.storeID != 0 && s.storeID == src.storeID) || (s.ID == src.ID && s.Port == src.Port) {
			existing = append(existing[:i], existing[i+1:]...)
			break
		}
	}
	m.sources[k] = append(existing, src)
}

// resolveStoreIDLocked finds the session a Disconnect without a StoreID means: by user
// hash, else by ed2k ID when exactly one session holds it. Every production caller
// passes the StoreID Connect returned; this keeps a bare-ClientInfo caller working
// without guessing between two sessions that share an ID.
func (m *MemoryEngine) resolveStoreIDLocked(info ClientInfo) uint64 {
	if len(info.Hash) > 0 {
		return m.clientsByHash[hashKey(info.Hash)]
	}
	var found uint64
	for id, c := range m.clients {
		if c.ID != info.ID {
			continue
		}
		if found != 0 {
			return 0
		}
		found = id
	}
	return found
}

// markOfferedLocked records that storeID published into source bucket k.
func (m *MemoryEngine) markOfferedLocked(storeID uint64, k string) {
	set := m.offered[storeID]
	if set == nil {
		set = map[string]struct{}{}
		m.offered[storeID] = set
	}
	set[k] = struct{}{}
}

// countSources returns how many of a bucket's sources offer size (0: any) and how
// many of them have the complete file — the FT_SOURCES and FT_COMPLETE_SOURCES a
// search result reports.
func countSources(sources []Source, size uint64) (total, complete uint32) {
	for _, s := range sources {
		if size != 0 && s.size != 0 && s.size != size {
			continue
		}
		total++
		if s.complete {
			complete++
		}
	}
	return total, complete
}

// liveFieldsLocked fills a search result's live fields from the file's sources: the
// source and complete counts, and the source a result names. The stored SourceID /
// SourcePort are the last offerer's and outlive its session, after which the ID can
// belong to someone else; the newest live source is reported instead, or none.
func (m *MemoryEngine) liveFieldsLocked(f *File) {
	sources := m.sources[hashKey(f.Hash)]
	f.Sources, f.Completed = countSources(sources, f.Size)
	f.SourceID, f.SourcePort = 0, 0
	for i := len(sources) - 1; i >= 0; i-- {
		if s := sources[i]; s.size == 0 || s.size == f.Size {
			f.SourceID, f.SourcePort = s.ID, s.Port
			break
		}
	}
}

// storeFileLocked puts file in its record, indexing a new file's name, or a stored
// file's new name.
func (m *MemoryEngine) storeFileLocked(file File) {
	key := fileMapKey(file.Hash, file.Size)
	if id, ok := m.files[key]; ok {
		m.names.renameFile(id, m.recs.at(id).Name, file.Name)
		*m.recs.at(id) = file
		return
	}
	var id uint32
	if n := len(m.free); n > 0 {
		id, m.free = m.free[n-1], m.free[:n-1]
		*m.recs.at(id) = file
	} else {
		id = m.recs.push(file)
	}
	m.files[key] = id
	m.names.indexName(id, file.Name)
}

// matchLocked appends recs[id] to out when it is live and matches expr.
func (m *MemoryEngine) matchLocked(expr *SearchExpr, id uint32, out []File) []File {
	f := *m.recs.at(id)
	if f.Hash == nil {
		return out
	}
	// The counters are taken from the live source list, not from the stored
	// record: nothing else keeps them current between cleanup sweeps, and an
	// FT_SOURCES / FT_COMPLETE_SOURCES constraint must see real values.
	m.liveFieldsLocked(&f)
	if MatchSearchExpr(expr, f) {
		out = append(out, f)
	}
	return out
}

// maintainIndexLocked drops removed files from the name index and frees their ids,
// or rebuilds the index outright once renames have left it mostly stale.
func (m *MemoryEngine) maintainIndexLocked() {
	if len(m.dead) > 0 {
		m.names.purge(func(id uint32) bool { return m.recs.at(id).Hash == nil })
		m.free = append(m.free, m.dead...)
		m.dead = m.dead[:0]
	}
	if m.names.needsRebuild() {
		m.rebuildIndexLocked()
	}
}

// rebuildIndexLocked renumbers the live records densely and indexes them afresh.
func (m *MemoryEngine) rebuildIndexLocked() {
	var recs fileSlab
	for id := range m.recs.len() {
		if f := m.recs.at(uint32(id)); f.Hash != nil {
			recs.push(*f)
		}
	}
	m.setFilesLocked(recs)
}

// setFilesLocked replaces every file record with recs and rebuilds the index.
func (m *MemoryEngine) setFilesLocked(recs fileSlab) {
	m.files = make(map[string]uint32, recs.len())
	m.names = newNameIndex()
	m.dead, m.free = nil, nil
	for id := range recs.len() {
		f := recs.at(uint32(id))
		m.files[fileMapKey(f.Hash, f.Size)] = uint32(id)
		m.names.indexName(uint32(id), f.Name)
	}
	m.recs = recs
}

// fileByKey returns the stored record for a fileMapKey.
func (m *MemoryEngine) fileByKey(key string) (File, bool) {
	id, ok := m.files[key]
	if !ok {
		return File{}, false
	}
	return *m.recs.at(id), true
}
