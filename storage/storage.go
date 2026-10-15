package storage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// hashLen is the ed2k hash width, and the width of the memory engine's files
	// map key.
	hashLen = 16
	// fileMapKeyLen is the width of a fileMapKey: hashLen plus an 8-byte size.
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

// searchRankScan is how many matches the memory engine looks at when a query has
// more than MaxSearchResults of them, to pick the ones with the most sources. A
// common word must not turn one search into a walk of every file that holds it.
const searchRankScan = 20000

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

// disconnectChunk is how many files a departing session's sources are removed from
// per acquisition of a lock, or per statement of a DB engine. A session may source
// a hundred thousand files; releasing them in one go held the memory engine's lock,
// and so every search and offer on the server, for as long as that took.
const disconnectChunk = 1000

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
	// Meta is set on a row that stands for a torrent, Usenet or web release rather than an
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

// MemoryEngine keeps the whole index in RAM, and is built to hold millions of files
// in as few bytes each as it can; see docs/memory-footprint.local.md for what a file costs.
//
// A file is one memRec in a slab, found by id. files maps a hash to the first record
// with that hash; a second size of the same hash, which the protocol treats as
// another file (see fileMapKey), hangs off it through memRec.next. That is rare, so
// one map keyed by the bare hash serves both the (hash, size) lookups and the
// size-less ones of the legacy UDP source request.
//
// The sources of a hash, whatever size each was offered at, are one list in offer
// order. It lives on the first record of the hash: the oldest source inline in
// memRec.first and the rest in more. Most files have a single source, so most
// files have no entry in more at all.
type MemoryEngine struct {
	mu           sync.RWMutex
	nextClientID uint64
	// clients is keyed by StoreID, the one identity no two live sessions share. The
	// ed2k ID is not: a HighID is the client's IP, so two users behind one NAT with
	// two forwarded ports both hold it, and keying on it let each overwrite, and on
	// disconnect delete, the other's row, hash index and sources.
	clients map[uint64]*memClient
	// clientsByHash indexes clients by user hash so IsConnected can be answered
	// on hash, as the MySQL and MongoDB engines do. The login path needs this:
	// at the point it checks, the ed2k ID is still the untrusted value supplied
	// by the client, so keying on ID would let a duplicate login through.
	clientsByHash map[string]uint64
	// files maps a file hash to the id of its first record. count is how many
	// records are live, over all sizes.
	files map[[hashLen]byte]uint32
	count int
	// recs holds the records by id, so the name index can list a file as a uint32.
	// A removed file's slot is cleared; its id waits in dead until CleanupStale has
	// purged it from the index, then in free for reuse.
	recs slab[memRec]
	// more holds, by the id of a hash's first record, its sources after the first.
	more  map[uint32][]memSource
	dead  []uint32
	free  []uint32
	names nameIndex
	// layout counts how often the records were renumbered, which is what makes a
	// BrowseFiles cursor from before unusable.
	layout  uint64
	servers []Server

	// accts is the AccountStore half (accounts_memory.go), under its own lock.
	acctMu sync.Mutex
	accts  memoryAccounts
}

// memRec is one file. Its fields are ordered and sized to fit 80 bytes; a record
// used to be a whole File, 168 bytes plus a separately allocated hash, with its
// source list in a second map under a second copy of the hash.
type memRec struct {
	name string
	// media holds what few files carry; nil for a file with none of it.
	media *memMedia
	// first is the oldest source of the hash, on the hash's first record only.
	// first.peer is nil when the hash has no source.
	first memSource
	size  uint64
	hash  [hashLen]byte
	// next is the id, plus one, of the next record with the same hash; zero ends
	// the chain.
	next uint32
	// typ indexes memFileTypes, or is memTypeOther with the type in media.
	typ uint8
	// hashLen is the length of the hash as offered. Every production path offers
	// exactly hashLen bytes; a fixture may offer fewer, and gets them back.
	hashLen uint8
	flags   uint8
}

const (
	// recLive marks a slot that holds a file.
	recLive = 1 << iota
	// recMore says the record has sources in MemoryEngine.more.
	recMore
	// recSibling marks a record that is not the first of its hash, so the first is
	// known without asking the files map for all the others.
	recSibling
)

// memMedia is the part of a File most files leave empty: the media tags of an audio
// or video file, the Meta of a row loaded with one, and a type outside
// memFileTypes. Behind one pointer, a file without any of it pays 8 bytes for all
// of it instead of 80.
type memMedia struct {
	title, artist, album, codec, typ string
	runtime, bitrate                 uint32
	meta                             *MetaInfo
}

// memFileTypes is every type NormalizeFile lets through, so a record names its
// type in a byte.
var memFileTypes = [...]string{"", "Image", "Audio", "Video", "Pro", "Doc"}

// memTypeOther is memRec.typ for a type not in memFileTypes. AddFile normalizes
// types, so only a file installed from a snapshot can have one.
const memTypeOther = 0xff

// memSource is one client offering one file: 24 bytes where a Source is 88 plus a
// copy of the user hash and of the IPv6 address per offered file.
type memSource struct {
	// peer is the offering session's identity, shared by all its sources.
	peer *memPeer
	// size is the file size this source offered under. Sources are listed per hash,
	// so a lookup by (hash, size) filters on it; 0 matches any size.
	size  uint64
	id    uint32
	port  uint16
	crypt byte
	flags byte
}

const (
	// srcComplete says the source has the whole file.
	srcComplete = 1 << iota
	// srcIPv6Reachable mirrors ClientInfo.IPv6Reachable at the time of the offer.
	srcIPv6Reachable
)

// memPeer is what a source says about its client beyond the address: the user hash
// and the IPv6 address a source list is built with, and the StoreID of the session
// the source leaves with (zero for a caller that never connected).
type memPeer struct {
	storeID uint64
	hash    []byte
	ipv6    []byte
}

// memClient is one connected session.
type memClient struct {
	info ClientInfo
	// peer is the identity the session's sources point at.
	peer *memPeer
	// offered lists the hashes the session sources, each as the id of the hash's
	// first record and each once. Disconnect walks it instead of scanning every
	// source, and its length is OfferedCount. Four bytes a file: it used to be a
	// set keyed by the 16-byte hash.
	offered []uint32
}

func NewMemoryEngine() *MemoryEngine {
	return &MemoryEngine{
		clients:       map[uint64]*memClient{},
		clientsByHash: map[string]uint64{},
		files:         map[[hashLen]byte]uint32{},
		more:          map[uint32][]memSource{},
		names:         newNameIndex(),
	}
}

// hashKey keys clientsByHash, on the user hash.
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
		if c.info.ID == info.ID {
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
	m.clients[info.StoreID] = &memClient{info: info, peer: newMemPeer(info)}
	if len(info.Hash) > 0 {
		m.clientsByHash[hashKey(info.Hash)] = info.StoreID
	}
	return info.StoreID, nil
}

// Disconnect removes the session info.StoreID names, and only it: its row, its hash
// index entry if that still points at it, and the sources it published. Another
// session with the same ed2k ID, or a newer session with the same hash, is untouched.
//
// The session is gone, and can publish nothing more, as soon as the first lock is
// released: addFileLocked refuses an offer from a StoreID that is not connected. Its
// sources then go disconnectChunk files at a time, with the lock released in between
// so searches and other sessions' offers are not held up behind a large share. A
// source lookup in that window may still name the departing client, as one sent a
// moment before the disconnect would.
func (m *MemoryEngine) Disconnect(info ClientInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info.StoreID == 0 {
		info.StoreID = m.resolveStoreIDLocked(info)
		if info.StoreID == 0 {
			return
		}
	}
	client, ok := m.clients[info.StoreID]
	if !ok {
		return
	}
	if len(client.info.Hash) > 0 {
		// Only drop the hash index when it still points at this session, so a
		// late Disconnect from a replaced session cannot unregister the live one.
		if id, ok := m.clientsByHash[hashKey(client.info.Hash)]; ok && id == info.StoreID {
			delete(m.clientsByHash, hashKey(client.info.Hash))
		}
	}
	delete(m.clients, info.StoreID)
	// Detached with the client, so nobody else holds the list and it can be walked
	// across unlocks.
	layout := m.layout
	for i, head := range client.offered {
		if i > 0 && i%disconnectChunk == 0 {
			m.mu.Unlock()
			m.mu.Lock()
			if m.layout != layout {
				// The records were renumbered while the lock was free, so the ids
				// left in the list no longer say where the sources are.
				m.removeAllSourcesOfLocked(info.StoreID)
				return
			}
		}
		m.removeSourcesOfLocked(head, info.StoreID)
	}
}

func (m *MemoryEngine) FilesCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.count
}

// FilesCountEstimate is exact here: the count is kept as files come and go.
func (m *MemoryEngine) FilesCountEstimate() int {
	return m.FilesCount()
}

// CleanupStale has far less to do here than on the DB engines.
//
// Disconnect already removes a client and its source entries outright — there is
// no `online` flag and no retained row — so nothing ages out and maxAge is not
// consulted for clients or sources. What does accumulate is the records: one stays
// after its last source has gone.
//
// So this drops the files nobody serves, when configured to. A record stores no
// source counts to bring up to date: every read derives them from the live sources.
func (m *MemoryEngine) CleanupStale(maxAge time.Duration, opts CleanupOptions) (CleanupResult, error) {
	var result CleanupResult
	if maxAge <= 0 {
		return result, fmt.Errorf("cleanup: maxAge must be positive, got %s", maxAge)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if !opts.KeepZeroSourceFiles {
		for i := range m.recs.len() {
			id := uint32(i)
			rec := m.recs.at(id)
			if rec.flags&recLive == 0 {
				continue
			}
			// The sources belong to the hash, so every size of it is empty together
			// and each record is reaped on its own turn.
			if head := m.recs.at(m.headLocked(id)); head.first.peer == nil {
				m.removeRecLocked(id)
				result.Files++
			}
		}
	}
	m.maintainIndexLocked()
	return result, nil
}

func (m *MemoryEngine) AddFile(file File, clientInfo ClientInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addFileLocked(file, clientInfo)
}

// AddFiles stores one client's offer, AddFile in order — which is the contract the
// DB engines' batched writes are held to. The lock is taken per offerBatchSize
// files rather than once for the packet: a conforming packet holds 200 and is one
// acquisition, but one crammed up to the hard limit must not stop every search for
// as long as it takes to index.
func (m *MemoryEngine) AddFiles(files []File, clientInfo ClientInfo) {
	for start := 0; start < len(files); start += offerBatchSize {
		m.mu.Lock()
		for _, file := range files[start:min(start+offerBatchSize, len(files))] {
			m.addFileLocked(file, clientInfo)
		}
		m.mu.Unlock()
	}
}

// OfferedCount is the length of the session's offered list, which holds each hash
// it sources once.
func (m *MemoryEngine) OfferedCount(info ClientInfo) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if info.StoreID == 0 {
		info.StoreID = m.resolveStoreIDLocked(info)
	}
	if client, ok := m.clients[info.StoreID]; ok {
		return len(client.offered)
	}
	return 0
}

// HasOffered looks for the session among each file's sources. No set of the
// session's files is kept for it: the source list answers, and is short for all
// but the most popular files.
func (m *MemoryEngine) HasOffered(info ClientInfo, files []File) []bool {
	out := make([]bool, len(files))
	m.mu.RLock()
	defer m.mu.RUnlock()
	if info.StoreID == 0 {
		info.StoreID = m.resolveStoreIDLocked(info)
	}
	if _, ok := m.clients[info.StoreID]; !ok {
		return out
	}
	for i, f := range files {
		head, ok := m.files[hashArray(f.Hash)]
		if !ok {
			continue
		}
		rec := m.recs.at(head)
		if rec.first.peer != nil && rec.first.peer.storeID == info.StoreID {
			out[i] = true
			continue
		}
		if rec.flags&recMore == 0 {
			continue
		}
		for _, s := range m.more[head] {
			if s.peer.storeID == info.StoreID {
				out[i] = true
				break
			}
		}
	}
	return out
}

func (m *MemoryEngine) GetSources(fileHash []byte, fileSize uint64) []Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := hashArray(fileHash)
	// Existence of the record *is* the size check: an offer at some other size
	// lands in its own record instead of rewriting this one's size.
	if _, ok := m.findLocked(key, fileSize); !ok {
		return nil
	}
	return m.capSourcesLocked(m.files[key], fileSize)
}

func (m *MemoryEngine) GetSourcesByHash(fileHash []byte) []Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	head, ok := m.files[hashArray(fileHash)]
	if !ok {
		return []Source{}
	}
	return m.capSourcesLocked(head, 0)
}

func (m *MemoryEngine) SharedFiles(hashes [][]byte) []File {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []File
	seen := make(map[uint32]struct{}, len(hashes))
	for _, hash := range hashes {
		key := hashArray(hash)
		head, ok := m.files[key]
		if !ok {
			continue
		}
		// A source says which size it offered, and that is the only way from a
		// bare hash to the records that are shared now.
		m.eachSourceLocked(head, func(s *memSource) {
			id, ok := m.findLocked(key, s.size)
			if !ok {
				return
			}
			if _, dup := seen[id]; dup {
				return
			}
			seen[id] = struct{}{}
			if f := m.fileLocked(id, true); f.Sources > 0 {
				out = append(out, f)
			}
		})
	}
	return out
}

// BrowseFiles walks the file records in id order. The cursor is the layout the
// walk started in and the next id to read: rebuilding the index renumbers the
// records, after which an id no longer says where the walk stood.
func (m *MemoryEngine) BrowseFiles(cursor []byte, limit int) ([]File, []byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	from := uint32(0)
	if len(cursor) != 0 {
		if len(cursor) != 12 || binary.BigEndian.Uint64(cursor) != m.layout {
			return nil, nil, ErrBrowseCursor
		}
		from = binary.BigEndian.Uint32(cursor[8:])
	}
	limit = browseLimit(limit)
	out := make([]File, 0, min(limit, 256))
	n := uint32(m.recs.len())
	for id := from; id < n; id++ {
		if m.recs.at(id).flags&recLive == 0 {
			continue
		}
		f := m.fileLocked(id, false)
		if f.Sources == 0 {
			continue
		}
		f.Hash = append([]byte(nil), f.Hash...)
		f.SourceID, f.SourcePort = 0, 0
		out = append(out, f)
		if len(out) == limit && id+1 < n {
			next := binary.BigEndian.AppendUint64(make([]byte, 0, 12), m.layout)
			return out, binary.BigEndian.AppendUint32(next, id+1), nil
		}
	}
	return out, nil, nil
}

func (m *MemoryEngine) FindByNameContains(term string) []File {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []File
	for i := range m.recs.len() {
		id := uint32(i)
		rec := m.recs.at(id)
		if rec.flags&recLive == 0 {
			continue
		}
		if term == "" || strings.Contains(rec.name, term) {
			out = append(out, m.fileLocked(id, true))
		}
	}
	return out
}

// FindBySearch returns up to MaxSearchResults files matching expr.
//
// A query with no more matches than that gets them all, in id order. One with more
// gets the ones with the most sources, best first, picked from its first
// searchRankScan matches. It used to get the first MaxSearchResults in id order,
// which is publication order: one session's share has contiguous ids, so a client
// sharing thousands of files holding a common word filled that word's whole answer,
// and whatever was published later was never returned.
func (m *MemoryEngine) FindBySearch(expr *SearchExpr) []File {
	if expr == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	rank := searchRanker{expr: expr, out: make([]File, 0, 32)}
	match := &searchMatcher{}
	// The index narrows the search to candidates and every one is re-checked, so the
	// answer is the one a full scan gives. A query it cannot narrow — no indexable
	// term, or a term in too many files to be worth collecting — scans instead, which
	// for a common term reaches the scan bound early.
	ids, all := m.names.candidates(expr, max(candidateFloor, m.count/8))
	if all {
		for id := range m.recs.len() {
			if f, ok := m.matchLocked(match, expr, uint32(id)); ok && !rank.add(uint32(id), f) {
				break
			}
		}
		return rank.result()
	}
	for _, id := range ids {
		if f, ok := m.matchLocked(match, expr, id); ok && !rank.add(id, f) {
			break
		}
	}
	return rank.result()
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

func (m *MemoryEngine) RemoveServer(server Server) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	var removed bool
	m.servers, removed = removeServer(m.servers, server)
	return removed
}

func (m *MemoryEngine) ServersAll() []Server {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Server(nil), m.servers...)
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
// fails the packet otherwise (ed2k/buffer.go), as does decodeHash for fixtures.
//
// The memory engine no longer keys a map with it: its records hang off the bare hash
// (see MemoryEngine), which keeps the legacy UDP OP_GLOBGETSOURCES (0x9a), with its
// bare hashes and no size, an O(1) lookup. The cost is that two sizes of one hash
// share a source list, which GetSources filters on each source's size;
// GetSourcesByHash, the size-less lookup, returns them all. The Mirror and the
// snapshot still identify a file by this key.
func fileMapKey(hash []byte, size uint64) string {
	var buf [fileMapKeyLen]byte
	copy(buf[:hashLen], hash)
	binary.BigEndian.PutUint64(buf[hashLen:], size)
	return string(buf[:])
}

// hashArray is a file hash as the files map keys it: exactly hashLen bytes.
func hashArray(hash []byte) (key [hashLen]byte) {
	copy(key[:], hash)
	return key
}

// newMemPeer copies out of info what a source says about its client.
func newMemPeer(info ClientInfo) *memPeer {
	return &memPeer{
		storeID: info.StoreID,
		hash:    append([]byte(nil), info.Hash...),
		ipv6:    append([]byte(nil), info.IPv6...),
	}
}

// addFileLocked is AddFile's body; the caller holds m.mu for writing.
func (m *MemoryEngine) addFileLocked(file File, clientInfo ClientInfo) {
	// An offer still in flight when its session was released (replaced by a
	// re-login, or dropped) lands after Disconnect; storing it would leave sources
	// that no Disconnect will ever remove.
	storeID := clientInfo.StoreID
	if storeID == 0 {
		// Every production caller passes the StoreID Connect returned; resolve it
		// for one that does not, so its sources still leave with its Disconnect.
		storeID = m.resolveStoreIDLocked(clientInfo)
	}
	client := m.clients[storeID]
	if client == nil && clientInfo.StoreID != 0 {
		return
	}
	// Normalized here too, so all three engines agree on what a given offer
	// stores. The memory engine has no schema to violate, but a search result
	// that differs by engine is its own bug.
	file = NormalizeFile(file)
	// Completed arrives as this source's own 0/1 and Sources as whatever the client
	// claimed; both are aggregates on the way out, computed from the live sources.
	head := m.storeFileLocked(file)
	src := memSource{
		size:  file.Size,
		id:    clientInfo.ID,
		port:  clientInfo.Port,
		crypt: clientInfo.CryptOptions,
	}
	if file.Completed > 0 {
		src.flags |= srcComplete
	}
	if clientInfo.IPv6Reachable {
		src.flags |= srcIPv6Reachable
	}
	// A session's sources share its identity, which is what spares each of them a
	// copy of the user hash and the IPv6 address. An offer that names another hash
	// or address than the session connected with gets its own, as does one from a
	// caller that never connected; neither happens outside tests.
	if client != nil && bytes.Equal(client.peer.hash, clientInfo.Hash) && bytes.Equal(client.peer.ipv6, clientInfo.IPv6) {
		src.peer = client.peer
	} else {
		clientInfo.StoreID = storeID
		src.peer = newMemPeer(clientInfo)
	}
	if !m.putSourceLocked(head, src) && client != nil {
		client.offered = append(client.offered, head)
	}
}

// putSourceLocked adds src to the sources of the hash whose first record is head,
// and reports whether src's session had a source there already.
//
// It takes over the first entry that is the same session re-offering, or one left at
// this address by a session that has since gone, with refreshed crypt options and
// identity. Two live sessions behind one NAT share the ID but not the port, so they
// never collide here. The entry moves to the end, so the list stays in offer order.
func (m *MemoryEngine) putSourceLocked(head uint32, src memSource) (had bool) {
	rec := m.recs.at(head)
	if rec.first.peer == nil {
		rec.first = src
		return false
	}
	own := src.peer.storeID
	same := func(s *memSource) bool {
		return (own != 0 && s.peer.storeID == own) || (s.id == src.id && s.port == src.port)
	}
	if rec.flags&recMore == 0 {
		// One source, the common case, and no map to touch.
		if same(&rec.first) {
			had = own != 0 && rec.first.peer.storeID == own
			m.forgetOfferLocked(rec.first.peer.storeID, own, head)
			rec.first = src
			return had
		}
		m.more[head] = []memSource{src}
		rec.flags |= recMore
		return false
	}
	more := m.more[head]
	taken := -1
	if same(&rec.first) {
		taken = 0
	}
	had = own != 0 && rec.first.peer.storeID == own
	for i := range more {
		if taken < 0 && same(&more[i]) {
			taken = i + 1
		}
		had = had || (own != 0 && more[i].peer.storeID == own)
	}
	switch {
	case taken == 0:
		m.forgetOfferLocked(rec.first.peer.storeID, own, head)
		rec.first = more[0]
		more = slices.Delete(more, 0, 1)
	case taken > 0:
		m.forgetOfferLocked(more[taken-1].peer.storeID, own, head)
		more = slices.Delete(more, taken-1, taken)
	}
	m.more[head] = append(more, src)
	return had
}

// forgetOfferLocked drops head from the offered list of session owner, whose source
// there has just been taken over by session taker. Nothing to do when they are the
// same session, which is nearly always: the list keeps its entry for the new source.
func (m *MemoryEngine) forgetOfferLocked(owner, taker uint64, head uint32) {
	if owner == 0 || owner == taker {
		return
	}
	client := m.clients[owner]
	if client == nil {
		return
	}
	if i := slices.Index(client.offered, head); i >= 0 {
		client.offered = slices.Delete(client.offered, i, i+1)
	}
}

// removeSourcesOfLocked removes session storeID's sources from the hash whose first
// record is head. A stale id — a slot freed and reused since — holds none of them.
func (m *MemoryEngine) removeSourcesOfLocked(head uint32, storeID uint64) {
	rec := m.recs.at(head)
	if rec.first.peer == nil {
		return
	}
	var more []memSource
	if rec.flags&recMore != 0 {
		more = m.more[head]
		kept := more[:0]
		for _, s := range more {
			if s.peer.storeID != storeID {
				kept = append(kept, s)
			}
		}
		clear(more[len(kept):])
		more = kept
	}
	if rec.first.peer.storeID == storeID {
		if len(more) == 0 {
			rec.first = memSource{}
		} else {
			rec.first = more[0]
			more = slices.Delete(more, 0, 1)
		}
	}
	if rec.flags&recMore == 0 {
		return
	}
	if len(more) == 0 {
		delete(m.more, head)
		rec.flags &^= recMore
		return
	}
	m.more[head] = more
}

// removeAllSourcesOfLocked removes every source of session storeID by visiting
// every record: what Disconnect falls back to when it cannot trust its list.
func (m *MemoryEngine) removeAllSourcesOfLocked(storeID uint64) {
	for id := range m.recs.len() {
		m.removeSourcesOfLocked(uint32(id), storeID)
	}
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
		if c.info.ID != info.ID {
			continue
		}
		if found != 0 {
			return 0
		}
		found = id
	}
	return found
}

// findLocked returns the id of the record for (key, size).
func (m *MemoryEngine) findLocked(key [hashLen]byte, size uint64) (uint32, bool) {
	id, ok := m.files[key]
	for ok {
		rec := m.recs.at(id)
		if rec.size == size {
			return id, true
		}
		id, ok = rec.next-1, rec.next != 0
	}
	return 0, false
}

// eachSourceLocked calls fn for the sources of the hash whose first record is head,
// in offer order.
func (m *MemoryEngine) eachSourceLocked(head uint32, fn func(*memSource)) {
	rec := m.recs.at(head)
	if rec.first.peer == nil {
		return
	}
	fn(&rec.first)
	if rec.flags&recMore == 0 {
		return
	}
	more := m.more[head]
	for i := range more {
		fn(&more[i])
	}
}

// capSourcesLocked returns up to MaxWireSources of a hash's sources offered at size
// (0: any size), newest first. The MySQL and MongoDB engines get this from their
// ORDER BY time_offer DESC LIMIT 255. The memory engine used to return everything,
// which overflowed the count byte at 256, and then the oldest 255, so the newer
// sources of a popular file were never handed out. The list is in offer order: a
// new source and a re-offer are appended at the end.
func (m *MemoryEngine) capSourcesLocked(head uint32, size uint64) []Source {
	rec := m.recs.at(head)
	var more []memSource
	if rec.flags&recMore != 0 {
		more = m.more[head]
	}
	out := make([]Source, 0, min(len(more)+1, MaxWireSources))
	matches := func(s *memSource) bool { return size == 0 || s.size == 0 || s.size == size }
	for i := len(more) - 1; i >= 0 && len(out) < MaxWireSources; i-- {
		if matches(&more[i]) {
			out = append(out, more[i].source())
		}
	}
	if rec.first.peer != nil && len(out) < MaxWireSources && matches(&rec.first) {
		out = append(out, rec.first.source())
	}
	return out
}

// source is s as callers see it. The hash and the address are the session's own
// slices, shared by every source list that names it; nothing writes to them.
func (s *memSource) source() Source {
	return Source{
		ID:            s.id,
		Port:          s.port,
		UserHash:      s.peer.hash,
		CryptOptions:  s.crypt,
		IPv6:          s.peer.ipv6,
		IPv6Reachable: s.flags&srcIPv6Reachable != 0,
	}
}

// liveFieldsLocked fills a file's live fields from the sources of its hash: how many
// offer its size (0: any) and how many of them have the complete file — the
// FT_SOURCES and FT_COMPLETE_SOURCES a search result reports — and the source a
// result names, which is the newest live one, or none. A record stores none of
// this: a stored address outlives its session, after which the ID can belong to
// someone else, and a stored count is stale by the next offer.
func (m *MemoryEngine) liveFieldsLocked(f *File, head uint32) {
	f.Sources, f.Completed, f.SourceID, f.SourcePort = 0, 0, 0, 0
	size := f.Size
	rec := m.recs.at(head)
	if rec.first.peer == nil {
		return
	}
	count := func(s *memSource) {
		if size != 0 && s.size != 0 && s.size != size {
			return
		}
		f.Sources++
		if s.flags&srcComplete != 0 {
			f.Completed++
		}
		// A file stored without a size counts every source of its hash, but is
		// named only a source that offered it that way.
		if s.size == 0 || s.size == size {
			f.SourceID, f.SourcePort = s.id, s.port
		}
	}
	count(&rec.first)
	if rec.flags&recMore == 0 {
		return
	}
	more := m.more[head]
	for i := range more {
		count(&more[i])
	}
}

// fileLocked returns record id as a File with its live fields. The Hash is the
// record's own bytes unless own is set: a caller that hands the file out must own
// it, since a slot is reused once its file is gone.
func (m *MemoryEngine) fileLocked(id uint32, own bool) File {
	rec := m.recs.at(id)
	f := File{
		Hash: rec.hash[:rec.hashLen:rec.hashLen],
		Name: rec.name,
		Size: rec.size,
	}
	if own {
		f.Hash = append([]byte(nil), f.Hash...)
	}
	if rec.typ != memTypeOther {
		f.Type = memFileTypes[rec.typ]
	}
	if md := rec.media; md != nil {
		f.Title, f.Artist, f.Album, f.Codec = md.title, md.artist, md.album, md.codec
		f.Runtime, f.Bitrate, f.Meta = md.runtime, md.bitrate, md.meta
		if rec.typ == memTypeOther {
			f.Type = md.typ
		}
	}
	m.liveFieldsLocked(&f, m.headLocked(id))
	return f
}

// headLocked returns the id of the first record with record id's hash, which is
// where the hash's sources are. Nearly always that is id itself.
func (m *MemoryEngine) headLocked(id uint32) uint32 {
	if rec := m.recs.at(id); rec.flags&recSibling != 0 {
		return m.files[rec.hash]
	}
	return id
}

// setRecLocked writes file into rec, leaving its sources and its place in the hash
// chain alone.
func setRecLocked(rec *memRec, file File) {
	rec.name = file.Name
	rec.size = file.Size
	rec.hash = hashArray(file.Hash)
	rec.hashLen = uint8(min(len(file.Hash), hashLen))
	rec.flags |= recLive
	rec.typ = memTypeOther
	for i, typ := range memFileTypes {
		if typ == file.Type {
			rec.typ = uint8(i)
			break
		}
	}
	md := memMedia{
		title: file.Title, artist: file.Artist, album: file.Album, codec: file.Codec,
		runtime: file.Runtime, bitrate: file.Bitrate, meta: file.Meta,
	}
	if rec.typ == memTypeOther {
		md.typ = file.Type
	}
	if md == (memMedia{}) {
		rec.media = nil
		return
	}
	rec.media = &md
}

// storeFileLocked puts file in its record, indexing a new file's name, or a stored
// file's new name, and returns the id of the first record of its hash.
func (m *MemoryEngine) storeFileLocked(file File) (head uint32) {
	key := hashArray(file.Hash)
	head, known := m.files[key]
	last := head
	for id, ok := head, known; ok; {
		rec := m.recs.at(id)
		if rec.size == file.Size {
			m.names.renameFile(id, rec.name, file.Name)
			setRecLocked(rec, file)
			return head
		}
		last = id
		id, ok = rec.next-1, rec.next != 0
	}
	var id uint32
	if n := len(m.free); n > 0 {
		id, m.free = m.free[n-1], m.free[:n-1]
	} else {
		id = m.recs.push(memRec{})
	}
	setRecLocked(m.recs.at(id), file)
	m.count++
	m.names.indexName(id, file.Name)
	if !known {
		m.files[key] = id
		return id
	}
	m.recs.at(last).next = id + 1
	m.recs.at(id).flags |= recSibling
	return head
}

// removeRecLocked drops record id, whose hash has no source left: out of its hash
// chain, out of the count, and onto dead until the index has let go of the id.
func (m *MemoryEngine) removeRecLocked(id uint32) {
	rec := m.recs.at(id)
	if head := m.files[rec.hash]; head == id {
		if rec.next != 0 {
			m.files[rec.hash] = rec.next - 1
			m.recs.at(rec.next - 1).flags &^= recSibling
		} else {
			delete(m.files, rec.hash)
		}
	} else {
		prev := m.recs.at(head)
		for prev.next != id+1 {
			prev = m.recs.at(prev.next - 1)
		}
		prev.next = rec.next
	}
	m.names.removeFile(rec.name)
	*rec = memRec{}
	m.dead = append(m.dead, id)
	m.count--
}

// matchLocked returns record id as a File, with its live fields, when it is live and
// matches expr. The File's Hash is the record's own bytes; see fileLocked.
func (m *MemoryEngine) matchLocked(match *searchMatcher, expr *SearchExpr, id uint32) (File, bool) {
	if m.recs.at(id).flags&recLive == 0 {
		return File{}, false
	}
	// The counters are taken from the live source list: an FT_SOURCES /
	// FT_COMPLETE_SOURCES constraint must see real values.
	f := m.fileLocked(id, false)
	return f, match.match(expr, f)
}

// maintainIndexLocked drops removed files from the name index and frees their ids,
// or rebuilds the index outright once renames have left it mostly stale.
func (m *MemoryEngine) maintainIndexLocked() {
	if len(m.dead) > 0 {
		m.names.purge(func(id uint32) bool { return m.recs.at(id).flags&recLive == 0 })
		m.free = append(m.free, m.dead...)
		m.dead = m.dead[:0]
	}
	if m.names.needsRebuild() {
		m.rebuildIndexLocked()
	}
}

// rebuildIndexLocked renumbers the live records densely and indexes them afresh.
// Everything that names a record by id is renumbered with them: the hash chains,
// the files map, the source lists in more and every session's offered list.
func (m *MemoryEngine) rebuildIndexLocked() {
	// renumber[old] is the new id plus one; zero for a slot that held no file.
	renumber := make([]uint32, m.recs.len())
	var recs slab[memRec]
	for id := range m.recs.len() {
		if rec := m.recs.at(uint32(id)); rec.flags&recLive != 0 {
			renumber[id] = recs.push(*rec) + 1
		}
	}
	m.names = newNameIndex()
	for id := range recs.len() {
		rec := recs.at(uint32(id))
		if rec.next != 0 {
			rec.next = renumber[rec.next-1]
		}
		m.names.indexName(uint32(id), rec.name)
	}
	for key, head := range m.files {
		m.files[key] = renumber[head] - 1
	}
	more := make(map[uint32][]memSource, len(m.more))
	for head, sources := range m.more {
		more[renumber[head]-1] = sources
	}
	for _, client := range m.clients {
		kept := client.offered[:0]
		for _, head := range client.offered {
			if renumber[head] != 0 {
				kept = append(kept, renumber[head]-1)
			}
		}
		client.offered = kept
	}
	m.recs, m.more = recs, more
	m.dead, m.free = nil, nil
	m.layout++
}

// installFilesLocked replaces every file with files, none of them with a source, and
// rebuilds the index. The sessions stay, sourcing nothing.
func (m *MemoryEngine) installFilesLocked(files map[string]File) {
	m.files = make(map[[hashLen]byte]uint32, len(files))
	m.more = map[uint32][]memSource{}
	m.recs = slab[memRec]{}
	m.names = newNameIndex()
	m.dead, m.free = nil, nil
	m.count = 0
	m.layout++
	for _, client := range m.clients {
		client.offered = nil
	}
	for _, file := range files {
		m.storeFileLocked(file)
	}
}

// fileByKey returns the file a fileMapKey names, with its live fields.
func (m *MemoryEngine) fileByKey(key string) (File, bool) {
	if len(key) != fileMapKeyLen {
		return File{}, false
	}
	id, ok := m.findLocked(hashArray([]byte(key[:hashLen])), binary.BigEndian.Uint64([]byte(key[hashLen:])))
	if !ok {
		return File{}, false
	}
	return m.fileLocked(id, true), true
}

// browseLimit bounds a BrowseFiles page: at least one file, at most MaxBrowsePage.
func browseLimit(limit int) int {
	return min(max(limit, 1), MaxBrowsePage)
}
