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
}

type Server struct {
	IP   string
	Port uint16
}

type MemoryEngine struct {
	mu           sync.RWMutex
	nextClientID uint64
	clients      map[uint32]ClientInfo
	// clientsByHash indexes clients by user hash so IsConnected can be answered
	// on hash, as the MySQL and MongoDB engines do. The login path needs this:
	// at the point it checks, the ed2k ID is still the untrusted value supplied
	// by the client, so keying on ID would let a duplicate login through.
	clientsByHash map[string]uint32
	// files is keyed by fileMapKey (hash+size); sources by hashKey (hash alone). The two
	// key spaces differ deliberately — see fileMapKey.
	files   map[string]File
	sources map[string][]Source
	servers []Server
}

func NewMemoryEngine() *MemoryEngine {
	return &MemoryEngine{
		clients:       map[uint32]ClientInfo{},
		clientsByHash: map[string]uint32{},
		files:         map[string]File{},
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
	_, ok := m.clients[info.ID]
	return ok
}

func (m *MemoryEngine) Connect(info ClientInfo) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextClientID++
	info.StoreID = m.nextClientID
	m.clients[info.ID] = info
	if len(info.Hash) > 0 {
		m.clientsByHash[hashKey(info.Hash)] = info.ID
	}
	return info.StoreID, nil
}

func (m *MemoryEngine) Disconnect(info ClientInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.clients[info.ID]; ok && len(existing.Hash) > 0 {
		// Only drop the hash index when it still points at this session, so a
		// late Disconnect from a replaced session cannot unregister the live one.
		if id, ok := m.clientsByHash[hashKey(existing.Hash)]; ok && id == info.ID {
			delete(m.clientsByHash, hashKey(existing.Hash))
		}
	}
	delete(m.clients, info.ID)
	for k, existing := range m.sources {
		kept := existing[:0]
		for _, s := range existing {
			if s.ID != info.ID {
				kept = append(kept, s)
			}
		}
		if len(kept) == 0 {
			delete(m.sources, k)
			continue
		}
		m.sources[k] = kept
	}
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
// So this recomputes Sources from the live source lists and, when configured to,
// drops the files nobody serves. The recompute runs regardless, because a stale
// count feeds the `sources > N` search filter and the totals in OP_SEARCHRESULT.
func (m *MemoryEngine) CleanupStale(maxAge time.Duration, opts CleanupOptions) (CleanupResult, error) {
	var result CleanupResult
	if maxAge <= 0 {
		return result, fmt.Errorf("cleanup: maxAge must be positive, got %s", maxAge)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for key, file := range m.files {
		hk := key[:hashLen]
		sources := m.sources[hk]
		if len(sources) == 0 && !opts.KeepZeroSourceFiles {
			delete(m.files, key)
			// Safe across sizes: the bucket is already empty, so this cannot strip
			// another size's sources. A sibling record is reaped on its own iteration.
			delete(m.sources, hk)
			result.Files++
			continue
		}
		if file.Sources != uint32(len(sources)) {
			file.Sources = uint32(len(sources))
			m.files[key] = file
		}
	}
	return result, nil
}

func (m *MemoryEngine) AddFile(file File, clientInfo ClientInfo) {
	// Normalized here too, so all three engines agree on what a given offer
	// stores. The memory engine has no schema to violate, but a search result
	// that differs by engine is its own bug.
	file = NormalizeFile(file)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[fileMapKey(file.Hash, file.Size)] = file
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
	}
	existing := m.sources[k]
	for i, s := range existing {
		if s.ID == src.ID && s.Port == src.Port {
			// Refresh hash, crypt options and IPv6 in case the client reconnected
			// with changed settings or a new address.
			existing[i].UserHash = append([]byte(nil), src.UserHash...)
			existing[i].CryptOptions = src.CryptOptions
			existing[i].IPv6 = append([]byte(nil), src.IPv6...)
			existing[i].IPv6Reachable = src.IPv6Reachable
			m.sources[k] = existing
			return
		}
	}
	m.sources[k] = append(existing, src)
}

func (m *MemoryEngine) GetSources(fileHash []byte, fileSize uint64) []Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Existence of the composite key *is* the size check: an offer at some other size
	// now lands in its own record instead of rewriting this one's Size.
	if _, ok := m.files[fileMapKey(fileHash, fileSize)]; !ok {
		return nil
	}
	return capSources(m.sources[hashKey(fileHash)])
}

func (m *MemoryEngine) GetSourcesByHash(fileHash []byte) []Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return capSources(m.sources[hashKey(fileHash)])
}

func (m *MemoryEngine) FindByNameContains(term string) []File {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []File
	for _, f := range m.files {
		if term == "" || bytes.Contains([]byte(f.Name), []byte(term)) {
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
	for _, f := range m.files {
		if MatchSearchExpr(expr, f) {
			out = append(out, f)
			if len(out) >= MaxSearchResults {
				break
			}
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

// capSources copies and truncates to MaxWireSources. The MySQL and MongoDB
// engines get this from their LIMIT 255; the memory engine returned everything,
// and it is the default engine, so a file with 256 sources produced a count byte
// of 0 followed by 256 records.
func capSources(sources []Source) []Source {
	if len(sources) > MaxWireSources {
		sources = sources[:MaxWireSources]
	}
	return append([]Source(nil), sources...)
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
// sizes of one hash share a source list, so GetSources returns a superset where the DB
// engines return only the matching size's — see docs/server-client-communication.md.
func fileMapKey(hash []byte, size uint64) string {
	var buf [fileMapKeyLen]byte
	copy(buf[:hashLen], hash)
	binary.BigEndian.PutUint64(buf[hashLen:], size)
	return string(buf[:])
}
