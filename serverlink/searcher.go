package serverlink

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"enode/logging"
	"enode/meta"
	"enode/storage"

	"connectrpc.com/connect/v2"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
	"github.com/ModderMule/enodemeta/model"
	"github.com/ModderMule/enodemeta/pbconv"
	"github.com/ModderMule/enodemeta/tags"
)

const (
	// downBackoff is how long a peer is left alone after an answer that will not
	// change on the next search.
	downBackoff = 30 * time.Second
	// infoTimeout and pageTimeout bound one call of a catalogue walk.
	infoTimeout = 10 * time.Second
	pageTimeout = 30 * time.Second
	// maxResets is how often one walk restarts before it is given up for this
	// round. A peer that resets every walk is rebuilding faster than it can be read.
	maxResets = 5
	// walkRetry is the wait after a walk that failed, when the interval is longer.
	walkRetry = 5 * time.Minute
	// maxNameBytes bounds a file name taken from a peer, eD2K's own limit.
	maxNameBytes = 255
)

// SearcherConfig is which servers are asked, and how.
type SearcherConfig struct {
	// Peers are the configured servers.
	Peers []ClientConfig
	// Discover returns the servers found by other means, those gossip advertises.
	// It is asked again every DiscoverEvery. May be nil.
	Discover      func() []ClientConfig
	DiscoverEvery time.Duration

	// Live asks the peers on a search. Timeout bounds one peer's answer and
	// MaxResults the files taken from it.
	Live       bool
	Timeout    time.Duration
	MaxResults int
	// CacheEntries and CacheTTL size the cache of live answers.
	CacheEntries int
	CacheTTL     time.Duration

	// Mirror keeps a copy of each peer's catalogue by walking it every Interval,
	// PageSize files a call, MaxFiles in all. A peer no walk of which completed
	// for Stale loses its copy.
	Mirror   bool
	Interval time.Duration
	MaxFiles int
	PageSize int
	Stale    time.Duration

	// NewClient builds a peer's client; nil uses NewClient. Tests replace it.
	NewClient func(ClientConfig) metav1connect.ServerSearchClient
}

// Searcher asks other servers for files: on a search, and by keeping a mirror of
// their catalogues. What it returns are plain eD2K files without a source.
type Searcher struct {
	cfg    SearcherConfig
	cache  *meta.Cache[[]storage.File]
	mirror *storage.Mirror
	// catalog answers MetaApi.Search; nil until EnableCatalog.
	catalog *catalog

	mu      sync.RWMutex
	peers   map[string]*peer
	nextID  uint32
	started bool
	ctx     context.Context
	wg      sync.WaitGroup
}

// peer is one server and what is known of it.
type peer struct {
	cfg    ClientConfig
	origin uint32
	static bool
	client metav1connect.ServerSearchClient
	cancel context.CancelFunc

	downUntil atomic.Int64
	// mirrored says a walk completed, took everything, and is not stale: the
	// mirror then answers for this peer and it is not called on a search.
	mirrored atomic.Bool

	mu          sync.Mutex
	info        model.ServerInfo
	lastError   string
	completedAt time.Time
	mirrorFiles int
	truncated   bool

	liveCalls    atomic.Int64
	liveErrors   atomic.Int64
	liveTimeouts atomic.Int64
	rows         atomic.Int64
	walks        atomic.Int64
	walkErrors   atomic.Int64
	resets       atomic.Int64
}

// PeerStats is the state of one peer, for the dashboard.
type PeerStats struct {
	URL    string
	Static bool
	// Name and Files are what the peer last said of itself.
	Name      string
	Files     uint64
	Down      bool
	LastError string

	// SearchOffered and BrowseOffered are what the peer said it serves.
	ContractVersion uint32
	SearchOffered   bool
	BrowseOffered   bool

	// Mirrored says the mirror answers for the peer; MirrorTrimmed that the
	// mirror was full and took only part of its catalogue.
	Mirrored      bool
	MirrorFiles   int
	MirrorAt      time.Time
	MirrorTrimmed bool
	Walks         int64
	WalkErrors    int64
	Resets        int64

	LiveCalls    int64
	LiveErrors   int64
	LiveTimeouts int64
	RowsServed   int64
}

// NewSearcher returns a searcher over the configured peers. Start runs the
// mirror and the discovery; without it the searcher still answers live.
func NewSearcher(cfg SearcherConfig) *Searcher {
	if cfg.NewClient == nil {
		cfg.NewClient = NewClient
	}
	if cfg.DiscoverEvery <= 0 {
		cfg.DiscoverEvery = time.Minute
	}
	s := &Searcher{cfg: cfg, peers: map[string]*peer{}}
	if cfg.Live {
		s.cache = meta.NewCache(cfg.CacheEntries, cfg.MaxResults, cfg.CacheTTL)
	}
	if cfg.Mirror {
		s.mirror = storage.NewMirror(cfg.MaxFiles)
	}
	for _, p := range cfg.Peers {
		if p.URL != "" {
			s.addPeer(p, true)
		}
	}
	return s
}

// Start runs the catalogue walks and the peer discovery until stop is called.
func (s *Searcher) Start(ctx context.Context) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.ctx, s.started = ctx, true
	for _, p := range s.peers {
		s.startWalkLocked(p)
	}
	s.mu.Unlock()

	if s.cfg.Discover != nil {
		s.discover()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			tick := time.NewTicker(s.cfg.DiscoverEvery)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					s.discover()
				}
			}
		}()
	}
	return func() {
		cancel()
		s.wg.Wait()
	}
}

// Search returns the files other servers hold for expr. A peer whose catalogue
// is mirrored is answered from the mirror; the others are asked, in parallel
// and each within the timeout, unless udp is set: a UDP search is answered from
// the mirror alone, so that one datagram never costs a call to every peer.
//
// The same file from several servers comes back once, with the largest counts.
func (s *Searcher) Search(ctx context.Context, expr *storage.SearchExpr, udp bool) []storage.File {
	q, ok := meta.BuildQuery(expr)
	if !ok {
		return nil
	}
	peers := s.peerList()
	if len(peers) == 0 {
		return nil
	}
	merged := newMerge()
	if s.mirror != nil {
		merged.add(s.mirror.Search(expr, min(s.cfg.MaxResults*len(peers), storage.MaxSearchResults)))
	}
	if s.cfg.Live && !udp {
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, p := range peers {
			if p.mirrored.Load() || p.isDown() {
				continue
			}
			wg.Add(1)
			go func(p *peer) {
				defer wg.Done()
				rows := s.live(ctx, p, q, expr)
				mu.Lock()
				merged.add(rows)
				mu.Unlock()
			}(p)
		}
		wg.Wait()
	}
	return merged.files
}

// Stats returns every peer's state, configured peers first.
func (s *Searcher) Stats() []PeerStats {
	peers := s.peerList()
	out := make([]PeerStats, 0, len(peers))
	for _, static := range []bool{true, false} {
		for _, p := range peers {
			if p.static == static {
				out = append(out, p.stats())
			}
		}
	}
	return out
}

// MirrorFiles is how many files the mirror holds, zero without one.
func (s *Searcher) MirrorFiles() int {
	if s.mirror == nil {
		return 0
	}
	return s.mirror.Len()
}

// -- internals ---------------------------------------------------------------

// live asks one peer, through the cache.
func (s *Searcher) live(ctx context.Context, p *peer, q meta.Query, expr *storage.SearchExpr) []storage.File {
	rows, err := s.cache.Get(ctx, p.cfg.URL+"\x00"+q.Key(), func() ([]storage.File, error) {
		p.liveCalls.Add(1)
		callCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
		defer cancel()
		res, err := p.client.SearchFiles(callCtx, &metav1.ServerSearchRequest{
			Query:   strings.Join(q.Terms, " "),
			Exclude: q.Exclude,
			Type:    q.FileType,
			MinSize: q.MinSize,
			MaxSize: q.MaxSize,
			Limit:   uint32(s.cfg.MaxResults),
		})
		if err != nil {
			return nil, err
		}
		return fromPeer(pbconv.ServerFilesFromProto(res.GetFiles())), nil
	})
	if err != nil {
		p.noteError(err, "search")
		return nil
	}
	// The request was narrower than the tree: an OR branch cannot be sent. The
	// tree itself decides what the client sees.
	out := make([]storage.File, 0, len(rows))
	for _, f := range rows {
		if storage.MatchSearchExpr(expr, f) {
			out = append(out, f)
		}
	}
	p.rows.Add(int64(len(out)))
	return out
}

// discover brings the peer set in line with what Discover returns now. A
// configured peer is never removed, and never replaced by a discovered one.
func (s *Searcher) discover() {
	found := map[string]ClientConfig{}
	for _, c := range s.cfg.Discover() {
		c.URL = strings.TrimRight(strings.TrimSpace(c.URL), "/")
		if c.URL != "" {
			found[c.URL] = c
		}
	}
	s.mu.Lock()
	var gone []*peer
	for url, p := range s.peers {
		if p.static {
			delete(found, url)
			continue
		}
		c, still := found[url]
		if still && c.Fingerprint == p.cfg.Fingerprint {
			delete(found, url)
			continue
		}
		// Gone, or it now advertises another certificate: either way the client
		// that was built for it is no longer the right one.
		delete(s.peers, url)
		gone = append(gone, p)
	}
	s.mu.Unlock()
	for _, p := range gone {
		if p.cancel != nil {
			p.cancel()
		}
		if s.mirror != nil {
			s.mirror.Drop(p.origin)
		}
		logging.Infof("server search: peer %s is no longer advertised", p.cfg.URL)
	}
	for _, c := range found {
		logging.Infof("server search: peer %s discovered", c.URL)
		s.addPeer(c, false)
	}
}

func (s *Searcher) addPeer(cfg ClientConfig, static bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.peers[cfg.URL]; dup {
		return
	}
	s.nextID++
	p := &peer{cfg: cfg, origin: s.nextID, static: static, client: s.cfg.NewClient(cfg)}
	s.peers[cfg.URL] = p
	if s.started {
		s.startWalkLocked(p)
	}
}

// startWalkLocked runs p's catalogue walks until the searcher stops or the peer
// is removed.
func (s *Searcher) startWalkLocked(p *peer) {
	if s.mirror == nil || p.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	p.cancel = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.walkLoop(ctx, p)
	}()
}

func (s *Searcher) walkLoop(ctx context.Context, p *peer) {
	walk := uint32(0)
	for {
		wait := s.cfg.Interval
		if err := s.walk(ctx, p, &walk); err != nil {
			if ctx.Err() != nil {
				return
			}
			p.walkErrors.Add(1)
			p.noteError(err, "catalogue walk")
			wait = min(wait, walkRetry)
			s.expire(p)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// walk reads p's whole catalogue into the mirror, then drops what p no longer
// has. walk numbers the attempts: a file is stamped with the one that saw it.
func (s *Searcher) walk(ctx context.Context, p *peer, walk *uint32) error {
	infoCtx, cancel := context.WithTimeout(ctx, infoTimeout)
	pb, err := p.client.GetServerInfo(infoCtx, &metav1.GetServerInfoRequest{})
	cancel()
	if err != nil {
		return err
	}
	info := pbconv.ServerInfoFromProto(pb)
	p.mu.Lock()
	p.info = info
	p.mu.Unlock()
	if !info.BrowseAvailable {
		return errNoBrowse
	}
	pause := time.Duration(info.BrowseMinIntervalSeconds) * time.Second

	*walk++
	var token []byte
	seen, taken, resets := 0, 0, 0
	for {
		pageCtx, cancel := context.WithTimeout(ctx, pageTimeout)
		res, err := p.client.BrowseFiles(pageCtx, &metav1.BrowseFilesRequest{PageToken: token, Limit: uint32(s.cfg.PageSize)})
		cancel()
		if err != nil {
			return err
		}
		page := pbconv.BrowsePageFromProto(res)
		if page.Reset {
			// The pages read so far are a partial view. They stay, stamped with
			// the abandoned attempt, and the walk that does complete sweeps them
			// if it does not see them again.
			p.resets.Add(1)
			if resets++; resets > maxResets {
				return errTooManyResets
			}
			*walk++
			token, seen, taken = nil, 0, 0
		} else {
			files := fromPeer(page.Files)
			seen += len(files)
			taken += s.mirror.Put(p.origin, *walk, files)
			if page.Done() {
				break
			}
			token = page.NextPageToken
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pause):
		}
	}
	removed := s.mirror.Sweep(p.origin, *walk)
	p.walks.Add(1)
	p.mu.Lock()
	p.completedAt, p.mirrorFiles, p.truncated, p.lastError = time.Now(), taken, taken < seen, ""
	p.mu.Unlock()
	// A mirror that could not take everything does not answer for the peer on
	// its own: the peer is still asked on a search.
	p.mirrored.Store(taken == seen)
	logging.Infof("server search: mirrored %s: %d files, %d removed", p.cfg.URL, taken, removed)
	return nil
}

// expire drops p's mirrored files once no walk of it has completed for Stale: a
// copy nobody has confirmed for that long is a list of files nobody vouches for.
func (s *Searcher) expire(p *peer) {
	p.mu.Lock()
	at := p.completedAt
	p.mu.Unlock()
	if at.IsZero() || time.Since(at) < s.cfg.Stale {
		return
	}
	if n := s.mirror.Drop(p.origin); n > 0 {
		logging.Warnf("server search: dropped %d mirrored files of %s: no walk completed for %s", n, p.cfg.URL, s.cfg.Stale)
	}
	p.mirrored.Store(false)
	p.mu.Lock()
	p.completedAt, p.mirrorFiles = time.Time{}, 0
	p.mu.Unlock()
}

func (s *Searcher) peerList() []*peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*peer, 0, len(s.peers))
	for _, p := range s.peers {
		out = append(out, p)
	}
	return out
}

var (
	errNoBrowse      = errors.New("the peer does not let other servers browse its catalogue")
	errTooManyResets = errors.New("the peer reset the walk too often")
)

func (p *peer) isDown() bool {
	return time.Now().UnixNano() < p.downUntil.Load()
}

// noteError records a failed call and, for an answer that will not change on
// the next search, leaves the peer alone for downBackoff.
func (p *peer) noteError(err error, what string) {
	if isTimeout(err) {
		p.liveTimeouts.Add(1)
		logging.Debugf("server search %s: %s: no answer within the deadline", p.cfg.URL, what)
		return
	}
	p.liveErrors.Add(1)
	p.mu.Lock()
	p.lastError = err.Error()
	p.mu.Unlock()
	switch connect.CodeOf(err) {
	case connect.CodeUnavailable, connect.CodeUnimplemented, connect.CodeUnauthenticated, connect.CodePermissionDenied:
		if !p.isDown() {
			logging.Warnf("server search %s: %s: %v; paused for %s", p.cfg.URL, what, err, downBackoff)
		}
		p.downUntil.Store(time.Now().Add(downBackoff).UnixNano())
	default:
		logging.Warnf("server search %s: %s: %v", p.cfg.URL, what, err)
	}
}

func (p *peer) stats() PeerStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PeerStats{
		URL: p.cfg.URL, Static: p.static,
		Name: p.info.Name, Files: p.info.Files,
		Down: p.isDown(), LastError: p.lastError,
		ContractVersion: p.info.ContractVersion,
		SearchOffered:   p.info.SearchAvailable, BrowseOffered: p.info.BrowseAvailable,
		Mirrored: p.mirrored.Load(), MirrorFiles: p.mirrorFiles, MirrorAt: p.completedAt, MirrorTrimmed: p.truncated,
		Walks: p.walks.Load(), WalkErrors: p.walkErrors.Load(), Resets: p.resets.Load(),
		LiveCalls: p.liveCalls.Load(), LiveErrors: p.liveErrors.Load(), LiveTimeouts: p.liveTimeouts.Load(),
		RowsServed: p.rows.Load(),
	}
}

// isTimeout reports whether a call ended at its deadline rather than failing.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	switch connect.CodeOf(err) {
	case connect.CodeDeadlineExceeded, connect.CodeCanceled:
		return true
	}
	return false
}

// fromPeer turns what another server sent into files this server can answer a
// client with. A peer is not trusted: a file without a proper hash or a name is
// dropped, a name is cut to eD2K's limit, and the source count is capped like a
// catalogue row's, since this server has no source to back a larger one with.
func fromPeer(files []model.ServerFile) []storage.File {
	out := make([]storage.File, 0, len(files))
	for _, f := range files {
		name := strings.ToValidUTF8(f.Name, "")
		if len(f.Hash) != 16 || name == "" || f.Size == 0 {
			continue
		}
		if len(name) > maxNameBytes {
			name = strings.ToValidUTF8(name[:maxNameBytes], "")
		}
		sources := min(f.Sources, tags.MaxSources)
		out = append(out, storage.File{
			Hash: f.Hash, Name: name, Size: f.Size, Type: f.Type,
			Sources: sources, Completed: min(f.CompleteSources, sources),
			Title: f.Title, Artist: f.Artist, Album: f.Album,
			Runtime: f.RuntimeSeconds, Bitrate: f.Bitrate, Codec: f.Codec,
		})
	}
	return out
}

// merge collects files from several servers, each once.
type merge struct {
	files []storage.File
	index map[mergeKey]int
}

// mergeKey is a file's identity: its hash and its size.
type mergeKey struct {
	hash [16]byte
	size uint64
}

func newMerge() *merge {
	return &merge{index: map[mergeKey]int{}}
}

// add takes rows, keeping the larger counts of a file already held.
func (m *merge) add(rows []storage.File) {
	for _, f := range rows {
		key := mergeKey{size: f.Size}
		copy(key.hash[:], f.Hash)
		if i, dup := m.index[key]; dup {
			m.files[i].Sources = max(m.files[i].Sources, f.Sources)
			m.files[i].Completed = max(m.files[i].Completed, f.Completed)
			continue
		}
		m.index[key] = len(m.files)
		m.files = append(m.files, f)
	}
}
