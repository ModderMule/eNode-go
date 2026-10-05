package meta

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"enode/config"
	"enode/storage"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectinprocess"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
	"github.com/ModderMule/enodemeta/metahash"
	"google.golang.org/protobuf/proto"
)

// fakeDaemon is an in-process MetaIngest server: the real generated handler and
// client, connected without a socket, so the tests exercise the same calls a daemon
// answers.
type fakeDaemon struct {
	metav1connect.UnimplementedMetaIngestHandler

	mu          sync.Mutex
	entries     []*metav1.MetaEntry
	searchDelay time.Duration
	searchErr   error
	searches    []*metav1.SearchRequest
	feed        []*metav1.SubscribeResponse
	subscribes  []uint64 // after_seq of each Subscribe
	info        *metav1.GetInfoResponse
	infoErr     error
}

func (d *fakeDaemon) GetInfo(context.Context, *metav1.GetInfoRequest) (*metav1.GetInfoResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.infoErr != nil {
		return nil, d.infoErr
	}
	if d.info == nil {
		return &metav1.GetInfoResponse{}, nil
	}
	return d.info, nil
}

func (d *fakeDaemon) Search(ctx context.Context, req *metav1.SearchRequest) (*metav1.SearchResponse, error) {
	d.mu.Lock()
	d.searches = append(d.searches, req)
	delay, err, entries := d.searchDelay, d.searchErr, d.entries
	d.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return &metav1.SearchResponse{Entries: entries}, nil
}

func (d *fakeDaemon) Subscribe(ctx context.Context, req *metav1.SubscribeRequest, stream metav1connect.MetaIngestSubscribeServerStream) error {
	d.mu.Lock()
	d.subscribes = append(d.subscribes, req.GetAfterSeq())
	feed := d.feed
	d.mu.Unlock()
	for _, msg := range feed {
		if err := stream.Send(msg); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func (d *fakeDaemon) searchCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.searches)
}

func (d *fakeDaemon) client() metav1connect.MetaIngestClient {
	server := connect.NewServer()
	metav1connect.RegisterMetaIngestHandler(server, d)
	return metav1connect.NewMetaIngestClient(connect.NewClient(connectinprocess.New(server)))
}

// torrentEntry is a valid single-file torrent row, as a daemon would publish it.
func torrentEntry(name string, seeders uint32) *metav1.MetaEntry {
	id := sha1.Sum([]byte(name))
	return &metav1.MetaEntry{
		Kind:      metav1.MetaKind_META_KIND_BT_V1,
		FileIndex: 0,
		Name:      name,
		Size:      700 << 20,
		TotalSize: 700 << 20,
		Type:      "Video",
		Seeders:   seeders,
		Peers:     seeders / 2,
		Indexer:   "dht",
		CatalogId: fmt.Sprintf("bt:v1:%X", id),
		Magnet:    fmt.Sprintf("magnet:?xt=urn:btih:%x", id),
		Identity:  id[:],
		FileCount: 1,
	}
}

// packEntries is a multi-file release as a daemon sends it: the whole-set row named
// after the release, then one row per file carrying its path inside the release.
func packEntries(base *metav1.MetaEntry, paths ...string) []*metav1.MetaEntry {
	whole := proto.Clone(base).(*metav1.MetaEntry)
	whole.FileIndex = metahash.FileIndexWholeSet32
	whole.FileCount = uint32(len(paths))
	whole.Size = whole.GetTotalSize()
	whole.Magnet = ""
	out := []*metav1.MetaEntry{whole}
	for i, p := range paths {
		file := proto.Clone(whole).(*metav1.MetaEntry)
		file.FileIndex = uint32(i)
		file.FilePath = p
		file.Name = path.Base(p)
		file.Size = whole.GetTotalSize() / uint64(len(paths))
		out = append(out, file)
	}
	return out
}

// nzbEntry is a valid single-file Usenet row.
func nzbEntry(name string) *metav1.MetaEntry {
	id := sha256.Sum256([]byte(name))
	return &metav1.MetaEntry{
		Kind:      metav1.MetaKind_META_KIND_NZB,
		Name:      name,
		Size:      2 << 30,
		TotalSize: 2 << 30,
		Type:      "Video",
		Seeders:   98, // completion percent, not a source count
		Peers:     1200,
		Indexer:   "usenet-crawler",
		CatalogId: fmt.Sprintf("nzb:%X", id),
		Identity:  id[:],
		FileCount: 1,
	}
}

// kadEntry is a file as kademlia-crawler publishes it: kind 4, the file's own MD4 as
// identity, peers the sources Kad reported and seeders the complete ones.
func kadEntry(name string, sources, complete uint32) *metav1.MetaEntry {
	id := md5.Sum([]byte(name))
	return &metav1.MetaEntry{
		Kind:      metav1.MetaKind_META_KIND_ED2K,
		Name:      name,
		Size:      700 << 20,
		TotalSize: 700 << 20,
		Type:      "Video",
		Seeders:   complete,
		Peers:     sources,
		AgeDays:   4,
		Indexer:   "kad",
		CatalogId: fmt.Sprintf("ed2k:%X", id),
		Identity:  id[:],
		FileCount: 1,
	}
}

// testConfig is a loaded-and-defaulted config with the given networks on.
func testConfig(t *testing.T, torrent, usenet bool) config.MetaSearchConfig {
	t.Helper()
	cfg := config.MetaSearchConfig{}
	cfg.Torrent.Enabled = torrent
	cfg.Usenet.Enabled = usenet
	loaded, err := config.ApplyMetaSearchDefaults(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

// searcherFor builds a searcher whose networks talk to the given fake daemons.
func searcherFor(cfg config.MetaSearchConfig, daemons map[string]*fakeDaemon) *Searcher {
	return NewWithClients(cfg, func(network string, _ config.MetaNetworkConfig) metav1connect.MetaIngestClient {
		return daemons[network].client()
	})
}

// fileNames lists row names for a log line.
func fileNames(rows []storage.File) string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Name)
	}
	return strings.Join(out, ", ")
}
