package metaapi

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/ModderMule/enodemeta/bencode"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/metahash"
	"github.com/ModderMule/enodemeta/torrentmeta"
)

// fakeSource is a catalogue daemon double: catalog_id → metafile or error.
type fakeSource struct {
	mu       sync.Mutex
	files    map[string]*metav1.MetaFile
	errs     map[string]error
	networks []string
	delay    time.Duration
	calls    atomic.Int64
}

func newFakeSource() *fakeSource {
	return &fakeSource{files: map[string]*metav1.MetaFile{}, errs: map[string]error{}, networks: []string{networkTorrent}}
}

func (f *fakeSource) Networks() []string { return f.networks }

func (f *fakeSource) FetchMetaFile(ctx context.Context, network, catalogID string) (*metav1.MetaFile, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.errs[catalogID]; err != nil {
		return nil, err
	}
	if mf, ok := f.files[catalogID]; ok {
		return mf, nil
	}
	return nil, connect.NewError(connect.CodeNotFound, "no such release")
}

// testTorrent returns a .torrent and the meta hash its row would carry.
func testTorrent(t *testing.T, name string) ([]byte, metahash.Hash) {
	t.Helper()
	raw := bencode.MustEncode(map[string]any{
		"name": name, "piece length": 262144,
		"pieces": strings.Repeat("01234567890123456789", 4), "length": 1 << 30,
	})
	info, err := torrentmeta.ParseInfo(raw)
	if err != nil {
		t.Fatal(err)
	}
	kind, identity := info.Identity()
	hash, err := metahash.Mint(metahash.MintInput{Kind: kind, Identity: identity, FileIndex: 0, FileCount: info.SelectableCount()})
	if err != nil {
		t.Fatal(err)
	}
	file, err := torrentmeta.BuildTorrentFile(raw, []string{"udp://tracker.example:6969"})
	if err != nil {
		t.Fatal(err)
	}
	return file, hash
}

func newTestFetcher(src MetaFileSource) *Fetcher {
	return NewFetcher(src, time.Second, 1<<20, 1<<20, time.Hour, time.Minute)
}

func TestFetcherServesAndCaches(t *testing.T) {
	file, hash := testTorrent(t, "Good.Release.2026")
	src := newFakeSource()
	src.files["cat-1"] = &metav1.MetaFile{Content: file}
	f := newTestFetcher(src)

	for i := 0; i < 3; i++ {
		mf, err := f.Get(context.Background(), hash[:], "cat-1")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(mf.GetContent(), file) || mf.GetContentType() != "application/x-bittorrent" || mf.GetKind() != metav1.MetaKind_META_KIND_BT_V1 {
			t.Fatalf("metafile: kind=%s type=%s len=%d", mf.GetKind(), mf.GetContentType(), len(mf.GetContent()))
		}
	}
	t.Logf("input: 3 gets of %s output: daemon calls=%d cache hits=%d cached=%dB", hash, src.calls.Load(), f.Stats().CacheHits.Load(), f.CacheBytes())
	if src.calls.Load() != 1 || f.Stats().CacheHits.Load() != 2 || f.Stats().Served.Load() != 3 {
		t.Fatalf("calls=%d hits=%d served=%d, want 1 2 3", src.calls.Load(), f.Stats().CacheHits.Load(), f.Stats().Served.Load())
	}
}

func TestFetcherRejectsSubstitutedFile(t *testing.T) {
	_, hash := testTorrent(t, "Advertised.Release")
	other, _ := testTorrent(t, "Something.Else")
	src := newFakeSource()
	src.files["cat-1"] = &metav1.MetaFile{Content: other}
	f := newTestFetcher(src)

	_, err := f.Get(context.Background(), hash[:], "cat-1")
	var fe *FetchError
	t.Logf("input: a daemon answering with another torrent output: %v", err)
	if !errors.As(err, &fe) || fe.Code != connect.CodeDataLoss || fe.MsgCode != CodeVerifyFailed {
		t.Fatalf("want data_loss %s, got %v", CodeVerifyFailed, err)
	}
	// Remembered: a second ask does not reach the daemon.
	_, _ = f.Get(context.Background(), hash[:], "cat-1")
	if src.calls.Load() != 1 || f.Stats().VerifyFailed.Load() != 1 {
		t.Fatalf("calls=%d verifyFailed=%d, want 1 1", src.calls.Load(), f.Stats().VerifyFailed.Load())
	}
	if f.CacheBytes() != 0 {
		t.Fatalf("an unverified file was cached")
	}
}

func TestFetcherErrors(t *testing.T) {
	file, hash := testTorrent(t, "Err.Release")
	src := newFakeSource()
	src.errs["down"] = connect.NewError(connect.CodeUnavailable, "down")
	src.errs["wrongkind"] = connect.NewError(connect.CodeInvalidArgument, "not a torrent id")
	src.files["huge"] = &metav1.MetaFile{Content: append(bytes.Repeat([]byte{'x'}, 2<<20), file...)}
	f := newTestFetcher(src)

	nzbHash := hash
	nzbHash[3] = byte(metahash.KindNZB)<<4 | nzbHash[3]&0x0f

	cases := []struct {
		name    string
		hash    []byte
		id      string
		code    connect.Code
		msgCode string
	}{
		{"short hash", hash[:10], "x", connect.CodeInvalidArgument, CodeInvalidRequest},
		{"not a meta hash", bytes.Repeat([]byte{1}, 16), "x", connect.CodeInvalidArgument, CodeInvalidRequest},
		{"no catalog id", hash[:], "", connect.CodeInvalidArgument, CodeInvalidRequest},
		{"usenet disabled", nzbHash[:], "x", connect.CodeNotFound, CodeNotFound},
		{"missing", hash[:], "gone", connect.CodeNotFound, CodeNotFound},
		{"wrong kind at daemon", hash[:], "wrongkind", connect.CodeNotFound, CodeNotFound},
		{"daemon down", hash[:], "down", connect.CodeUnavailable, CodeUnavailable},
		{"too large", hash[:], "huge", connect.CodeResourceExhausted, CodeTooLarge},
	}
	for _, c := range cases {
		_, err := f.Get(context.Background(), c.hash, c.id)
		var fe *FetchError
		t.Logf("input: %s output: %v", c.name, err)
		if !errors.As(err, &fe) || fe.Code != c.code || fe.MsgCode != c.msgCode {
			t.Errorf("%s: got %v, want %s %s", c.name, err, c.code, c.msgCode)
		}
	}
	// "missing" is negatively cached; "down" is not, so the next try asks again.
	before := src.calls.Load()
	_, _ = f.Get(context.Background(), hash[:], "gone")
	_, _ = f.Get(context.Background(), hash[:], "down")
	if got := src.calls.Load() - before; got != 1 {
		t.Fatalf("after one not-found and one outage, %d new daemon calls, want 1 (the outage retried)", got)
	}

	var noSource *Fetcher = NewFetcher(nil, time.Second, 1<<20, 1<<20, time.Hour, time.Minute)
	if _, err := noSource.Get(context.Background(), hash[:], "x"); err == nil {
		t.Fatalf("a fetcher without meta search served something")
	}
}

func TestFetcherCollapsesConcurrentMisses(t *testing.T) {
	file, hash := testTorrent(t, "Popular.Release")
	src := newFakeSource()
	src.files["cat-1"] = &metav1.MetaFile{Content: file}
	src.delay = 50 * time.Millisecond
	f := newTestFetcher(src)

	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.Get(context.Background(), hash[:], "cat-1"); err != nil {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()
	t.Logf("input: 16 concurrent gets of one uncached file output: daemon calls=%d failures=%d", src.calls.Load(), failures.Load())
	if src.calls.Load() != 1 || failures.Load() != 0 {
		t.Fatalf("calls=%d failures=%d, want 1 0", src.calls.Load(), failures.Load())
	}
}

func TestByteCacheEvictsBySize(t *testing.T) {
	c := newByteCache(100, time.Hour)
	now := time.Now()
	for _, k := range []string{"a", "b", "c"} {
		c.put(k, &metav1.MetaFile{Content: bytes.Repeat([]byte{'x'}, 40)}, now)
	}
	_, hasA := c.get("a", now)
	_, hasC := c.get("c", now)
	t.Logf("input: 3×40B into a 100B cache output: a=%v c=%v size=%d", hasA, hasC, c.size())
	if hasA || !hasC || c.size() != 80 {
		t.Fatalf("LRU by bytes: a=%v c=%v size=%d", hasA, hasC, c.size())
	}
	if _, ok := c.get("c", now.Add(2*time.Hour)); ok {
		t.Fatalf("an expired entry was served")
	}
	c.put("big", &metav1.MetaFile{Content: bytes.Repeat([]byte{'x'}, 200)}, now)
	if _, ok := c.get("big", now); ok {
		t.Fatalf("an entry larger than the cache was stored")
	}
}
