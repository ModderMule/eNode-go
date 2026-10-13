package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"enode/admin"
	"enode/config"
	"enode/contentfilter"
	"enode/ed2k"
	"enode/storage"
)

// newTestViews builds the adapter over a memory engine, with or without a keyword
// content filter.
func newTestViews(t *testing.T, keywords string) (*adminViews, storage.Engine) {
	t.Helper()
	engine := storage.NewMemoryEngine()
	filter, err := contentfilter.New(context.Background(), contentfilter.Config{Keywords: keywords})
	if err != nil {
		t.Fatal(err)
	}
	rt := ed2k.NewServerRuntime(ed2k.TCPRuntimeConfig{}, ed2k.UDPRuntimeConfig{
		BotDetection: ed2k.BotDetectionConfig{Enabled: true},
	}, engine)
	cfg := config.Config{Name: "boot name"}
	cfg.Admin.Password = "boot-secret"
	return &adminViews{
		runtime: rt, engine: engine, served: withFilter(engine, filter), content: filter,
		configPath: "/etc/enode/enode.config.yaml",
		config:     func() config.Config { return cfg },
	}, engine
}

func offerTestFile(t *testing.T, engine storage.Engine, client storage.ClientInfo, seed byte, name string) []byte {
	t.Helper()
	hash := bytes.Repeat([]byte{seed}, 16)
	engine.AddFile(storage.File{Hash: hash, Name: name, Size: 1000 + uint64(seed)}, client)
	return hash
}

func TestAdminViewsFeaturesFollowWhatIsConfigured(t *testing.T) {
	plain, _ := newTestViews(t, "")
	filtered, _ := newTestViews(t, "blockedword")
	t.Logf("input: no filter at all, then a keyword filter")
	t.Logf("output: plain=%+v filtered=%+v", plain.Features(), filtered.Features())
	if got := plain.Features(); got != (admin.Features{Bots: true}) {
		t.Fatalf("features without any filter = %+v", got)
	}
	// Keywords are not a file, so there is nothing to reload, but bans exist.
	if got := filtered.Features(); got != (admin.Features{Bots: true, Bans: true}) {
		t.Fatalf("features with a keyword filter = %+v", got)
	}
	if _, err := plain.Bans(); !errors.Is(err, admin.ErrUnavailable) {
		t.Fatalf("bans without a content filter answered %v, want ErrUnavailable", err)
	}
	if _, err := plain.UpdateFilter(context.Background()); !errors.Is(err, admin.ErrUnavailable) {
		t.Fatalf("update without an updater answered %v, want ErrUnavailable", err)
	}
}

func TestAdminViewsFilesLeaveOutWithheldFiles(t *testing.T) {
	v, engine := newTestViews(t, "blockedword")
	client := storage.ClientInfo{ID: 0x0a0b0c0d, Port: 4662, Hash: bytes.Repeat([]byte{9}, 16)}
	storeID, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = storeID
	good := offerTestFile(t, engine, client, 1, "ubuntu linux.iso")
	offerTestFile(t, engine, client, 2, "blockedword clip.avi")

	browse, err := v.Files(admin.FileQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	search, _ := v.Files(admin.FileQuery{Search: "ubuntu", Limit: 10})
	hidden, _ := v.Files(admin.FileQuery{Search: "clip", Limit: 10})
	t.Logf("input: one ordinary file and one whose name matches the keyword filter")
	t.Logf("output: browse=%+v search(ubuntu)=%+v search(clip)=%+v", browse, search, hidden)
	if len(browse.Rows) != 1 || browse.Rows[0].Name != "ubuntu linux.iso" || browse.Rows[0].Sources != 1 {
		t.Fatalf("browse = %+v", browse)
	}
	if len(search.Rows) != 1 || len(hidden.Rows) != 0 {
		t.Fatalf("search rows: ubuntu=%d clip=%d, want 1 and 0", len(search.Rows), len(hidden.Rows))
	}

	// A keyword match is judged by name, so only the listing can hide such a file; a
	// real server never indexes it in the first place.
	sources, err := v.FileSources(strings.Repeat("01", 16))
	_, badErr := v.FileSources("xyz")
	t.Logf("input: sources of %x, and of a malformed hash", good)
	t.Logf("output: sources=%+v err=%v malformed=%v", sources, err, badErr)
	if len(sources) != 1 || sources[0].IP != "13.12.11.10" || sources[0].Port != 4662 || sources[0].LowID {
		t.Fatalf("sources = %+v", sources)
	}
	if badErr == nil {
		t.Fatalf("a malformed hash was accepted")
	}
}

func TestAdminViewsServerList(t *testing.T) {
	v, _ := newTestViews(t, "")
	errBad := v.AddServer("not-an-address", 4661)
	errAdd := v.AddServer("203.0.113.5", 4661)
	afterAdd := v.Peers().Static
	errMissing := v.RemoveServer("203.0.113.6", 4661)
	errRemove := v.RemoveServer("203.0.113.5", 4661)
	t.Logf("input: add a bad address, add 203.0.113.5:4661, remove .6 then .5")
	t.Logf("output: bad=%v add=%v list=%+v missing=%v remove=%v left=%+v", errBad, errAdd, afterAdd, errMissing, errRemove, v.Peers().Static)
	if errBad == nil || errAdd != nil || len(afterAdd) != 1 {
		t.Fatalf("add: bad=%v add=%v list=%+v", errBad, errAdd, afterAdd)
	}
	if !errors.Is(errMissing, admin.ErrNotFound) || errRemove != nil || len(v.Peers().Static) != 0 {
		t.Fatalf("remove: missing=%v remove=%v", errMissing, errRemove)
	}
}

func TestAdminViewsBansAndBlocks(t *testing.T) {
	v, _ := newTestViews(t, "blockedword")
	if err := v.AddBan("ip:203.0.113.9", 30); err != nil {
		t.Fatal(err)
	}
	bans, _ := v.Bans()
	errMissing := v.RemoveBan("ip:203.0.113.10")
	errRemove := v.RemoveBan("ip:203.0.113.9")
	t.Logf("input: ban 203.0.113.9 for 30 minutes, lift .10 then .9")
	t.Logf("output: bans=%+v missing=%v remove=%v", bans, errMissing, errRemove)
	if len(bans) != 1 || bans[0].Key != "ip:203.0.113.9" || bans[0].RemainingSeconds < 1700 {
		t.Fatalf("bans = %+v", bans)
	}
	if !errors.Is(errMissing, admin.ErrNotFound) || errRemove != nil {
		t.Fatalf("lift: missing=%v remove=%v", errMissing, errRemove)
	}

	blocks := v.Blocks()
	t.Logf("output: %d block rows, first=%+v", len(blocks), blocks[0])
	if len(blocks) != 12 {
		t.Fatalf("block rows = %d, want 12", len(blocks))
	}
	for _, b := range blocks {
		if b.Reason == "" || b.What == "" || b.Count != 0 {
			t.Errorf("block row %+v on a fresh server", b)
		}
	}
}

func TestAdminViewsConfigIsRedactedAndFollowsTheReloader(t *testing.T) {
	v, _ := newTestViews(t, "")
	bootView, err := v.Config()
	if err != nil {
		t.Fatal(err)
	}
	reloaded := config.Config{Name: "reloaded name"}
	v.setConfig(func() config.Config { return reloaded })
	afterView, _ := v.Config()
	boot, after := bootView.YAML, afterView.YAML
	t.Logf("output: path at boot=%q after reload=%q", bootView.Path, afterView.Path)
	if bootView.Path != "/etc/enode/enode.config.yaml" || afterView.Path != bootView.Path {
		t.Fatalf("the config view does not name the loaded file")
	}
	t.Logf("input: boot config with admin.password set, then a reloader config")
	t.Logf("output: boot has name=%t secret=%t mark=%t; after reload has new name=%t",
		strings.Contains(boot, "boot name"), strings.Contains(boot, "boot-secret"),
		strings.Contains(boot, config.RedactedMark), strings.Contains(after, "reloaded name"))
	if !strings.Contains(boot, "boot name") || strings.Contains(boot, "boot-secret") || !strings.Contains(boot, config.RedactedMark) {
		t.Fatalf("the boot config view is wrong")
	}
	if !strings.Contains(after, "reloaded name") {
		t.Fatalf("the view did not follow the reloader")
	}
}

func TestAdminViewsRuntimeAndHealth(t *testing.T) {
	v, _ := newTestViews(t, "")
	first := v.Runtime()
	second := v.Runtime()
	health := v.Health()
	t.Logf("input: two runtime reads in a row, then health")
	t.Logf("output: go=%s goroutines=%d heap=%d sampledAt=%s/%s storage=%+v files=%d",
		first.GoVersion, first.Goroutines, first.HeapAlloc, first.SampledAt, second.SampledAt, first.Storage, len(health.Files))
	if first.GoVersion == "" || first.HeapAlloc == 0 || first.Goroutines == 0 || len(first.Storage) == 0 {
		t.Fatalf("runtime = %+v", first)
	}
	if first.SampledAt != second.SampledAt || first.HeapAlloc != second.HeapAlloc {
		t.Fatalf("the memory figures were read twice inside the cache window")
	}
	if health.Files == nil || health.Log == nil {
		t.Fatalf("health lists must be empty, not null: %+v", health)
	}
}
