package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enode/admin"
	"enode/config"
	"enode/contentfilter"
	"enode/ed2k"
	"enode/spamfilter"
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
	if err := v.AddBan("ip:203.0.113.9", 30, "shares fakes"); err != nil {
		t.Fatal(err)
	}
	bans, _ := v.Bans()
	errMissing := v.RemoveBan("ip:203.0.113.10")
	errRemove := v.RemoveBan("ip:203.0.113.9")
	t.Logf("input: ban 203.0.113.9 for 30 minutes, lift .10 then .9")
	t.Logf("output: bans=%+v missing=%v remove=%v", bans, errMissing, errRemove)
	if len(bans) != 1 || bans[0].Key != "ip:203.0.113.9" || bans[0].Reason != "shares fakes" || bans[0].RemainingSeconds < 1700 {
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

// TestAdminViewsSpam: the Spam tab shows what the detector scored through the offer
// adapter, and answers empty, with the tab off, when detection is off.
func TestAdminViewsSpam(t *testing.T) {
	v, _ := newTestViews(t, "")
	off := v.Spam()
	t.Logf("input: no detector output: feature=%t view=%+v", v.Features().Spam, off)
	if v.Features().Spam || off.Assessed != 0 || len(off.Files) != 0 || len(off.Publishers) != 0 {
		t.Fatalf("without a detector: feature=%t view=%+v, want off and empty", v.Features().Spam, off)
	}

	v.spam = spamfilter.New()
	observer := spamObserver{detector: v.spam}
	var files []storage.File
	for i := 0; i < 12; i++ {
		files = append(files, storage.File{
			Hash: bytes.Repeat([]byte{byte(0x20 + i)}, 16), Name: fmt.Sprintf("Title%d full crack keygen.zip", i),
			Size: 1_500_000, Type: "Video",
		})
	}
	session := observer.ObserveOffer(nil, bytes.Repeat([]byte{0x5a}, 16), net.IPv4(203, 0, 113, 7), files)
	again := observer.ObserveOffer(session, bytes.Repeat([]byte{0x5a}, 16), net.IPv4(203, 0, 113, 7), files[:1])

	view := v.Spam()
	t.Logf("input: 12 template-named archives claimed as video, then one again")
	t.Logf("output: feature=%t assessed=%d caution=%d files=%d first=%+v publishers=%+v",
		v.Features().Spam, view.Assessed, view.Caution, len(view.Files), view.Files[0], view.Publishers)
	if !v.Features().Spam || session == nil || again != session {
		t.Fatalf("feature=%t session=%v again=%v, want the tab on and one session state kept", v.Features().Spam, session, again)
	}
	if view.Assessed != 13 || view.Caution != 13 || len(view.Files) != 12 {
		t.Fatalf("assessed=%d caution=%d files=%d, want 13, 13 and 12 distinct files", view.Assessed, view.Caution, len(view.Files))
	}
	row := view.Files[0]
	if row.Score != 45 || row.Band != "caution" || len(row.Hash) != 32 || len(row.Reasons) != 2 {
		t.Errorf("file row = %+v, want score 45, caution, a hex hash and two reasons", row)
	}
	if len(view.Publishers) != 1 || view.Publishers[0].Address != "203.0.113.7" || view.Publishers[0].Files != 13 ||
		view.Publishers[0].Reasons[0] != "publisher_name_template +30" {
		t.Errorf("publishers = %+v, want the session once with its 13 offers and the template reason", view.Publishers)
	}
}

// TestAdminViewsSpamDecide: a button of the Spam tab puts the file on the local list
// under the name it was listed with, the file leaves the tab, and the content filter
// refuses it from then on.
func TestAdminViewsSpamDecide(t *testing.T) {
	dir := t.TempDir()
	filter, err := contentfilter.New(context.Background(), contentfilter.Config{
		LocalBanlistFile: filepath.Join(dir, "ban.txt"), LocalFilterFile: filepath.Join(dir, "filter.txt"),
		LocalWhitelistFile: filepath.Join(dir, "white.txt"),
	})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := newTestViews(t, "")
	hash := bytes.Repeat([]byte{0x21}, 16)
	if err := v.SpamDecide(hex.EncodeToString(hash), "filter"); !errors.Is(err, admin.ErrUnavailable) {
		t.Fatalf("SpamDecide without a detector and local lists = %v, want ErrUnavailable", err)
	}

	v.content, v.spam = filter, spamfilter.New()
	v.spam.SetExempt(filter.Whitelisted)
	observer := spamObserver{detector: v.spam}
	var files []storage.File
	for i := 0; i < 12; i++ {
		files = append(files, storage.File{Hash: bytes.Repeat([]byte{byte(0x20 + i)}, 16), Name: fmt.Sprintf("Title%d full crack keygen.zip", i), Size: 1_500_000})
	}
	observer.ObserveOffer(nil, nil, net.IPv4(203, 0, 113, 7), files)

	bad := v.SpamDecide("zz", "filter")
	unknown := v.SpamDecide(hex.EncodeToString(hash), "greylist")
	if err := v.SpamDecide(hex.EncodeToString(hash), "filter"); err != nil {
		t.Fatal(err)
	}
	fine := bytes.Repeat([]byte{0x22}, 16)
	if err := v.SpamDecide(hex.EncodeToString(fine), "whitelist"); err != nil {
		t.Fatal(err)
	}
	observer.ObserveOffer(nil, nil, net.IPv4(203, 0, 113, 8), files) // the same share from somebody else
	raw, _ := os.ReadFile(filepath.Join(dir, "filter.txt"))
	_, fineListed := v.spam.File(fine)
	t.Logf("input: 12 listed files; #1 put on the filter list, #2 on the whitelist, then the share offered again")
	t.Logf("output: features=%+v bad hash=%v unknown list=%v filter file=%q withheld=%t files=%d whitelistedListed=%t",
		v.Features(), bad, unknown, raw, filter.Withheld(hash, ""), len(v.Spam().Files), fineListed)
	if !v.Features().SpamLists || bad == nil || unknown == nil {
		t.Errorf("features=%+v bad=%v unknown=%v, want the buttons on and both bad requests refused", v.Features(), bad, unknown)
	}
	if !filter.Withheld(hash, "") || !strings.Contains(string(raw), "; Title1 full crack keygen.zip") {
		t.Errorf("filter file = %q, want the hash with the name it was listed under", raw)
	}
	if fineListed {
		t.Error("a whitelisted file must not be listed again")
	}
}
